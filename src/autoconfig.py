# autoconfig.py
import subprocess
import os
import threading
import time
import log_utils
import rclone_wrapper # For RCLONE_EXE_PATH and run_rclone_command, get_remotes
import sys

logger = log_utils.get_logger("AutoConfig")

MSG_TYPE_RCLONE_OUTPUT = "rclone_output"
MSG_TYPE_PROMPT_AUTH_DIALOG = "prompt_auth_dialog"
MSG_TYPE_AUTOMATION_COMPLETE = "automation_complete"


def stream_output_for_automation(pipe, is_stderr, worker_queue_to_gui):
    try:
        for line in iter(pipe.readline, ''):
            if worker_queue_to_gui:
                worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (line, is_stderr)))
    except Exception as e: # pragma: no cover
        log_msg = f"Error streaming rclone output: {e}"
        logger.error(log_msg, exc_info=True)
        if worker_queue_to_gui:
             try:
                 worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"{log_msg}\n", True)))
             except Exception: pass


def automate_pcloud_config(remote_name,
                           worker_queue_to_gui,
                           auth_event_from_gui,
                           get_auth_result_func,
                           completion_queue_to_gui,
                           get_detected_auth_url_func,
                           config_password=None
                           ):
    logger.info(f"Starting automated pCloud config for remote: '{remote_name}'")
    if worker_queue_to_gui:
        worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"--- Starting pCloud configuration for '{remote_name}' ---\n", False)))

    process = None
    stdout_thread = stderr_thread = None
    final_rc = -1 # Default to a non-zero to indicate issues if not set later
    operation_considered_complete = False
    user_cancelled_auth_flag = False

    try:
        command_args_for_rclone = ["config"]
        process = rclone_wrapper.run_rclone_command(
            command_args_for_rclone, capture_output=False,
            is_config_command=True,
            gui_log_func=None, # Output is streamed directly by this function's threads
            config_password=config_password
        )
        if not isinstance(process, subprocess.Popen):
            error_msg_from_rclone_run = str(process) # run_rclone_command returns error string on failure before Popen
            logger.error(f"Failed to start rclone config process. run_rclone_command reported: {error_msg_from_rclone_run}")
            if worker_queue_to_gui:
                worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"ERROR: Could not start rclone config: {error_msg_from_rclone_run}\nIs rclone.exe available and not blocked by antivirus?\n", True)))
            if completion_queue_to_gui:
                completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, False))
            return


        stdout_thread = threading.Thread(target=stream_output_for_automation, args=(process.stdout, False, worker_queue_to_gui))
        stderr_thread = threading.Thread(target=stream_output_for_automation, args=(process.stderr, True, worker_queue_to_gui))
        for t in [stdout_thread, stderr_thread]: t.daemon = True; t.start()

        initial_inputs = ["n", remote_name, "pcloud", "", "", "n", "y"] # "y" is for "Use auto config?"

        for item_idx, item_to_send in enumerate(initial_inputs):
            if process.poll() is not None: # Check if process terminated prematurely
                log_detail = f"Rclone process ended prematurely (before input {item_idx+1}: {repr(item_to_send)})."
                if process.returncode is not None: # pragma: no branch
                    log_detail += f" RC: {process.returncode}"
                time.sleep(0.2) # Give stream threads a moment to catch trailing output
                raise Exception(log_detail)

            logger.debug(f"Automate PCloud: Sending input {item_idx+1}: {repr(item_to_send)}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Sending to rclone: {repr(item_to_send)}\n", False)))
            try:
                process.stdin.write(item_to_send + "\n"); process.stdin.flush()
            except BrokenPipeError: # pragma: no cover
                raise Exception(f"BrokenPipeError sending input {repr(item_to_send)} to rclone. Rclone might have exited (e.g. config password issue or other error).")
            time.sleep(0.8) # Wait for rclone to process the input

        if process.poll() is not None: # pragma: no cover
            raise Exception("Rclone process ended after initial inputs, before auth prompt stage.")

        logger.info("Automate PCloud: Requesting GUI to show browser auth dialog.")
        detected_auth_url_for_dialog = get_detected_auth_url_func()
        if worker_queue_to_gui:
             worker_queue_to_gui.put((MSG_TYPE_PROMPT_AUTH_DIALOG, detected_auth_url_for_dialog))

        auth_event_from_gui.wait(timeout=360) # Wait for user to interact with GUI dialog (6 minutes)

        if not auth_event_from_gui.is_set(): # pragma: no cover
            raise Exception("User did not respond to browser authorization dialog within timeout (6 minutes).")

        auth_success = get_auth_result_func()
        auth_event_from_gui.clear()

        if auth_success:
            logger.info("Automate PCloud: User confirmed successful browser auth. Sending final 'y' to save config.")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,("--- Browser auth reported SUCCESS by user. Sending save command... ---\n", False)))

            if process.poll() is None:
                try:
                    process.stdin.write("y\n"); process.stdin.flush()
                    operation_considered_complete = True # Set flag *after* sending final 'y'
                    time.sleep(0.5)

                    if process.poll() is None: # If rclone is still running (back at config menu)
                        logger.info("Automate PCloud: Sending 'q' to quit rclone config.")
                        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,("Sending to rclone: 'q' (to quit config)\n", False)))
                        process.stdin.write("q\n"); process.stdin.flush()
                        time.sleep(0.5)
                    else: # pragma: no cover
                        logger.warning("Automate PCloud: Rclone process terminated after save, before 'q' could be sent. This is usually OK if RC is 0.")
                except BrokenPipeError: # pragma: no cover
                    if operation_considered_complete:
                        logger.info("Automate PCloud: BrokenPipeError after sending 'y' (save) or 'q' (quit). Rclone might have exited normally.")
                    else:
                        raise Exception("BrokenPipeError sending final 'y' (save remote) or 'q' (quit) to rclone.")
            else: # pragma: no cover
                raise Exception("Rclone process terminated before final 'y' (save remote) could be sent after auth success.")
        else:
            user_cancelled_auth_flag = True
            raise Exception("UserCancelledAuth")

    except Exception as e:
        is_user_cancel = str(e) == "UserCancelledAuth"
        log_level_for_error = logging.INFO if is_user_cancel else logging.ERROR
        logger.log(log_level_for_error, f"Automate PCloud: {'User cancelled authentication.' if is_user_cancel else f'Error during automation: {e}'}", exc_info=not is_user_cancel)

        if worker_queue_to_gui:
            user_message = "Automation cancelled by user." if is_user_cancel else f"ERROR during automation: {e}"
            worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"{user_message}\n", not is_user_cancel)))


    finally:
        current_exception = sys.exc_info()[1]
        if isinstance(current_exception, Exception) and str(current_exception) == "UserCancelledAuth": # pragma: no branch
            user_cancelled_auth_flag = True

        success_flag_for_callback = False

        if process:
            if process.stdin and not process.stdin.closed:
                try:
                    process.stdin.close()
                except Exception as e_stdin_close: # pragma: no cover
                    logger.debug(f"Automate PCloud: Exception closing process.stdin in finally: {e_stdin_close}")

            if process.poll() is None:
                if user_cancelled_auth_flag: # pragma: no branch
                    logger.info("Automate PCloud: Terminating rclone config due to user auth cancellation/failure.")
                    if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,("--- User indicated auth failed/cancelled. Terminating rclone config process... ---\n", True)))
                    process.terminate()
                elif not operation_considered_complete : # pragma: no cover
                    logger.warning("Automate PCloud: Terminating rclone config due to an earlier error before explicit completion.")
                    process.terminate()
            
            try:
                if process.poll() is None: # pragma: no cover
                    logger.info(f"Automate PCloud: Waiting for rclone config process to exit (timeout 10s). UserCancelled: {user_cancelled_auth_flag}, OpComplete: {operation_considered_complete}")
                    process.wait(timeout=10)
            except subprocess.TimeoutExpired: # pragma: no cover
                logger.warning("Automate PCloud: Rclone process did not exit after wait. Killing.")
                process.kill()
            except Exception as e_wait_generic: # pragma: no cover
                 logger.error(f"Automate PCloud: Exception during process.wait(): {e_wait_generic}", exc_info=True)


            final_rc = process.returncode if process.returncode is not None else -999
            logger.info(f"Automate PCloud: Rclone config process ended with RC: {final_rc}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"\n--- Rclone config process finished (RC: {final_rc}) ---\n", False)))

            if final_rc == 0 and operation_considered_complete:
                success_flag_for_callback = True
            elif operation_considered_complete and final_rc != 0: # pragma: no cover
                logger.info(f"Automate PCloud: RC was {final_rc} after operation was considered complete. Verifying remote '{remote_name}' creation...")
                time.sleep(0.5)
                if remote_name in rclone_wrapper.get_remotes(config_password=config_password):
                    logger.info(f"Automate PCloud: Remote '{remote_name}' WAS created successfully despite non-zero RC ({final_rc}) after quit command.")
                    success_flag_for_callback = True
                else:
                    logger.warning(f"Automate PCloud: Remote '{remote_name}' was NOT found after non-zero RC ({final_rc}). Config likely failed.")

            if user_cancelled_auth_flag:
                success_flag_for_callback = False
                logger.info(f"Automate PCloud: User cancelled. Attempting to delete remote '{remote_name}' if it was partially created.")
                if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Attempting to delete remote '{remote_name}' due to auth cancellation...\n", False)))

                def gui_log_for_delete(msg, err=False):
                    if worker_queue_to_gui:
                        try: # pragma: no branch
                            worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (msg if msg.endswith('\n') else msg + "\n", err)))
                        except Exception: pass

                del_cmd_args = ["config", "delete", remote_name]
                del_stdout, del_stderr, del_rc = rclone_wrapper.run_rclone_command(
                    del_cmd_args,
                    capture_output=True,
                    gui_log_func=gui_log_for_delete,
                    config_password=config_password
                )
                logger.info(f"Delete attempt for '{remote_name}' after cancellation: RC={del_rc}\nOut: {del_stdout}\nErr: {del_stderr}")
                if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Delete result for '{remote_name}': RC={del_rc} (0 means deleted or not found)\n", (del_rc!=0))))


        if stdout_thread and stdout_thread.is_alive(): stdout_thread.join(timeout=2) # pragma: no cover
        if stderr_thread and stderr_thread.is_alive(): stderr_thread.join(timeout=2) # pragma: no cover
        if stdout_thread and stdout_thread.is_alive(): logger.warning("stdout_thread still alive after join attempt.") # pragma: no cover
        if stderr_thread and stderr_thread.is_alive(): logger.warning("stderr_thread still alive after join attempt.") # pragma: no cover

        if completion_queue_to_gui:
             try:
                 completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, success_flag_for_callback))
             except Exception as e_queue_put: # pragma: no cover
                 logger.error(f"Automate PCloud: Failed to put completion message on queue: {e_queue_put}")
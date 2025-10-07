import subprocess
import os
import threading
import time
import log_utils
import rclone_wrapper
import sys
import logging

logger = log_utils.get_logger("AutoConfig")

MSG_TYPE_RCLONE_OUTPUT = "rclone_output"
MSG_TYPE_PROMPT_AUTH_DIALOG = "prompt_auth_dialog"
MSG_TYPE_AUTOMATION_COMPLETE = "automation_complete"

DEFAULT_PASSWORD_STRENGTH_BITS = "128"

def stream_output_for_automation(pipe, is_stderr, worker_queue_to_gui):
    try:
        for line in iter(pipe.readline, ''):
            if worker_queue_to_gui:
                worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (line, is_stderr)))
    except Exception as e: 
        log_msg = f"Error streaming rclone output: {e}"
        logger.error(log_msg, exc_info=True)
        if worker_queue_to_gui:
             try:
                 worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"{log_msg}\n", True)))
             except Exception: pass


def automate_pcloud_config(remote_name, worker_queue_to_gui, auth_event_from_gui, get_auth_result_func, completion_queue_to_gui, get_detected_auth_url_func, config_password=None ):
    logger.info(f"Starting automated pCloud config for remote: '{remote_name}'")
    if worker_queue_to_gui:
        worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"--- Starting pCloud configuration for '{remote_name}' ---\n", False)))
    process = None
    stdout_thread = stderr_thread = None
    final_rc = -1 
    operation_considered_complete = False
    user_cancelled_auth_flag = False 
    try:
        command_args_for_rclone = ["config"]
        process = rclone_wrapper.run_rclone_command(command_args_for_rclone, capture_output=False,is_config_command=True,gui_log_func=None, config_password=config_password)
        if not isinstance(process, subprocess.Popen):
            error_msg_from_rclone_run = str(process)
            logger.error(f"Failed to start rclone config process. run_rclone_command reported: {error_msg_from_rclone_run}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"ERROR: Could not start rclone config: {error_msg_from_rclone_run}\nIs rclone executable available and not blocked by antivirus?\n", True)))
            if completion_queue_to_gui: completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, (False, "pCloud")))
            return
        stdout_thread = threading.Thread(target=stream_output_for_automation, args=(process.stdout, False, worker_queue_to_gui))
        stderr_thread = threading.Thread(target=stream_output_for_automation, args=(process.stderr, True, worker_queue_to_gui))
        for t in [stdout_thread, stderr_thread]: t.daemon = True; t.start()
        initial_inputs = ["n", remote_name, "pcloud", "", "", "n", "y"] 
        for item_idx, item_to_send in enumerate(initial_inputs):
            if process.poll() is not None:
                log_detail = f"Rclone process ended prematurely (before input {item_idx+1}: {repr(item_to_send)})."
                if process.returncode is not None: log_detail += f" RC: {process.returncode}"
                time.sleep(0.2); raise Exception(log_detail)
            logger.debug(f"Automate PCloud: Sending input {item_idx+1}: {repr(item_to_send)}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Sending to rclone: {repr(item_to_send)}\n", False)))
            try: process.stdin.write(item_to_send + "\n"); process.stdin.flush()
            except BrokenPipeError: raise Exception(f"BrokenPipeError sending input {repr(item_to_send)} to rclone. Rclone might have exited.")
            time.sleep(0.8)
        if process.poll() is not None: raise Exception("Rclone process ended after initial inputs, before auth prompt stage.")
        logger.info("Automate PCloud: Requesting GUI to show browser auth dialog.")
        detected_auth_url_for_dialog = get_detected_auth_url_func()
        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_PROMPT_AUTH_DIALOG, detected_auth_url_for_dialog))
        auth_event_from_gui.wait(timeout=360)
        if not auth_event_from_gui.is_set(): raise Exception("User did not respond to browser authorization dialog within timeout (6 minutes).")
        auth_success = get_auth_result_func()
        auth_event_from_gui.clear()
        if auth_success:
            logger.info("Automate PCloud: User confirmed successful browser auth. Sending final 'y' to save config.")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,("--- Browser auth reported SUCCESS by user. Sending save command... ---\n", False)))
            if process.poll() is None:
                try:
                    process.stdin.write("y\n"); process.stdin.flush()
                    operation_considered_complete = True; time.sleep(0.5)
                    if process.poll() is None: 
                        logger.info("Automate PCloud: Sending 'q' to quit rclone config.")
                        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,("Sending to rclone: 'q' (to quit config)\n", False)))
                        process.stdin.write("q\n"); process.stdin.flush(); time.sleep(0.5)
                    else: logger.warning("Automate PCloud: Rclone process terminated after save, before 'q' could be sent. RC: %s", process.returncode)
                except BrokenPipeError: 
                    if operation_considered_complete: logger.info("Automate PCloud: BrokenPipeError after sending 'y' or 'q'. Rclone might have exited normally.")
                    else: raise Exception("BrokenPipeError sending final 'y' or 'q' to rclone.")
            else: raise Exception("Rclone process terminated before final 'y' could be sent after auth success.")
        else: user_cancelled_auth_flag = True; raise Exception("UserCancelledAuth") 
    except Exception as e:
        is_user_cancel = str(e) == "UserCancelledAuth"
        log_level = logging.INFO if is_user_cancel else logging.ERROR
        logger.log(log_level, f"Automate PCloud: {'User cancelled.' if is_user_cancel else 'Error:'} {e}", exc_info=not is_user_cancel)
        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"{'Cancelled by user.' if is_user_cancel else f'ERROR: {e}'}\n", not is_user_cancel)))
    finally:
        if isinstance(sys.exc_info()[1], Exception) and str(sys.exc_info()[1]) == "UserCancelledAuth": user_cancelled_auth_flag = True
        success_flag = False 
        if process:
            if process.stdin and not process.stdin.closed:
                try: process.stdin.close()
                except Exception: pass 
            if process.poll() is None and (user_cancelled_auth_flag or not operation_considered_complete) : 
                reason = "user auth cancellation" if user_cancelled_auth_flag else "earlier error"
                logger.info(f"Automate PCloud: Terminating rclone config due to {reason}.")
                if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"--- Terminating rclone config due to {reason}... ---\n", True)))
                process.terminate()
            try:
                if process.poll() is None: logger.info("Automate PCloud: Waiting for rclone config process to exit (10s)."); process.wait(timeout=10)
            except subprocess.TimeoutExpired: logger.warning("Automate PCloud: Rclone timed out. Killing."); process.kill()
            except Exception as e: logger.error("Automate PCloud: Wait exception: %s", e, exc_info=True)
            final_rc = process.returncode if process.returncode is not None else -999 
            logger.info(f"Automate PCloud: Rclone config ended with RC: {final_rc}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"\n--- Rclone config finished (RC: {final_rc}) ---\n", False)))
            if final_rc == 0 and operation_considered_complete: success_flag = True
            elif operation_considered_complete and final_rc != 0: 
                logger.info(f"PCloud: RC {final_rc} after op complete. Verifying '{remote_name}'...")
                if remote_name in rclone_wrapper.get_remotes(config_password=config_password):
                    logger.info(f"PCloud: Remote '{remote_name}' created despite non-zero RC. Success."); success_flag = True
                else: logger.warning(f"PCloud: Remote '{remote_name}' NOT found after non-zero RC. Failed.")
            if user_cancelled_auth_flag: 
                success_flag = False 
                logger.info(f"PCloud: Attempting to delete '{remote_name}' due to user cancellation.")
                if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Attempting delete of '{remote_name}'...\n", False)))
                def gui_log_del_safe(msg, err=False):
                    if worker_queue_to_gui:
                        worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (msg + "\n", err)))
                del_o, del_e, del_rc = rclone_wrapper.run_rclone_command(["config", "delete", remote_name], True, gui_log_del_safe, False, config_password)
                logger.info(f"Delete of '{remote_name}': RC={del_rc}\nOut:{del_o}\nErr:{del_e}")
                if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Delete result for '{remote_name}': RC={del_rc}\n", (del_rc!=0))))
        if stdout_thread and stdout_thread.is_alive(): stdout_thread.join(timeout=2)
        if stderr_thread and stderr_thread.is_alive(): stderr_thread.join(timeout=2)
        if stdout_thread and stdout_thread.is_alive(): logger.warning("PCloud stdout_thread still alive.")
        if stderr_thread and stderr_thread.is_alive(): logger.warning("PCloud stderr_thread still alive.")
        if completion_queue_to_gui:
             try: completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, (success_flag, "pCloud")))
             except Exception as e: logger.error("PCloud: Failed to put completion on queue: %s", e)


def automate_crypt_config(remote_name,
                          target_remote, 
                          filename_encryption_gui_choice, 
                          directory_name_encryption_gui_choice,
                          password_main_value,
                          worker_queue_to_gui,
                          completion_queue_to_gui,
                          config_password=None
                          ):
    logger.info(f"Starting Crypt config: '{remote_name}', target: '{target_remote}', fn_encrypt: '{filename_encryption_gui_choice}', dir_encrypt: {directory_name_encryption_gui_choice}")
    if worker_queue_to_gui:
        worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"--- Starting Crypt configuration for '{remote_name}' ---\n", False)))

    process = None
    stdout_thread = stderr_thread = None
    final_rc = -1
    operation_considered_complete = False 

    try:
        process = rclone_wrapper.run_rclone_command(
            ["config"], capture_output=False, is_config_command=True,
            gui_log_func=None, config_password=config_password
        )
        if not isinstance(process, subprocess.Popen):
            logger.error(f"Failed to start rclone config for Crypt. Reported: {str(process)}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"ERROR: Could not start rclone config: {str(process)}\n", True)))
            if completion_queue_to_gui: completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, (False, "Crypt")))
            return

        stdout_thread = threading.Thread(target=stream_output_for_automation, args=(process.stdout, False, worker_queue_to_gui))
        stderr_thread = threading.Thread(target=stream_output_for_automation, args=(process.stderr, True, worker_queue_to_gui))
        for t in [stdout_thread, stderr_thread]: t.daemon = True; t.start()

        fn_encrypt_rclone_map = {"standard": "1", "obfuscate": "2", "off": "3"}
        fn_encrypt_input = fn_encrypt_rclone_map.get(filename_encryption_gui_choice, "1") 

        dir_encrypt_input = "1" if directory_name_encryption_gui_choice else "2"
        main_password_choice_rclone = "y"
        salt_choice_rclone = "n"

        inputs = [
            "n",
            remote_name,
            "crypt",
            target_remote, 
            fn_encrypt_input,
            dir_encrypt_input,
            main_password_choice_rclone,
            password_main_value,
            password_main_value,
            salt_choice_rclone,
            "n",
            "y"
        ]
        
        current_input_description = "Initial inputs"
        for item_idx, item_to_send in enumerate(inputs):
            if process.poll() is not None:
                log_detail = f"Rclone process ended prematurely (Crypt: before {current_input_description}, input {item_idx+1}: {repr(item_to_send)}). RC: {process.returncode}"
                time.sleep(0.3); raise Exception(log_detail)
            
            is_pw_field = (item_to_send == password_main_value and inputs[item_idx-1] == 'y')
            
            log_item_display = '********' if is_pw_field else item_to_send
            gui_item_display = log_item_display
            
            idx_of_main_pw_choice = inputs.index(main_password_choice_rclone)
            if item_idx <= idx_of_main_pw_choice : current_input_description = f"option/choice {item_idx+1}"
            elif item_idx <= idx_of_main_pw_choice + 2: current_input_description = "main password value/confirm"
            elif item_idx == idx_of_main_pw_choice + 3 : current_input_description = "salt choice 'n'"
            elif item_to_send == "y" and item_idx == len(inputs)-1: current_input_description = "final 'y' confirmation"
            else: current_input_description = "other option"
            
            logger.debug(f"Automate Crypt: Sending input {item_idx+1} ('{current_input_description}'): {repr(log_item_display)}")
            if worker_queue_to_gui:
                worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"Sending to rclone: {repr(gui_item_display)}\n", False)))
            try:
                process.stdin.write(item_to_send + "\n"); process.stdin.flush()
            except BrokenPipeError: 
                time.sleep(0.3) 
                rc_pipe_err = process.poll()
                raise Exception(f"BrokenPipeError sending for '{current_input_description}' ({repr(log_item_display)}). Rclone exited? RC: {rc_pipe_err}")
            time.sleep(1.5) 

        operation_considered_complete = True 
        logger.info(f"Automate Crypt: All config inputs for '{remote_name}' sent. Awaiting rclone.")
        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"--- Config for '{remote_name}' sent. Awaiting rclone... ---\n", False)))
        time.sleep(2.5) 

        if process.poll() is None: 
            logger.info(f"Automate Crypt: Sending 'q' to quit rclone config for '{remote_name}'.")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"Sending to rclone: 'q'\n", False)))
            try:
                process.stdin.write("q\n"); process.stdin.flush()
                time.sleep(1.0) 
            except BrokenPipeError: 
                logger.info(f"Automate Crypt: BrokenPipeError sending 'q' for '{remote_name}'. Rclone likely exited after 'y'.")
        else: 
            rc_after_y = process.returncode
            logger.warning(f"Automate Crypt: Rclone terminated after save for '{remote_name}' (RC: {rc_after_y}), before 'q'. OK if RC=0.")
            if rc_after_y != 0: operation_considered_complete = False; logger.error(f"Crypt: Rclone exited with error {rc_after_y} after 'y'.")

    except Exception as e:
        logger.error(f"Automate Crypt: Error during automation for '{remote_name}': {e}", exc_info=True)
        if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT, (f"ERROR Crypt automation: {e}\n", True)))
        operation_considered_complete = False 
    finally:
        success_flag = False 
        if process:
            if process.stdin and not process.stdin.closed:
                try: process.stdin.close()
                except Exception: pass 
            if process.poll() is None and not operation_considered_complete : 
                logger.warning(f"Automate Crypt: Terminating rclone for '{remote_name}' due to error."); process.terminate()
            try: 
                if process.poll() is None: logger.info(f"Crypt: Waiting for rclone for '{remote_name}' (10s)."); process.wait(timeout=10)
            except subprocess.TimeoutExpired: logger.warning(f"Crypt: Rclone for '{remote_name}' timed out. Killing."); process.kill()
            except Exception as e: logger.error(f"Crypt: Wait for '{remote_name}' exception: {e}", exc_info=True)
            final_rc = process.returncode if process.returncode is not None else -998 
            logger.info(f"Automate Crypt: Rclone config for '{remote_name}' ended, RC: {final_rc}")
            if worker_queue_to_gui: worker_queue_to_gui.put((MSG_TYPE_RCLONE_OUTPUT,(f"\n--- Rclone Crypt config for '{remote_name}' finished (RC: {final_rc}) ---\n", False)))
            
            if operation_considered_complete and final_rc == 0:
                success_flag = True
                logger.info(f"Crypt: Configured '{remote_name}' (RC=0, op_complete=True).")
            elif operation_considered_complete and final_rc != 0: 
                logger.warning(f"Crypt: RC for '{remote_name}' was {final_rc} after op_complete. Verifying...")
                time.sleep(0.5) 
                if remote_name in rclone_wrapper.get_remotes(config_password=config_password):
                    stdout_ls, stderr_ls, list_rc = rclone_wrapper.list_files(f"{remote_name}:", gui_log_func=None, config_password=config_password)
                    if list_rc == 0 or "directory not found" in stderr_ls.lower() or (not stdout_ls and not stderr_ls): 
                         logger.info(f"Crypt: Remote '{remote_name}' created and seems accessible despite config RC={final_rc}. Success.")
                         success_flag = True 
                    else:
                         logger.error(f"Crypt: Remote '{remote_name}' created but not accessible (lsjson RC={list_rc}, stderr='{stderr_ls}'). Passwords likely NOT set. FAILED.")
                         success_flag = False
                else: 
                    logger.error(f"Crypt: Remote '{remote_name}' NOT found after RC={final_rc}. FAILED.")
                    success_flag = False
            else: 
                 logger.error(f"Crypt: Op for '{remote_name}' failed or not complete. RC: {final_rc}. FAILED.")
                 success_flag = False
        
        if stdout_thread and stdout_thread.is_alive(): stdout_thread.join(timeout=2)
        if stderr_thread and stderr_thread.is_alive(): stderr_thread.join(timeout=2)
        if stdout_thread and stdout_thread.is_alive(): logger.warning(f"Crypt stdout for {remote_name} alive.")
        if stderr_thread and stderr_thread.is_alive(): logger.warning(f"Crypt stderr for {remote_name} alive.")
        
        if completion_queue_to_gui:
            try: completion_queue_to_gui.put((MSG_TYPE_AUTOMATION_COMPLETE, (success_flag, "Crypt")))
            except Exception as e: logger.error(f"Crypt: Failed to put completion on queue for '{remote_name}': {e}")
import subprocess
import os
import shutil
import log_utils
import json
import sys

logger = log_utils.get_logger("RcloneWrapper")

if sys.platform == "win32":
    RCLONE_EXE_NAME = "rclone.exe"
else:
    RCLONE_EXE_NAME = "rclone"

RCLONE_EXE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), RCLONE_EXE_NAME)

if not os.path.exists(RCLONE_EXE_PATH):
    found_in_path = shutil.which(RCLONE_EXE_NAME)
    if found_in_path:
        RCLONE_EXE_PATH = found_in_path
    else:
        logger.error(f"{RCLONE_EXE_NAME} not found at application start. Subsequent calls might fail if it's not placed correctly or in PATH.")


def run_rclone_command(command_args, capture_output=True, gui_log_func=None, is_config_command=False, config_password=None):
    if not os.path.exists(RCLONE_EXE_PATH):
        err_msg = f"Error: {RCLONE_EXE_NAME} not found at {RCLONE_EXE_PATH}. " \
                  f"Please place it in the script's directory or ensure it's in your system PATH."
        log_utils.app_log(err_msg, level="error", gui_log_func=gui_log_func, log_to_gui=True)
        if is_config_command and not capture_output:
            return f"Error: Rclone executable not found: {RCLONE_EXE_PATH}"
        return "", err_msg, -1

    current_env = os.environ.copy()
    if config_password:
        current_env["RCLONE_CONFIG_PASS"] = config_password

    try:
        cmd_list = [RCLONE_EXE_PATH] + command_args
        log_utils.app_log(f"Executing rclone command: rclone {' '.join(command_args)}",
                          gui_log_func=gui_log_func,
                          log_to_gui=capture_output)
        
        popen_kwargs = {"env": current_env}
        if sys.platform == "win32":
            popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        if is_config_command and not capture_output:
            process = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace',
                bufsize=1,
                **popen_kwargs
            )
            return process

        if capture_output:
            process = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace',
                **popen_kwargs
            )
            stdout, stderr = process.communicate()
            return_code = process.returncode
        else:
            process = subprocess.Popen(cmd_list, **popen_kwargs)
            stdout, stderr = "", "" 
            return_code = process.pid

        if stdout and capture_output:
            log_utils.app_log(f"Rclone stdout:\n{stdout.strip()}", gui_log_func=gui_log_func, log_to_gui=True)
        if stderr and capture_output:
            log_utils.app_log(f"Rclone stderr:\n{stderr.strip()}", level="error", gui_log_func=gui_log_func, log_to_gui=True)

        if capture_output and return_code != 0:
             log_utils.app_log(f"Rclone command finished with error code: {return_code}", level="error", gui_log_func=gui_log_func, log_to_gui=True)

        return stdout, stderr, return_code
    except FileNotFoundError:
        err_msg = f"Critical Error: {RCLONE_EXE_NAME} somehow not found when trying to execute (path: {RCLONE_EXE_PATH})."
        log_utils.app_log(err_msg, level="critical", gui_log_func=gui_log_func, log_to_gui=True)
        if is_config_command and not capture_output:
            return f"Error: Rclone executable FileNotFoundError during Popen: {RCLONE_EXE_PATH}"
        return "", err_msg, -1
    except Exception as e:
        err_msg = f"An unexpected error occurred while running rclone: {e}"
        log_utils.app_log(err_msg, level="error", gui_log_func=gui_log_func, log_to_gui=True)
        logger.error("Rclone execution exception details:", exc_info=True)
        if is_config_command and not capture_output:
            return f"Popen failed for config: {str(e)}"
        return "", str(e), -1


def get_remotes(gui_log_func=None, config_password=None):
    stdout, stderr, return_code = run_rclone_command(
        ["listremotes"],
        capture_output=True,
        gui_log_func=gui_log_func,
        config_password=config_password
    )
    if return_code == 0 and stdout:
        return [line.strip().replace(":", "") for line in stdout.strip().split('\n') if line.strip()]
    if return_code != 0 and stderr:
        logger.warning(f"get_remotes failed. RC: {return_code}, Stderr: {stderr.strip()}")
    return []

def list_files(path, gui_log_func=None, config_password=None):
    if not path:
        log_utils.app_log("list_files: Path cannot be empty.", level="error", gui_log_func=gui_log_func, log_to_gui=True)
        return [], "Path cannot be empty.", -1
    
    cmd = ["lsjson", path]
    stdout, stderr, return_code = run_rclone_command(
        cmd,
        capture_output=True,
        gui_log_func=gui_log_func,
        config_password=config_password
    )
    items = []
    if return_code == 0 and stdout:
        try:
            raw_items = json.loads(stdout)
            for item in raw_items:
                item_display_name = item['Path']
                if item['IsDir']:
                    item_display_name += "/"
                items.append(item_display_name)
        except json.JSONDecodeError as e:
            err_msg = f"Error decoding lsjson output: {e}\nOutput (first 500 chars):\n{stdout[:500]}"
            log_utils.app_log(err_msg, level="error", gui_log_func=gui_log_func, log_to_gui=True)
            return [], err_msg, -1
        except TypeError:
            err_msg = f"Error processing lsjson output: rclone returned non-JSON list or empty. Output: '{stdout[:500]}'"
            log_utils.app_log(err_msg, level="error", gui_log_func=gui_log_func, log_to_gui=True)
            return [], err_msg, -1
    elif return_code != 0 and stderr:
         log_utils.app_log(f"Listing remote failed for '{path}'. Rclone stderr: {stderr.strip()}", level="error", gui_log_func=gui_log_func, log_to_gui=True)

    return items, stderr, return_code

def check_if_config_encrypted(gui_log_func=None):
    logger.info("Checking if rclone.conf is encrypted...")
    if not os.path.exists(RCLONE_EXE_PATH):
        log_utils.app_log(f"Config encryption check: {RCLONE_EXE_NAME} not found at {RCLONE_EXE_PATH}", level="error", gui_log_func=gui_log_func, log_to_gui=False)
        return False

    current_env = os.environ.copy()
    current_env["RCLONE_ASK_PASSWORD"] = "false"

    try:
        cmd_list = [RCLONE_EXE_PATH, "listremotes"]
        
        popen_kwargs = {"env": current_env, "stdout":subprocess.PIPE, "stderr":subprocess.PIPE, "text":True, "encoding":'utf-8', "errors":'replace'}
        if sys.platform == "win32":
            popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        process = subprocess.Popen(
            cmd_list,
            **popen_kwargs
        )
        stdout, stderr = process.communicate(timeout=15)
        return_code = process.returncode

        log_message_for_file = f"Config encryption check: RC={return_code}."
        if stdout.strip(): log_message_for_file += f" stdout='{stdout.strip()}'"
        if stderr.strip(): log_message_for_file += f" stderr='{stderr.strip()}'"
        log_utils.app_log(log_message_for_file, gui_log_func=gui_log_func, log_to_gui=False)


        if return_code != 0 and stderr:
            encryption_indicators = [
                "unable to decrypt configuration",
                "can't decrypt config file",
                "failed to decrypt config file",
                "configuration password",
                "config file is encrypted",
                "password for rclone config"
            ]
            for indicator in encryption_indicators:
                if indicator.lower() in stderr.lower():
                    logger.info(f"Rclone config appears to be encrypted based on stderr: {stderr.strip()}")
                    return True
        
        if return_code == 0:
             logger.info("Rclone config does not appear to be encrypted (listremotes succeeded with ASK_PASSWORD=false).")
             return False

    except subprocess.TimeoutExpired:
        log_utils.app_log("Config encryption check: rclone command timed out.", level="warning", gui_log_func=gui_log_func, log_to_gui=False)
        logger.warning("Rclone command timed out during encryption check.")
        return False
    except Exception as e:
        log_utils.app_log(f"Config encryption check: Error during check: {e}", level="error", gui_log_func=gui_log_func, log_to_gui=False)
        logger.error(f"Exception during rclone config encryption check: {e}", exc_info=True)
        return False

    logger.info("Rclone config encryption status undetermined or not matching known encrypted indicators (RC != 0 but no clear encryption error message).")
    return False
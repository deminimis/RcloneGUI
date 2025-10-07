import logging
import sys
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.txt")
is_configured = False

def get_logger(name):
    return logging.getLogger(name)

def setup_logging():
    global is_configured
    if is_configured:
        return

    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            if f.tell() == 0:
                f.write(f"--- Log session started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    except Exception as e:
        print(f"CRITICAL ERROR: Could not initialize log file {LOG_FILE} with UTF-8: {e}")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(filename)s:%(lineno)d - %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'),
        ]
    )

    sys.stderr = LogWriter(logging.getLogger("stderr_redirect").error)
    sys.excepthook = handle_exception

    logging.info("--- Logging initialized (UTF-8) ---")
    is_configured = True

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    exception_logger = get_logger("uncaught_exception_handler")
    exception_logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

class LogWriter:
    def __init__(self, log_function):
        self.log_function = log_function

    def write(self, message):
        if message.strip():
            self.log_function(message.strip())

    def flush(self):
        pass

def app_log(message, level="info", gui_log_func=None, log_to_gui=True):
    logger_instance = get_logger("RcloneGUI_App")

    log_level_actual = getattr(logging, level.upper(), logging.INFO)
    logger_instance.log(log_level_actual, message)

    if gui_log_func and log_to_gui:
        is_error_flag = (level.lower() in ["error", "critical"])
        try:
            gui_log_func(message, is_error=is_error_flag)
        except Exception as e_gui_log:
            logger_instance.error(f"Failed to log message to GUI: {e_gui_log}", exc_info=False)


if __name__ == "__main__":
    setup_logging()
    test_logger = get_logger("TestLogger")
    test_logger.info("Test log from log_utils.py's TestLogger (UTF-8)")
    
    def dummy_gui_logger(msg, is_error=False):
        print(f"DUMMY_GUI_LOG ({'ERROR' if is_error else 'INFO'}): {msg.strip()}")

    app_log("App log test info (UTF-8) - to GUI and file", gui_log_func=dummy_gui_logger)
    app_log("App log test error with arrow ➔ (UTF-8) - to GUI and file", level="error", gui_log_func=dummy_gui_logger)
    app_log("App log test info (UTF-8) - to file ONLY", gui_log_func=dummy_gui_logger, log_to_gui=False)
    print("Check log.txt and console for dummy GUI logs.")
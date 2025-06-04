# rclone_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import rclone_wrapper as rclone
import autoconfig
import os
import sys
import subprocess
import log_utils # Primary logging utility
import threading
import queue
import traceback
import logging # For isinstance checks and standard logging levels
import json
import re
from datetime import datetime

from graphite_theme import apply_graphite_theme

# Define PrintLogger in the global script scope as a fallback
class PrintLogger:
    def _log(self, level_name, msg, exc_info=False):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{timestamp} - {level_name.upper()}: {msg}")
        if exc_info:
            print(traceback.format_exc())

    def info(self, msg, exc_info=False): self._log("info", msg, exc_info)
    def error(self, msg, exc_info=False): self._log("error", msg, exc_info)
    def warning(self, msg, exc_info=False): self._log("warning", msg, exc_info)
    def critical(self, msg, exc_info=False): self._log("critical", msg, exc_info)
    def debug(self, msg, exc_info=False): self._log("debug", msg, exc_info)
    
    def log(self, level, msg, exc_info=False):
        level_name = level
        if isinstance(level, int):
            level_name = logging.getLevelName(level)
        self._log(str(level_name).lower(), msg, exc_info)

# Global logger instance, initialized using log_utils or PrintLogger fallback
logger = None
try:
    log_utils.setup_logging()
    logger = log_utils.get_logger("RcloneGUI_App")
except Exception as e_log_setup: # pragma: no cover
    # This block executes if log_utils.setup_logging() or get_logger() fails
    fallback_logger = PrintLogger() # Create an instance of the globally defined PrintLogger
    fallback_logger.critical(f"CRITICAL ERROR during initial logging setup with log_utils: {e_log_setup}", exc_info=True)
    fallback_logger.critical("Falling back to console-based PrintLogger.")
    logger = fallback_logger # Assign the fallback logger to the global logger variable

# Ensure logger is not None, even if PrintLogger somehow failed (highly unlikely here)
if logger is None: # pragma: no cover
    logger = PrintLogger()
    logger.critical("Logger was unexpectedly None after fallback. Re-initialized to PrintLogger.")


MSG_TYPE_RCLONE_OUTPUT = "rclone_output"
MSG_TYPE_PROMPT_AUTH_DIALOG = "prompt_auth_dialog"
MSG_TYPE_AUTOMATION_COMPLETE = "automation_complete"
ASSOCIATED_LISTS_FILE = "rclone_gui_associated_lists.json"


class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Rclone Configuration Password", theme_colors_dict=None):
        self.theme_colors = theme_colors_dict
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        label_fg = 'SystemButtonText'
        if self.theme_colors: # pragma: no branch
            master.configure(bg=self.theme_colors['WINDOW_BG'])
            label_fg = self.theme_colors.get('TEXT_COLOR', 'SystemButtonText')

        instr_text = "Rclone configuration seems to be encrypted.\nPlease enter the password:"
        instr_label = tk.Label(master, text=instr_text, wraplength=300, justify=tk.LEFT)
        if self.theme_colors: # pragma: no branch
            instr_label.configure(bg=self.theme_colors['WINDOW_BG'], fg=label_fg)
        instr_label.pack(pady=(10,5), padx=10)

        self.password_entry = ttk.Entry(master, show="*", width=40)
        self.password_entry.pack(pady=5, padx=10)
        return self.password_entry

    def apply(self):
        self.result = self.password_entry.get()

    def buttonbox(self):
        box = ttk.Frame(self)
        ok_button = ttk.Button(box, text="OK", width=10, command=self.ok, default=tk.ACTIVE)
        ok_button.pack(side=tk.LEFT, padx=5, pady=5)
        cancel_button = ttk.Button(box, text="Cancel", width=10, command=self.cancel)
        cancel_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()


class AuthSuccessDialog(tk.Toplevel):
    def __init__(self, parent, auth_url="", theme_colors=None):
        super().__init__(parent)
        if theme_colors: # pragma: no branch
            self.configure(bg=theme_colors['WINDOW_BG'])
        
        self.transient(parent)
        self.title("Browser Authorization Step")
        self.result = None
        self.parent_window = parent
        
        frame_padding = {"padding": "20"}
        frame = ttk.Frame(self, **frame_padding)
        frame.pack(expand=True, fill=tk.BOTH)
        
        instr_text = "Please complete authorization in your web browser."
        if auth_url: instr_text += f"\n\nIf your browser didn't open automatically, please go to:\n{auth_url}"
        else: instr_text += "\nRclone should have opened a browser or provided an authorization URL in the pCloud setup window's output area."
        instr_text += "\n\nThen, confirm the result below."
        
        ttk.Label(frame, text=instr_text, wraplength=400, justify=tk.CENTER).pack(pady=10)
        ttk.Label(frame, text="Was authorization successful?", font=('Arial', 12, 'bold')).pack(pady=10)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        yes_btn = ttk.Button(btn_frame, text="Yes, Authorization Succeeded", command=self.on_yes)
        yes_btn.pack(side=tk.LEFT, padx=10)
        no_btn = ttk.Button(btn_frame, text="No / Cancel", command=self.on_no)
        no_btn.pack(side=tk.LEFT, padx=10)
        
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_no)
        self.center_dialog()
        self.wait_window()

    def center_dialog(self):
        self.update_idletasks()
        parent_x = self.parent_window.winfo_x()
        parent_y = self.parent_window.winfo_y()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()
        
        dialog_width = self.winfo_reqwidth() + 60
        dialog_height = self.winfo_reqheight() + 40
        
        if dialog_width > parent_width - 20 : dialog_width = parent_width - 20
        if dialog_height > parent_height - 20 : dialog_height = parent_height - 20

        position_x = parent_x + (parent_width // 2) - (dialog_width // 2)
        position_y = parent_y + (parent_height // 2) - (dialog_height // 2)
        
        self.geometry(f"{dialog_width}x{dialog_height}+{position_x}+{position_y}")

    def on_yes(self):
        self.result = True
        self.destroy()

    def on_no(self):
        self.result = False
        self.destroy()

class AssociatedListSettingsDialog(tk.Toplevel):
    def __init__(self, parent, current_dest_segment="", current_flags="", theme_colors=None):
        super().__init__(parent)
        if theme_colors: # pragma: no branch
            self.configure(bg=theme_colors['WINDOW_BG'])

        self.transient(parent)
        self.title("Configure List Settings")
        self.result = None
        self.parent = parent
        
        frame_padding = {"padding": "15"}
        frame = ttk.Frame(self, **frame_padding)
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Remote Destination Subfolder:",font=('Arial', 10)).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.dest_segment_entry = ttk.Entry(frame, width=50)
        self.dest_segment_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.dest_segment_entry.insert(0, current_dest_segment)
        ttk.Label(frame, text="(e.g., 'MyFiles/Backup' - leave empty for remote root)").grid(row=1, column=1, sticky="w", padx=5, pady=2, columnspan=2)
        
        ttk.Label(frame, text="Rclone Flags:",font=('Arial', 10)).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.flags_entry = ttk.Entry(frame, width=50)
        self.flags_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        self.flags_entry.insert(0, current_flags if current_flags else "-P --checksum --transfers=4")
        ttk.Label(frame, text="(e.g., '-P --checksum --verbose')").grid(row=3, column=1, sticky="w", padx=5, pady=2, columnspan=2)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="e")
        save_btn = ttk.Button(btn_frame, text="Save Settings", command=self.on_save)
        save_btn.pack(side=tk.LEFT, padx=5)
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        frame.columnconfigure(1, weight=1)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window()

    def on_save(self):
        dest_segment = self.dest_segment_entry.get().strip().strip('/')
        flags = self.flags_entry.get().strip()
        self.result = {"remote_dest_segment": dest_segment, "rclone_flags": flags}
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class BatchGenDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Generate Batch File Options", theme_colors_dict=None, default_rclone_exe=""):
        self.theme_colors = theme_colors_dict
        self.default_rclone_exe = default_rclone_exe
        self.result = None 
        # Use the global logger instance for dialog-specific logging
        self.dialog_logger = logger # Or log_utils.get_logger("RcloneGUI_App.BatchGenDialog") if more specific needed
        super().__init__(parent, title)

    def body(self, master):
        if self.theme_colors: # pragma: no branch
            master.configure(bg=self.theme_colors['WINDOW_BG'])

        op_frame = ttk.LabelFrame(master, text="Operation Type", padding=5)
        op_frame.pack(fill=tk.X, padx=10, pady=5)
        self.operation_var = tk.StringVar(value="sync")
        
        self.rb_sync = ttk.Radiobutton(op_frame, text="Sync", variable=self.operation_var, value="sync")
        self.rb_sync.pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(op_frame, text="Copy", variable=self.operation_var, value="copy").pack(side=tk.LEFT, padx=5)

        log_frame = ttk.LabelFrame(master, text="Rclone Logging", padding=5)
        log_frame.pack(fill=tk.X, padx=10, pady=5)
        self.log_enabled_var = tk.BooleanVar(value=True)
        self.log_file_var = tk.StringVar(value=os.path.join(os.getcwd(), "rclone_task_log.txt")) 

        log_check = ttk.Checkbutton(log_frame, text="Enable rclone log file for this script?", variable=self.log_enabled_var, command=self._toggle_log_file_entry)
        log_check.grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=2) 
        
        ttk.Label(log_frame, text="Log File Path:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.log_file_entry = ttk.Entry(log_frame, textvariable=self.log_file_var, width=50)
        self.log_file_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        log_browse_btn = ttk.Button(log_frame, text="Browse...", command=self._browse_log_file)
        log_browse_btn.grid(row=1, column=2, padx=5, pady=2)
        log_frame.columnconfigure(1, weight=1)

        pass_frame = ttk.LabelFrame(master, text="Password Handling (if rclone.conf is encrypted)", padding=5)
        pass_frame.pack(fill=tk.X, padx=10, pady=5)
        self.password_option_var = tk.StringVar(value="prompt") 
        
        ttk.Radiobutton(pass_frame, text="Interactively prompt for password when script runs (@echo on)", variable=self.password_option_var, value="prompt").pack(anchor="w")
        
        hardcode_frame = ttk.Frame(pass_frame) 
        hardcode_frame.pack(anchor="w")
        ttk.Radiobutton(hardcode_frame, text="Hardcode password in script (Least Secure - @echo off)", variable=self.password_option_var, value="hardcode").pack(side=tk.LEFT)
        self.hardcoded_password_var = tk.StringVar()
        self.hardcoded_password_entry = ttk.Entry(hardcode_frame, textvariable=self.hardcoded_password_var, show="*", width=25) 
        self.hardcoded_password_entry.pack(side=tk.LEFT, padx=5) 
        
        self.password_option_var.trace_add("write", self._toggle_hardcoded_password_entry) 

        exe_frame = ttk.LabelFrame(master, text="Rclone Executable", padding=5)
        exe_frame.pack(fill=tk.X, padx=10, pady=5)
        self.rclone_exe_var = tk.StringVar(value=self.default_rclone_exe)
        ttk.Label(exe_frame, text="Path to rclone.exe:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.rclone_exe_entry = ttk.Entry(exe_frame, textvariable=self.rclone_exe_var, width=50)
        self.rclone_exe_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        exe_browse_btn = ttk.Button(exe_frame, text="Browse...", command=self._browse_rclone_exe)
        exe_browse_btn.grid(row=0, column=2, padx=5, pady=2)
        exe_frame.columnconfigure(1, weight=1)

        self._toggle_log_file_entry() 
        self._toggle_hardcoded_password_entry() 
        return self.rb_sync

    def _toggle_log_file_entry(self, *args):
        state = tk.NORMAL if self.log_enabled_var.get() else tk.DISABLED
        self.log_file_entry.config(state=state)
            
    def _toggle_hardcoded_password_entry(self, *args):
        state = tk.NORMAL if self.password_option_var.get() == "hardcode" else tk.DISABLED
        self.hardcoded_password_entry.config(state=state)
        if self.password_option_var.get() != "hardcode": # pragma: no branch
            self.hardcoded_password_var.set("") 

    def _browse_log_file(self):
        filepath = filedialog.asksaveasfilename(
            parent=self, 
            title="Specify Log File Path",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filepath: # pragma: no branch
            self.log_file_var.set(filepath)

    def _browse_rclone_exe(self):
        filepath = filedialog.askopenfilename(
            parent=self,
            title="Select rclone.exe",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filepath: # pragma: no branch
            self.rclone_exe_var.set(filepath)

    def ok(self, event=None):
        self.dialog_logger.debug("BatchGenDialog ok method called.")
        if not self.validate():
            self.dialog_logger.info("BatchGenDialog validate() returned false.") 
            self.initial_focus.focus_set()
            return
        self.dialog_logger.debug("BatchGenDialog validate() returned true.")

        self.withdraw()
        self.update_idletasks()

        try:
            self.apply() 
            self.dialog_logger.debug(f"BatchGenDialog apply() called, internal self.result is now: {self.result}")
        except Exception as e: # pragma: no cover
            self.dialog_logger.error(f"Exception in BatchGenDialog apply(): {e}", exc_info=True)
            pass
        
        super().ok(event)


    def validate(self):
        self.dialog_logger.debug("BatchGenDialog validate() called.")
        if self.log_enabled_var.get() and not self.log_file_var.get().strip():
            self.dialog_logger.warning("Validation failed: Log file path empty.")
            messagebox.showerror("Validation Error", "Log file path cannot be empty if logging is enabled.", parent=self)
            return 0
        if not self.rclone_exe_var.get().strip():
            self.dialog_logger.warning("Validation failed: Rclone exe path empty.")
            messagebox.showerror("Validation Error", "Rclone executable path cannot be empty.", parent=self)
            return 0
        if self.password_option_var.get() == "hardcode" and not self.hardcoded_password_var.get():
            self.dialog_logger.warning("Validation: Hardcode password selected but field empty.")
            if not messagebox.askyesno("Confirm Empty Password", 
                                       "You selected to hardcode the password, but left it blank. "
                                       "This is usually not intended for encrypted configurations.\nContinue anyway?", 
                                       parent=self, icon=messagebox.WARNING):
                self.dialog_logger.info("Validation failed: User chose not to continue with empty hardcoded password.")
                return 0
        self.dialog_logger.debug("BatchGenDialog validate() passed.")
        return 1

    def apply(self):
        self.dialog_logger.debug("BatchGenDialog apply() called.")
        self.result = { 
            "operation": self.operation_var.get(),
            "log_enabled": self.log_enabled_var.get(),
            "log_file": self.log_file_var.get().strip() if self.log_enabled_var.get() else "",
            "password_option": self.password_option_var.get(),
            "hardcoded_password": self.hardcoded_password_var.get() if self.password_option_var.get() == "hardcode" else "",
            "rclone_exe": self.rclone_exe_var.get().strip()
        }
        self.dialog_logger.debug(f"BatchGenDialog apply() - self.result set to: {self.result}")


class RcloneGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Rclone GUI")
        self.master.geometry("950x800") 
        self.master.minsize(860, 650) 

        style = ttk.Style()
        self.theme_colors = apply_graphite_theme(style)
        master.configure(bg=self.theme_colors['WINDOW_BG'])

        app_font_tuple = ('Arial', 10)
        master.option_add('*TCombobox*Listbox.background', self.theme_colors['WIDGET_BG'])
        master.option_add('*TCombobox*Listbox.foreground', self.theme_colors['TEXT_COLOR'])
        master.option_add('*TCombobox*Listbox.selectBackground', self.theme_colors['SELECT_BG_COLOR'])
        master.option_add('*TCombobox*Listbox.selectForeground', self.theme_colors['SELECT_FG_COLOR'])
        master.option_add('*TCombobox*Listbox.font', app_font_tuple)
        master.option_add('*TCombobox*Listbox.borderWidth', '0')
        master.option_add('*TCombobox*Listbox.relief', 'flat')
        master.option_add('*TCombobox*Listbox.highlightThickness', '0')

        if not os.path.exists(rclone.RCLONE_EXE_PATH): # pragma: no cover
            critical_msg = f"CRITICAL ERROR: {rclone.RCLONE_EXE_NAME} not found at {rclone.RCLONE_EXE_PATH}."
            log_utils.app_log(critical_msg, level="critical", gui_log_func=self._gui_log_callback)
            messagebox.showerror("Rclone Not Found", critical_msg + "\nPlease place rclone.exe in the script's directory or ensure it's in your system PATH.", parent=master if master.winfo_exists() else None)
            if master.winfo_exists(): master.destroy()
            raise SystemExit("Rclone executable not found, aborting GUI init.")
        
        self.rclone_config_password = None
        self.current_local_path = tk.StringVar(value=os.getcwd())
        self.current_remote_base = tk.StringVar()
        self.current_remote_path_segment = tk.StringVar(value="")
        self.remotes = []
        self.pcloud_config_window_ref = None
        self.worker_thread_queue = queue.Queue()
        self.pcloud_auth_result_holder = {'result': None}
        self.pcloud_auth_event = threading.Event()
        self.associated_remote_lists = {}
        self.auto_setup_providers = ["pCloud"]
        self.selected_auto_setup_provider = tk.StringVar()

        style.configure("Path.TLabel", font=('Arial', 10, 'bold'))
        style.configure("Header.TLabel", font=('Arial', 12, 'bold'))

        self.main_canvas = tk.Canvas(master, borderwidth=0, background=self.theme_colors['WINDOW_BG'])
        self.main_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(master, orient=tk.VERTICAL, command=self.main_canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollable_frame = ttk.Frame(self.main_canvas, padding="10") 
        self.canvas_frame_id = self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", self._on_frame_configure)
        self.main_canvas.bind("<Configure>", self._on_canvas_configure)

        main_content_frame = self.scrollable_frame 

        log_frame_gui_container = ttk.LabelFrame(main_content_frame, text="GUI Log (Detailed logs in log.txt)", padding="10")
        scrolled_text_options = {
            'background': self.theme_colors['WIDGET_BG'], 'foreground': self.theme_colors['TEXT_COLOR'],
            'selectbackground': self.theme_colors['SELECT_BG_COLOR'], 'selectforeground': self.theme_colors['SELECT_FG_COLOR'],
            'insertbackground': self.theme_colors['TEXT_INSERT_BG'], 'borderwidth': 0, 'relief': tk.FLAT,
            'highlightthickness': 1, 'highlightbackground': self.theme_colors['LISTBOX_HIGHLIGHT_BG'],
            'highlightcolor': self.theme_colors['LISTBOX_HIGHLIGHT_COLOR'], 'wrap': tk.WORD,
            'font': ("Consolas", 9)
        }
        self.gui_log_text = scrolledtext.ScrolledText(log_frame_gui_container, height=4, state=tk.DISABLED, **scrolled_text_options)
        self.gui_log_text.tag_config("error", foreground=self.theme_colors['LOG_ERROR_FG'])
        self.gui_log_text.tag_config("info", foreground=self.theme_colors['LOG_INFO_FG'])
        self.gui_log_text.tag_config("stdout", foreground=self.theme_colors['LOG_STDOUT_FG'])
        self.gui_log_text.tag_config("stdin", foreground=self.theme_colors['LOG_STDIN_FG'])

        self.check_and_get_config_password() 

        top_bar_frame = ttk.Frame(main_content_frame)
        top_bar_frame.pack(fill=tk.X, pady=5) 

        config_buttons_frame = ttk.Frame(top_bar_frame)
        config_buttons_frame.pack(side=tk.RIGHT, padx=(10,0), pady=0, fill=tk.Y) 
        cmd_config_btn = ttk.Button(config_buttons_frame, text="Configure (CMD)", command=self.launch_rclone_config_cmd)
        cmd_config_btn.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2)
        provider_label = ttk.Label(config_buttons_frame, text="Auto-Setup:")
        provider_label.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=(5,0))
        self.provider_auto_setup_combo = ttk.Combobox(config_buttons_frame, textvariable=self.selected_auto_setup_provider,
                                                      values=self.auto_setup_providers, state="readonly", width=12, font=app_font_tuple)
        if self.auto_setup_providers: self.provider_auto_setup_combo.current(0)
        self.provider_auto_setup_combo.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2, fill=tk.X)
        auto_setup_btn = ttk.Button(config_buttons_frame, text="Run", command=self.initiate_auto_setup)
        auto_setup_btn.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2)
        
        remote_frame = ttk.LabelFrame(top_bar_frame, text="Remote Selection", padding="10")
        remote_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5), pady=0) 
        ttk.Label(remote_frame, text="Select Remote:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.remote_combo = ttk.Combobox(remote_frame, width=20, state="readonly", font=app_font_tuple)
        self.remote_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.remote_combo.bind("<<ComboboxSelected>>", self.on_remote_selected)
        refresh_remotes_btn = ttk.Button(remote_frame, text="Refresh", command=self.load_remotes)
        refresh_remotes_btn.grid(row=0, column=2, padx=(5,2), pady=5)
        delete_remote_btn = ttk.Button(remote_frame, text="Delete", command=self.confirm_delete_remote)
        delete_remote_btn.grid(row=0, column=3, padx=(2,5), pady=5)
        remote_frame.columnconfigure(1, weight=1)

        path_frame = ttk.Frame(main_content_frame, padding="5")
        path_frame.pack(fill=tk.X, pady=5) 
        path_frame.columnconfigure(0, weight=1)
        ttk.Label(path_frame, text="Local Path:", style="Header.TLabel").grid(row=0, column=0, padx=5, pady=(10,0), sticky="w")
        ttk.Label(path_frame, textvariable=self.current_local_path, style="Path.TLabel", wraplength=450).grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        local_path_buttons_frame = ttk.Frame(path_frame)
        local_path_buttons_frame.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        local_browse_btn = ttk.Button(local_path_buttons_frame, text="Browse Local", command=self.browse_local_path)
        local_browse_btn.pack(side=tk.LEFT, padx=(0,5))
        refresh_dirs_btn = ttk.Button(local_path_buttons_frame, text="Refresh Directories", command=self.refresh_all_listings)
        refresh_dirs_btn.pack(side=tk.LEFT)

        listings_frame = ttk.Frame(main_content_frame) 
        listings_frame.pack(expand=True, fill=tk.BOTH, pady=5) 
        listings_frame.columnconfigure(0, weight=1)
        listings_frame.columnconfigure(1, weight=1)
        listings_frame.rowconfigure(2, weight=1) 

        self.listbox_options = {
            'background': self.theme_colors['WIDGET_BG'], 'foreground': self.theme_colors['TEXT_COLOR'],
            'selectbackground': self.theme_colors['SELECT_BG_COLOR'], 'selectforeground': self.theme_colors['SELECT_FG_COLOR'],
            'borderwidth': 0, 'relief': tk.FLAT, 'highlightthickness': 1,
            'highlightbackground': self.theme_colors['LISTBOX_HIGHLIGHT_BG'],
            'highlightcolor': self.theme_colors['LISTBOX_HIGHLIGHT_COLOR'],
            'exportselection': False, 'font': app_font_tuple
        }
        self.local_files_list = tk.Listbox(listings_frame, selectmode=tk.EXTENDED, **self.listbox_options)
        local_scrollbar = ttk.Scrollbar(listings_frame, orient=tk.VERTICAL, command=self.local_files_list.yview)
        self.local_files_list.config(yscrollcommand=local_scrollbar.set)
        self.local_files_list.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=5)
        local_scrollbar.grid(row=0, column=0, rowspan=3, sticky="nse", padx=(0,5))
        self.local_files_list.bind("<Double-1>", self.on_local_double_click)
        
        ttk.Label(listings_frame, text="Remote Path:", style="Header.TLabel").grid(row=0, column=1, padx=(5,0), pady=(0,0), sticky="sw")
        self.remote_path_display = ttk.Label(listings_frame, text="<Select Remote>", style="Path.TLabel", wraplength=400)
        self.remote_path_display.grid(row=1, column=1, padx=(5,0), pady=2, sticky="new")
        self.remote_files_list = tk.Listbox(listings_frame, selectmode=tk.EXTENDED, **self.listbox_options)
        remote_scrollbar = ttk.Scrollbar(listings_frame, orient=tk.VERTICAL, command=self.remote_files_list.yview)
        self.remote_files_list.config(yscrollcommand=remote_scrollbar.set)
        self.remote_files_list.grid(row=2, column=1, sticky="nsew", padx=5)
        remote_scrollbar.grid(row=2, column=1, sticky="nse", padx=(0,5))
        self.remote_files_list.bind("<Double-1>", self.on_remote_double_click)

        actions_frame = ttk.LabelFrame(main_content_frame, text="Direct Actions (on selected items in above listings)", padding="10")
        actions_frame.pack(fill=tk.X, pady=(5,0), padx=5) 
        save_selected_btn = ttk.Button(actions_frame, text="Save Selected Files/Folders Below", command=self.save_selected_to_associated_list)
        save_selected_btn.pack(side=tk.LEFT, padx=5)
        copy_lr_btn = ttk.Button(actions_frame, text="Copy Selected to Remote", command=lambda: self.start_operation("copy", "lr"))
        copy_lr_btn.pack(side=tk.LEFT, padx=5)
        sync_lr_btn = ttk.Button(actions_frame, text="Sync Selected to Remote", command=lambda: self.start_operation("sync", "lr"))
        sync_lr_btn.pack(side=tk.LEFT, padx=5)
        copy_rl_btn = ttk.Button(actions_frame, text="Copy Selected to Local", command=lambda: self.start_operation("copy", "rl"))
        copy_rl_btn.pack(side=tk.LEFT, padx=5)
        sync_rl_btn = ttk.Button(actions_frame, text="Sync Selected to Local", command=lambda: self.start_operation("sync", "rl"))
        sync_rl_btn.pack(side=tk.LEFT, padx=5)

        self.create_associated_items_frame(main_content_frame) 
        
        log_frame_gui_container.pack(fill=tk.X, pady=(5,10), padx=5) 
        self.gui_log_text.pack(expand=True, fill=tk.BOTH) 

        self.log_message_gui("GUI Started. Check log.txt for detailed startup logs and rclone outputs.\n", is_info=True)
        self.load_associated_lists_from_file()
        self.load_remotes()
        self.refresh_local_files()
        self.update_remote_path_display()
        self.master.after(100, self.process_worker_thread_queue)

    def _on_frame_configure(self, event=None):
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

    def _on_canvas_configure(self, event=None):
        canvas_width = event.width
        self.main_canvas.itemconfig(self.canvas_frame_id, width=canvas_width)

    def check_and_get_config_password(self):
        initial_log_msg = "Checking rclone configuration encryption status...\n"
        self.log_message_gui(initial_log_msg, is_info=True) 

        try:
            is_encrypted = rclone.check_if_config_encrypted(gui_log_func=self._gui_log_callback)
            if is_encrypted:
                log_msg_encrypted = "Rclone configuration appears to be encrypted. Prompting for password.\n"
                self.log_message_gui(log_msg_encrypted, is_info=True)
                log_utils.app_log(log_msg_encrypted.strip(), gui_log_func=self._gui_log_callback, log_to_gui=False)

                dialog = PasswordDialog(self.master, title="Rclone Configuration Password", theme_colors_dict=self.theme_colors)
                self.rclone_config_password = dialog.result 

                if self.rclone_config_password:
                    msg = "Password received. Will be used for rclone operations this session.\n"
                    self.log_message_gui(msg, is_info=True)
                    log_utils.app_log(msg.strip(), gui_log_func=self._gui_log_callback, log_to_gui=False)
                else:
                    msg = "Password not provided by user. Rclone operations may fail if config is encrypted.\n"
                    self.log_message_gui(msg, is_error=True)
                    log_utils.app_log(msg.strip(), level="warning", gui_log_func=self._gui_log_callback, log_to_gui=False)
            else:
                msg = "Rclone configuration does not appear to be encrypted, or status is undetermined.\n"
                self.log_message_gui(msg, is_info=True)
                log_utils.app_log(msg.strip(), gui_log_func=self._gui_log_callback, log_to_gui=False)
        except Exception as e: # pragma: no cover
            err_msg = f"Error during rclone configuration encryption check: {e}\n"
            self.log_message_gui(err_msg, is_error=True)
            log_utils.app_log(f"Failed to check rclone config encryption: {e}", level="error", gui_log_func=self._gui_log_callback, log_to_gui=False)
            logger.error("Exception during check_and_get_config_password", exc_info=True)

    def _gui_log_callback(self, message, is_error=False):
        if hasattr(self, 'gui_log_text') and self.gui_log_text.winfo_exists():
            self.log_message_gui(message, is_error=is_error)
        else: 
            prefix = "GUI Log (widget not ready): "
            if is_error: prefix = "GUI Log ERROR (widget not ready): "
            print(f"{prefix}{message.strip()}")
            log_method = logger.error if is_error else logger.info
            log_method(f"(Early log via callback) {message.strip()}")


    def log_message_gui(self, message, is_error=False, is_info=False):
        if not hasattr(self, 'gui_log_text') or not self.gui_log_text.winfo_exists(): # pragma: no cover
            return
        
        self.gui_log_text.config(state=tk.NORMAL)
        tag_to_use = ()
        if is_error: tag_to_use = ("error",)
        elif is_info: tag_to_use = ("info",)
        elif message.startswith("Sending to rclone:"): tag_to_use =("stdin",)
        elif not is_error and not is_info : tag_to_use = ("stdout",)
        
        self.gui_log_text.insert(tk.END, message, tag_to_use)
        self.gui_log_text.see(tk.END)
        self.gui_log_text.config(state=tk.DISABLED)

    def create_associated_items_frame(self, parent_frame):
        self.associated_items_labelframe = ttk.LabelFrame(parent_frame, text="Associated Local Items for <No Remote Selected>", padding="10")
        self.associated_items_labelframe.pack(fill=tk.X, pady=(5,0), padx=5) 
        
        list_container = ttk.Frame(self.associated_items_labelframe)
        list_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5))
        
        self.associated_items_listbox = tk.Listbox(list_container, height=5, selectmode=tk.SINGLE, **self.listbox_options) 
        items_scrollbar = ttk.Scrollbar(list_container, orient=tk.VERTICAL, command=self.associated_items_listbox.yview)
        self.associated_items_listbox.config(yscrollcommand=items_scrollbar.set)
        self.associated_items_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        items_scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        
        buttons_frame = ttk.Frame(self.associated_items_labelframe)
        buttons_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        remove_item_btn = ttk.Button(buttons_frame, text="Remove Item", command=self.remove_item_from_list)
        remove_item_btn.pack(pady=2, fill=tk.X)
        
        configure_btn = ttk.Button(buttons_frame, text="List Settings...", command=self.configure_list_settings)
        configure_btn.pack(pady=2, fill=tk.X)
        
        copy_all_btn = ttk.Button(buttons_frame, text="Copy List ➔ Remote", command=lambda: self.run_operation_for_list("copy")) 
        copy_all_btn.pack(pady=(8,2), fill=tk.X) 
        
        sync_all_btn = ttk.Button(buttons_frame, text="Sync List ➔ Remote", command=lambda: self.run_operation_for_list("sync")) 
        sync_all_btn.pack(pady=2, fill=tk.X)

        generate_script_btn = ttk.Button(buttons_frame, text="Generate Batch File", command=self.prompt_generate_batch_file)
        generate_script_btn.pack(pady=(8,2), fill=tk.X)


    def load_associated_lists_from_file(self):
        self.associated_remote_lists = {}
        if os.path.exists(ASSOCIATED_LISTS_FILE):
            try:
                with open(ASSOCIATED_LISTS_FILE, "r", encoding="utf-8") as f:
                    self.associated_remote_lists = json.load(f)
                log_utils.app_log(f"Loaded associated item lists from {ASSOCIATED_LISTS_FILE}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            except json.JSONDecodeError: # pragma: no cover
                log_utils.app_log(f"Error decoding JSON from {ASSOCIATED_LISTS_FILE}. File might be corrupted.", level="error", gui_log_func=self._gui_log_callback)
                messagebox.showerror("Load Error", f"Could not load associated lists from {ASSOCIATED_LISTS_FILE}.\nIt might be corrupted. A new file will be created if you save changes.", parent=self.master)
            except Exception as e: # pragma: no cover
                log_utils.app_log(f"Failed to load associated lists: {e}", level="error", gui_log_func=self._gui_log_callback)
                messagebox.showerror("Load Error", f"An error occurred while loading associated lists: {e}", parent=self.master)
        else:
            log_utils.app_log(f"{ASSOCIATED_LISTS_FILE} not found. Starting with no saved associated lists.", gui_log_func=self._gui_log_callback, log_to_gui=False)

    def save_associated_lists_to_file(self):
        try:
            with open(ASSOCIATED_LISTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.associated_remote_lists, f, indent=4)
            log_utils.app_log(f"Saved associated item lists to {ASSOCIATED_LISTS_FILE}", gui_log_func=self._gui_log_callback, log_to_gui=False)
        except Exception as e: # pragma: no cover
            log_utils.app_log(f"Failed to save associated lists: {e}", level="error", gui_log_func=self._gui_log_callback)
            messagebox.showerror("Save Error", f"Could not save associated lists: {e}", parent=self.master)

    def display_associated_items_for_selected_remote(self):
        if not hasattr(self, 'associated_items_listbox'): return # pragma: no cover
        
        self.associated_items_listbox.delete(0, tk.END)
        selected_remote_name = self._get_current_remote_name()
        
        if selected_remote_name:
            self.associated_items_labelframe.config(text=f"Associated Local Items for: {selected_remote_name}")
            if selected_remote_name in self.associated_remote_lists: # pragma: no branch
                list_data = self.associated_remote_lists[selected_remote_name]
                for item_path in list_data.get("local_items", []):
                    self.associated_items_listbox.insert(tk.END, item_path)
        else:
            self.associated_items_labelframe.config(text="Associated Local Items for <No Remote Selected>")

    def _get_current_remote_name(self):
        return self.current_remote_base.get().rstrip(':')

    def _ensure_remote_list_entry(self, remote_name):
        if remote_name not in self.associated_remote_lists:
            self.associated_remote_lists[remote_name] = {
                "local_items": [], 
                "remote_dest_segment": "", 
                "rclone_flags": "-P --checksum --transfers=4"
            }

    def save_selected_to_associated_list(self):
        remote_name = self._get_current_remote_name()
        if not remote_name:
            messagebox.showwarning("No Remote", "Please select a remote first to associate items with.", parent=self.master)
            return
        
        selected_indices = self.local_files_list.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select files/folders from the 'Local Path' listing to save.", parent=self.master)
            return
            
        self._ensure_remote_list_entry(remote_name)
        current_local_dir = self.current_local_path.get()
        added_count = 0
        items_added_log = []
        
        for i in selected_indices:
            item_name_in_listbox = self.local_files_list.get(i)
            if item_name_in_listbox == "../": continue
            
            full_item_path = os.path.normpath(os.path.join(current_local_dir, item_name_in_listbox.rstrip('/')))
            
            if full_item_path not in self.associated_remote_lists[remote_name]["local_items"]:
                self.associated_remote_lists[remote_name]["local_items"].append(full_item_path)
                items_added_log.append(full_item_path)
                added_count +=1
                
        if added_count > 0:
            self.associated_remote_lists[remote_name]["local_items"].sort()
            self.save_associated_lists_to_file()
            self.display_associated_items_for_selected_remote()
            log_utils.app_log(f"Saved {added_count} item(s) to associated list for remote '{remote_name}': {', '.join(items_added_log)}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            self.log_message_gui(f"{added_count} selected item(s) saved to the list for remote '{remote_name}'.\n", is_info=True)
        else:
            messagebox.showinfo("No New Items", "Selected items were already in the list or no valid items selected.", parent=self.master)

    def remove_item_from_list(self):
        remote_name = self._get_current_remote_name()
        if not remote_name:
            messagebox.showwarning("No Remote", "Please select a remote first.", parent=self.master)
            return
            
        selected_indices = self.associated_items_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select an item from the 'Associated Local Items' list to remove.", parent=self.master)
            return
            
        selected_item_path = self.associated_items_listbox.get(selected_indices[0])
        
        if remote_name in self.associated_remote_lists and \
           selected_item_path in self.associated_remote_lists[remote_name].get("local_items", []):
            if messagebox.askyesno("Confirm Removal", f"Remove '{selected_item_path}' from the list for remote '{remote_name}'?", parent=self.master):
                self.associated_remote_lists[remote_name]["local_items"].remove(selected_item_path)
                self.save_associated_lists_to_file()
                self.display_associated_items_for_selected_remote()
                log_utils.app_log(f"Removed '{selected_item_path}' from list for remote '{remote_name}'.", gui_log_func=self._gui_log_callback, log_to_gui=False)
        else: # pragma: no cover
            messagebox.showerror("Error", "Could not find the selected item in the data for removal.", parent=self.master)

    def configure_list_settings(self):
        remote_name = self._get_current_remote_name()
        if not remote_name:
            messagebox.showwarning("No Remote", "Please select a remote first to configure its list settings.", parent=self.master)
            return
            
        self._ensure_remote_list_entry(remote_name)
        current_data = self.associated_remote_lists[remote_name]
        
        dialog = AssociatedListSettingsDialog(self.master,
                                              current_data.get("remote_dest_segment", ""),
                                              current_data.get("rclone_flags", "-P --checksum --transfers=4"),
                                              theme_colors=self.theme_colors)
        if dialog.result:
            self.associated_remote_lists[remote_name]["remote_dest_segment"] = dialog.result["remote_dest_segment"]
            self.associated_remote_lists[remote_name]["rclone_flags"] = dialog.result["rclone_flags"]
            self.save_associated_lists_to_file()
            log_utils.app_log(f"Updated destination/flags for remote '{remote_name}'. Dest: '{dialog.result['remote_dest_segment']}', Flags: '{dialog.result['rclone_flags']}'", 
                              gui_log_func=self._gui_log_callback, log_to_gui=False)
            messagebox.showinfo("Settings Saved", f"Settings updated for remote '{remote_name}'.", parent=self.master)

    def run_operation_for_list(self, operation_type="copy"):
        remote_name = self._get_current_remote_name()
        if not remote_name:
            messagebox.showwarning("No Remote", "Please select a remote first.", parent=self.master)
            return
        
        if remote_name not in self.associated_remote_lists or \
           not self.associated_remote_lists[remote_name].get("local_items"):
            messagebox.showinfo("No Items", f"There are no local items associated with remote '{remote_name}' to {operation_type}.", parent=self.master)
            return
        
        list_data = self.associated_remote_lists[remote_name]
        local_items_to_process = list_data["local_items"]
        dest_segment = list_data.get("remote_dest_segment", "")
        flags_str = list_data.get("rclone_flags", "")
        flags = flags_str.split() if flags_str else []
        op_display_name = operation_type.capitalize()

        confirm_msg = f"Are you sure you want to {operation_type} all {len(local_items_to_process)} listed items for remote '{remote_name}'?"
        if dest_segment: confirm_msg += f"\nDestination subfolder on remote: '{dest_segment}'"
        if flags_str: confirm_msg += f"\nWith flags: '{flags_str}'"


        if not messagebox.askyesno(f"Confirm {op_display_name} All", confirm_msg, parent=self.master):
            self.log_message_gui(f"{op_display_name} all listed items for remote '{remote_name}' cancelled by user.\n", is_info=True)
            return
        
        self.log_message_gui(f"Initiating {op_display_name} for {len(local_items_to_process)} listed item(s) to remote '{remote_name}'...\n", is_info=True)
        
        operation_count = 0
        for local_item_path in local_items_to_process:
            operation_count += 1
            item_basename = os.path.basename(local_item_path)
            
            individual_remote_dest_parts = [remote_name + ":"]
            if dest_segment: 
                individual_remote_dest_parts.append(dest_segment)
            individual_remote_dest_parts.append(item_basename) 
            
            individual_remote_dest = "/".join(s.strip("/") for s in individual_remote_dest_parts if s)
            if not individual_remote_dest.startswith(remote_name + ":"): # pragma: no cover
                individual_remote_dest = remote_name + ":" + individual_remote_dest.split(":",1)[-1]
            
            cmd_parts = [operation_type] + flags + [local_item_path, individual_remote_dest]
            
            log_utils.app_log(f"Executing ({operation_count}/{len(local_items_to_process)} for list): rclone {' '.join(cmd_parts)}",
                              gui_log_func=self._gui_log_callback, 
                              log_to_gui=False)

            rclone.run_rclone_command(cmd_parts, 
                                      capture_output=False,
                                      gui_log_func=self._gui_log_callback,
                                      config_password=self.rclone_config_password)
        
        self.log_message_gui(f"All {op_display_name} commands for remote '{remote_name}' have been initiated.\nCheck log.txt and rclone console windows for detailed progress and status.\n", is_info=True)
        
        if self.master.winfo_exists(): # pragma: no branch
            self.master.after(10000, lambda: self.refresh_remote_files(sub_item_nav=None))


    def refresh_all_listings(self):
        self.log_message_gui("Refreshing directories...\n", is_info=True)
        self.refresh_local_files()
        self.refresh_remote_files(sub_item_nav=None)

    def browse_local_path(self):
        directory = filedialog.askdirectory(initialdir=self.current_local_path.get(), parent=self.master)
        if directory: # pragma: no branch
            self.current_local_path.set(os.path.normpath(directory))
            self.refresh_local_files()
            log_utils.app_log(f"Browsed local path: {directory}", gui_log_func=self._gui_log_callback, log_to_gui=False)

    def load_remotes(self):
        log_utils.app_log("Loading remotes...", gui_log_func=self._gui_log_callback, log_to_gui=False)
        try:
            current_selection_before_load = self.remote_combo.get()
            self.remotes = rclone.get_remotes(gui_log_func=self._gui_log_callback, config_password=self.rclone_config_password)
            
            if self.remotes:
                self.remote_combo['values'] = self.remotes
                if current_selection_before_load and current_selection_before_load in self.remotes:
                    self.remote_combo.set(current_selection_before_load)
                elif not self.current_remote_base.get() and self.remotes:
                    self.remote_combo.current(0)
                else: # pragma: no cover
                    if not self.remotes: self.remote_combo.set('')
                
                self.on_remote_selected(None)
                log_utils.app_log(f"Found remotes: {', '.join(self.remotes)}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            else:
                self.remote_combo['values'] = []
                self.remote_combo.set('')
                self.on_remote_selected(None)
                log_utils.app_log("No rclone remotes found or accessible (check password if config encrypted).", level="warning", gui_log_func=self._gui_log_callback, log_to_gui=True)
        except Exception as e: # pragma: no cover
            log_utils.app_log(f"Error loading remotes: {e}", level="error", gui_log_func=self._gui_log_callback, log_to_gui=True)
            logger.error("Exception during load_remotes", exc_info=True)
            messagebox.showerror("Error Loading Remotes", f"Could not load rclone remotes: {e}\nCheck log.txt. If config is encrypted, ensure password was entered correctly.", parent=self.master)
            self.remote_combo['values'] = []
            self.remote_combo.set('')
            self.on_remote_selected(None)

    def on_remote_selected(self, event):
        selected_remote_name_no_colon = self.remote_combo.get()
        
        if selected_remote_name_no_colon:
            self.current_remote_base.set(selected_remote_name_no_colon + ":")
            self.current_remote_path_segment.set("")
            self.update_remote_path_display()
            self.refresh_remote_files()
            self.display_associated_items_for_selected_remote()
            log_utils.app_log(f"Selected remote: {self.current_remote_base.get()}", gui_log_func=self._gui_log_callback, log_to_gui=False)
        else:
            self.current_remote_base.set("")
            self.current_remote_path_segment.set("")
            self.update_remote_path_display()
            if hasattr(self, 'remote_files_list'): # pragma: no branch
                self.remote_files_list.delete(0, tk.END) 
                self.remote_files_list.insert(tk.END, "<No remote selected or accessible>") 
            self.display_associated_items_for_selected_remote()


    def refresh_local_files(self):
        if not hasattr(self, 'local_files_list'): return # pragma: no cover
        
        self.local_files_list.delete(0, tk.END)
        path = self.current_local_path.get()
        
        if not path or not os.path.isdir(path): # pragma: no cover
            self.local_files_list.insert(tk.END, "<Invalid local path>")
            return
            
        self.local_files_list.insert(tk.END, "../")
        try:
            items = os.listdir(path)
            sorted_items = sorted(items, key=lambda s: (not os.path.isdir(os.path.join(path, s)), s.lower()))
            for item in sorted_items:
                display_name = item + ("/" if os.path.isdir(os.path.join(path, item)) else "")
                self.local_files_list.insert(tk.END, display_name)
        except Exception as e: # pragma: no cover
            log_utils.app_log(f"Error listing local files in '{path}': {e}", level="error", gui_log_func=self._gui_log_callback, log_to_gui=True)
            logger.error(f"Error listing local files {path}", exc_info=True)
            self.local_files_list.insert(tk.END, f"<Error listing: {e}>")


    def on_local_double_click(self, event):
        if not hasattr(self, 'local_files_list'): return # pragma: no cover
        selection = self.local_files_list.curselection()
        if not selection: return
        
        item_name = self.local_files_list.get(selection[0])
        current_dir = self.current_local_path.get()
        new_path = ""
        
        if item_name == "../":
            new_path = os.path.dirname(current_dir)
        elif item_name.endswith("/"):
            new_path = os.path.normpath(os.path.join(current_dir, item_name.rstrip('/')))
        else:
            self.log_message_gui(f"Double-clicked local file: {item_name}. No action defined for files.\n", is_info=True)
            return
        
        if os.path.isdir(new_path):
            self.current_local_path.set(new_path)
            self.refresh_local_files()
        else: # pragma: no cover
            log_utils.app_log(f"Cannot navigate to local '{new_path}', not a valid directory.", level="warning", gui_log_func=self._gui_log_callback, log_to_gui=True)
            messagebox.showwarning("Navigation Error", f"Path '{new_path}' is not a valid directory.", parent=self.master)


    def refresh_remote_files(self, sub_item_nav=None):
        if not hasattr(self, 'remote_files_list'): return # pragma: no cover
        
        full_remote_path_to_list = ""
        if sub_item_nav:
            base_remote_for_nav = self.current_remote_base.get()
            if not base_remote_for_nav: # pragma: no cover
                messagebox.showwarning("No Remote", "Select a remote first to browse.", parent=self.master)
                self.remote_files_list.delete(0, tk.END)
                self.remote_files_list.insert(tk.END, "<Select Remote to browse>")
                return

            current_segment_for_nav = self.current_remote_path_segment.get().strip("/")
            if sub_item_nav == "../":
                if not current_segment_for_nav or "/" not in current_segment_for_nav:
                    self.current_remote_path_segment.set("")
                else:
                    self.current_remote_path_segment.set("/".join(current_segment_for_nav.split("/")[:-1]))
            elif sub_item_nav.endswith("/"):
                new_segment_part_for_nav = sub_item_nav.rstrip('/')
                if current_segment_for_nav:
                    self.current_remote_path_segment.set(f"{current_segment_for_nav}/{new_segment_part_for_nav}")
                else:
                    self.current_remote_path_segment.set(new_segment_part_for_nav)
            self.update_remote_path_display() 
            full_remote_path_to_list = self.get_full_remote_path()

        else:
            full_remote_path_to_list = self.get_full_remote_path()

        self.remote_files_list.delete(0, tk.END)
        if not full_remote_path_to_list or not self.current_remote_base.get():
            self.remote_files_list.insert(tk.END, "<Select Remote or path is invalid>")
            return

        log_utils.app_log(f"Listing remote files for: {full_remote_path_to_list}...", gui_log_func=self._gui_log_callback, log_to_gui=False) 
        items, err_msg_from_rclone, code = rclone.list_files(full_remote_path_to_list, gui_log_func=self._gui_log_callback, config_password=self.rclone_config_password)
        
        if code == 0:
            if self.current_remote_path_segment.get().strip("/"): 
                 self.remote_files_list.insert(tk.END, "../")

            if items:
                sorted_items = sorted(items, key=lambda s: (not s.endswith("/"), s.lower()))
                for item_name in sorted_items:
                    self.remote_files_list.insert(tk.END, item_name)
            elif not self.remote_files_list.size():
                self.remote_files_list.insert(tk.END, "<Remote folder is empty>")
        else:
            error_message_display = f"Error listing '{full_remote_path_to_list}'."
            if err_msg_from_rclone: error_message_display += f" Rclone msg: {err_msg_from_rclone.strip()}"
            self.log_message_gui(f"{error_message_display}\n", is_error=True) 
            self.remote_files_list.insert(tk.END, f"<Error: {err_msg_from_rclone.strip() if err_msg_from_rclone else 'See logs'}>")


    def on_remote_double_click(self, event):
        if not hasattr(self, 'remote_files_list'): return # pragma: no cover
        selection = self.remote_files_list.curselection()
        if not selection: return
        
        item_name = self.remote_files_list.get(selection[0])
        if item_name.endswith("/") or item_name == "../":
            self.refresh_remote_files(sub_item_nav=item_name)
        else:
            self.log_message_gui(f"Double-clicked remote file: {item_name}. No action defined for files.\n", is_info=True)


    def update_remote_path_display(self):
        if not hasattr(self, 'remote_path_display'): return # pragma: no cover
        full_path = self.get_full_remote_path()
        self.remote_path_display.config(text=full_path if full_path else "<Select Remote>")

    def get_full_remote_path(self):
        base = self.current_remote_base.get()
        segment = self.current_remote_path_segment.get().strip("/")
        if not base: return ""
        return base + segment if segment else base

    def process_worker_thread_queue(self):
        try:
            while True:
                msg_type, data = self.worker_thread_queue.get_nowait()
                
                if msg_type == MSG_TYPE_RCLONE_OUTPUT:
                    message, is_stderr = data
                    if self.pcloud_config_window_ref and self.pcloud_config_window_ref.winfo_exists():
                        self.pcloud_config_window_ref.update_output_display(message, is_stderr)
                    else: # pragma: no cover
                        self.log_message_gui(message, is_error=is_stderr)
                
                elif msg_type == MSG_TYPE_PROMPT_AUTH_DIALOG:
                    auth_url_from_rclone = data
                    self.pcloud_auth_event.clear()
                    self.pcloud_auth_result_holder['result'] = None
                    
                    dialog_parent = self.master
                    if self.pcloud_config_window_ref and self.pcloud_config_window_ref.winfo_exists(): # pragma: no branch
                        dialog_parent = self.pcloud_config_window_ref
                    
                    auth_dialog = AuthSuccessDialog(dialog_parent, auth_url=auth_url_from_rclone, theme_colors=self.theme_colors)
                    self.pcloud_auth_result_holder['result'] = auth_dialog.result
                    self.pcloud_auth_event.set()
                
                elif msg_type == MSG_TYPE_AUTOMATION_COMPLETE:
                    success = data
                    self.pcloud_automation_completion_handler(success)
                    
        except queue.Empty:
            pass 
        except Exception as e: # pragma: no cover
            logger.error(f"Error processing worker thread queue: {e}", exc_info=True)
            self.log_message_gui(f"Internal error processing background task: {e}\n", is_error=True)
        finally:
            if self.master.winfo_exists(): # pragma: no branch
                self.master.after(100, self.process_worker_thread_queue)

    def start_operation(self, operation_type, direction):
        sources_to_process = []
        source_items_display_names = []
        destination_base_path = ""

        if direction == "lr": 
            selected_indices = self.local_files_list.curselection()
            if not selected_indices:
                messagebox.showwarning("No Selection", "Please select one or more local items to transfer.", parent=self.master)
                return
            source_items_display_names = [self.local_files_list.get(i) for i in selected_indices if self.local_files_list.get(i) != '../']
            if not source_items_display_names:
                messagebox.showwarning("Invalid Selection", "Cannot operate on '../'. Please select actual files or folders.", parent=self.master)
                return
            
            current_local_dir = self.current_local_path.get()
            sources_to_process = [os.path.normpath(os.path.join(current_local_dir, name.rstrip('/'))) for name in source_items_display_names]
            
            destination_base_path = self.get_full_remote_path()
            if not destination_base_path or not self.current_remote_base.get(): # pragma: no cover
                messagebox.showerror("Error", "Remote destination path not set. Please select a remote.", parent=self.master)
                return

        elif direction == "rl": 
            selected_indices = self.remote_files_list.curselection()
            if not selected_indices:
                messagebox.showwarning("No Selection", "Please select one or more remote items to transfer.", parent=self.master)
                return
            source_items_display_names = [self.remote_files_list.get(i) for i in selected_indices if self.remote_files_list.get(i) != '../']
            if not source_items_display_names:
                messagebox.showwarning("Invalid Selection", "Cannot operate on '../'. Please select actual files or folders.", parent=self.master)
                return

            current_remote_full_path = self.get_full_remote_path() 
            if not current_remote_full_path or not self.current_remote_base.get(): # pragma: no cover
                messagebox.showerror("Error", "Remote source path not set. Please select a remote and navigate if needed.", parent=self.master)
                return
            
            sources_to_process = [f"{current_remote_full_path.rstrip('/')}/{name.rstrip('/')}" for name in source_items_display_names]
            
            destination_base_path = self.current_local_path.get()
            if not destination_base_path or not os.path.isdir(destination_base_path): # pragma: no cover
                messagebox.showerror("Error", "Local destination path is not a valid directory.", parent=self.master)
                return
        else: return # pragma: no cover

        op_display_name = operation_type.capitalize()
        confirm_msg = f"Are you sure you want to {operation_type} the selected item(s)?\n\n"
        confirm_msg += f"Source(s) ({len(source_items_display_names)} item(s) like: '{source_items_display_names[0]}', ...)\n"
        confirm_msg += f"Destination Base: '{destination_base_path}'"

        if not messagebox.askyesno(f"Confirm {op_display_name}", confirm_msg, parent=self.master):
            self.log_message_gui(f"{op_display_name} for selected items cancelled.\n", is_info=True)
            return

        self.log_message_gui(f"Initiating {op_display_name} for {len(sources_to_process)} selected item(s)...\n", is_info=True)
        log_utils.app_log(f"User confirmed {op_display_name}: {len(sources_to_process)} items. Sources like: {sources_to_process[0]}... Dest Base: {destination_base_path}",
                          gui_log_func=self._gui_log_callback,
                          log_to_gui=False)


        for i, src_full_path in enumerate(sources_to_process):
            item_basename_for_dest = os.path.basename(src_full_path.rstrip('/\\'))
            actual_rclone_destination = ""

            is_source_dir = (direction == "lr" and os.path.isdir(src_full_path)) or \
                            (direction == "rl" and source_items_display_names[i].endswith("/"))

            if is_source_dir:
                if direction == "lr": 
                    actual_rclone_destination = f"{destination_base_path.rstrip('/')}/{item_basename_for_dest}"
                else: 
                    actual_rclone_destination = os.path.join(destination_base_path, item_basename_for_dest)
            else:
                actual_rclone_destination = destination_base_path

            if direction == "lr": actual_rclone_destination = actual_rclone_destination.replace(os.sep, "/")
            else: actual_rclone_destination = os.path.normpath(actual_rclone_destination)

            rclone_flags = ["-v", "--stats=5s", "--stats-one-line", "-P"]
            cmd_args = [operation_type] + rclone_flags + [src_full_path, actual_rclone_destination]
            
            log_utils.app_log(f"Rclone cmd ({i+1}/{len(sources_to_process)} direct selection): rclone {' '.join(cmd_args)}",
                              gui_log_func=self._gui_log_callback, 
                              log_to_gui=False) 

            rclone.run_rclone_command(cmd_args, 
                                      capture_output=False,
                                      gui_log_func=self._gui_log_callback, 
                                      config_password=self.rclone_config_password)

        self.log_message_gui(f"{op_display_name} for {len(sources_to_process)} items initiated.\nCheck log.txt or rclone console window(s) for progress and completion.\n", is_info=True)
        
        if self.master.winfo_exists(): # pragma: no branch
            self.master.after(10000, self.refresh_local_files) 
            self.master.after(10000, lambda: self.refresh_remote_files(sub_item_nav=None))

    def launch_rclone_config_cmd(self):
        rclone_executable = rclone.RCLONE_EXE_PATH
        info_msg = "A Command Prompt will open for 'rclone config'.\n" \
                   "Follow instructions there. Close CMD when done.\n" \
                   "Then, 'Refresh Remotes' here."
        if self.rclone_config_password: # pragma: no branch
            info_msg += "\n\nNOTE: Your rclone config seems to be password protected. " \
                        "You will likely need to enter this password in the CMD window if rclone prompts."
            
        messagebox.showinfo("Rclone Configuration via CMD", info_msg, parent=self.master)
        try:
            log_utils.app_log(f"Launching CMD for rclone config: {rclone_executable} config", gui_log_func=self._gui_log_callback, log_to_gui=False)

            env = os.environ.copy()
            if self.rclone_config_password: # pragma: no branch
                env["RCLONE_CONFIG_PASS"] = self.rclone_config_password
                log_utils.app_log("Attempting to pass RCLONE_CONFIG_PASS to external rclone config process.", gui_log_func=self._gui_log_callback, log_to_gui=False)

            subprocess.Popen([rclone_executable, "config"], creationflags=subprocess.CREATE_NEW_CONSOLE, env=env)
            self.log_message_gui("CMD for 'rclone config' launched. Refresh remotes when done.\n", is_info=True)
        except Exception as e: # pragma: no cover
            err_msg = f"Failed to launch 'rclone config' CMD: {e}"
            log_utils.app_log(err_msg, level="error", gui_log_func=self._gui_log_callback, log_to_gui=True)
            logger.error("Launch CMD Error", exc_info=True)
            messagebox.showerror("Launch Error", f"{err_msg}\nCheck log.txt.", parent=self.master)

    def initiate_auto_setup(self):
        provider = self.selected_auto_setup_provider.get()
        if not provider:
            messagebox.showwarning("No Provider", "No cloud provider selected or available for auto-setup.", parent=self.master)
            return
        if provider == "pCloud":
            self.open_pcloud_config_prototype_window()
        else: # pragma: no cover
            messagebox.showinfo("Not Implemented", f"Auto-setup for '{provider}' is not yet implemented.", parent=self.master)

    def open_pcloud_config_prototype_window(self):
        if self.pcloud_config_window_ref and self.pcloud_config_window_ref.winfo_exists(): # pragma: no cover
            self.pcloud_config_window_ref.lift()
            return
        self.pcloud_config_window_ref = PCloudConfigPrototypeWindow(
            self.master, self,
            self.worker_thread_queue,
            self.pcloud_auth_event,
            lambda: self.pcloud_auth_result_holder['result'],
            self.theme_colors, 
            self.rclone_config_password
        ) 

    def pcloud_automation_completion_handler(self, success):
        pcloud_window = self.pcloud_config_window_ref 
        pcloud_window_was_open_and_exists = pcloud_window and pcloud_window.winfo_exists()

        if success:
            self.log_message_gui("Automated pCloud config successful. Refreshing remotes...\n", is_info=True)
            self.load_remotes()
        elif pcloud_window_was_open_and_exists: # pragma: no cover
            pass 
        else:
            self.log_message_gui("Automated pCloud config failed or was cancelled. Check log.txt or pCloud window output if it was visible.\n", is_error=True)
        
        if pcloud_window_was_open_and_exists: # pragma: no branch
            pcloud_window.handle_automation_result(success)


    def confirm_delete_remote(self):
        selected_remote_name = self.remote_combo.get()
        if not selected_remote_name:
            messagebox.showwarning("No Remote Selected", "Please select a remote from the dropdown list to delete.", parent=self.master)
            return

        if messagebox.askyesno("Confirm Delete Remote",
                               f"Are you sure you want to permanently delete the remote '{selected_remote_name}'?\n"
                               "This action cannot be undone from the GUI.",
                               parent=self.master, icon=messagebox.WARNING):
            self.delete_remote(selected_remote_name)

    def delete_remote(self, remote_name):
        self.log_message_gui(f"Attempting to delete remote: {remote_name}...\n", is_info=True)
        log_utils.app_log(f"User initiated deletion of remote: {remote_name}", gui_log_func=self._gui_log_callback, log_to_gui=False)
        cmd_args = ["config", "delete", remote_name]
        
        stdout, stderr, return_code = rclone.run_rclone_command(
            cmd_args,
            capture_output=True, 
            gui_log_func=self._gui_log_callback,
            config_password=self.rclone_config_password 
        )

        if return_code == 0:
            self.log_message_gui(f"Remote '{remote_name}' deleted successfully.\n", is_info=True) 
            if stdout.strip(): # pragma: no cover
                 log_utils.app_log(f"Remote '{remote_name}' delete stdout: {stdout.strip()}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            log_utils.app_log(f"Remote '{remote_name}' deleted. RC: {return_code}.", gui_log_func=self._gui_log_callback, log_to_gui=False)
        else: # pragma: no cover
            error_msg = f"Failed to delete remote '{remote_name}'. RC: {return_code}.\n"
            if stderr: error_msg += f"Error: {stderr.strip()}\n"
            self.log_message_gui(error_msg, is_error=True)
            log_utils.app_log(f"Error deleting remote '{remote_name}'. RC: {return_code}. Stderr: {stderr.strip()}. Stdout: {stdout.strip() if stdout else ''}", level="error", gui_log_func=self._gui_log_callback, log_to_gui=False)
            messagebox.showerror("Delete Failed", f"Could not delete remote '{remote_name}'.\n{stderr.strip() if stderr else 'Unknown error, check log.txt.'}", parent=self.master)

        self.load_remotes()

    def prompt_generate_batch_file(self):
        remote_name = self._get_current_remote_name()
        if not remote_name:
            messagebox.showwarning("No Remote Selected", "Please select a remote to generate a batch file for its associated list.", parent=self.master)
            return
        if remote_name not in self.associated_remote_lists or \
           not self.associated_remote_lists[remote_name].get("local_items"):
            messagebox.showinfo("No Associated Items", f"There are no local items associated with remote '{remote_name}' to include in a batch file.", parent=self.master)
            return

        log_utils.app_log(f"Opening BatchGenDialog for remote: {remote_name}", gui_log_func=self._gui_log_callback, log_to_gui=True)

        dialog = BatchGenDialog(self.master, 
                                title=f"Generate Batch for '{remote_name}'", 
                                theme_colors_dict=self.theme_colors,
                                default_rclone_exe=rclone.RCLONE_EXE_PATH)
        
        log_utils.app_log(f"BatchGenDialog closed. dialog.result from simpledialog: {dialog.result}", gui_log_func=self._gui_log_callback, log_to_gui=True)

        if dialog.result:
            options = dialog.result
            list_data = self.associated_remote_lists[remote_name]
            
            log_utils.app_log(f"BatchGenDialog options received: {options}", gui_log_func=self._gui_log_callback, log_to_gui=False) 
            self.log_message_gui(f"Proceeding to generate script content with options: {options}\n", is_info=True)

            script_content = self.generate_batch_script_content(remote_name, list_data, options)
            
            default_filename = f"rclone_{remote_name.replace(':', '_')}_{options['operation']}.bat"
            
            log_utils.app_log(f"Prompting to save batch file: {default_filename}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            filepath = filedialog.asksaveasfilename(
                parent=self.master,
                title="Save Batch File",
                initialfile=default_filename,
                defaultextension=".bat",
                filetypes=[("Batch files", "*.bat"), ("All files", "*.*")]
            )
            log_utils.app_log(f"asksaveasfilename returned: {filepath}", gui_log_func=self._gui_log_callback, log_to_gui=False)
            
            if filepath:
                try:
                    with open(filepath, "w", encoding="utf-8", newline="\r\n") as f: 
                        f.write(script_content)
                    self.log_message_gui(f"Batch file saved to: {filepath}\n", is_info=True)
                    
                    instructions = f"Batch file '{os.path.basename(filepath)}' saved successfully.\n\n"
                    instructions += "To use it for scheduled tasks (e.g., via Windows Task Scheduler):\n"
                    instructions += "1. Open Task Scheduler.\n"
                    instructions += "2. Create a new basic task.\n"
                    instructions += "3. For 'Action', choose 'Start a program'.\n"
                    instructions += f"4. For 'Program/script', browse to and select this file:\n   {filepath}\n"
                    
                    if options["password_option"] == "prompt":
                        instructions += "\nNOTE: The script is set to prompt for a password. The Task Scheduler window may need to be visible or run interactively for the prompt to appear.\n"
                    elif options["password_option"] == "hardcode" and not options["hardcoded_password"]:
                         instructions += "\nWARNING: You chose to hardcode the password but left it blank in the script. The script will likely fail if your config is encrypted.\n"
                    elif options["password_option"] == "hardcode": # pragma: no branch
                         instructions += "\nWARNING: Password has been hardcoded into the script. This is less secure. Ensure the script file is protected.\n"
                    else:
                        instructions += "\nIf your rclone.conf is password-protected, ensure the script can access the password (e.g., via prompt if enabled in script, or by setting RCLONE_CONFIG_PASS environment variable for the task in Task Scheduler if you modify the script or task settings manually).\n"

                    instructions += "\nRefer to your OS documentation for more details on scheduling tasks."
                    messagebox.showinfo("Batch File Generated", instructions, parent=self.master)
                    
                except Exception as e: # pragma: no cover
                    self.log_message_gui(f"Error saving batch file: {e}\n", is_error=True)
                    messagebox.showerror("Save Error", f"Failed to save batch file: {e}", parent=self.master)
        else:
            log_utils.app_log("BatchGenDialog was cancelled or returned no result. Batch file not generated.", gui_log_func=self._gui_log_callback, log_to_gui=True) 
            self.log_message_gui("Batch file generation cancelled.\n", is_info=True)


    def generate_batch_script_content(self, remote_name, list_data, options):
        lines = []
        
        if options["password_option"] == "hardcode":
            lines.append("@echo off") 
        else:
            lines.append("@echo on") 
        
        lines.append("setlocal")
        lines.append("")
        lines.append(":: --- BEGIN SCRIPT CONFIGURATION ---")
        lines.append(f":: Batch script for rclone: Remote '{remote_name}', Operation: {options['operation'].capitalize()}")
        lines.append(f":: Generated by Rclone GUI on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(":: ")
        lines.append(":: IMPORTANT: If your rclone.conf is password-protected and you did NOT choose")
        lines.append(":: to hardcode the password in this script, you might need to:")
        lines.append(":: 1. Ensure this script prompts for the password (if that option was chosen).")
        lines.append(":: 2. OR, set the RCLONE_CONFIG_PASS environment variable in your Task Scheduler")
        lines.append("::    settings for this task if you intend to run it non-interactively.")
        lines.append("")


        lines.append(f"set RCLONE_EXE=\"{options['rclone_exe']}\"")
        lines.append("if not exist %RCLONE_EXE% (")
        lines.append("  echo ERROR: Rclone executable not found at %RCLONE_EXE%")
        lines.append("  echo Please correct the RCLONE_EXE path in this script or ensure rclone is in your system PATH and change RCLONE_EXE to just \"rclone\".")
        lines.append("  goto end_script")
        lines.append(")")
        lines.append("")

        if options["password_option"] == "prompt":
            lines.append(":: Interactively enter your password when the script runs.")
            lines.append("echo Make sure this window is visible if your rclone.conf is password protected.")
            lines.append("set /p RCLONE_CONFIG_PASS=\"Enter rclone config password (leave blank if none): \"")
        elif options["password_option"] == "hardcode":
            lines.append(":: WARNING: Password is hardcoded in this script. This is INSECURE.")
            lines.append(":: Ensure this file is protected if you use this option.")
            lines.append(f"set RCLONE_CONFIG_PASS={options['hardcoded_password']}") 
        lines.append("")

        lines.append(":: --- RCLONE COMMANDS ---")
        
        local_items = list_data.get("local_items", [])
        dest_segment = list_data.get("remote_dest_segment", "")
        base_flags = list_data.get("rclone_flags", "") 

        if not local_items:
            lines.append("REM No local items found in the associated list for this remote.")
        
        for i, local_item_path in enumerate(local_items):
            item_basename = os.path.basename(local_item_path)
            remote_dest_parts = [remote_name + ":"]
            if dest_segment:
                remote_dest_parts.append(dest_segment)
            remote_dest_parts.append(item_basename) 
            
            individual_remote_dest = "/".join(s.strip("/") for s in remote_dest_parts if s)
            
            cmd = ["%RCLONE_EXE%"] 
            cmd.append(options["operation"])
            if base_flags:
                cmd.extend(base_flags.split()) 
            
            if options["log_enabled"] and options["log_file"]:
                cmd.append(f"--log-file=\"{options['log_file']}\"")
                cmd.append("--log-level=INFO") 
            
            cmd.append(f"\"{local_item_path}\"")
            cmd.append(f"\"{individual_remote_dest}\"")
            
            lines.append("")
            lines.append(f"echo Processing item {i+1}/{len(local_items)}: {local_item_path} TO {individual_remote_dest}")
            lines.append(" ".join(cmd))

        lines.append("")
        lines.append(":: --- END OF SCRIPT ---")
        lines.append(":end_script")
        lines.append("echo Batch script operations complete. Check logs/output for details.")
        lines.append("endlocal")
        if options["password_option"] == "prompt": 
            lines.append("timeout /t 10 /nobreak >nul")


        return "\r\n".join(lines) 

class PCloudConfigPrototypeWindow(tk.Toplevel):
    def __init__(self, parent, main_gui_controller, worker_queue_from_main, 
                 auth_event_for_worker, get_auth_result_func_from_main, 
                 theme_colors, rclone_config_password): 
        super().__init__(parent)
        if theme_colors: # pragma: no branch
            self.configure(bg=theme_colors['WINDOW_BG'])
        self.theme_colors = theme_colors

        self.main_gui = main_gui_controller
        self.worker_queue_for_output = worker_queue_from_main
        self.auth_event_for_worker_to_wait_on = auth_event_for_worker
        self.get_auth_result_from_main_gui = get_auth_result_func_from_main
        self.rclone_config_password = rclone_config_password

        self.title("Automated pCloud Setup")
        self.geometry("700x550")
        self.transient(parent)
        
        self.automation_thread = None
        self.auth_url_from_rclone = ""
        
        frame = ttk.Frame(self, padding="10")
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Automate pCloud Remote Setup", font=('Arial', 14, 'bold')).pack(pady=(0,10))
        ttk.Label(frame, text="This will attempt to guide rclone through pCloud setup.", wraplength=650).pack()
        ttk.Label(frame, text="A dialog will prompt you to confirm browser authentication after rclone provides a URL.", wraplength=650).pack(pady=(0,10))
        
        name_frame = ttk.Frame(frame)
        name_frame.pack(fill=tk.X, pady=5)
        ttk.Label(name_frame, text="Enter Name for pCloud Remote:").pack(side=tk.LEFT, padx=5)
        self.remote_name_entry = ttk.Entry(name_frame, width=30)
        self.remote_name_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.remote_name_entry.focus_set()
        
        self.start_button = ttk.Button(frame, text="Start pCloud Setup", command=self.start_automation)
        self.start_button.pack(pady=10)
        
        output_label = ttk.Label(frame, text="Rclone Output & Automation Log:")
        output_label.pack(anchor="w", pady=(5,0))
        
        pcloud_output_options = {
            'background': self.theme_colors['WIDGET_BG'], 'foreground': self.theme_colors['TEXT_COLOR'],
            'selectbackground': self.theme_colors['SELECT_BG_COLOR'], 'selectforeground': self.theme_colors['SELECT_FG_COLOR'],
            'insertbackground': self.theme_colors['TEXT_INSERT_BG'], 'borderwidth': 0, 'relief': tk.FLAT,
            'highlightthickness': 1, 'highlightbackground': self.theme_colors['LISTBOX_HIGHLIGHT_BG'],
            'highlightcolor': self.theme_colors['LISTBOX_HIGHLIGHT_COLOR'], 'wrap': tk.WORD,
            'font': ("Consolas", 9)
        }
        self.output_text = scrolledtext.ScrolledText(frame, height=15, state=tk.DISABLED, **pcloud_output_options)
        self.output_text.pack(expand=True, fill=tk.BOTH, pady=5)
        
        self.output_text.tag_config("error", foreground=self.theme_colors['LOG_ERROR_FG'])
        self.output_text.tag_config("info", foreground=self.theme_colors['LOG_INFO_FG'], font=("Consolas", 9, "bold")) 
        self.output_text.tag_config("stdout", foreground=self.theme_colors['LOG_STDOUT_FG'])
        self.output_text.tag_config("stdin", foreground=self.theme_colors['LOG_STDIN_FG']) 
        
        self.close_button = ttk.Button(frame, text="Close Window", command=self.close_window)
        self.close_button.pack(pady=5)
        self.protocol("WM_DELETE_WINDOW", self.close_window)

    def extract_auth_url(self, rclone_output_line):
        match_localhost = re.search(r'(https?://(?:localhost|127\.0\.0\.1):\d+/auth\S*)', rclone_output_line)
        if match_localhost:
            return match_localhost.group(1)
        
        match_direct_link = re.search(r'(?:go to(?: the following link)?|link|visit|url|open this link|verification code):\s*(https?://\S+)', rclone_output_line, re.IGNORECASE)
        if match_direct_link:
            return match_direct_link.group(1)
        
        return None


    def update_output_display(self, message, is_stderr=False):
        if not self.winfo_exists(): return # pragma: no cover
        
        self.output_text.config(state=tk.NORMAL)
        
        tag_to_use = ("stdout",)
        if is_stderr: tag_to_use = ("error",)
        if "ACTION REQUIRED" in message or "Waiting for browser authentication" in message or \
           "If your browser doesn't open automatically" in message or \
           message.strip().startswith("---") or "Normally rclone will open a web browser" in message: # pragma: no cover
            tag_to_use = ("info",) 
        elif message.startswith("Sending to rclone:"): # pragma: no branch
            tag_to_use = ("stdin",) 

        if not self.auth_url_from_rclone: # pragma: no branch
            url = self.extract_auth_url(message)
            if url:
                self.auth_url_from_rclone = url
                log_utils.app_log(f"PCloud Auth URL detected by PCloudConfigWindow: {url}", gui_log_func=self.main_gui._gui_log_callback, log_to_gui=False)
                self.output_text.insert(tk.END, f"--- Detected auth URL for browser: {url} ---\n", ("info", "bold")) 

        self.output_text.insert(tk.END, message, tag_to_use)
        self.output_text.see(tk.END) 
        self.output_text.config(state=tk.DISABLED)


    def start_automation(self):
        remote_name = self.remote_name_entry.get().strip()
        if not remote_name:
            messagebox.showerror("Input Error", "Please enter a name for the new pCloud remote.", parent=self)
            return
        if any(c in remote_name for c in ":\\/\"'*?<>| "):
             messagebox.showerror("Input Error", "Remote name contains invalid characters (e.g., :\\/\"'*?<>| or spaces). Please use a simple name.", parent=self)
             return

        self.start_button.config(state=tk.DISABLED)
        self.remote_name_entry.config(state=tk.DISABLED)
        self.output_text.config(state=tk.NORMAL); self.output_text.delete("1.0", tk.END); self.output_text.config(state=tk.DISABLED)
        self.auth_url_from_rclone = ""
        
        self.main_gui.pcloud_auth_event.clear()
        self.main_gui.pcloud_auth_result_holder['result'] = None
        
        self.update_output_display("--- Starting pCloud automation thread... ---\n", is_stderr=False) 
        
        self.automation_thread = threading.Thread(
            target=autoconfig.automate_pcloud_config,
            args=(
                remote_name,
                self.worker_queue_for_output,
                self.auth_event_for_worker_to_wait_on,
                self.get_auth_result_from_main_gui,
                self.worker_queue_for_output,
                lambda: self.auth_url_from_rclone,
                self.rclone_config_password
            )
        )
        self.automation_thread.daemon = True
        self.automation_thread.start()

    def handle_automation_result(self, success):
        if not self.winfo_exists(): return # pragma: no cover

        self.start_button.config(state=tk.NORMAL)
        self.remote_name_entry.config(state=tk.NORMAL)
        final_message_text = "pCloud automation completed successfully!" if success else "pCloud automation failed or was cancelled. Check output above."
        
        self.update_output_display(f"\n--- {final_message_text} ---\n", is_stderr=not success)
        log_utils.app_log(f"PCloudConfigWindow.handle_automation_result: Success={success}", level="info" if success else "warning", gui_log_func=self.main_gui._gui_log_callback, log_to_gui=False)

        if success:
            messagebox.showinfo("Automation Status", final_message_text, parent=self)
            self.master.after(2500, self.close_window_if_exists)
        else:
            messagebox.showerror("Automation Status", final_message_text, parent=self)

    def close_window_if_exists(self): # pragma: no cover
        if self.winfo_exists():
            self.close_window()

    def close_window(self):
        log_utils.app_log("PCloud config window close action initiated.", gui_log_func=self.main_gui._gui_log_callback, log_to_gui=False)
        if self.automation_thread and self.automation_thread.is_alive(): # pragma: no cover
            self.update_output_display("--- Window close requested during active automation. Attempting to cancel... ---\n", False) 
            self.main_gui.pcloud_auth_result_holder['result'] = False 
            self.auth_event_for_worker_to_wait_on.set()
            log_utils.app_log("PCloud config window: Signalled cancellation to active automation thread.", gui_log_func=self.main_gui._gui_log_callback, log_to_gui=False)

        if hasattr(self, 'main_gui') and self.main_gui: # pragma: no branch
            self.main_gui.pcloud_config_window_ref = None 
        self.destroy()

if __name__ == '__main__': # pragma: no cover
    _FINISH_PROGRAM_AND_EXIT_MAIN_ = False
    try:
        # The global 'logger' should now be definitively initialized (either by log_utils or PrintLogger)
        # before this __main__ block is entered.
        # The check below is an additional safeguard or for contexts where it might be redefined.
        if not isinstance(logger, (logging.Logger, PrintLogger)):
            # This indicates a more severe issue if logger isn't one of the expected types.
            emergency_logger = PrintLogger()
            emergency_logger.critical(f"Global logger is not of expected type (Logger or PrintLogger). Type: {type(logger)}. This is unexpected.", exc_info=True)
            # Forcing it to PrintLogger if something went very wrong.
            logger = emergency_logger 
            # Potentially set _FINISH_PROGRAM_AND_EXIT_MAIN_ = True if this state is considered unrecoverable.

        logger.info("Application __main__ starting up...")
        root = tk.Tk()
        gui = None

        try:
            gui = RcloneGUI(root)
        except SystemExit as se:
            logger.error(f"SystemExit during RcloneGUI initialization: {se}")
            _FINISH_PROGRAM_AND_EXIT_MAIN_ = True
        except Exception as e_gui_init:
            logger.critical("Unhandled Exception during RcloneGUI initialization!", exc_info=True)
            try:
                err_root_temp = tk.Tk()
                err_root_temp.withdraw()
                bg_color = '#2E2E2E'
                if hasattr(gui, 'theme_colors') and gui.theme_colors and 'WINDOW_BG' in gui.theme_colors: # Check gui and theme_colors
                    bg_color = gui.theme_colors['WINDOW_BG']
                
                if err_root_temp.winfo_exists(): # Check before configure
                    err_root_temp.configure(bg=bg_color)
                messagebox.showerror("GUI Initialization Error", f"Failed to initialize main GUI: {e_gui_init}\nPlease check log.txt for details.", parent=None)
                if err_root_temp.winfo_exists(): # Check before destroy
                     err_root_temp.destroy()
            except Exception as e_msgbox:
                print(f"Could not display Tkinter error messagebox for GUI init failure: {e_msgbox}")

            if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists():
                root.destroy()
            _FINISH_PROGRAM_AND_EXIT_MAIN_ = True


        if _FINISH_PROGRAM_AND_EXIT_MAIN_:
            if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists():
                try: root.destroy()
                except tk.TclError: pass
            sys.exit(1)

        if gui and root.winfo_exists():
            logger.info("Root window exists, starting Tkinter mainloop.")
            root.mainloop()
            logger.info("Tkinter mainloop finished.")
        else:
            logger.error("Application will exit as main window (root or RcloneGUI) is not available or GUI failed to initialize.")
            if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists():
                try: root.destroy()
                except tk.TclError: pass
            sys.exit(1)

    except Exception as e_main:
        final_error_message = f"Fatal unhandled exception in RcloneGUI __main__ block: {e_main}"
        # Use the global logger if it exists and is valid, otherwise print
        if 'logger' in globals() and logger and hasattr(logger, 'critical'):
            logger.critical(final_error_message, exc_info=True)
        else:
            print(final_error_message)
            print(traceback.format_exc())
            try:
                with open("rclone_gui_fatal_error.txt", "a", encoding="utf-8") as felog:
                    felog.write(f"{datetime.now()}: {final_error_message}\n{traceback.format_exc()}\n")
            except Exception:
                print("Failed to write to rclone_gui_fatal_error.txt during critical exception handling.")

        try:
            err_root_final = tk.Tk()
            err_root_final.withdraw()
            messagebox.showerror("Fatal Application Error", f"A critical error occurred: {e_main}\nPlease check rclone_gui_fatal_error.txt or console output.", parent=None)
            if err_root_final.winfo_exists(): # Check before destroy
                err_root_final.destroy()
        except Exception:
            print("Could not display final Tkinter error messagebox for fatal application error.")
        sys.exit(1)
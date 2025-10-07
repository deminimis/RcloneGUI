import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import rclone_wrapper as rclone
import autoconfig
import os
import sys
import subprocess
import log_utils
import threading
import queue
import traceback
import logging
import json
import re
from datetime import datetime
from graphite_theme import apply_graphite_theme

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

logger = None
try:
    log_utils.setup_logging()
    logger = log_utils.get_logger("RcloneGUI_App")
except Exception as e_log_setup:
    fallback_logger = PrintLogger()
    fallback_logger.critical(f"CRITICAL ERROR during initial logging setup with log_utils: {e_log_setup}", exc_info=True)
    fallback_logger.critical("Falling back to console-based PrintLogger.")
    logger = fallback_logger

if logger is None:
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
        if self.theme_colors:
            master.configure(bg=self.theme_colors['WINDOW_BG'])
            label_fg = self.theme_colors.get('TEXT_COLOR', 'SystemButtonText')
        instr_text = "Rclone configuration seems to be encrypted.\nPlease enter the password:"
        instr_label = tk.Label(master, text=instr_text, wraplength=300, justify=tk.LEFT)
        if self.theme_colors:
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
        if theme_colors:
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
        else: instr_text += "\nRclone should have opened a browser or provided an authorization URL in the setup window's output area."
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
        parent_x = self.parent_window.winfo_x(); parent_y = self.parent_window.winfo_y()
        parent_width = self.parent_window.winfo_width(); parent_height = self.parent_window.winfo_height()
        dialog_width = self.winfo_reqwidth() + 60; dialog_height = self.winfo_reqheight() + 40
        if dialog_width > parent_width - 20 : dialog_width = parent_width - 20
        if dialog_height > parent_height - 20 : dialog_height = parent_height - 20
        position_x = parent_x + (parent_width // 2) - (dialog_width // 2)
        position_y = parent_y + (parent_height // 2) - (dialog_height // 2)
        self.geometry(f"{dialog_width}x{dialog_height}+{position_x}+{position_y}")
    def on_yes(self): self.result = True; self.destroy()
    def on_no(self): self.result = False; self.destroy()

class AssociatedListSettingsDialog(tk.Toplevel):
    def __init__(self, parent, current_dest_segment="", current_flags="", theme_colors=None):
        super().__init__(parent)
        if theme_colors: self.configure(bg=theme_colors['WINDOW_BG'])
        self.transient(parent); self.title("Configure List Settings"); self.result = None; self.parent = parent
        frame = ttk.Frame(self, padding="15"); frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Remote Destination Subfolder:",font=('Arial', 10)).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.dest_segment_entry = ttk.Entry(frame, width=50); self.dest_segment_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.dest_segment_entry.insert(0, current_dest_segment)
        ttk.Label(frame, text="(e.g., 'MyFiles/Backup' - leave empty for remote root)").grid(row=1, column=1, sticky="w", padx=5, pady=2, columnspan=2)
        ttk.Label(frame, text="Rclone Flags:",font=('Arial', 10)).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.flags_entry = ttk.Entry(frame, width=50); self.flags_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        self.flags_entry.insert(0, current_flags if current_flags else "-P --checksum --transfers=4")
        ttk.Label(frame, text="(e.g., '-P --checksum --verbose')").grid(row=3, column=1, sticky="w", padx=5, pady=2, columnspan=2)
        btn_frame = ttk.Frame(frame); btn_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky="e")
        save_btn = ttk.Button(btn_frame, text="Save Settings", command=self.on_save); save_btn.pack(side=tk.LEFT, padx=5)
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel); cancel_btn.pack(side=tk.LEFT, padx=5)
        frame.columnconfigure(1, weight=1); self.grab_set(); self.protocol("WM_DELETE_WINDOW", self.on_cancel); self.wait_window()
    def on_save(self):
        dest_segment = self.dest_segment_entry.get().strip().strip('/'); flags = self.flags_entry.get().strip()
        self.result = {"remote_dest_segment": dest_segment, "rclone_flags": flags}; self.destroy()
    def on_cancel(self): self.result = None; self.destroy()

class BatchGenDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Generate Batch File Options", theme_colors_dict=None, default_rclone_exe=""):
        self.theme_colors = theme_colors_dict; self.default_rclone_exe = default_rclone_exe
        self.result = None; self.dialog_logger = logger; super().__init__(parent, title)
    def body(self, master):
        if self.theme_colors: master.configure(bg=self.theme_colors['WINDOW_BG'])
        op_frame = ttk.LabelFrame(master, text="Operation Type", padding=5); op_frame.pack(fill=tk.X, padx=10, pady=5)
        self.operation_var = tk.StringVar(value="sync")
        self.rb_sync = ttk.Radiobutton(op_frame, text="Sync", variable=self.operation_var, value="sync"); self.rb_sync.pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(op_frame, text="Copy", variable=self.operation_var, value="copy").pack(side=tk.LEFT, padx=5)
        log_frame = ttk.LabelFrame(master, text="Rclone Logging", padding=5); log_frame.pack(fill=tk.X, padx=10, pady=5)
        self.log_enabled_var = tk.BooleanVar(value=True); self.log_file_var = tk.StringVar(value=os.path.join(os.getcwd(), "rclone_task_log.txt")) 
        log_check = ttk.Checkbutton(log_frame, text="Enable rclone log file?", variable=self.log_enabled_var, command=self._toggle_log_file_entry)
        log_check.grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=2) 
        ttk.Label(log_frame, text="Log File Path:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.log_file_entry = ttk.Entry(log_frame, textvariable=self.log_file_var, width=50); self.log_file_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        log_browse_btn = ttk.Button(log_frame, text="Browse...", command=self._browse_log_file); log_browse_btn.grid(row=1, column=2, padx=5, pady=2)
        log_frame.columnconfigure(1, weight=1)
        pass_frame = ttk.LabelFrame(master, text="Password Handling (if rclone.conf encrypted)", padding=5); pass_frame.pack(fill=tk.X, padx=10, pady=5)
        self.password_option_var = tk.StringVar(value="prompt") 
        ttk.Radiobutton(pass_frame, text="Prompt for password when script runs (@echo on)", variable=self.password_option_var, value="prompt").pack(anchor="w")
        hardcode_frame = ttk.Frame(pass_frame); hardcode_frame.pack(anchor="w")
        ttk.Radiobutton(hardcode_frame, text="Hardcode password (Least Secure - @echo off)", variable=self.password_option_var, value="hardcode").pack(side=tk.LEFT)
        self.hardcoded_password_var = tk.StringVar()
        self.hardcoded_password_entry = ttk.Entry(hardcode_frame, textvariable=self.hardcoded_password_var, show="*", width=25); self.hardcoded_password_entry.pack(side=tk.LEFT, padx=5) 
        self.password_option_var.trace_add("write", self._toggle_hardcoded_password_entry) 
        exe_frame = ttk.LabelFrame(master, text="Rclone Executable", padding=5); exe_frame.pack(fill=tk.X, padx=10, pady=5)
        self.rclone_exe_var = tk.StringVar(value=self.default_rclone_exe)
        ttk.Label(exe_frame, text="Path to rclone.exe:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.rclone_exe_entry = ttk.Entry(exe_frame, textvariable=self.rclone_exe_var, width=50); self.rclone_exe_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        exe_browse_btn = ttk.Button(exe_frame, text="Browse...", command=self._browse_rclone_exe); exe_browse_btn.grid(row=0, column=2, padx=5, pady=2)
        exe_frame.columnconfigure(1, weight=1); self._toggle_log_file_entry(); self._toggle_hardcoded_password_entry(); return self.rb_sync
    def _toggle_log_file_entry(self, *args): self.log_file_entry.config(state=tk.NORMAL if self.log_enabled_var.get() else tk.DISABLED)
    def _toggle_hardcoded_password_entry(self, *args):
        self.hardcoded_password_entry.config(state=tk.NORMAL if self.password_option_var.get() == "hardcode" else tk.DISABLED)
        if self.password_option_var.get() != "hardcode": self.hardcoded_password_var.set("") 
    def _browse_log_file(self):
        fp = filedialog.asksaveasfilename(parent=self, title="Log File Path",defaultextension=".log",filetypes=[("Log","*.log"),("Txt","*.txt"),("All","*.*")])
        if fp: self.log_file_var.set(fp)
    def _browse_rclone_exe(self):
        fp = filedialog.askopenfilename(parent=self,title="Select rclone.exe",filetypes=[("Exe","*.exe"),("All","*.*")])
        if fp: self.rclone_exe_var.set(fp)
    def ok(self, event=None):
        if not self.validate(): self.initial_focus.focus_set(); return
        self.withdraw(); self.update_idletasks(); self.apply(); super().ok(event) 
    def validate(self):
        if self.log_enabled_var.get() and not self.log_file_var.get().strip(): messagebox.showerror("Validation Error","Log file path empty.",parent=self); return 0
        if not self.rclone_exe_var.get().strip(): messagebox.showerror("Validation Error","Rclone exe path empty.",parent=self); return 0
        if self.password_option_var.get() == "hardcode" and not self.hardcoded_password_var.get():
            if not messagebox.askyesno("Confirm Empty Password","Hardcode password selected but blank.\nContinue anyway?",parent=self,icon=messagebox.WARNING): return 0
        return 1
    def apply(self): 
        self.result = {"operation":self.operation_var.get(),"log_enabled":self.log_enabled_var.get(),
                       "log_file":self.log_file_var.get().strip() if self.log_enabled_var.get() else "",
                       "password_option":self.password_option_var.get(),
                       "hardcoded_password":self.hardcoded_password_var.get() if self.password_option_var.get()=="hardcode" else "",
                       "rclone_exe":self.rclone_exe_var.get().strip()}

class CryptSetupDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Setup Crypt Remote", theme_colors_dict=None, existing_remotes=None):
        self.theme_colors = theme_colors_dict
        self.existing_remotes = existing_remotes if existing_remotes else []
        self.result = None
        self.dialog_logger = logger 
        super().__init__(parent, title)
    def body(self, master):
        if self.theme_colors: 
            master.configure(bg=self.theme_colors['WINDOW_BG'])
        outer_frame = ttk.Frame(master) 
        outer_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(outer_frame, text="New Crypt Remote Name:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.remote_name_entry = ttk.Entry(outer_frame, width=45)
        self.remote_name_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=3)
        ttk.Label(outer_frame, text="(e.g., mySecureDrive)").grid(row=1, column=1, sticky="w", padx=5, pady=(0,10))
        ttk.Label(outer_frame, text="Target Remote (crypt uses its root):").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        if not self.existing_remotes:
             ttk.Label(outer_frame, text="No existing remotes found to target!", foreground="red").grid(row=2, column=1, sticky="ew", padx=5, pady=3)
             self.target_combo = None 
        else:
            self.target_remote_var = tk.StringVar()
            self.target_combo = ttk.Combobox(outer_frame, textvariable=self.target_remote_var, values=self.existing_remotes, state="readonly", width=43)
            self.target_combo.grid(row=2, column=1, sticky="ew", padx=5, pady=3)
            if self.existing_remotes: self.target_combo.current(0) 
        ttk.Label(outer_frame, text="Select an existing remote. Encrypted data will be stored in its root.").grid(row=3, column=1, sticky="w", padx=5, pady=(0,10))
        ttk.Label(outer_frame, text="Filename Encryption:").grid(row=4, column=0, sticky="w", padx=5, pady=3)
        self.fn_encrypt_var = tk.StringVar(value="standard") 
        fn_options = {
            "Standard (encrypts filenames)": "standard", 
            "Obfuscate (simple name hiding)": "obfuscate",
            "Off (.bin extension only)": "off"
        }
        fn_frame = ttk.Frame(outer_frame); fn_frame.grid(row=5, column=0, columnspan=2, sticky="w", padx=5)
        for text, val in fn_options.items():
            ttk.Radiobutton(fn_frame, text=text, variable=self.fn_encrypt_var, value=val).pack(anchor="w", pady=1)
        ttk.Label(outer_frame, text="Directory Name Encryption:").grid(row=6, column=0, sticky="w", padx=5, pady=(10,3))
        self.dir_encrypt_var = tk.BooleanVar(value=True)
        dir_frame = ttk.Frame(outer_frame)
        dir_frame.grid(row=7, column=0, columnspan=2, sticky="w", padx=5)
        ttk.Radiobutton(dir_frame, text="Encrypt directory names (Recommended)", variable=self.dir_encrypt_var, value=True).pack(anchor="w", pady=1)
        ttk.Radiobutton(dir_frame, text="Do NOT encrypt directory names", variable=self.dir_encrypt_var, value=False).pack(anchor="w", pady=1)
        ttk.Label(outer_frame, text=" ").grid(row=8, column=1, sticky="w", padx=5, pady=(0,5))
        pw_frame = ttk.LabelFrame(outer_frame, text="Main Encryption Password (Required)", padding=5)
        pw_frame.grid(row=9, column=0, columnspan=2, sticky="ew", padx=5, pady=(5,5))
        pw_frame.columnconfigure(1, weight=1)
        ttk.Label(pw_frame, text="Main Password:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.pw1_entry = ttk.Entry(pw_frame, show="*", width=35)
        self.pw1_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=3)
        ttk.Label(pw_frame, text="Confirm Main Password:").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.pw1_confirm_entry = ttk.Entry(pw_frame, show="*", width=35)
        self.pw1_confirm_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=3)
        pw_help_text = ("- You MUST enter a main password.\n"
                        "- Rclone's default internal salt will be used (no user input for salt).")
        ttk.Label(pw_frame, text=pw_help_text, justify=tk.LEFT).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=(5,2))
        outer_frame.columnconfigure(1, weight=1)
        return self.remote_name_entry 
    def validate(self):
        remote_name = self.remote_name_entry.get().strip()
        if not remote_name:
            messagebox.showerror("Validation Error", "Crypt remote name cannot be empty.", parent=self)
            return 0
        if any(c in remote_name for c in ":\\/\"'*?<>| "):
            messagebox.showerror("Validation Error", "Remote name contains invalid characters or spaces.", parent=self)
            return 0
        if not self.target_combo: 
             messagebox.showerror("Validation Error", "No existing remotes found. Cannot create crypt target.", parent=self)
             return 0
        if not self.target_remote_var.get():
            messagebox.showerror("Validation Error", "Please select a target remote.", parent=self)
            return 0
        pw1 = self.pw1_entry.get()
        pw1_confirm = self.pw1_confirm_entry.get()
        if not pw1:
            messagebox.showerror("Validation Error", "Main password cannot be empty.", parent=self)
            return 0
        if pw1 != pw1_confirm:
            messagebox.showerror("Validation Error", "Main passwords do not match.", parent=self)
            return 0
        return 1
    def apply(self):
        target_remote_name = self.target_remote_var.get() if self.target_combo else ""
        params = {
            "remote_name": self.remote_name_entry.get().strip(),
            "target_remote": f"{target_remote_name}:" if target_remote_name else "", 
            "filename_encryption_gui_choice": self.fn_encrypt_var.get(),
            "directory_name_encryption_gui_choice": self.dir_encrypt_var.get(),
            "password_main_choice_gui": "y",
            "password_main_value": self.pw1_entry.get()
        }
        self.result = params
        self.dialog_logger.debug(f"CryptSetupDialog apply() - self.result: {self.result}")

class ConfigProgressWindow(tk.Toplevel):
    def __init__(self, parent, main_gui_controller, title="Automated Setup Progress", theme_colors=None):
        super().__init__(parent)
        if theme_colors: self.configure(bg=theme_colors['WINDOW_BG'])
        self.theme_colors = theme_colors 
        self.main_gui = main_gui_controller 
        self.title(title); self.geometry("700x500"); self.transient(parent)
        frame = ttk.Frame(self, padding="10"); frame.pack(expand=True, fill=tk.BOTH)
        self.header_label = ttk.Label(frame, text=title, font=('Arial', 14, 'bold')); self.header_label.pack(pady=(0,10))
        self.info_label = ttk.Label(frame, text="Follow rclone output.", wraplength=650); self.info_label.pack(pady=(0,10))
        output_label_text = ttk.Label(frame, text="Rclone Output & Automation Log:"); output_label_text.pack(anchor="w", pady=(5,0))
        sc_opts = {'background':self.theme_colors.get('WIDGET_BG','#4A4A4A'),'foreground':self.theme_colors.get('TEXT_COLOR','#FFFFFF'),
                   'selectbackground':self.theme_colors.get('SELECT_BG_COLOR','#007ACC'),'selectforeground':self.theme_colors.get('SELECT_FG_COLOR','#FFFFFF'),
                   'insertbackground':self.theme_colors.get('TEXT_INSERT_BG','#FFFFFF'),'borderwidth':0,'relief':tk.FLAT,'highlightthickness':1,
                   'highlightbackground':self.theme_colors.get('LISTBOX_HIGHLIGHT_BG','#3C3C3C'),'highlightcolor':self.theme_colors.get('LISTBOX_HIGHLIGHT_COLOR','#007ACC'),
                   'wrap':tk.WORD,'font':("Consolas",9)}
        self.output_text = scrolledtext.ScrolledText(frame, height=15, state=tk.DISABLED, **sc_opts); self.output_text.pack(expand=True, fill=tk.BOTH, pady=5)
        self.output_text.tag_config("error", foreground=self.theme_colors.get('LOG_ERROR_FG','#FF8A80'))
        self.output_text.tag_config("info", foreground=self.theme_colors.get('LOG_INFO_FG','#82B1FF'),font=("Consolas",9,"bold"))
        self.output_text.tag_config("stdout", foreground=self.theme_colors.get('LOG_STDOUT_FG','#FFFFFF'))
        self.output_text.tag_config("stdin", foreground=self.theme_colors.get('LOG_STDIN_FG','#CE93D8'))
        self.close_button = ttk.Button(frame, text="Close Window", command=self.close_window, state=tk.DISABLED); self.close_button.pack(pady=5)
        self.protocol("WM_DELETE_WINDOW", self.close_window); self.automation_active = False; self.auth_url_from_rclone = ""
    def set_header(self, text): self.header_label.config(text=text); self.title(text)
    def set_info_text(self, text): self.info_label.config(text=text)
    def update_output_display(self, message, is_stderr=False):
        if not self.winfo_exists(): return
        self.output_text.config(state=tk.NORMAL); tag_to_use = ("stdout",)
        if is_stderr: tag_to_use = ("error",)
        info_kw = ["ACTION REQUIRED","Waiting for","If your browser","Normally rclone will open","Please go to","Enter verification","---"]
        if any(kw.lower() in message.lower() for kw in info_kw) or message.strip().startswith("---"): tag_to_use = ("info",)
        elif message.startswith("Sending to rclone:"): tag_to_use = ("stdin",)
        if not self.auth_url_from_rclone:
            url = self._extract_auth_url(message)
            if url: self.auth_url_from_rclone=url; log_utils.app_log(f"URL detected: {url}",gui_log_func=self.main_gui._gui_log_callback,log_to_gui=False); self.output_text.insert(tk.END,f"--- Auth URL: {url} ---\n",("info","bold"))
        self.output_text.insert(tk.END, message, tag_to_use); self.output_text.see(tk.END); self.output_text.config(state=tk.DISABLED)
    def _extract_auth_url(self, line):
        m_localhost = re.search(r'(https?://(?:localhost|127\.0\.0\.1):\d+/auth\S*)', line)
        if m_localhost: return m_localhost.group(1)
        m_direct = re.search(r'(?:go to|link|visit|url|open this link|verification code):\s*(https?://\S+)', line, re.IGNORECASE)
        if m_direct: return m_direct.group(1); return None
    def automation_started(self):
        self.automation_active=True; self.close_button.config(state=tk.NORMAL,text="Cancel Setup")
        self.output_text.config(state=tk.NORMAL);self.output_text.delete("1.0",tk.END);self.output_text.config(state=tk.DISABLED);self.auth_url_from_rclone=""
    def handle_automation_result(self, success, provider_name="Setup"):
        self.automation_active=False; self.close_button.config(state=tk.NORMAL,text="Close Window")
        msg_text = f"{provider_name} automation {'completed successfully' if success else 'failed or was cancelled'}."
        self.update_output_display(f"\n--- {msg_text} ---\n",is_stderr=not success)
        log_utils.app_log(f"ConfigProgressWindow for {provider_name}: Success={success}",level="info" if success else "warning",gui_log_func=self.main_gui._gui_log_callback,log_to_gui=False)
        if success: messagebox.showinfo("Automation Status",msg_text,parent=self); self.master.after(1500,self.destroy_if_exists)
        else: messagebox.showerror("Automation Status",msg_text,parent=self)
    def destroy_if_exists(self):
        if self.winfo_exists(): self.destroy()
    def close_window(self):
        log_utils.app_log("ConfigProgressWindow close.",gui_log_func=self.main_gui._gui_log_callback,log_to_gui=False)
        if self.automation_active:
            if messagebox.askyesno("Cancel Setup?","Configuration in progress. Cancel?",parent=self):
                self.update_output_display("--- Close requested. Attempting cancel... ---\n",False)
                if "pCloud" in self.title() and hasattr(self.main_gui,'pcloud_auth_event'):
                    self.main_gui.pcloud_auth_result_holder['result']=False; self.main_gui.pcloud_auth_event.set()
            else: return 
        if hasattr(self.main_gui,'active_config_window_ref') and self.main_gui.active_config_window_ref==self: self.main_gui.active_config_window_ref=None
        self.destroy()

class RcloneGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Rclone GUI")
        self.master.geometry("950x800") 
        self.master.minsize(860, 650) 
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smalllogo.png")
            if os.path.exists(icon_path):
                photo = tk.PhotoImage(file=icon_path)
                self.master.iconphoto(True, photo)
            else:
                 if sys.platform == "win32":
                    icon_path_ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smalllogo.ico")
                    if os.path.exists(icon_path_ico):
                        self.master.iconbitmap(icon_path_ico)
        except Exception:
            pass
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
        global logger 
        if logger is None: 
             log_utils.setup_logging() 
             logger = log_utils.get_logger("RcloneGUI_App_Recovery")
             logger.warning("Logger was None in RcloneGUI init, re-attempted setup.")
        if not os.path.exists(rclone.RCLONE_EXE_PATH): 
            critical_msg = f"CRITICAL ERROR: {rclone.RCLONE_EXE_NAME} not found at {rclone.RCLONE_EXE_PATH}."
            logger.critical(critical_msg) 
            if hasattr(log_utils, 'app_log'): log_utils.app_log(critical_msg, level="critical", gui_log_func=self._gui_log_callback)
            else: print(critical_msg) 
            messagebox.showerror("Rclone Not Found", critical_msg + "\nPlease place rclone executable in the script's directory or ensure it's in your system PATH.", parent=master if master.winfo_exists() else None)
            if master.winfo_exists(): master.destroy()
            raise SystemExit("Rclone executable not found, aborting GUI init.")
        self.rclone_config_password = None
        self.current_local_path = tk.StringVar(value=os.getcwd())
        self.current_remote_base = tk.StringVar()
        self.current_remote_path_segment = tk.StringVar(value="")
        self.remotes = []
        self.active_config_window_ref = None 
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
        scrolled_text_options_gui_log = {
            'background': self.theme_colors['WIDGET_BG'], 'foreground': self.theme_colors['TEXT_COLOR'],
            'selectbackground': self.theme_colors['SELECT_BG_COLOR'], 'selectforeground': self.theme_colors['SELECT_FG_COLOR'],
            'insertbackground': self.theme_colors['TEXT_INSERT_BG'], 'borderwidth': 0, 'relief': tk.FLAT,
            'highlightthickness': 1, 'highlightbackground': self.theme_colors['LISTBOX_HIGHLIGHT_BG'],
            'highlightcolor': self.theme_colors['LISTBOX_HIGHLIGHT_COLOR'], 'wrap': tk.WORD,
            'font': ("Consolas", 9)
        }
        self.gui_log_text = scrolledtext.ScrolledText(log_frame_gui_container, height=4, state=tk.DISABLED, **scrolled_text_options_gui_log)
        self.gui_log_text.tag_config("error", foreground=self.theme_colors['LOG_ERROR_FG'])
        self.gui_log_text.tag_config("info", foreground=self.theme_colors['LOG_INFO_FG'])
        self.gui_log_text.tag_config("stdout", foreground=self.theme_colors['LOG_STDOUT_FG'])
        self.gui_log_text.tag_config("stdin", foreground=self.theme_colors['LOG_STDIN_FG'])
        self.check_and_get_config_password() 
        top_bar_frame = ttk.Frame(main_content_frame)
        top_bar_frame.pack(fill=tk.X, pady=5) 
        config_buttons_frame = ttk.Frame(top_bar_frame)
        config_buttons_frame.pack(side=tk.RIGHT, padx=(10,0), pady=0, fill=tk.Y) 
        cmd_config_btn = ttk.Button(config_buttons_frame, text="Rclone Config", command=self.launch_rclone_config_cmd)
        cmd_config_btn.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2, fill=tk.X)
        create_crypt_btn = ttk.Button(config_buttons_frame, text="Create Crypt Remote", command=self.open_crypt_setup_dialog)
        create_crypt_btn.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2, fill=tk.X)
        provider_label = ttk.Label(config_buttons_frame, text="Auto-Setup (pCloud):")
        provider_label.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=(8,0))
        self.provider_auto_setup_combo = ttk.Combobox(config_buttons_frame, textvariable=self.selected_auto_setup_provider,
                                                      values=self.auto_setup_providers, state="readonly", width=15, font=app_font_tuple)
        if self.auto_setup_providers: self.provider_auto_setup_combo.current(0)
        self.provider_auto_setup_combo.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2, fill=tk.X)
        auto_setup_btn = ttk.Button(config_buttons_frame, text="Run pCloud Setup", command=self.initiate_auto_setup)
        auto_setup_btn.pack(side=tk.TOP, anchor=tk.W, padx=2, pady=2, fill=tk.X)
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
        path_frame.pack(fill=tk.X, pady=5); path_frame.columnconfigure(0, weight=1)
        ttk.Label(path_frame, text="Local Path:", style="Header.TLabel").grid(row=0, column=0, padx=5, pady=(10,0), sticky="w")
        ttk.Label(path_frame, textvariable=self.current_local_path, style="Path.TLabel", wraplength=450).grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        local_path_buttons_frame = ttk.Frame(path_frame); local_path_buttons_frame.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        local_browse_btn = ttk.Button(local_path_buttons_frame, text="Browse Local", command=self.browse_local_path); local_browse_btn.pack(side=tk.LEFT, padx=(0,5))
        refresh_dirs_btn = ttk.Button(local_path_buttons_frame, text="Refresh Directories", command=self.refresh_all_listings); refresh_dirs_btn.pack(side=tk.LEFT)
        listings_frame = ttk.Frame(main_content_frame) 
        listings_frame.pack(expand=True, fill=tk.BOTH, pady=5); listings_frame.columnconfigure(0, weight=1); listings_frame.columnconfigure(1, weight=1); listings_frame.rowconfigure(2, weight=1) 
        self.listbox_options = {'background':self.theme_colors['WIDGET_BG'],'foreground':self.theme_colors['TEXT_COLOR'],'selectbackground':self.theme_colors['SELECT_BG_COLOR'],
                                'selectforeground':self.theme_colors['SELECT_FG_COLOR'],'borderwidth':0,'relief':tk.FLAT,'highlightthickness':1,
                                'highlightbackground':self.theme_colors['LISTBOX_HIGHLIGHT_BG'],'highlightcolor':self.theme_colors['LISTBOX_HIGHLIGHT_COLOR'],
                                'exportselection':False,'font':app_font_tuple}
        self.local_files_list = tk.Listbox(listings_frame, selectmode=tk.EXTENDED, **self.listbox_options)
        local_scrollbar = ttk.Scrollbar(listings_frame, orient=tk.VERTICAL, command=self.local_files_list.yview); self.local_files_list.config(yscrollcommand=local_scrollbar.set)
        self.local_files_list.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=5); local_scrollbar.grid(row=0, column=0, rowspan=3, sticky="nse", padx=(0,5))
        self.local_files_list.bind("<Double-1>", self.on_local_double_click)
        ttk.Label(listings_frame, text="Remote Path:", style="Header.TLabel").grid(row=0, column=1, padx=(5,0), pady=(0,0), sticky="sw")
        self.remote_path_display = ttk.Label(listings_frame, text="<Select Remote>", style="Path.TLabel", wraplength=400); self.remote_path_display.grid(row=1, column=1, padx=(5,0), pady=2, sticky="new")
        self.remote_files_list = tk.Listbox(listings_frame, selectmode=tk.EXTENDED, **self.listbox_options)
        remote_scrollbar = ttk.Scrollbar(listings_frame, orient=tk.VERTICAL, command=self.remote_files_list.yview); self.remote_files_list.config(yscrollcommand=remote_scrollbar.set)
        self.remote_files_list.grid(row=2, column=1, sticky="nsew", padx=5); remote_scrollbar.grid(row=2, column=1, sticky="nse", padx=(0,5))
        self.remote_files_list.bind("<Double-1>", self.on_remote_double_click)
        actions_frame = ttk.LabelFrame(main_content_frame, text="Direct Actions (on selected items)", padding="10") 
        actions_frame.pack(fill=tk.X, pady=(5,0), padx=5) 
        save_selected_btn = ttk.Button(actions_frame, text="Save Selected Files/Folders Below", command=self.save_selected_to_associated_list); save_selected_btn.pack(side=tk.LEFT, padx=5)
        copy_lr_btn = ttk.Button(actions_frame, text="Copy Selected to Remote", command=lambda: self.start_operation("copy", "lr")); copy_lr_btn.pack(side=tk.LEFT, padx=5)
        sync_lr_btn = ttk.Button(actions_frame, text="Sync Selected to Remote", command=lambda: self.start_operation("sync", "lr")); sync_lr_btn.pack(side=tk.LEFT, padx=5)
        copy_rl_btn = ttk.Button(actions_frame, text="Copy Selected to Local", command=lambda: self.start_operation("copy", "rl")); copy_rl_btn.pack(side=tk.LEFT, padx=5)
        sync_rl_btn = ttk.Button(actions_frame, text="Sync Selected to Local", command=lambda: self.start_operation("sync", "rl")); sync_rl_btn.pack(side=tk.LEFT, padx=5)
        self.create_associated_items_frame(main_content_frame) 
        log_frame_gui_container.pack(fill=tk.X, pady=(5,10), padx=5) 
        self.gui_log_text.pack(expand=True, fill=tk.BOTH) 
        self.log_message_gui("GUI Started. Check log.txt for detailed logs.\n", is_info=True)
        self.load_associated_lists_from_file()
        self.load_remotes()
        self.refresh_local_files()
        self.update_remote_path_display()
        self.master.after(100, self.process_worker_thread_queue)
        self.master.lift()
        self.master.attributes('-topmost', True)
        self.master.after_idle(self.master.attributes, '-topmost', False)
        self.master.focus_force()
    def _on_frame_configure(self, event=None): self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
    def _on_canvas_configure(self, event=None): self.main_canvas.itemconfig(self.canvas_frame_id, width=event.width)
    def check_and_get_config_password(self):
        self.log_message_gui("Checking rclone configuration encryption...\n", is_info=True) 
        try:
            is_encrypted = rclone.check_if_config_encrypted(gui_log_func=self._gui_log_callback)
            if is_encrypted:
                self.log_message_gui("Rclone config encrypted. Prompting for password.\n", is_info=True)
                log_utils.app_log("Rclone config encrypted.", gui_log_func=self._gui_log_callback, log_to_gui=False)
                dialog = PasswordDialog(self.master, theme_colors_dict=self.theme_colors)
                self.rclone_config_password = dialog.result 
                if self.rclone_config_password: self.log_message_gui("Password received for this session.\n", is_info=True); log_utils.app_log("Password received.", gui_log_func=self._gui_log_callback,log_to_gui=False)
                else: self.log_message_gui("Password not provided. Operations may fail if config is encrypted.\n", is_error=True); log_utils.app_log("Password not provided.",level="warning",gui_log_func=self._gui_log_callback,log_to_gui=False)
            else: self.log_message_gui("Rclone config not encrypted or status undetermined.\n", is_info=True); log_utils.app_log("Rclone config not encrypted/undetermined.",gui_log_func=self._gui_log_callback,log_to_gui=False)
        except Exception as e: 
            self.log_message_gui(f"Error checking config encryption: {e}\n",is_error=True); log_utils.app_log(f"Failed config encryption check: {e}",level="error",gui_log_func=self._gui_log_callback,log_to_gui=False); logger.error("check_and_get_config_password error",exc_info=True)
    def _gui_log_callback(self, message, is_error=False):
        if hasattr(self,'gui_log_text') and self.gui_log_text.winfo_exists(): self.log_message_gui(message,is_error=is_error)
        else: print(f"GUI Log ({'ERR' if is_error else 'INFO'}, widget not ready): {message.strip()}"); (logger.error if is_error else logger.info)(f"(Early log) {message.strip()}")
    def log_message_gui(self, message, is_error=False, is_info=False):
        if not hasattr(self,'gui_log_text') or not self.gui_log_text.winfo_exists(): return
        self.gui_log_text.config(state=tk.NORMAL)
        tag = ("error",) if is_error else ("info",) if is_info else ("stdin",) if message.startswith("Sending to rclone:") else ("stdout",)
        self.gui_log_text.insert(tk.END, message, tag); self.gui_log_text.see(tk.END); self.gui_log_text.config(state=tk.DISABLED)
    def create_associated_items_frame(self,parent_frame):
        self.associated_items_labelframe=ttk.LabelFrame(parent_frame,text="Associated Local Items for <No Remote Selected>",padding="10"); self.associated_items_labelframe.pack(fill=tk.X,pady=(5,0),padx=5)
        list_c=ttk.Frame(self.associated_items_labelframe); list_c.pack(side=tk.LEFT,fill=tk.BOTH,expand=True,padx=(0,5))
        self.associated_items_listbox=tk.Listbox(list_c,height=5,selectmode=tk.SINGLE,**self.listbox_options)
        items_sb=ttk.Scrollbar(list_c,orient=tk.VERTICAL,command=self.associated_items_listbox.yview); self.associated_items_listbox.config(yscrollcommand=items_sb.set)
        self.associated_items_listbox.pack(side=tk.LEFT,fill=tk.BOTH,expand=True); items_sb.pack(side=tk.LEFT,fill=tk.Y)
        btns_f=ttk.Frame(self.associated_items_labelframe); btns_f.pack(side=tk.LEFT,fill=tk.Y,padx=5)
        ttk.Button(btns_f,text="Remove Item",command=self.remove_item_from_list).pack(pady=2,fill=tk.X)
        ttk.Button(btns_f,text="List Settings...",command=self.configure_list_settings).pack(pady=2,fill=tk.X)
        ttk.Button(btns_f,text="Copy List ➔ Remote",command=lambda:self.run_operation_for_list("copy")).pack(pady=(8,2),fill=tk.X)
        ttk.Button(btns_f,text="Sync List ➔ Remote",command=lambda:self.run_operation_for_list("sync")).pack(pady=2,fill=tk.X)
        ttk.Button(btns_f,text="Generate Script",command=self.prompt_generate_batch_file).pack(pady=(8,2),fill=tk.X)
    def load_associated_lists_from_file(self): 
        self.associated_remote_lists={}; log_utils.app_log(f"Loading lists from {ASSOCIATED_LISTS_FILE}",gui_log_func=self._gui_log_callback,log_to_gui=False)
        if os.path.exists(ASSOCIATED_LISTS_FILE):
            try:
                with open(ASSOCIATED_LISTS_FILE,"r",encoding="utf-8") as f: self.associated_remote_lists=json.load(f)
            except Exception as e: log_utils.app_log(f"Error loading lists: {e}",level="error",gui_log_func=self._gui_log_callback); messagebox.showerror("Load Error",f"Could not load {ASSOCIATED_LISTS_FILE}: {e}",parent=self.master)
    def save_associated_lists_to_file(self): 
        try:
            with open(ASSOCIATED_LISTS_FILE,"w",encoding="utf-8") as f: json.dump(self.associated_remote_lists,f,indent=4)
            log_utils.app_log(f"Saved lists to {ASSOCIATED_LISTS_FILE}",gui_log_func=self._gui_log_callback,log_to_gui=False)
        except Exception as e: log_utils.app_log(f"Error saving lists: {e}",level="error",gui_log_func=self._gui_log_callback); messagebox.showerror("Save Error",f"Could not save lists: {e}",parent=self.master)
    def display_associated_items_for_selected_remote(self): 
        if not hasattr(self,'associated_items_listbox'): return
        self.associated_items_listbox.delete(0,tk.END); remote_name=self._get_current_remote_name()
        self.associated_items_labelframe.config(text=f"Associated Items for: {remote_name if remote_name else '<No Remote>'}")
        if remote_name and remote_name in self.associated_remote_lists:
            for item_path in self.associated_remote_lists[remote_name].get("local_items",[]): self.associated_items_listbox.insert(tk.END,item_path)
    def _get_current_remote_name(self): return self.current_remote_base.get().rstrip(':') 
    def _ensure_remote_list_entry(self,remote_name): 
        if remote_name not in self.associated_remote_lists: self.associated_remote_lists[remote_name]={"local_items":[],"remote_dest_segment":"","rclone_flags":"-P --checksum --transfers=4"}
    def save_selected_to_associated_list(self): 
        remote_name=self._get_current_remote_name(); sel_indices=self.local_files_list.curselection()
        if not remote_name: messagebox.showwarning("No Remote","Select remote first.",parent=self.master); return
        if not sel_indices: messagebox.showwarning("No Selection","Select local items.",parent=self.master); return
        self._ensure_remote_list_entry(remote_name); cur_local_dir=self.current_local_path.get(); added_count=0; items_log=[]
        for i in sel_indices:
            item_name=self.local_files_list.get(i);
            if item_name=="../": continue
            full_path=os.path.normpath(os.path.join(cur_local_dir,item_name.rstrip('/')))
            if full_path not in self.associated_remote_lists[remote_name]["local_items"]:
                self.associated_remote_lists[remote_name]["local_items"].append(full_path); items_log.append(full_path); added_count+=1
        if added_count > 0: self.associated_remote_lists[remote_name]["local_items"].sort(); self.save_associated_lists_to_file(); self.display_associated_items_for_selected_remote(); self.log_message_gui(f"{added_count} item(s) saved to list for '{remote_name}'.\n",is_info=True)
        else: messagebox.showinfo("No New Items","Selected items already in list or invalid.",parent=self.master)
    def remove_item_from_list(self): 
        remote_name=self._get_current_remote_name(); sel_indices=self.associated_items_listbox.curselection()
        if not remote_name: messagebox.showwarning("No Remote","Select remote.",parent=self.master); return
        if not sel_indices: messagebox.showwarning("No Selection","Select item to remove.",parent=self.master); return
        item_path=self.associated_items_listbox.get(sel_indices[0])
        if remote_name in self.associated_remote_lists and item_path in self.associated_remote_lists[remote_name].get("local_items",[]):
            if messagebox.askyesno("Confirm Removal",f"Remove '{item_path}' from list for '{remote_name}'?",parent=self.master):
                self.associated_remote_lists[remote_name]["local_items"].remove(item_path); self.save_associated_lists_to_file(); self.display_associated_items_for_selected_remote()
    def configure_list_settings(self): 
        remote_name=self._get_current_remote_name()
        if not remote_name: messagebox.showwarning("No Remote","Select remote.",parent=self.master); return
        self._ensure_remote_list_entry(remote_name); current_data=self.associated_remote_lists[remote_name]
        dialog=AssociatedListSettingsDialog(self.master,current_data.get("remote_dest_segment",""),current_data.get("rclone_flags","-P --checksum --transfers=4"),self.theme_colors)
        if dialog.result: self.associated_remote_lists[remote_name].update(dialog.result); self.save_associated_lists_to_file(); messagebox.showinfo("Settings Saved",f"Settings updated for '{remote_name}'.",parent=self.master)
    def run_operation_for_list(self,operation_type="copy"): 
        remote_name=self._get_current_remote_name()
        if not remote_name: messagebox.showwarning("No Remote","Select remote.",parent=self.master); return
        if remote_name not in self.associated_remote_lists or not self.associated_remote_lists[remote_name].get("local_items"): messagebox.showinfo("No Items",f"No items for '{remote_name}' to {operation_type}.",parent=self.master); return
        list_data=self.associated_remote_lists[remote_name]; items_to_proc=list_data["local_items"]; dest_seg=list_data.get("remote_dest_segment",""); flags_str=list_data.get("rclone_flags",""); flags=flags_str.split() if flags_str else []
        op_name=operation_type.capitalize(); confirm_msg=f"Are you sure you want to {operation_type} all {len(items_to_proc)} listed items for '{remote_name}'?"
        if dest_seg: confirm_msg+=f"\nDestination subfolder: '{dest_seg}'"
        if flags_str: confirm_msg+=f"\nWith flags: '{flags_str}'"
        if not messagebox.askyesno(f"Confirm {op_name} All",confirm_msg,parent=self.master): self.log_message_gui(f"{op_name} all for '{remote_name}' cancelled.\n",is_info=True); return
        self.log_message_gui(f"Initiating {op_name} for {len(items_to_proc)} items to '{remote_name}'...\n",is_info=True)
        for i,local_item in enumerate(items_to_proc):
            item_base=os.path.basename(local_item); remote_dest_parts=[remote_name+":"];
            if dest_seg: remote_dest_parts.append(dest_seg)
            remote_dest_parts.append(item_base); final_dest="/".join(s.strip("/") for s in remote_dest_parts if s)
            cmd=[operation_type]+flags+[local_item,final_dest]
            log_utils.app_log(f"Executing ({i+1}/{len(items_to_proc)}): rclone {' '.join(cmd)}",gui_log_func=self._gui_log_callback,log_to_gui=False)
            rclone.run_rclone_command(cmd,False,self._gui_log_callback,False,self.rclone_config_password)
        self.log_message_gui(f"All {op_name} commands for '{remote_name}' initiated. Check logs/consoles.\n",is_info=True)
        if self.master.winfo_exists(): self.master.after(10000,lambda:self.refresh_remote_files(None))
    def refresh_all_listings(self): self.log_message_gui("Refreshing directories...\n",is_info=True); self.refresh_local_files(); self.refresh_remote_files(None) 
    def browse_local_path(self): 
        d=filedialog.askdirectory(initialdir=self.current_local_path.get(),parent=self.master)
        if d: self.current_local_path.set(os.path.normpath(d)); self.refresh_local_files(); log_utils.app_log(f"Browsed local: {d}",gui_log_func=self._gui_log_callback,log_to_gui=False)
    def load_remotes(self): 
        log_utils.app_log("Loading remotes...",gui_log_func=self._gui_log_callback,log_to_gui=False)
        try:
            cur_sel=self.remote_combo.get(); self.remotes=rclone.get_remotes(self._gui_log_callback,self.rclone_config_password)
            if self.remotes:
                self.remote_combo['values']=self.remotes
                if cur_sel and cur_sel in self.remotes: self.remote_combo.set(cur_sel)
                elif not self.current_remote_base.get() and self.remotes: self.remote_combo.current(0)
                self.on_remote_selected(None); log_utils.app_log(f"Found remotes: {', '.join(self.remotes)}",gui_log_func=self._gui_log_callback,log_to_gui=False)
            else: self.remote_combo['values']=[]; self.remote_combo.set(''); self.on_remote_selected(None); log_utils.app_log("No rclone remotes found.",level="warning",gui_log_func=self._gui_log_callback,log_to_gui=True)
        except Exception as e: log_utils.app_log(f"Error loading remotes: {e}",level="error",gui_log_func=self._gui_log_callback,log_to_gui=True); logger.error("load_remotes error",exc_info=True); messagebox.showerror("Error",f"Could not load remotes: {e}",parent=self.master); self.remote_combo['values']=[]; self.remote_combo.set(''); self.on_remote_selected(None)
    def on_remote_selected(self,event): 
        sel_remote=self.remote_combo.get()
        if sel_remote: self.current_remote_base.set(sel_remote+":"); self.current_remote_path_segment.set(""); self.update_remote_path_display(); self.refresh_remote_files(); self.display_associated_items_for_selected_remote(); log_utils.app_log(f"Selected remote: {sel_remote}",gui_log_func=self._gui_log_callback,log_to_gui=False)
        else: self.current_remote_base.set(""); self.current_remote_path_segment.set(""); self.update_remote_path_display(); self.remote_files_list.delete(0,tk.END); self.remote_files_list.insert(tk.END,"<No remote selected>"); self.display_associated_items_for_selected_remote()
    def refresh_local_files(self): 
        if not hasattr(self,'local_files_list') or not self.local_files_list.winfo_exists():
            logger.warning("refresh_local_files: local_files_list widget does not exist or not ready.")
            return 
        self.local_files_list.delete(0,tk.END)
        current_path_str = ""
        try:
            current_path_str = self.current_local_path.get()
        except Exception as e:
            logger.error(f"Error getting current_local_path: {e}")
            self.local_files_list.insert(tk.END,"<Error getting local path>")
            return
        if not current_path_str or not os.path.isdir(current_path_str): 
            self.local_files_list.insert(tk.END,f"<Invalid local path: '{current_path_str}'>")
            logger.warning(f"refresh_local_files: Invalid local path '{current_path_str}'.")
            return
        self.local_files_list.insert(tk.END,"../")
        try:
            items=sorted(os.listdir(current_path_str),key=lambda s:(not os.path.isdir(os.path.join(current_path_str,s)),s.lower()))
            for item in items: 
                self.local_files_list.insert(tk.END,item+("/" if os.path.isdir(os.path.join(current_path_str,item)) else ""))
        except Exception as e: 
            log_utils.app_log(f"Error listing local '{current_path_str}': {e}",level="error",gui_log_func=self._gui_log_callback,log_to_gui=True)
            self.local_files_list.insert(tk.END,f"<Error listing files: {e}>")
            logger.error(f"Error listing local files in {current_path_str}", exc_info=True)
    def on_local_double_click(self,event): 
        if not hasattr(self,'local_files_list'): return; sel=self.local_files_list.curselection();
        if not sel: return; item=self.local_files_list.get(sel[0]); cur_dir=self.current_local_path.get(); new_path=""
        if item=="../": new_path=os.path.dirname(cur_dir)
        elif item.endswith("/"): new_path=os.path.normpath(os.path.join(cur_dir,item.rstrip('/')))
        else: self.log_message_gui(f"Dbl-clicked local file: {item}.\n",is_info=True); return
        if os.path.isdir(new_path): self.current_local_path.set(new_path); self.refresh_local_files()
        else: messagebox.showwarning("Navigation Error",f"Path '{new_path}' not valid.",parent=self.master)
    def refresh_remote_files(self,sub_item_nav=None): 
        if not hasattr(self,'remote_files_list'): return; full_remote_path=""
        if sub_item_nav:
            base=self.current_remote_base.get();
            if not base: messagebox.showwarning("No Remote","Select remote.",parent=self.master); self.remote_files_list.delete(0,tk.END);self.remote_files_list.insert(tk.END,"<Select Remote>"); return
            cur_seg=self.current_remote_path_segment.get().strip("/")
            if sub_item_nav=="../": self.current_remote_path_segment.set("/".join(cur_seg.split("/")[:-1]) if "/" in cur_seg else "")
            elif sub_item_nav.endswith("/"): self.current_remote_path_segment.set(f"{cur_seg}/{sub_item_nav.rstrip('/')}" if cur_seg else sub_item_nav.rstrip('/'))
            self.update_remote_path_display(); full_remote_path=self.get_full_remote_path()
        else: full_remote_path=self.get_full_remote_path()
        self.remote_files_list.delete(0,tk.END)
        if not full_remote_path or not self.current_remote_base.get(): self.remote_files_list.insert(tk.END,"<Select Remote/Invalid Path>"); return
        log_utils.app_log(f"Listing remote: {full_remote_path}...",gui_log_func=self._gui_log_callback,log_to_gui=False)
        items,err_msg,code=rclone.list_files(full_remote_path,self._gui_log_callback,self.rclone_config_password)
        if code==0:
            if self.current_remote_path_segment.get().strip("/"): self.remote_files_list.insert(tk.END,"../")
            if items:
                for item_name in sorted(items,key=lambda s:(not s.endswith("/"),s.lower())): self.remote_files_list.insert(tk.END,item_name)
            elif not self.remote_files_list.size(): self.remote_files_list.insert(tk.END,"<Remote folder empty>")
        else: self.log_message_gui(f"Error listing '{full_remote_path}'. Rclone: {err_msg.strip() if err_msg else 'See logs'}\n",is_error=True); self.remote_files_list.insert(tk.END,f"<Error: {err_msg.strip() if err_msg else 'See logs'}>")
    def on_remote_double_click(self,event): 
        if not hasattr(self,'remote_files_list'): return; sel=self.remote_files_list.curselection();
        if not sel: return; item=self.remote_files_list.get(sel[0])
        if item.endswith("/") or item=="../": self.refresh_remote_files(sub_item_nav=item)
        else: self.log_message_gui(f"Dbl-clicked remote file: {item}.\n",is_info=True)
    def update_remote_path_display(self): 
        if not hasattr(self,'remote_path_display'):return; self.remote_path_display.config(text=self.get_full_remote_path() or "<Select Remote>")
    def get_full_remote_path(self): 
        base=self.current_remote_base.get(); seg=self.current_remote_path_segment.get().strip("/")
        return base+seg if base and seg else base if base else ""
    def process_worker_thread_queue(self):
        try:
            while True: 
                msg_type, data = self.worker_thread_queue.get_nowait()
                if msg_type == MSG_TYPE_RCLONE_OUTPUT:
                    message, is_stderr = data
                    if self.active_config_window_ref and self.active_config_window_ref.winfo_exists():
                        self.active_config_window_ref.update_output_display(message, is_stderr)
                    else: self.log_message_gui(message, is_error=is_stderr)
                elif msg_type == MSG_TYPE_PROMPT_AUTH_DIALOG: 
                    auth_url = data; self.pcloud_auth_event.clear(); self.pcloud_auth_result_holder['result'] = None
                    parent = self.active_config_window_ref if self.active_config_window_ref and self.active_config_window_ref.winfo_exists() else self.master
                    auth_dialog = AuthSuccessDialog(parent, auth_url, self.theme_colors)
                    self.pcloud_auth_result_holder['result'] = auth_dialog.result; self.pcloud_auth_event.set() 
                elif msg_type == MSG_TYPE_AUTOMATION_COMPLETE: 
                    success, provider_name = data 
                    self.generic_automation_completion_handler(success, provider_name)
        except queue.Empty: pass 
        except Exception as e: logger.error(f"Error processing worker queue: {e}", exc_info=True); self.log_message_gui(f"Internal error: {e}\n",is_error=True)
        finally:
            if self.master.winfo_exists(): self.master.after(100, self.process_worker_thread_queue)
    def generic_automation_completion_handler(self, success, provider_name="Unknown"):
        config_window = self.active_config_window_ref
        if success: self.log_message_gui(f"{provider_name} config successful. Refreshing remotes...\n",is_info=True); self.load_remotes() 
        else: self.log_message_gui(f"{provider_name} config failed/cancelled. Check logs/setup window.\n",is_error=True)
        if config_window and config_window.winfo_exists(): config_window.handle_automation_result(success, provider_name)
    def initiate_auto_setup(self): 
        provider = self.selected_auto_setup_provider.get()
        if not provider: messagebox.showwarning("No Provider", "No provider for pCloud auto-setup.", parent=self.master); return
        if provider == "pCloud": self.open_pcloud_config_window()
        else: messagebox.showinfo("Not Implemented", f"Auto-setup for '{provider}' N/A.", parent=self.master)
    def open_pcloud_config_window(self): 
        if self.active_config_window_ref and self.active_config_window_ref.winfo_exists():
            messagebox.showwarning("Setup in Progress", "Another config window is open.", parent=self.master); self.active_config_window_ref.lift(); return
        name = simpledialog.askstring("pCloud Remote Name", "Enter name for new pCloud remote:", parent=self.master)
        if not name: self.log_message_gui("pCloud setup cancelled.\n",is_info=True); return
        self.active_config_window_ref = ConfigProgressWindow(self.master,self,f"Automated pCloud Setup: {name}",self.theme_colors)
        self.active_config_window_ref.set_info_text("Guiding rclone for pCloud. Browser auth needed.")
        self.active_config_window_ref.automation_started(); self.pcloud_auth_event.clear(); self.pcloud_auth_result_holder['result']=None
        log_utils.app_log(f"Starting pCloud automation for: {name}",gui_log_func=self._gui_log_callback)
        threading.Thread(target=autoconfig.automate_pcloud_config,
            args=(name,self.worker_thread_queue,self.pcloud_auth_event,lambda:self.pcloud_auth_result_holder['result'],
                  self.worker_thread_queue, lambda:self.active_config_window_ref.auth_url_from_rclone if self.active_config_window_ref and self.active_config_window_ref.winfo_exists() else "",
                  self.rclone_config_password), daemon=True).start()
    def open_crypt_setup_dialog(self):
        if self.active_config_window_ref and self.active_config_window_ref.winfo_exists():
            messagebox.showwarning("Setup in Progress", "Another config window is open.", parent=self.master); self.active_config_window_ref.lift(); return
        if not self.remotes:
             messagebox.showerror("No Target Remotes", "No existing remotes found. Please create a standard remote first to use as a target for crypt.", parent=self.master)
             return
        crypt_dialog = CryptSetupDialog(self.master, theme_colors_dict=self.theme_colors, existing_remotes=self.remotes)
        if crypt_dialog.result:
            params = crypt_dialog.result
            if not params["target_remote"] or not params["target_remote"].endswith(":"): 
                messagebox.showerror("Error", "Invalid target remote selected for crypt.", parent=self.master); return
            self.log_message_gui(f"Starting Crypt setup for '{params['remote_name']}'...\n", is_info=True)
            self.active_config_window_ref = ConfigProgressWindow(self.master, self, f"Automated Crypt Setup: {params['remote_name']}", self.theme_colors)
            info_text = (f"Creating Crypt remote '{params['remote_name']}' targeting root of '{params['target_remote']}'.\n"
                         f"Directory names will be {'encrypted' if params['directory_name_encryption_gui_choice'] else 'left as is'}.\n"
                         "Rclone's default internal salt will be used.")
            self.active_config_window_ref.set_info_text(info_text)
            self.active_config_window_ref.automation_started()
            log_utils.app_log(f"Starting Crypt automation for: {params['remote_name']}, Params: {params}", gui_log_func=self._gui_log_callback)
            threading.Thread(
                target=autoconfig.automate_crypt_config,
                args=(params["remote_name"], 
                      params["target_remote"], 
                      params["filename_encryption_gui_choice"],
                      params["directory_name_encryption_gui_choice"],
                      params["password_main_value"], 
                      self.worker_thread_queue, 
                      self.worker_thread_queue, 
                      self.rclone_config_password),
                daemon=True
            ).start()
        else:
            self.log_message_gui("Crypt remote setup cancelled.\n", is_info=True)
    def start_operation(self, operation_type, direction):
        sources_to_process = []
        source_items_display_names = []
        destination_base_path = ""
        if direction == "lr": 
            selected_indices = self.local_files_list.curselection()
            if not selected_indices: messagebox.showwarning("No Selection", "Please select local items.", parent=self.master); return
            source_items_display_names = [self.local_files_list.get(i) for i in selected_indices if self.local_files_list.get(i) != '../']
            if not source_items_display_names: messagebox.showwarning("Invalid Selection", "Cannot operate on '../'.", parent=self.master); return
            current_local_dir = self.current_local_path.get()
            sources_to_process = [os.path.normpath(os.path.join(current_local_dir, name.rstrip('/'))) for name in source_items_display_names]
            destination_base_path = self.get_full_remote_path()
            if not destination_base_path or not self.current_remote_base.get(): messagebox.showerror("Error", "Remote destination not set.", parent=self.master); return
        elif direction == "rl": 
            selected_indices = self.remote_files_list.curselection()
            if not selected_indices: messagebox.showwarning("No Selection", "Please select remote items.", parent=self.master); return
            source_items_display_names = [self.remote_files_list.get(i) for i in selected_indices if self.remote_files_list.get(i) != '../']
            if not source_items_display_names: messagebox.showwarning("Invalid Selection", "Cannot operate on '../'.", parent=self.master); return
            current_remote_full_path = self.get_full_remote_path() 
            if not current_remote_full_path or not self.current_remote_base.get(): messagebox.showerror("Error", "Remote source not set.", parent=self.master); return
            sources_to_process = [f"{current_remote_full_path.rstrip('/')}/{name.rstrip('/')}" for name in source_items_display_names]
            destination_base_path = self.current_local_path.get()
            if not destination_base_path or not os.path.isdir(destination_base_path): messagebox.showerror("Error", "Local destination not valid.", parent=self.master); return
        else: return
        op_display_name = operation_type.capitalize()
        confirm_msg = f"Are you sure you want to {operation_type} the selected item(s)?\n\n"
        confirm_msg += f"Source(s) ({len(source_items_display_names)} item(s) like: '{source_items_display_names[0]}', ...)\n"
        confirm_msg += f"Destination Base: '{destination_base_path}'"
        if not messagebox.askyesno(f"Confirm {op_display_name}", confirm_msg, parent=self.master):
            self.log_message_gui(f"{op_display_name} for selected items cancelled.\n", is_info=True); return
        self.log_message_gui(f"Initiating {op_display_name} for {len(sources_to_process)} selected item(s)...\n", is_info=True)
        log_utils.app_log(f"User confirmed {op_display_name}: {len(sources_to_process)} items. Sources like: {sources_to_process[0]}... Dest Base: {destination_base_path}", gui_log_func=self._gui_log_callback, log_to_gui=False)
        for i, src_full_path in enumerate(sources_to_process):
            item_basename_for_dest = os.path.basename(src_full_path.rstrip('/\\'))
            actual_rclone_destination = ""
            is_source_dir = (direction == "lr" and os.path.isdir(src_full_path)) or \
                            (direction == "rl" and source_items_display_names[i].endswith("/"))
            if is_source_dir:
                if direction == "lr": actual_rclone_destination = f"{destination_base_path.rstrip('/')}/{item_basename_for_dest}"
                else: actual_rclone_destination = os.path.join(destination_base_path, item_basename_for_dest)
            else: actual_rclone_destination = destination_base_path
            if direction == "lr": actual_rclone_destination = actual_rclone_destination.replace(os.sep, "/")
            else: actual_rclone_destination = os.path.normpath(actual_rclone_destination)
            rclone_flags = ["-v", "--stats=5s", "--stats-one-line", "-P"]
            cmd_args = [operation_type] + rclone_flags + [src_full_path, actual_rclone_destination]
            log_utils.app_log(f"Rclone cmd ({i+1}/{len(sources_to_process)} direct selection): rclone {' '.join(cmd_args)}", gui_log_func=self._gui_log_callback, log_to_gui=False) 
            rclone.run_rclone_command(cmd_args, capture_output=False, gui_log_func=self._gui_log_callback, config_password=self.rclone_config_password)
        self.log_message_gui(f"{op_display_name} for {len(sources_to_process)} items initiated.\nCheck log.txt or rclone console window(s) for progress.\n", is_info=True)
        if self.master.winfo_exists():
            self.master.after(10000, self.refresh_local_files) 
            self.master.after(10000, lambda: self.refresh_remote_files(sub_item_nav=None))
    def launch_rclone_config_cmd(self):
        rclone_exe = rclone.RCLONE_EXE_PATH
        info = "A terminal for 'rclone config' will be launched. Follow the instructions inside it. When finished, close the terminal and then click 'Refresh Remotes' in the GUI."
        if self.rclone_config_password:
            info += "\n\nNOTE: Your configuration is password protected. You may need to enter the password in the terminal."
        messagebox.showinfo("Rclone Config via Terminal", info, parent=self.master)
        try:
            log_utils.app_log(f"Launching terminal for: {rclone_exe} config", gui_log_func=self._gui_log_callback, log_to_gui=False)
            env = os.environ.copy()
            if self.rclone_config_password:
                env["RCLONE_CONFIG_PASS"] = self.rclone_config_password
            if sys.platform == "win32":
                subprocess.Popen([rclone_exe, "config"], creationflags=subprocess.CREATE_NEW_CONSOLE, env=env)
            else:
                cmd = ['xterm', '-e', rclone_exe, 'config']
                try:
                    subprocess.Popen(cmd, env=env)
                except FileNotFoundError:
                    err_msg = "Could not find 'xterm'. Please install it or modify the script to use your preferred terminal (e.g., gnome-terminal)."
                    messagebox.showerror("Terminal Not Found", err_msg, parent=self.master)
                    log_utils.app_log(err_msg, level="error", gui_log_func=self._gui_log_callback, log_to_gui=True)
                    return
            self.log_message_gui("Terminal for 'rclone config' launched. Refresh remotes when done.\n", is_info=True)
        except Exception as e:
            err_msg = f"Failed to launch 'rclone config' terminal: {e}"
            log_utils.app_log(err_msg, level="error", gui_log_func=self._gui_log_callback, log_to_gui=True)
            logger.error("Launch Terminal Error", exc_info=True)
            messagebox.showerror("Launch Error", f"{err_msg}\nCheck log.txt.", parent=self.master)
    def confirm_delete_remote(self): 
        sel_remote=self.remote_combo.get()
        if not sel_remote: messagebox.showwarning("No Remote","Select remote to delete.",parent=self.master); return
        if messagebox.askyesno("Confirm Delete",f"Permanently delete remote '{sel_remote}'?\nCannot be undone from GUI.",parent=self.master,icon=messagebox.WARNING): self.delete_remote(sel_remote)
    def delete_remote(self,remote_name): 
        self.log_message_gui(f"Deleting remote: {remote_name}...\n",is_info=True); log_utils.app_log(f"Deleting remote: {remote_name}",gui_log_func=self._gui_log_callback,log_to_gui=False)
        out,err,rc=rclone.run_rclone_command(["config","delete",remote_name],True,self._gui_log_callback,False,self.rclone_config_password)
        if rc==0: self.log_message_gui(f"Remote '{remote_name}' deleted.\n",is_info=True); log_utils.app_log(f"Remote '{remote_name}' deleted. RC:{rc}.",gui_log_func=self._gui_log_callback,log_to_gui=False)
        else: err_msg=f"Failed to delete '{remote_name}'. RC:{rc}.\n"; err_msg+=f"Error: {err.strip()}\n" if err else ""; self.log_message_gui(err_msg,is_error=True); log_utils.app_log(f"Error deleting '{remote_name}'. RC:{rc}. Stderr:{err.strip()}",level="error",gui_log_func=self._gui_log_callback,log_to_gui=False); messagebox.showerror("Delete Failed",f"Could not delete '{remote_name}'.\n{err.strip() or 'Unknown error.'}",parent=self.master)
        self.load_remotes()
    def prompt_generate_batch_file(self): 
        remote_name=self._get_current_remote_name()
        if not remote_name: messagebox.showwarning("No Remote","Select remote for script.",parent=self.master); return
        if remote_name not in self.associated_remote_lists or not self.associated_remote_lists[remote_name].get("local_items"): messagebox.showinfo("No Items",f"No items for '{remote_name}' for script.",parent=self.master); return
        is_windows = sys.platform == "win32"
        script_type = "Batch File" if is_windows else "Shell Script"
        default_extension = ".bat" if is_windows else ".sh"
        file_types = [("Batch", "*.bat"), ("All", "*.*")] if is_windows else [("Shell Script", "*.sh"), ("All", "*.*")]
        dialog=BatchGenDialog(self.master,f"Generate {script_type} for '{remote_name}'",self.theme_colors,rclone.RCLONE_EXE_PATH)
        if dialog.result:
            opts=dialog.result; list_data=self.associated_remote_lists[remote_name]
            self.log_message_gui(f"Generating script with opts: {opts}\n",is_info=True)
            if is_windows:
                script_content = self.generate_batch_script_content(remote_name, list_data, opts)
            else:
                script_content = self.generate_shell_script_content(remote_name, list_data, opts)
            def_fn=f"rclone_{remote_name.replace(':','_')}_{opts['operation']}{default_extension}"
            fp=filedialog.asksaveasfilename(parent=self.master,title=f"Save {script_type}",initialfile=def_fn,defaultextension=default_extension,filetypes=file_types)
            if fp:
                try:
                    with open(fp,"w",encoding="utf-8") as f: f.write(script_content)
                    if not is_windows:
                        os.chmod(fp, 0o755)
                    self.log_message_gui(f"{script_type} saved: {fp}\n",is_info=True)
                    instr=f"{script_type} '{os.path.basename(fp)}' saved."
                    messagebox.showinfo(f"{script_type} Generated",instr,parent=self.master)
                except Exception as e: self.log_message_gui(f"Error saving script: {e}\n",is_error=True); messagebox.showerror("Save Error",f"Failed to save: {e}",parent=self.master)
        else: self.log_message_gui("Script generation cancelled.\n",is_info=True)
    def generate_batch_script_content(self,remote_name,list_data,options): 
        lines=[]; lines.append("@echo off" if options["password_option"]=="hardcode" else "@echo on"); lines.append("setlocal\n")
        lines.append(f":: Rclone Batch: Remote '{remote_name}', Op: {options['operation'].capitalize()}"); lines.append(f":: Generated by Rclone GUI {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        lines.append(f"set RCLONE_EXE=\"{options['rclone_exe']}\"")
        lines.append("if not exist %RCLONE_EXE% (echo ERROR: Rclone not found at %RCLONE_EXE% & goto end_script)\n")
        if options["password_option"]=="prompt": lines.append("set /p RCLONE_CONFIG_PASS=\"Enter rclone config password (blank if none): \"")
        elif options["password_option"]=="hardcode": lines.append(f"set RCLONE_CONFIG_PASS={options['hardcoded_password']}")
        lines.append("\n:: --- RCLONE COMMANDS ---")
        local_items=list_data.get("local_items",[]); dest_seg=list_data.get("remote_dest_segment",""); base_flags=list_data.get("rclone_flags","")
        if not local_items: lines.append("REM No local items in list.")
        for i,local_item in enumerate(local_items):
            item_base=os.path.basename(local_item); remote_dest_parts=[remote_name+":"]
            if dest_seg: remote_dest_parts.append(dest_seg)
            remote_dest_parts.append(item_base); final_dest="/".join(s.strip("/") for s in remote_dest_parts if s)
            cmd=["%RCLONE_EXE%",options["operation"]];
            if base_flags: cmd.extend(base_flags.split())
            if options["log_enabled"] and options["log_file"]: cmd.append(f"--log-file=\"{options['log_file']}\" --log-level=INFO")
            cmd.append(f"\"{local_item}\""); cmd.append(f"\"{final_dest}\"")
            lines.append(f"\necho Processing item {i+1}/{len(local_items)}: {local_item} TO {final_dest}"); lines.append(" ".join(cmd))
        lines.append("\n:: --- END OF SCRIPT ---"); lines.append(":end_script"); lines.append("echo Batch script operations complete."); lines.append("endlocal")
        if options["password_option"]=="prompt": lines.append("timeout /t 10 /nobreak >nul")
        return "\r\n".join(lines)
    def generate_shell_script_content(self, remote_name, list_data, options):
        lines = ["#!/bin/bash", "set -e\n"]
        lines.append(f"# Rclone Shell Script: Remote '{remote_name}', Op: {options['operation'].capitalize()}")
        lines.append(f"# Generated by Rclone GUI {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        lines.append(f"RCLONE_EXE=\"{options['rclone_exe']}\"")
        lines.append('if [ ! -f "$RCLONE_EXE" ]; then')
        lines.append('    echo "ERROR: Rclone not found at $RCLONE_EXE"')
        lines.append('    exit 1')
        lines.append('fi\n')
        if options["password_option"] == "prompt":
            lines.append('read -s -p "Enter rclone config password (blank if none): " RCLONE_CONFIG_PASS')
            lines.append('export RCLONE_CONFIG_PASS')
            lines.append('echo')
        elif options["password_option"] == "hardcode":
            lines.append(f"export RCLONE_CONFIG_PASS='{options['hardcoded_password']}'")
        lines.append("\n# --- RCLONE COMMANDS ---")
        local_items = list_data.get("local_items", [])
        dest_seg = list_data.get("remote_dest_segment", "")
        base_flags = list_data.get("rclone_flags", "")
        if not local_items:
            lines.append("# No local items in list.")
        for i, local_item in enumerate(local_items):
            item_base = os.path.basename(local_item)
            remote_dest_parts = [remote_name + ":"]
            if dest_seg:
                remote_dest_parts.append(dest_seg)
            remote_dest_parts.append(item_base)
            final_dest = "/".join(s.strip("/") for s in remote_dest_parts if s)
            cmd = ["\"$RCLONE_EXE\"", options["operation"]]
            if base_flags:
                cmd.extend(base_flags.split())
            if options["log_enabled"] and options["log_file"]:
                cmd.append(f"--log-file=\"{options['log_file']}\" --log-level=INFO")
            cmd.append(f"\"{local_item}\"")
            cmd.append(f"\"{final_dest}\"")
            lines.append(f"\necho \"Processing item {i+1}/{len(local_items)}: {local_item} TO {final_dest}\"")
            lines.append(" ".join(cmd))
        lines.append("\n# --- END OF SCRIPT ---")
        lines.append('echo "Shell script operations complete."')
        return "\n".join(lines)

if __name__ == '__main__': 
    _FINISH_PROGRAM_AND_EXIT_MAIN_ = False
    try:
        if not isinstance(logger, (logging.Logger, PrintLogger)):
            log_utils.setup_logging() 
            logger = log_utils.get_logger("RcloneGUI_App_MainRecovery")
            logger.warning("Logger was not of expected type in __main__, re-initialized.")
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
                err_root_temp = tk.Tk(); err_root_temp.withdraw()
                bg_color = '#2E2E2E' 
                if hasattr(gui, 'theme_colors') and gui.theme_colors and 'WINDOW_BG' in gui.theme_colors: bg_color = gui.theme_colors['WINDOW_BG']
                if err_root_temp.winfo_exists(): err_root_temp.configure(bg=bg_color)
                messagebox.showerror("GUI Initialization Error", f"Failed to initialize main GUI: {e_gui_init}\nPlease check log.txt for details.", parent=None)
                if err_root_temp.winfo_exists(): err_root_temp.destroy()
            except Exception as e_msgbox: print(f"Could not display Tkinter error messagebox for GUI init failure: {e_msgbox}")
            if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists(): root.destroy()
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
            logger.error("Application will exit as main window is not available or GUI failed to initialize.")
            if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists():
                try: root.destroy()
                except tk.TclError: pass
            sys.exit(1)
    except Exception as e_main:
        final_error_message = f"Fatal unhandled exception in RcloneGUI __main__ block: {e_main}"
        if 'logger' in globals() and logger and hasattr(logger, 'critical'): logger.critical(final_error_message, exc_info=True)
        else: print(final_error_message); print(traceback.format_exc())
        try:
            with open("rclone_gui_fatal_error.txt", "a", encoding="utf-8") as felog: felog.write(f"{datetime.now()}: {final_error_message}\n{traceback.format_exc()}\n")
        except Exception: print("Failed to write to rclone_gui_fatal_error.txt during critical exception handling.")
        try:
            err_root_final = tk.Tk(); err_root_final.withdraw()
            messagebox.showerror("Fatal Application Error", f"A critical error occurred: {e_main}\nPlease check rclone_gui_fatal_error.txt or console output.", parent=None)
            if err_root_final.winfo_exists(): err_root_final.destroy()
        except Exception: print("Could not display final Tkinter error messagebox for fatal application error.")
        sys.exit(1)
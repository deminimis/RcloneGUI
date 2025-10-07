import tkinter as tk
from tkinter import ttk

def apply_graphite_theme(style):
    WINDOW_BG = "#2E2E2E"
    FRAME_BG = "#3C3C3C"
    WIDGET_BG = "#4A4A4A"
    TEXT_COLOR = "#FFFFFF"
    TEXT_DISABLED_COLOR = "#888888"
    SELECT_BG_COLOR = "#007ACC"
    SELECT_FG_COLOR = "#FFFFFF"
    
    BORDER_COLOR_WIDGET = "#202020"
    BORDER_COLOR_FRAME = "#555555"
    
    BUTTON_BG_COLOR = "#555555"
    BUTTON_FG_COLOR = TEXT_COLOR
    BUTTON_ACTIVE_BG_COLOR = "#6A6A6A"
    BUTTON_PRESSED_BG_COLOR = "#454545"
    
    TROUGH_COLOR = "#2E2E2E"
    SCROLLBAR_THUMB_BG = "#5F5F5F"
    SCROLLBAR_THUMB_ACTIVE_BG = "#7A7A7A"
    SCROLLBAR_ARROW_COLOR = TEXT_COLOR

    try:
        style.theme_use('clam')
    except tk.TclError:
        current_themes = style.theme_names()
        if current_themes:
            style.theme_use(current_themes[0])

    style.configure('.',
                    background=FRAME_BG,
                    foreground=TEXT_COLOR,
                    fieldbackground=WIDGET_BG,
                    borderwidth=0, 
                    relief='flat',
                    focuscolor=SELECT_BG_COLOR) 

    style.map('.',
              foreground=[('disabled', TEXT_DISABLED_COLOR)],
              fieldbackground=[('disabled', WIDGET_BG)], 
              background=[('disabled', FRAME_BG)])

    style.configure('TFrame', background=FRAME_BG)

    style.configure('TLabel', background=FRAME_BG, foreground=TEXT_COLOR, padding=(2,2))
    style.configure('Header.TLabel', background=FRAME_BG, foreground=TEXT_COLOR)
    style.configure('Path.TLabel', background=FRAME_BG, foreground=TEXT_COLOR)

    style.configure('TButton',
                    background=BUTTON_BG_COLOR,
                    foreground=BUTTON_FG_COLOR,
                    relief='flat',
                    borderwidth=1, 
                    bordercolor=BORDER_COLOR_WIDGET,
                    padding=(10, 6)) 
    style.map('TButton',
              background=[('pressed', BUTTON_PRESSED_BG_COLOR),
                          ('active', BUTTON_ACTIVE_BG_COLOR), 
                          ('disabled', '#4A4A4A')],
              foreground=[('disabled', TEXT_DISABLED_COLOR)],
              bordercolor=[('active', SELECT_BG_COLOR), 
                           ('!active', BORDER_COLOR_WIDGET)],
              relief=[('pressed', 'flat'), ('!pressed', 'flat')]) 

    style.configure('TEntry',
                    fieldbackground=WIDGET_BG,
                    foreground=TEXT_COLOR,
                    insertcolor=TEXT_COLOR, 
                    borderwidth=1,
                    relief='solid', 
                    padding=(5, 5))
    style.map('TEntry',
              bordercolor=[('focus', SELECT_BG_COLOR), ('!focus', BORDER_COLOR_WIDGET)],
              fieldbackground=[('disabled', '#404040'), ('readonly', WIDGET_BG)],
              foreground=[('disabled', TEXT_DISABLED_COLOR), ('readonly', TEXT_COLOR)])

    style.configure('TCombobox',
                    fieldbackground=WIDGET_BG, 
                    foreground=TEXT_COLOR,     
                    insertcolor=TEXT_COLOR,    
                    arrowcolor=TEXT_COLOR,     
                    borderwidth=1,
                    relief='solid',
                    padding=(5,4,24,4), 
                    selectbackground=WIDGET_BG, 
                    selectforeground=TEXT_COLOR)
    style.map('TCombobox',
              bordercolor=[('focus', SELECT_BG_COLOR), ('!focus', BORDER_COLOR_WIDGET)],
              fieldbackground=[('readonly', WIDGET_BG), 
                               ('disabled', '#404040'), 
                               ('focus', WIDGET_BG), 
                               ('pressed', WIDGET_BG), 
                               ('hover', WIDGET_BG)], 
              foreground=[('disabled', TEXT_DISABLED_COLOR), ('readonly', TEXT_COLOR)],
              arrowcolor=[('disabled', TEXT_DISABLED_COLOR), 
                          ('pressed', SELECT_BG_COLOR), 
                          ('hover', SELECT_BG_COLOR)])  

    style.configure('TLabelFrame',
                    background=FRAME_BG, 
                    foreground=TEXT_COLOR,    
                    relief='solid',           
                    borderwidth=1,
                    bordercolor=BORDER_COLOR_FRAME, 
                    labelmargins=(5, 2, 5, 2),
                    padding=(10, 10))         

    style.configure('TLabelFrame.Label',
                    background=FRAME_BG, 
                    foreground=TEXT_COLOR)

    style.configure('TScrollbar',
                    relief='flat',
                    borderwidth=0,
                    background=FRAME_BG,          
                    troughcolor=TROUGH_COLOR,     
                    arrowsize=14,                 
                    arrowcolor=SCROLLBAR_ARROW_COLOR,
                    gripcount=0) 

    style.configure('Vertical.TScrollbar', background=SCROLLBAR_THUMB_BG, width=12)
    style.map('Vertical.TScrollbar', 
              background=[('pressed', SCROLLBAR_THUMB_ACTIVE_BG),
                          ('active', SCROLLBAR_THUMB_ACTIVE_BG), 
                          ('disabled', SCROLLBAR_THUMB_BG)])

    style.configure('Horizontal.TScrollbar', background=SCROLLBAR_THUMB_BG, height=12)
    style.map('Horizontal.TScrollbar', 
              background=[('pressed', SCROLLBAR_THUMB_ACTIVE_BG),
                          ('active', SCROLLBAR_THUMB_ACTIVE_BG), 
                          ('disabled', SCROLLBAR_THUMB_BG)])
    
    style.map('TScrollbar', 
              arrowcolor=[('disabled', TEXT_DISABLED_COLOR),
                          ('pressed', SELECT_BG_COLOR), 
                          ('active', SELECT_BG_COLOR)])  

    try:
        for element_suffix in ['uparrow', 'downarrow', 'leftarrow', 'rightarrow']:
            element_name = f'Scrollbar.{element_suffix}'
            style.configure(element_name, background=BUTTON_BG_COLOR, relief='flat', borderwidth=0)
            style.map(element_name,
                      background=[('pressed', BUTTON_PRESSED_BG_COLOR),
                                  ('active', BUTTON_ACTIVE_BG_COLOR)])
    except tk.TclError:
        pass

    style.configure('TProgressbar',
                    background=SELECT_BG_COLOR, 
                    troughcolor=TROUGH_COLOR,
                    borderwidth=1,
                    relief='solid',
                    bordercolor=BORDER_COLOR_WIDGET)

    return {
        'WINDOW_BG': WINDOW_BG,
        'FRAME_BG': FRAME_BG,
        'WIDGET_BG': WIDGET_BG,
        'TEXT_COLOR': TEXT_COLOR,
        'TEXT_DISABLED_COLOR': TEXT_DISABLED_COLOR,
        'SELECT_BG_COLOR': SELECT_BG_COLOR,
        'SELECT_FG_COLOR': SELECT_FG_COLOR,
        'BORDER_COLOR_WIDGET': BORDER_COLOR_WIDGET,
        'BORDER_COLOR_FRAME': BORDER_COLOR_FRAME,
        'LISTBOX_HIGHLIGHT_BG': FRAME_BG, 
        'LISTBOX_HIGHLIGHT_COLOR': SELECT_BG_COLOR, 
        'LOG_ERROR_FG': '#FF8A80',   
        'LOG_INFO_FG': '#82B1FF',    
        'LOG_STDIN_FG': '#CE93D8',   
        'LOG_STDOUT_FG': TEXT_COLOR, 
        'TEXT_INSERT_BG': TEXT_COLOR 
    }
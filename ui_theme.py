# -*- coding: utf-8 -*-
"""ui_theme.py —— 深色主题与通用控件样式

配色参考 Tokyo Night，兼顾长时间抓包时的可读性：
协议用不同色相区分，选中行用高对比蓝，正文避免纯白（降低眩光）。
"""

import ctypes
import sys
import tkinter as tk
from tkinter import ttk

BG = "#16161e"
BG_PANEL = "#1f1f2e"
BG_ALT = "#252536"
BG_INPUT = "#2a2a3c"
FG = "#d7d7e0"
FG_DIM = "#8b8ba7"
FG_FAINT = "#5f5f7a"
ACCENT = "#7aa2f7"
ACCENT2 = "#bb9af7"
GREEN = "#9ece6a"
YELLOW = "#e0af68"
RED = "#f7768e"
CYAN = "#7dcfff"
ORANGE = "#ff9e64"
BORDER = "#3b3b52"
SELECT = "#33467c"
SELECT_FG = "#ffffff"

PROTO_COLORS = {
    "HTTP": "#bb9af7", "HTTP-ALT": "#bb9af7", "HTTPS": "#9d7cd8",
    "TLS": "#9d7cd8", "DNS": "#7dcfff", "TCP": "#e0af68",
    "UDP": "#9ece6a", "ICMP": "#7aa2f7", "ICMPv6": "#7aa2f7",
    "ARP": "#ff9e64", "DHCP": "#9ece6a", "IPv4": "#c0caf5",
    "IPv6": "#c0caf5", "OTHER": "#a9b1d6",
}

FONT_UI = ("Microsoft YaHei UI", 9)
FONT_UI_BOLD = ("Microsoft YaHei UI", 9, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 15, "bold")
FONT_SUB = ("Microsoft YaHei UI", 8)
FONT_MONO = ("Consolas", 9)
FONT_MONO_SM = ("Consolas", 8)


def enable_dpi_awareness():
    """在创建 Tk 之前调用，避免高分屏下界面被系统缩放糊掉。"""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def apply_dark_titlebar(win: tk.Misc):
    """Windows 10/11：把窗口标题栏设为深色；失败时静默忽略。"""
    if sys.platform != "win32":
        return
    try:
        hwnd = ctypes.windll.user32.GetAncestor(win.winfo_id(), 2) or win.winfo_id()
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def center_window(win: tk.Misc, width: int, height: int, parent: tk.Misc = None):
    win.update_idletasks()
    if parent is not None:
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + max(0, (pw - width) // 2)
        y = py + max(0, (ph - height) // 3)
    else:
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        x, y = max(0, (sw - width) // 2), max(0, (sh - height) // 3)
    win.geometry(f"{width}x{height}+{x}+{y}")


def setup_style(root: tk.Tk):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.option_add("*Font", FONT_UI)
    root.option_add("*TCombobox*Listbox.background", BG_INPUT)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT)
    root.option_add("*TCombobox*Listbox.selectForeground", SELECT_FG)
    root.option_add("*TCombobox*Listbox.font", FONT_UI)

    style.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BG,
                    font=FONT_UI)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=BG_PANEL)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=FONT_SUB)
    style.configure("Title.TLabel", background=BG, foreground=FG, font=FONT_TITLE)
    style.configure("Accent.TLabel", background=BG, foreground=ACCENT)
    style.configure("TLabelframe", background=BG, foreground=FG, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=FG_DIM)
    style.configure("Treeview", background=BG_PANEL, fieldbackground=BG_PANEL,
                    foreground=FG, rowheight=23, borderwidth=0, font=FONT_UI)
    style.configure("Treeview.Heading", background="#2b2b3f", foreground=FG,
                    relief="flat", font=FONT_UI_BOLD, padding=(4, 4))
    style.map("Treeview",
              background=[("selected", SELECT)],
              foreground=[("selected", SELECT_FG)])
    style.map("Treeview.Heading", background=[("active", "#34344c")])
    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(4, 4, 4, 0))
    style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_DIM,
                    padding=(16, 7), borderwidth=0, font=FONT_UI)
    style.map("TNotebook.Tab",
              background=[("selected", BG_ALT)],
              foreground=[("selected", ACCENT)])
    style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                    foreground=FG, arrowcolor=FG, bordercolor=BORDER,
                    selectbackground=BG_INPUT, selectforeground=FG)
    style.map("TCombobox",
              fieldbackground=[("readonly", BG_INPUT)],
              foreground=[("readonly", FG)],
              selectbackground=[("readonly", BG_INPUT)])
    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG,
                    insertcolor=FG, bordercolor=BORDER)
    style.configure("TButton", background=BG_ALT, foreground=FG, borderwidth=0,
                    padding=(10, 5), font=FONT_UI)
    style.map("TButton",
              background=[("active", "#34344c"), ("disabled", BG_PANEL)],
              foreground=[("disabled", FG_FAINT)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#101018",
                    borderwidth=0, padding=(10, 5), font=FONT_UI_BOLD)
    style.map("Accent.TButton", background=[("active", "#89b0ff")])
    style.configure("Stop.TButton", background="#a33", foreground="#fff")
    style.map("Stop.TButton", background=[("active", "#c44")])
    style.configure("TScrollbar", background=BG_ALT, troughcolor=BG,
                    arrowcolor=FG_DIM, bordercolor=BG)
    style.configure("TPanedwindow", background=BG)
    style.configure("Sash", background=BORDER, sashthickness=4)


def make_text(parent, **kw):
    opts = dict(bg=BG_PANEL, fg=FG, insertbackground=FG, relief="flat",
                wrap=tk.NONE, font=FONT_MONO, borderwidth=0, highlightthickness=0,
                padx=8, pady=6)
    opts.update(kw)
    return tk.Text(parent, **opts)


def make_button(parent, text, command, accent=False, stop=False, width=None):
    if accent:
        style = "Accent.TButton"
    elif stop:
        style = "Stop.TButton"
    else:
        style = "TButton"
    btn = ttk.Button(parent, text=text, command=command, style=style,
                     takefocus=False)
    if width:
        btn.configure(width=width)
    return btn
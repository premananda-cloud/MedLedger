"""
ui/components/widgets.py - Reusable UI widgets for MedLedger desktop app.
"""

import tkinter as tk
from tkinter import ttk
from config import THEME_COLOR


# ── Colours ───────────────────────────────────────────────────────────────────
BG_DARK    = "#1e2330"
BG_PANEL   = "#252b3b"
BG_CARD    = "#2d3448"
TEXT_WHITE = "#f0f2f8"
TEXT_GRAY  = "#8a93b0"
ACCENT     = THEME_COLOR         # "#1a73e8"
SUCCESS    = "#22c55e"
WARNING    = "#f59e0b"
DANGER     = "#ef4444"
BORDER     = "#3d4560"


def apply_dark_theme(root: tk.Tk):
    """Apply global dark theme styles."""
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".",
        background=BG_DARK,
        foreground=TEXT_WHITE,
        fieldbackground=BG_CARD,
        bordercolor=BORDER,
        focuscolor=ACCENT,
        font=("Segoe UI", 10),
    )
    style.configure("TFrame", background=BG_DARK)
    style.configure("Card.TFrame", background=BG_CARD)
    style.configure("Panel.TFrame", background=BG_PANEL)

    style.configure("TLabel",
        background=BG_DARK,
        foreground=TEXT_WHITE,
        font=("Segoe UI", 10),
    )
    style.configure("Title.TLabel",
        background=BG_DARK,
        foreground=TEXT_WHITE,
        font=("Segoe UI", 22, "bold"),
    )
    style.configure("Subtitle.TLabel",
        background=BG_DARK,
        foreground=TEXT_GRAY,
        font=("Segoe UI", 11),
    )
    style.configure("Card.TLabel",
        background=BG_CARD,
        foreground=TEXT_WHITE,
        font=("Segoe UI", 10),
    )
    style.configure("Success.TLabel",
        background=BG_DARK,
        foreground=SUCCESS,
        font=("Segoe UI", 10),
    )
    style.configure("Error.TLabel",
        background=BG_DARK,
        foreground=DANGER,
        font=("Segoe UI", 10),
    )
    style.configure("TEntry",
        fieldbackground=BG_CARD,
        foreground=TEXT_WHITE,
        insertcolor=TEXT_WHITE,
        bordercolor=BORDER,
        font=("Segoe UI", 10),
    )
    style.configure("TCombobox",
        fieldbackground=BG_CARD,
        foreground=TEXT_WHITE,
        background=BG_CARD,
    )
    style.configure("Primary.TButton",
        background=ACCENT,
        foreground="white",
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        focusthickness=0,
        padding=(16, 8),
    )
    style.map("Primary.TButton",
        background=[("active", "#1557c0"), ("disabled", "#3d4560")],
    )
    style.configure("Danger.TButton",
        background=DANGER,
        foreground="white",
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        padding=(12, 6),
    )
    style.map("Danger.TButton",
        background=[("active", "#b91c1c")],
    )
    style.configure("Ghost.TButton",
        background=BG_PANEL,
        foreground=TEXT_WHITE,
        font=("Segoe UI", 10),
        borderwidth=1,
        padding=(12, 6),
    )
    style.map("Ghost.TButton",
        background=[("active", BG_CARD)],
    )
    style.configure("Nav.TButton",
        background=BG_PANEL,
        foreground=TEXT_GRAY,
        font=("Segoe UI", 10),
        borderwidth=0,
        padding=(20, 10),
        anchor="w",
    )
    style.map("Nav.TButton",
        background=[("active", BG_CARD)],
        foreground=[("active", TEXT_WHITE)],
    )
    style.configure("NavActive.TButton",
        background=BG_CARD,
        foreground=TEXT_WHITE,
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        padding=(20, 10),
        anchor="w",
    )
    style.configure("Treeview",
        background=BG_CARD,
        foreground=TEXT_WHITE,
        fieldbackground=BG_CARD,
        rowheight=32,
        font=("Segoe UI", 9),
    )
    style.configure("Treeview.Heading",
        background=BG_PANEL,
        foreground=TEXT_GRAY,
        font=("Segoe UI", 9, "bold"),
        borderwidth=0,
    )
    style.map("Treeview",
        background=[("selected", ACCENT)],
        foreground=[("selected", "white")],
    )
    style.configure("TScrollbar",
        background=BG_PANEL,
        troughcolor=BG_DARK,
        bordercolor=BG_DARK,
        arrowcolor=TEXT_GRAY,
    )
    root.configure(bg=BG_DARK)


class StatusBar(ttk.Frame):
    """Bottom status bar showing online/offline status."""

    def __init__(self, parent, orchestrator, **kwargs):
        super().__init__(parent, **kwargs)
        self.orch = orchestrator
        self.configure(style="Panel.TFrame")

        self._dot  = ttk.Label(self, text="●", style="TLabel", font=("Segoe UI", 12))
        self._text = ttk.Label(self, text="Checking connection…", style="Subtitle.TLabel")
        self._dot.pack(side="left", padx=(12, 4), pady=4)
        self._text.pack(side="left", pady=4)

        self._version = ttk.Label(self, text="MedLedger v1.0", style="Subtitle.TLabel")
        self._version.pack(side="right", padx=12, pady=4)

        self._refresh()

    def _refresh(self):
        online = self.orch.is_online
        self._dot.configure(foreground=SUCCESS if online else DANGER)
        self._text.configure(text="Connected to server" if online else "Offline mode")
        self.after(10_000, self._refresh)   # re-check every 10 s


class ProgressDialog(tk.Toplevel):
    """Modal dialog showing step-by-step progress for long operations."""

    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG_DARK)
        self.resizable(False, False)
        self.grab_set()

        w, h = 420, 220
        px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

        ttk.Label(self, text=title, style="Title.TLabel",
                  font=("Segoe UI", 14, "bold")).pack(pady=(20, 8), padx=24)

        self._status_var = tk.StringVar(value="Starting…")
        ttk.Label(self, textvariable=self._status_var,
                  style="Subtitle.TLabel").pack(padx=24)

        self._bar = ttk.Progressbar(self, mode="indeterminate", length=360)
        self._bar.pack(pady=20, padx=24)
        self._bar.start(12)

        self._result_var = tk.StringVar()
        self._result_lbl = ttk.Label(self, textvariable=self._result_var, style="TLabel",
                                     wraplength=380, justify="center")
        self._result_lbl.pack(padx=24)

    def update_status(self, msg: str):
        self._status_var.set(msg)
        self.update_idletasks()

    def finish(self, success: bool, message: str):
        self._bar.stop()
        self._bar.configure(mode="determinate", value=100 if success else 0)
        style = "Success.TLabel" if success else "Error.TLabel"
        self._result_lbl.configure(style=style)
        self._result_var.set(message)
        self._status_var.set("Complete" if success else "Failed")

        btn = ttk.Button(self, text="Close", style="Primary.TButton",
                         command=self.destroy)
        btn.pack(pady=12)
        self.update_idletasks()


def card_frame(parent, **kwargs) -> ttk.Frame:
    f = ttk.Frame(parent, style="Card.TFrame", **kwargs)
    return f


def section_label(parent, text: str) -> ttk.Label:
    return ttk.Label(parent, text=text, style="TLabel",
                     font=("Segoe UI", 11, "bold"))


def field_label(parent, text: str) -> ttk.Label:
    return ttk.Label(parent, text=text, style="Subtitle.TLabel")


def entry_field(parent, show=None, **kwargs) -> ttk.Entry:
    e = ttk.Entry(parent, show=show, **kwargs)
    return e


def primary_button(parent, text: str, command, **kwargs) -> ttk.Button:
    return ttk.Button(parent, text=text, command=command,
                      style="Primary.TButton", **kwargs)


def danger_button(parent, text: str, command, **kwargs) -> ttk.Button:
    return ttk.Button(parent, text=text, command=command,
                      style="Danger.TButton", **kwargs)

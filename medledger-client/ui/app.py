"""
ui/app.py - Main application window.
Handles screen navigation and sidebar.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from config import APP_TITLE, WINDOW_W, WINDOW_H
from ui.components.widgets import (
    apply_dark_theme, StatusBar,
    BG_DARK, BG_PANEL, BG_CARD, TEXT_WHITE, TEXT_GRAY, ACCENT, BORDER
)
from ui.screens.login    import LoginScreen
from ui.screens.register import RegisterScreen
from ui.screens.upload   import UploadScreen
from ui.screens.records  import RecordsScreen
from ui.screens.doctor_view import DoctorViewScreen


class App(tk.Tk):

    def __init__(self, orchestrator):
        super().__init__()
        self.orch = orchestrator

        self.title(APP_TITLE)
        self.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.minsize(900, 580)
        self.configure(bg=BG_DARK)

        apply_dark_theme(self)

        self._content_frame = None
        self._sidebar       = None
        self._status_bar    = None
        self._current_screen = None

        # Always start at login — user must enter key passphrase each session
        # to unlock the private key (even if a JWT token was persisted on disk).
        self._show_auth_layout("login")

    # ══════════════════════════════════════════════════════════════════════════
    # Layout builders
    # ══════════════════════════════════════════════════════════════════════════

    def _clear(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._sidebar = None
        self._content_frame = None
        self._status_bar = None

    def _show_auth_layout(self, screen: str):
        self._clear()
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        if screen == "login":
            LoginScreen(
                container,
                orchestrator=self.orch,
                on_success=self._on_login_success,
                on_register=lambda: self._show_auth_layout("register"),
            ).pack(fill="both", expand=True)
        else:
            RegisterScreen(
                container,
                orchestrator=self.orch,
                on_success=self._on_login_success,
                on_back=lambda: self._show_auth_layout("login"),
            ).pack(fill="both", expand=True)

    def _show_main_layout(self):
        self._clear()

        # ── Top bar ───────────────────────────────────────────────────────────
        topbar = ttk.Frame(self, style="Panel.TFrame", height=52)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        ttk.Label(topbar, text="🏥  MedLedger",
                  font=("Segoe UI", 14, "bold"), style="TLabel").pack(
                  side="left", padx=16, pady=12)

        user_info = f"{self.orch.full_name or self.orch.username}  ·  {self.orch.role}"
        ttk.Label(topbar, text=user_info,
                  style="Subtitle.TLabel").pack(side="right", padx=16)

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_bar = StatusBar(self, self.orch, style="Panel.TFrame")
        self._status_bar.pack(fill="x", side="bottom")

        # ── Body (sidebar + content) ──────────────────────────────────────────
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)

        # Sidebar
        self._sidebar = ttk.Frame(body, style="Panel.TFrame", width=200)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)
        self._build_sidebar()

        # Divider
        ttk.Separator(body, orient="vertical").pack(side="left", fill="y")

        # Content
        self._content_frame = ttk.Frame(body)
        self._content_frame.pack(side="left", fill="both", expand=True)

        # Show default screen
        if self.orch.is_patient:
            self._navigate("records")
        else:
            self._navigate("doctor_view")

    def _build_sidebar(self):
        for w in self._sidebar.winfo_children():
            w.destroy()

        ttk.Label(self._sidebar, text="MENU",
                  style="Subtitle.TLabel",
                  font=("Segoe UI", 8, "bold")).pack(
                  anchor="w", padx=20, pady=(20, 8))

        nav_items = []
        if self.orch.is_patient:
            nav_items = [
                ("📋  My Records",  "records"),
                ("⬆  Upload File",  "upload"),
            ]
        else:
            nav_items = [
                ("👁  View Record", "doctor_view"),
            ]

        self._nav_buttons = {}
        for label, screen_name in nav_items:
            btn = ttk.Button(
                self._sidebar,
                text=label,
                style="Nav.TButton",
                command=lambda s=screen_name: self._navigate(s),
            )
            btn.pack(fill="x")
            self._nav_buttons[screen_name] = btn

        # Spacer
        ttk.Frame(self._sidebar, style="Panel.TFrame").pack(fill="both", expand=True)

        # Public key section
        key_frame = ttk.Frame(self._sidebar, style="Panel.TFrame")
        key_frame.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Label(key_frame, text="Your Public Key Hash",
                  style="Subtitle.TLabel", font=("Segoe UI", 8)).pack(anchor="w")
        hash_preview = (self.orch.public_key_hash or "")[:24] + "…"
        def copy_hash():
            self.clipboard_clear()
            self.clipboard_append(self.orch.public_key_hex or "")
            messagebox.showinfo("Copied", "Full public key copied to clipboard.")
        ttk.Label(key_frame, text=hash_preview,
                  style="Subtitle.TLabel", font=("Courier", 8),
                  cursor="hand2").pack(anchor="w")
        ttk.Button(key_frame, text="Copy Key",
                   style="Ghost.TButton", command=copy_hash).pack(
                   anchor="w", pady=(4, 0))

        ttk.Separator(self._sidebar, orient="horizontal").pack(fill="x", padx=12, pady=8)

        # Logout
        ttk.Button(
            self._sidebar,
            text="🚪  Log Out",
            style="Nav.TButton",
            command=self._logout,
        ).pack(fill="x")

    def _navigate(self, screen_name: str):
        # Update sidebar active state
        for name, btn in getattr(self, "_nav_buttons", {}).items():
            btn.configure(style="NavActive.TButton" if name == screen_name else "Nav.TButton")

        # Clear content frame
        for w in self._content_frame.winfo_children():
            w.destroy()

        # Mount correct screen
        screen_map = {
            "records":     lambda: RecordsScreen(self._content_frame, self.orch),
            "upload":      lambda: UploadScreen(self._content_frame, self.orch,
                                                on_uploaded=lambda: self._navigate("records")),
            "doctor_view": lambda: DoctorViewScreen(self._content_frame, self.orch),
        }
        factory = screen_map.get(screen_name)
        if factory:
            widget = factory()
            widget.pack(fill="both", expand=True, padx=24, pady=20)
        self._current_screen = screen_name

    # ══════════════════════════════════════════════════════════════════════════
    # Auth callbacks
    # ══════════════════════════════════════════════════════════════════════════

    def _on_login_success(self, user_info: dict):
        self._show_main_layout()

    def _logout(self):
        if messagebox.askyesno("Log Out", "Are you sure you want to log out?"):
            self.orch.logout()
            self._show_auth_layout("login")

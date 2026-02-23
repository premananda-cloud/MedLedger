"""
ui/screens/login.py - Login screen (simplified — no key passphrase field).
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from ui.components.widgets import (
    ProgressDialog, primary_button,
    BG_DARK, BG_CARD, TEXT_GRAY, ACCENT
)


class LoginScreen(ttk.Frame):

    def __init__(self, parent, orchestrator, on_success, on_register):
        super().__init__(parent)
        self.orch        = orchestrator
        self.on_success  = on_success
        self.on_register = on_register
        self._build()

    def _build(self):
        # ── Left panel ────────────────────────────────────────────────────────
        left = ttk.Frame(self, style="Panel.TFrame", width=300)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        ttk.Label(left, text="🏥", font=("Segoe UI", 52),
                  style="TLabel").pack(pady=(100, 12))
        ttk.Label(left, text="MedLedger",
                  font=("Segoe UI", 24, "bold"), style="TLabel").pack()
        ttk.Label(left, text="Secure Medical Records",
                  style="Subtitle.TLabel").pack(pady=4)

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=40, pady=24)
        ttk.Label(left,
                  text="💾  Your private key is stored\n"
                       "in medledger.db on this device.\n"
                       "It is never sent to the server.",
                  style="Subtitle.TLabel", font=("Segoe UI", 9),
                  justify="center").pack(padx=24)

        # ── Right form ────────────────────────────────────────────────────────
        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True)

        form = ttk.Frame(right)
        form.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(form, text="Welcome back",
                  font=("Segoe UI", 22, "bold"), style="TLabel").grid(
                  row=0, column=0, pady=(0, 4), sticky="w")
        ttk.Label(form, text="Sign in to access your encrypted records.",
                  style="Subtitle.TLabel").grid(
                  row=1, column=0, pady=(0, 24), sticky="w")

        ttk.Label(form, text="Email", style="Subtitle.TLabel").grid(
            row=2, column=0, sticky="w", pady=(0, 2))
        self._email_var = tk.StringVar()
        email_entry = ttk.Entry(form, textvariable=self._email_var, width=36)
        email_entry.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        email_entry.focus()

        ttk.Label(form, text="Password", style="Subtitle.TLabel").grid(
            row=4, column=0, sticky="w", pady=(0, 2))
        self._pw_var = tk.StringVar()
        pw_entry = ttk.Entry(form, textvariable=self._pw_var, show="●", width=36)
        pw_entry.grid(row=5, column=0, sticky="ew", pady=(0, 4))
        pw_entry.bind("<Return>", lambda _: self._submit())

        ttk.Label(form,
                  text="Your private key is loaded automatically from this device.",
                  style="Subtitle.TLabel", font=("Segoe UI", 8),
                  wraplength=300).grid(row=6, column=0, sticky="w", pady=(0, 16))

        primary_button(form, "Sign In", self._submit).grid(
            row=7, column=0, sticky="ew", pady=(0, 8))

        ttk.Button(form, text="Create new account →",
                   style="Ghost.TButton", command=self.on_register).grid(
                   row=8, column=0, sticky="ew")

        ttk.Label(form,
                  text="Tip: if offline, your local session will be restored automatically.",
                  style="Subtitle.TLabel", font=("Segoe UI", 8),
                  wraplength=300).grid(row=9, column=0, pady=(16, 0))

    def _submit(self):
        email = self._email_var.get().strip()
        pw    = self._pw_var.get()
        if not email or not pw:
            messagebox.showerror("Error", "Email and password are required.")
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Signing In")

        def run():
            try:
                dlg.update_status("Authenticating…")
                result = self.orch.login(email=email, password=pw,
                                         on_progress=dlg.update_status)
                dlg.finish(True,
                           f"Welcome, {result.get('full_name') or result.get('username', '')}!")
                self.after(900, lambda: [dlg.destroy(), self.on_success(result)])
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

"""
ui/screens/register.py - User registration screen (simplified — no passphrase).
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from ui.components.widgets import (
    apply_dark_theme, ProgressDialog, card_frame,
    primary_button,
    BG_DARK, BG_CARD, TEXT_WHITE, TEXT_GRAY, ACCENT, BORDER
)


class RegisterScreen(ttk.Frame):

    def __init__(self, parent, orchestrator, on_success, on_back):
        super().__init__(parent)
        self.orch       = orchestrator
        self.on_success = on_success
        self.on_back    = on_back
        self._build()

    def _build(self):
        # ── Left panel ────────────────────────────────────────────────────────
        left = ttk.Frame(self, style="Panel.TFrame", width=300)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        ttk.Label(left, text="🏥", font=("Segoe UI", 48),
                  style="TLabel").pack(pady=(80, 12))
        ttk.Label(left, text="MedLedger",
                  font=("Segoe UI", 22, "bold"), style="TLabel").pack()
        ttk.Label(left, text="Zero-trust medical\nrecord storage",
                  font=("Segoe UI", 11), style="Subtitle.TLabel",
                  justify="center").pack(pady=8)

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=40, pady=20)

        for line in [
            "🔐  Keys generated locally",
            "💾  Private key saved to this device",
            "📄  Files encrypted before upload",
            "🚫  Server never sees plaintext",
        ]:
            ttk.Label(left, text=line, style="Subtitle.TLabel",
                      font=("Segoe UI", 10)).pack(anchor="w", padx=28, pady=3)

        # ── Right form ────────────────────────────────────────────────────────
        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True)

        form = ttk.Frame(right)
        form.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(form, text="Create Account",
                  font=("Segoe UI", 20, "bold"), style="TLabel").grid(
                  row=0, column=0, columnspan=2, pady=(0, 4), sticky="w")
        ttk.Label(form,
                  text="Your private key is generated here and saved to this device.",
                  style="Subtitle.TLabel", wraplength=400).grid(
                  row=1, column=0, columnspan=2, pady=(0, 18), sticky="w")

        fields = [
            ("Full Name",  "full_name",  False),
            ("Username",   "username",   False),
            ("Email",      "email",      False),
            ("Password",   "password",   True),
        ]
        self._vars = {}
        for i, (label, key, secret) in enumerate(fields):
            lr = 2 + i * 2
            ttk.Label(form, text=label, style="Subtitle.TLabel").grid(
                row=lr, column=0, columnspan=2, sticky="w", pady=(8, 1))
            var = tk.StringVar()
            self._vars[key] = var
            e = ttk.Entry(form, textvariable=var,
                          show="●" if secret else "", width=36)
            e.grid(row=lr + 1, column=0, columnspan=2, sticky="ew")
            if i == 0:
                e.focus()

        # Role selector
        row = 2 + len(fields) * 2
        ttk.Label(form, text="Role", style="Subtitle.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(8, 1))
        self._role_var = tk.StringVar(value="patient")
        rf = ttk.Frame(form)
        rf.grid(row=row + 1, column=0, columnspan=2, sticky="ew")
        for val, label in [("patient", "👤  Patient"), ("doctor", "⚕️  Doctor")]:
            ttk.Radiobutton(rf, text=label, value=val,
                            variable=self._role_var).pack(side="left", padx=(0, 20))

        # Key notice
        notice = ttk.Frame(form, style="Card.TFrame")
        notice.grid(row=row + 2, column=0, columnspan=2,
                    sticky="ew", pady=(14, 0))
        ttk.Label(notice,
                  text="🔑  A unique encryption key will be generated and saved\n"
                       "    to this device. Keep medledger.db safe — it holds your key.",
                  style="Subtitle.TLabel", font=("Segoe UI", 9),
                  justify="left").pack(padx=12, pady=8)

        # Buttons
        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=row + 3, column=0, columnspan=2,
                       pady=(14, 0), sticky="ew")
        primary_button(btn_frame, "Create Account & Generate Key",
                       self._submit).pack(fill="x", pady=(0, 8))
        ttk.Button(btn_frame, text="← Back to Login",
                   style="Ghost.TButton", command=self.on_back).pack(fill="x")

    def _submit(self):
        v = {k: var.get().strip() for k, var in self._vars.items()}

        if not all([v["full_name"], v["username"], v["email"], v["password"]]):
            messagebox.showerror("Validation Error",
                                 "Full name, username, email, and password are required.")
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Creating Account")

        def run():
            try:
                result = self.orch.register(
                    username=v["username"],
                    email=v["email"],
                    full_name=v["full_name"],
                    role=self._role_var.get(),
                    password=v["password"],
                    on_progress=dlg.update_status,
                )
                dlg.finish(True,
                           f"Account created!\n"
                           f"User ID: {result['user_id']}\n\n"
                           f"Your private key is stored in:\n"
                           f"medledger-client/keys/medledger.db")
                self.after(1800, lambda: [dlg.destroy(), self.on_success(result)])
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

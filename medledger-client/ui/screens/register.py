"""
ui/screens/register.py - User registration screen.
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from ui.components.widgets import (
    apply_dark_theme, ProgressDialog, card_frame,
    section_label, field_label, entry_field, primary_button,
    BG_DARK, BG_CARD, TEXT_WHITE, TEXT_GRAY, ACCENT, BORDER
)


class RegisterScreen(ttk.Frame):

    def __init__(self, parent, orchestrator, on_success, on_back):
        super().__init__(parent)
        self.orch       = orchestrator
        self.on_success = on_success   # callback(user_info_dict)
        self.on_back    = on_back      # callback()
        self._build()

    def _build(self):
        # ── Left decorative panel ─────────────────────────────────────────────
        left = ttk.Frame(self, style="Panel.TFrame", width=320)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        ttk.Label(left, text="🏥", font=("Segoe UI", 48),
                  style="TLabel").pack(pady=(80, 12))
        ttk.Label(left, text="MedLedger",
                  font=("Segoe UI", 22, "bold"), style="TLabel").pack()
        ttk.Label(left, text="Zero-trust medical\nrecord storage",
                  font=("Segoe UI", 11), style="Subtitle.TLabel",
                  justify="center").pack(pady=8)

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=40, pady=24)

        for line in ["🔐 Keys generated locally",
                     "📄 Files encrypted before upload",
                     "🔗 Tamper-evident audit trail",
                     "🚫 Server never sees plaintext"]:
            ttk.Label(left, text=line, style="Subtitle.TLabel",
                      font=("Segoe UI", 10)).pack(anchor="w", padx=32, pady=3)

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=40, pady=16)
        ttk.Label(left,
                  text="🔑 Key Passphrase encrypts your\nprivate key on disk.\nRemember it — it cannot be\nrecovered if lost.",
                  style="Subtitle.TLabel", font=("Segoe UI", 9),
                  justify="center").pack(padx=24)

        # ── Right form panel ──────────────────────────────────────────────────
        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True)

        form = ttk.Frame(right)
        form.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(form, text="Create Account",
                  font=("Segoe UI", 20, "bold"), style="TLabel").grid(
                  row=0, column=0, columnspan=2, pady=(0, 4), sticky="w")
        ttk.Label(form, text="Your private key is generated here and never leaves this device.",
                  style="Subtitle.TLabel", wraplength=400).grid(
                  row=1, column=0, columnspan=2, pady=(0, 20), sticky="w")

        # Fields
        fields = [
            ("Full Name",      "full_name",      False),
            ("Username",       "username",       False),
            ("Email",          "email",          False),
            ("Phone",          "phone",          False),
            ("Password",       "password",       True),
            ("Key Passphrase", "key_passphrase", True),
        ]
        self._vars = {}
        for i, (label, key, secret) in enumerate(fields):
            label_row = 2 + i * 2
            entry_row = label_row + 1
            ttk.Label(form, text=label, style="Subtitle.TLabel").grid(
                row=label_row, column=0, columnspan=2, sticky="w", pady=(8, 1))
            var = tk.StringVar()
            self._vars[key] = var
            e = ttk.Entry(form, textvariable=var, show="●" if secret else "",
                          width=36)
            e.grid(row=entry_row, column=0, columnspan=2, sticky="ew")
            if i == 0:
                e.focus()

        # Role selector
        row = 2 + len(fields) * 2
        ttk.Label(form, text="Role", style="Subtitle.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(8, 1))
        self._role_var = tk.StringVar(value="patient")
        role_frame = ttk.Frame(form)
        role_frame.grid(row=row+1, column=0, columnspan=2, sticky="ew")
        for val, label in [("patient", "👤  Patient"), ("doctor", "⚕️  Doctor")]:
            ttk.Radiobutton(role_frame, text=label, value=val,
                            variable=self._role_var).pack(side="left", padx=(0, 20))

        # Buttons
        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=row+2, column=0, columnspan=2, pady=(20, 0), sticky="ew")

        primary_button(btn_frame, "Create Account & Generate Keys",
                       self._submit).pack(fill="x", pady=(0, 8))
        ttk.Button(btn_frame, text="← Back to Login",
                   style="Ghost.TButton", command=self.on_back).pack(fill="x")

    def _submit(self):
        v = {k: var.get().strip() for k, var in self._vars.items()}

        if not all([v["full_name"], v["username"], v["email"], v["password"]]):
            messagebox.showerror("Validation Error",
                                 "Full name, username, email, and password are required.")
            return

        if not v.get("key_passphrase"):
            messagebox.showerror("Validation Error",
                                 "Key Passphrase is required.\n\n"
                                 "It encrypts your private key on this device. "
                                 "Choose something memorable — it cannot be recovered if lost.")
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
                    key_passphrase=v["key_passphrase"],
                    on_progress=dlg.update_status,
                )
                dlg.finish(True, f"Account created! User ID: {result['user_id']}")
                self.after(1200, lambda: [dlg.destroy(), self.on_success(result)])
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

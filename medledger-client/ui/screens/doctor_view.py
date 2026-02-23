"""
ui/screens/doctor_view.py - Doctor's record viewer screen.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from ui.components.widgets import (
    ProgressDialog, card_frame, primary_button, TEXT_GRAY
)


class DoctorViewScreen(ttk.Frame):
    """
    Doctor enters a record_id and the patient's public key hex,
    then downloads and decrypts the record if permission exists.
    """

    def __init__(self, parent, orchestrator):
        super().__init__(parent)
        self.orch = orchestrator
        self._build()

    def _build(self):
        ttk.Label(self, text="View Patient Record",
                  font=("Segoe UI", 18, "bold"), style="TLabel").pack(
                  anchor="w", pady=(0, 4))
        ttk.Label(self,
                  text="Enter the Record ID and patient's public key. "
                       "The server verifies your permission before releasing the encrypted file.",
                  style="Subtitle.TLabel", wraplength=640).pack(anchor="w", pady=(0, 20))

        form = card_frame(self)
        form.pack(fill="x", pady=(0, 16))
        inner = ttk.Frame(form, style="Card.TFrame")
        inner.pack(fill="x", padx=20, pady=16)

        # Record ID
        ttk.Label(inner, text="Record ID", style="Subtitle.TLabel").pack(anchor="w")
        self._record_id_var = tk.StringVar()
        ttk.Entry(inner, textvariable=self._record_id_var, width=72).pack(
            fill="x", pady=(2, 12))

        # Patient public key
        ttk.Label(inner, text="Patient's Public Key (hex)",
                  style="Subtitle.TLabel").pack(anchor="w")
        self._patient_key_var = tk.StringVar()
        ttk.Entry(inner, textvariable=self._patient_key_var, width=72).pack(
            fill="x", pady=(2, 0))

        ttk.Label(inner,
                  text="Ask the patient to share their public key from their MedLedger app.",
                  style="Subtitle.TLabel", font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))

        # Action row
        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 0))

        primary_button(actions, "⬇  Download & Decrypt Record",
                       self._fetch).pack(side="left")

        # ── Doctor's own public key display (for sharing with patients) ───────
        info_card = card_frame(self)
        info_card.pack(fill="x", pady=(20, 0))
        ic_inner = ttk.Frame(info_card, style="Card.TFrame")
        ic_inner.pack(fill="x", padx=16, pady=12)

        ttk.Label(ic_inner, text="Your Public Key (share with patients to grant access)",
                  style="Subtitle.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        pub_key = self.orch.public_key_hex or "Not available — please log in again"
        ttk.Label(ic_inner, text=pub_key[:64] + ("…" if len(pub_key) > 64 else ""),
                  style="Card.TLabel", font=("Courier", 9),
                  wraplength=600).pack(anchor="w", pady=(4, 6))

        ttk.Label(ic_inner, text=f"User ID: {self.orch.user_id}",
                  style="Subtitle.TLabel").pack(anchor="w")

        def copy_pubkey():
            self.clipboard_clear()
            self.clipboard_append(self.orch.public_key_hex or "")
            messagebox.showinfo("Copied", "Public key copied to clipboard.")
        ttk.Button(ic_inner, text="Copy Full Key",
                   style="Ghost.TButton", command=copy_pubkey).pack(
                   anchor="w", pady=(6, 0))

    def _fetch(self):
        record_id  = self._record_id_var.get().strip()
        patient_key = self._patient_key_var.get().strip()

        if not record_id:
            messagebox.showerror("Error", "Record ID is required.")
            return
        if not patient_key:
            messagebox.showerror("Error", "Patient's public key is required.")
            return

        # Ask where to save
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted record as",
            initialfile="patient_record",
        )
        if not save_path:
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Fetching & Decrypting")

        def run():
            try:
                result_path = self.orch.doctor_download_and_decrypt(
                    record_id=record_id,
                    patient_public_key_hex=patient_key,
                    save_path=save_path,
                    on_progress=dlg.update_status,
                )
                dlg.finish(True, f"File saved to:\n{result_path}")
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

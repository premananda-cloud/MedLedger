"""
ui/screens/upload.py - File upload and encryption screen.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from config import SUPPORTED_EXTENSIONS
from ui.components.widgets import (
    ProgressDialog, card_frame, section_label,
    primary_button, BG_CARD, TEXT_GRAY, SUCCESS, DANGER, TEXT_WHITE
)


class UploadScreen(ttk.Frame):

    def __init__(self, parent, orchestrator, on_uploaded):
        super().__init__(parent)
        self.orch        = orchestrator
        self.on_uploaded = on_uploaded   # callback() to refresh records list
        self._selected_path = None
        self._build()

    def _build(self):
        ttk.Label(self, text="Upload Medical Record",
                  font=("Segoe UI", 18, "bold"), style="TLabel").pack(
                  anchor="w", pady=(0, 4))
        ttk.Label(self,
                  text="Files are hashed, signed, and encrypted before leaving your device.",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(0, 20))

        # ── Drop zone / file picker ───────────────────────────────────────────
        drop = card_frame(self)
        drop.pack(fill="x", pady=(0, 16))

        inner = ttk.Frame(drop, style="Card.TFrame")
        inner.pack(padx=24, pady=24)

        ttk.Label(inner, text="📂", font=("Segoe UI", 36),
                  style="Card.TLabel").pack()
        ttk.Label(inner, text="Select a file to encrypt and upload",
                  style="Card.TLabel", font=("Segoe UI", 12)).pack(pady=4)
        ttk.Label(inner, text="Supported: PDF · JPEG · PNG · DICOM",
                  style="Subtitle.TLabel").pack()

        ttk.Button(inner, text="Browse File…",
                   style="Ghost.TButton", command=self._pick_file).pack(pady=(12, 0))

        # ── Selected file display ─────────────────────────────────────────────
        self._file_var = tk.StringVar(value="No file selected")
        file_card = card_frame(self)
        file_card.pack(fill="x", pady=(0, 16))

        fc_inner = ttk.Frame(file_card, style="Card.TFrame")
        fc_inner.pack(fill="x", padx=16, pady=12)
        ttk.Label(fc_inner, text="Selected file:", style="Subtitle.TLabel").pack(
            anchor="w")
        ttk.Label(fc_inner, textvariable=self._file_var,
                  style="Card.TLabel", font=("Segoe UI", 10, "bold"),
                  wraplength=600).pack(anchor="w", pady=(2, 0))

        # ── Encryption steps display ──────────────────────────────────────────
        steps_card = card_frame(self)
        steps_card.pack(fill="x", pady=(0, 20))

        sc_inner = ttk.Frame(steps_card, style="Card.TFrame")
        sc_inner.pack(fill="x", padx=16, pady=12)
        ttk.Label(sc_inner, text="What happens when you upload:",
                  style="Subtitle.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w")

        steps = [
            ("1", "SHA-256 hash computed from original file"),
            ("2", "Hash signed with your private key (ECDSA)"),
            ("3", "Random 256-bit Data Encryption Key (DEK) generated"),
            ("4", "File encrypted with DEK using AES-256-GCM"),
            ("5", "DEK encrypted with your public key (ECIES)"),
            ("6", "Encrypted blob + encrypted DEK sent to server"),
        ]
        for num, desc in steps:
            row = ttk.Frame(sc_inner, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f" {num} ", style="Card.TLabel",
                      background="#1a73e8", foreground="white",
                      font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 8))
            ttk.Label(row, text=desc, style="Card.TLabel",
                      font=("Segoe UI", 9)).pack(side="left")

        # ── Upload button ─────────────────────────────────────────────────────
        self._upload_btn = primary_button(
            self, "🔐  Encrypt & Upload", self._upload)
        self._upload_btn.pack(fill="x")
        self._upload_btn.state(["disabled"])

    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Select medical record",
            filetypes=SUPPORTED_EXTENSIONS,
        )
        if path:
            self._selected_path = path
            p = Path(path)
            size_kb = p.stat().st_size / 1024
            self._file_var.set(f"{p.name}  ({size_kb:.1f} KB)  —  {p.parent}")
            self._upload_btn.state(["!disabled"])

    def _upload(self):
        if not self._selected_path:
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Encrypting & Uploading")

        def run():
            try:
                result = self.orch.upload_file(
                    file_path=self._selected_path,
                    on_progress=dlg.update_status,
                )
                status = "Queued (offline)" if result.get("offline") else "Uploaded ✓"
                dlg.finish(True, f"{status}\nRecord ID: {result.get('record_id', 'N/A')}")
                self._selected_path = None
                self._file_var.set("No file selected")
                self._upload_btn.state(["disabled"])
                self.after(1500, lambda: [dlg.destroy(), self.on_uploaded()])
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

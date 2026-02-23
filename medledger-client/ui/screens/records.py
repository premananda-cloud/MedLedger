"""
ui/screens/records.py - Patient records list with download and grant-access actions.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path

from ui.components.widgets import (
    ProgressDialog, card_frame, primary_button, danger_button,
    BG_CARD, TEXT_GRAY, TEXT_WHITE, SUCCESS, WARNING
)


class RecordsScreen(ttk.Frame):

    def __init__(self, parent, orchestrator):
        super().__init__(parent)
        self.orch    = orchestrator
        self._records = []
        self._build()
        self.refresh()

    def _build(self):
        # ── Header ────────────────────────────────────────────────────────────
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 16))

        ttk.Label(header, text="My Medical Records",
                  font=("Segoe UI", 18, "bold"), style="TLabel").pack(side="left")
        ttk.Button(header, text="⟳  Refresh",
                   style="Ghost.TButton", command=self.refresh).pack(side="right")

        # ── Records table ─────────────────────────────────────────────────────
        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True)

        cols = ("filename", "content_type", "hash_preview", "created_at", "status")
        self._tree = ttk.Treeview(table_frame, columns=cols,
                                  show="headings", selectmode="browse")

        headers = {
            "filename":      ("File Name",      200),
            "content_type":  ("Type",           100),
            "hash_preview":  ("SHA-256 (preview)", 140),
            "created_at":    ("Uploaded",        140),
            "status":        ("Status",           80),
        }
        for col, (heading, width) in headers.items():
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical",
                            command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # ── Action buttons ────────────────────────────────────────────────────
        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 0))

        primary_button(actions, "⬇  Download & Decrypt",
                       self._download).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="🔓  Grant Doctor Access",
                   style="Ghost.TButton",
                   command=self._grant_access).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="📋  View Permissions",
                   style="Ghost.TButton",
                   command=self._view_permissions).pack(side="left")

        self._status_lbl = ttk.Label(actions, text="", style="Subtitle.TLabel")
        self._status_lbl.pack(side="right")

    def refresh(self):
        self._status_lbl.configure(text="Loading…")
        self._tree.delete(*self._tree.get_children())

        def run():
            try:
                self._records = self.orch.list_records()
                self.after(0, self._populate)
            except Exception as exc:
                self.after(0, lambda: self._status_lbl.configure(
                    text=f"Error: {exc}"))

        threading.Thread(target=run, daemon=True).start()

    def _populate(self):
        self._tree.delete(*self._tree.get_children())
        for rec in self._records:
            filename   = rec.get("filename") or rec.get("original_filename", "—")
            ctype      = rec.get("content_type", "—")
            chash      = rec.get("content_hash", "")
            preview    = chash[:16] + "…" if chash else "—"
            created    = str(rec.get("created_at", ""))[:16]
            status     = "⚠ offline" if rec.get("offline") else "✓ synced"
            self._tree.insert("", "end",
                              iid=rec.get("record_id") or rec.get("local_id"),
                              values=(filename, ctype, preview, created, status))
        count = len(self._records)
        self._status_lbl.configure(text=f"{count} record{'s' if count != 1 else ''}")

    def _selected_record(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select a record", "Please select a record first.")
            return None
        record_id = sel[0]
        return next((r for r in self._records
                     if str(r.get("record_id") or r.get("local_id")) == record_id), None)

    def _download(self):
        rec = self._selected_record()
        if not rec:
            return
        if rec.get("offline"):
            messagebox.showinfo("Offline record",
                                "This record hasn't synced yet. Connect to server and refresh.")
            return

        filename = rec.get("filename") or rec.get("original_filename", "record")
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=filename,
        )
        if not save_path:
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Downloading & Decrypting")

        def run():
            try:
                result_path = self.orch.download_and_decrypt(
                    record_id=rec["record_id"],
                    save_path=save_path,
                    on_progress=dlg.update_status,
                )
                dlg.finish(True, f"Saved to:\n{result_path}")
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()

    def _grant_access(self):
        rec = self._selected_record()
        if not rec:
            return
        if rec.get("offline"):
            messagebox.showinfo("Offline", "Cannot grant access to unsynced records.")
            return

        dlg = _GrantAccessDialog(self.winfo_toplevel(), self.orch, rec)
        self.wait_window(dlg)

    def _view_permissions(self):
        rec = self._selected_record()
        if not rec:
            return
        _PermissionsDialog(self.winfo_toplevel(), self.orch, rec)


# ── Grant Access Dialog ───────────────────────────────────────────────────────

class _GrantAccessDialog(tk.Toplevel):

    def __init__(self, parent, orchestrator, record):
        super().__init__(parent)
        self.orch   = orchestrator
        self.record = record
        self.title("Grant Doctor Access")
        self.configure(bg="#1e2330")
        self.resizable(False, False)
        self.grab_set()

        w, h = 460, 340
        px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

        self._build()

    def _build(self):
        ttk.Label(self, text="Grant Doctor Access",
                  font=("Segoe UI", 16, "bold"), style="TLabel").pack(
                  pady=(20, 4), padx=24, anchor="w")

        filename = self.record.get("filename") or self.record.get("original_filename", "")
        ttk.Label(self, text=f"Record: {filename}",
                  style="Subtitle.TLabel").pack(padx=24, anchor="w")
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=24, pady=12)

        form = ttk.Frame(self)
        form.pack(fill="x", padx=24)

        ttk.Label(form, text="Doctor's User ID", style="Subtitle.TLabel").pack(anchor="w")
        self._doctor_id_var = tk.StringVar()
        ttk.Entry(form, textvariable=self._doctor_id_var, width=36).pack(
            fill="x", pady=(2, 10))

        ttk.Label(form, text="Access duration (hours)",
                  style="Subtitle.TLabel").pack(anchor="w")
        self._hours_var = tk.StringVar(value="24")
        ttk.Entry(form, textvariable=self._hours_var, width=12).pack(
            anchor="w", pady=(2, 10))

        ttk.Label(form, text="Permission level", style="Subtitle.TLabel").pack(anchor="w")
        self._level_var = tk.StringVar(value="view_only")
        frame = ttk.Frame(form)
        frame.pack(anchor="w", pady=(2, 16))
        for val, label in [("view_only", "View only"), ("view_download", "View & download")]:
            ttk.Radiobutton(frame, text=label, value=val,
                            variable=self._level_var).pack(side="left", padx=(0, 16))

        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", padx=24, pady=(0, 16))
        primary_button(btn_row, "Grant Access", self._submit).pack(
            side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", style="Ghost.TButton",
                   command=self.destroy).pack(side="left")

    def _submit(self):
        try:
            doctor_id = int(self._doctor_id_var.get().strip())
            hours     = int(self._hours_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Doctor ID must be a number and hours must be an integer.")
            return

        dlg = ProgressDialog(self.winfo_toplevel(), "Granting Access")

        def run():
            try:
                result = self.orch.grant_doctor_access(
                    record_id=self.record["record_id"],
                    doctor_id=doctor_id,
                    time_window_hours=hours,
                    permission_level=self._level_var.get(),
                    on_progress=dlg.update_status,
                )
                dlg.finish(True,
                           f"Access granted ✓\nPermission ID: {result.get('permission_id')}")
                self.after(1500, lambda: [dlg.destroy(), self.destroy()])
            except Exception as exc:
                dlg.finish(False, str(exc))

        threading.Thread(target=run, daemon=True).start()


# ── Permissions Dialog ────────────────────────────────────────────────────────

class _PermissionsDialog(tk.Toplevel):

    def __init__(self, parent, orchestrator, record):
        super().__init__(parent)
        self.orch   = orchestrator
        self.record = record
        self.title("Active Permissions")
        self.configure(bg="#1e2330")
        self.grab_set()

        w, h = 680, 380
        px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

        self._build()
        self._load()

    def _build(self):
        ttk.Label(self, text="Active Permissions",
                  font=("Segoe UI", 16, "bold"), style="TLabel").pack(
                  pady=(20, 4), padx=24, anchor="w")
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=24, pady=8)

        cols = ("perm_id", "grantee_hash", "valid_until", "active")
        self._tree = ttk.Treeview(self, columns=cols, show="headings",
                                  selectmode="browse")
        self._tree.heading("perm_id",      text="Permission ID")
        self._tree.heading("grantee_hash", text="Grantee Key Hash")
        self._tree.heading("valid_until",  text="Expires")
        self._tree.heading("active",       text="Status")
        self._tree.column("perm_id",      width=280)
        self._tree.column("grantee_hash", width=140)
        self._tree.column("valid_until",  width=140)
        self._tree.column("active",       width=80)
        self._tree.pack(fill="both", expand=True, padx=24)

        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", padx=24, pady=12)
        danger_button(btn_row, "🚫  Revoke Selected", self._revoke).pack(side="left")
        ttk.Button(btn_row, text="Close", style="Ghost.TButton",
                   command=self.destroy).pack(side="right")

    def _load(self):
        self._tree.delete(*self._tree.get_children())
        perms = self.orch.list_my_permissions()
        for p in perms:
            if p.get("record_id") != self.record.get("record_id"):
                continue
            status = "revoked" if p.get("is_revoked") else ("active" if p.get("is_active") else "inactive")
            self._tree.insert("", "end", iid=p["permission_id"],
                              values=(
                                  p["permission_id"],
                                  p.get("grantee_public_key_hash", "")[:20] + "…",
                                  str(p.get("valid_until", ""))[:16],
                                  status,
                              ))

    def _revoke(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a permission to revoke.")
            return
        perm_id = sel[0]
        if not messagebox.askyesno("Confirm Revoke",
                                   f"Revoke permission:\n{perm_id}\n\nThe doctor will immediately lose access."):
            return
        try:
            self.orch.revoke_permission(perm_id)
            messagebox.showinfo("Revoked", "Permission revoked successfully.")
            self._load()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

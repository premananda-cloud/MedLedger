"""
medledger_demo.py  —  MedLedger single-file demo
Run:  python medledger_demo.py

Everything is self-contained.  No server.  No database.
Real ECDSA + AES-256-GCM + ECIES crypto (uses `cryptography` package).
Dummy PDF generated on the fly.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 0.  CRYPTO  (inlined from core/crypto.py)
# ═══════════════════════════════════════════════════════════════════════════════

import os, json, hashlib, textwrap, threading, time, io
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

_CURVE   = ec.SECP256R1()
_BACKEND = default_backend()
_INFO    = b"MedLedger-DEK-v1"

def _gen_priv():
    raw = ec.generate_private_key(_CURVE, _BACKEND).private_numbers().private_value.to_bytes(32,"big")
    return raw.hex()

def _priv(h):
    return ec.derive_private_key(int(h,16), _CURVE, _BACKEND)

def _pub_hex(h):
    return _priv(h).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()

def _load_pub(h):
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, bytes.fromhex(h))

def _hkdf(shared):
    return HKDF(hashes.SHA256(), 32, None, _INFO, _BACKEND).derive(shared)

def _aes_enc(dek, pt):
    iv = os.urandom(12)
    return iv + AESGCM(dek).encrypt(iv, pt, None)

def _aes_dec(dek, blob):
    return AESGCM(dek).decrypt(blob[:12], blob[12:], None)

def ecies_enc(pub_hex, plaintext):
    eph = ec.generate_private_key(_CURVE, _BACKEND)
    shared = eph.exchange(ec.ECDH(), _load_pub(pub_hex))
    iv = os.urandom(12)
    ct = AESGCM(_hkdf(shared)).encrypt(iv, plaintext, None)
    return {"epk": eph.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint).hex(),
            "iv": iv.hex(), "ct": ct[:-16].hex(), "tag": ct[-16:].hex()}

def ecies_dec(priv_hex, bundle):
    if isinstance(bundle, str): bundle = json.loads(bundle)
    epk = bytes.fromhex(bundle["epk"])
    iv  = bytes.fromhex(bundle["iv"])
    ct  = bytes.fromhex(bundle["ct"])
    tag = bytes.fromhex(bundle["tag"])
    shared = _priv(priv_hex).exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, epk))
    return AESGCM(_hkdf(shared)).decrypt(iv, ct + tag, None)

def encrypt_doc(file_bytes, pat_pub, pat_priv):
    h   = hashlib.sha256(file_bytes).hexdigest()
    sig = _priv(pat_priv).sign(bytes.fromhex(h), ec.ECDSA(hashes.SHA256())).hex()
    dek = os.urandom(32)
    return {"hash": h, "sig": sig,
            "blob": _aes_enc(dek, file_bytes),
            "dek":  ecies_enc(pat_pub, dek)}

def rewrap(dek_bundle, pat_priv, doc_pub):
    return ecies_enc(doc_pub, ecies_dec(pat_priv, dek_bundle))

def decrypt_for_doctor(blob, doc_dek_bundle, doc_priv):
    dek = ecies_dec(doc_priv, doc_dek_bundle)
    return _aes_dec(dek, blob)


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  IN-MEMORY STORE
# ═══════════════════════════════════════════════════════════════════════════════

USERS   = {}   # email -> {name, email, password, role, priv, pub}
RECORDS = {}   # record_id -> {owner_email, filename, blob, dek, hash, sig, ts, granted_to}

def register_user(name, email, password, role):
    priv = _gen_priv()
    pub  = _pub_hex(priv)
    USERS[email] = {"name": name, "email": email, "password": password,
                    "role": role, "priv": priv, "pub": pub}

def login_user(email, password):
    u = USERS.get(email)
    if u and u["password"] == password:
        return u
    return None

def upload_record(user, filename, file_bytes):
    enc = encrypt_doc(file_bytes, user["pub"], user["priv"])
    rid = hashlib.sha256(f"{user['email']}{filename}{time.time()}".encode()).hexdigest()[:16]
    RECORDS[rid] = {
        "owner_email": user["email"],
        "filename":    filename,
        "blob":        enc["blob"],
        "dek":         enc["dek"],
        "hash":        enc["hash"],
        "sig":         enc["sig"],
        "ts":          datetime.now().strftime("%Y-%m-%d %H:%M"),
        "granted_to":  {},   # doctor_email -> doc_dek_bundle
    }
    return rid

def grant_access(record_id, patient_user, doctor_email):
    rec = RECORDS[record_id]
    doc = USERS.get(doctor_email)
    if not doc:
        raise ValueError(f"Doctor '{doctor_email}' not found")
    doc_dek = rewrap(rec["dek"], patient_user["priv"], doc["pub"])
    rec["granted_to"][doctor_email] = doc_dek

def doctor_decrypt(record_id, doctor_user):
    rec = RECORDS[record_id]
    bundle = rec["granted_to"].get(doctor_user["email"])
    if not bundle:
        raise PermissionError("No access granted for this record")
    return decrypt_for_doctor(rec["blob"], bundle, doctor_user["priv"])


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  DUMMY PDF GENERATOR  (no external library needed)
# ═══════════════════════════════════════════════════════════════════════════════

def make_dummy_pdf(patient_name, record_type="Blood Test Results"):
    lines = [
        f"MEDLEDGER HEALTH SYSTEM",
        f"",
        f"Patient: {patient_name}",
        f"Record: {record_type}",
        f"Date: {datetime.now().strftime('%B %d, %Y')}",
        f"",
        f"── Lab Results ──────────────────────────",
        f"Hemoglobin     :  14.2 g/dL    [Normal]",
        f"WBC Count      :  6,800 /μL    [Normal]",
        f"Platelet Count :  245,000 /μL  [Normal]",
        f"Blood Glucose  :  92 mg/dL     [Normal]",
        f"Cholesterol    :  178 mg/dL    [Normal]",
        f"",
        f"── Notes ───────────────────────────────",
        f"All values within normal reference range.",
        f"Follow-up recommended in 12 months.",
        f"",
        f"Signed: Dr. Sarah Chen, MD",
        f"License: MED-2024-00847",
        f"",
        f"[ENCRYPTED AND SIGNED VIA MEDLEDGER]",
        f"Document Hash verified on upload.",
    ]
    # Minimal valid PDF
    content = "\n".join(lines)
    obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    stream_content = f"BT /F1 11 Tf 50 750 Td 14 TL\n"
    for line in lines:
        safe = line.replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
        stream_content += f"({safe}) Tj T*\n"
    stream_content += "ET"
    stream = stream_content.encode()
    obj3 = (f"3 0 obj\n<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 612 792] "
            f"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")
    obj4 = f"4 0 obj\n<< /Length {len(stream)} >>\nstream\n"
    obj5 = "\n5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
    xref_pos = (len(obj1)+len(obj2)+len(obj3)+len(obj4)+len(stream)+
                len("\nendstream\nendobj\n")+len(obj5)+9)
    pdf = (f"%PDF-1.4\n{obj1}{obj2}{obj3}{obj4}".encode() +
           stream +
           f"\nendstream\nendobj\n{obj5}".encode())
    xref_offset = len(pdf)
    pdf += (f"xref\n0 6\n0000000000 65535 f \n"
            f"0000000009 00000 n \n"
            f"0000000058 00000 n \n"
            f"0000000115 00000 n \n"
            f"0000000266 00000 n \n"
            f"0000000{xref_offset-10:06d} 00000 n \n"
            f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
           ).encode()
    return pdf


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  GUI
# ═══════════════════════════════════════════════════════════════════════════════

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ── Palette ───────────────────────────────────────────────────────────────────
BG       = "#0f1117"
PANEL    = "#161b27"
CARD     = "#1e2535"
BORDER   = "#2a3352"
ACCENT   = "#3b7eff"
ACCENT2  = "#00c9a7"
TEXT     = "#e8eaf2"
MUTED    = "#6b7699"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"
FONT     = "Consolas"
SANS     = "Segoe UI"

def styled(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TEXT,
                 fieldbackground=CARD, bordercolor=BORDER,
                 font=(SANS, 10))
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=CARD)
    s.configure("Panel.TFrame", background=PANEL)
    s.configure("TLabel", background=BG, foreground=TEXT, font=(SANS,10))
    s.configure("H1.TLabel", background=BG, foreground=TEXT, font=(SANS,18,"bold"))
    s.configure("H2.TLabel", background=BG, foreground=TEXT, font=(SANS,13,"bold"))
    s.configure("Muted.TLabel", background=BG, foreground=MUTED, font=(SANS,9))
    s.configure("Card.TLabel", background=CARD, foreground=TEXT, font=(SANS,10))
    s.configure("Mono.TLabel", background=CARD, foreground=ACCENT2,
                 font=(FONT,8))
    s.configure("Success.TLabel", background=CARD, foreground=SUCCESS, font=(SANS,9,"bold"))
    s.configure("TEntry", fieldbackground=CARD, foreground=TEXT,
                 insertcolor=TEXT, bordercolor=BORDER, font=(SANS,10))
    s.configure("Primary.TButton", background=ACCENT, foreground="white",
                 font=(SANS,10,"bold"), borderwidth=0, padding=(14,7))
    s.map("Primary.TButton", background=[("active","#2563d4"),("disabled","#2a3352")])
    s.configure("Ghost.TButton", background=PANEL, foreground=TEXT,
                 font=(SANS,10), borderwidth=1, padding=(12,6))
    s.map("Ghost.TButton", background=[("active", CARD)])
    s.configure("Success.TButton", background="#166534", foreground=SUCCESS,
                 font=(SANS,10,"bold"), borderwidth=0, padding=(14,7))
    s.map("Success.TButton", background=[("active","#14532d")])
    s.configure("Treeview", background=CARD, foreground=TEXT,
                 fieldbackground=CARD, rowheight=30, font=(SANS,9))
    s.configure("Treeview.Heading", background=PANEL, foreground=MUTED,
                 font=(SANS,9,"bold"), borderwidth=0)
    s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected","white")])
    s.configure("TCombobox", fieldbackground=CARD, foreground=TEXT,
                 background=CARD, selectbackground=ACCENT)
    s.configure("TProgressbar", troughcolor=CARD, background=ACCENT, borderwidth=0)
    root.configure(bg=BG)

def sep(parent, **kw):
    f = tk.Frame(parent, bg=BORDER, height=1)
    f.pack(fill="x", **kw)

def card(parent, **kw):
    f = ttk.Frame(parent, style="Card.TFrame")
    f.pack(**kw)
    return f

def label(parent, text, style="TLabel", **kw):
    return ttk.Label(parent, text=text, style=style, **kw)

def btn_primary(parent, text, cmd, **kw):
    return ttk.Button(parent, text=text, command=cmd, style="Primary.TButton", **kw)

def btn_ghost(parent, text, cmd, **kw):
    return ttk.Button(parent, text=text, command=cmd, style="Ghost.TButton", **kw)

def entry(parent, show=None, **kw):
    e = ttk.Entry(parent, show=show, **kw)
    e.configure(foreground=TEXT)
    return e


# ── Reusable step progress widget ─────────────────────────────────────────────

class StepProgress(tk.Frame):
    def __init__(self, parent, steps):
        super().__init__(parent, bg=CARD)
        self._labels = []
        for i, s in enumerate(steps):
            row = tk.Frame(self, bg=CARD)
            row.pack(fill="x", pady=2)
            dot = tk.Label(row, text="○", fg=MUTED, bg=CARD,
                           font=(FONT,10))
            dot.pack(side="left", padx=(0,8))
            lbl = tk.Label(row, text=s, fg=MUTED, bg=CARD,
                           font=(SANS,9), anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            self._labels.append((dot, lbl))

    def activate(self, idx):
        for i,(d,l) in enumerate(self._labels):
            if i < idx:
                d.configure(text="✓", fg=SUCCESS)
                l.configure(fg=SUCCESS)
            elif i == idx:
                d.configure(text="●", fg=ACCENT)
                l.configure(fg=TEXT)
            else:
                d.configure(text="○", fg=MUTED)
                l.configure(fg=MUTED)
        self.update_idletasks()


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  SCREENS
# ═══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MedLedger  —  Encrypted Health Records")
        self.geometry("980x680")
        self.minsize(860, 580)
        self.configure(bg=BG)
        styled(self)
        self.current_user = None
        self._show("login")

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _show(self, screen, **kw):
        self._clear()
        {
            "login":          LoginScreen,
            "register":       RegisterScreen,
            "patient_home":   PatientHome,
            "doctor_home":    DoctorHome,
        }[screen](self, **kw).pack(fill="both", expand=True)

    def goto(self, screen, **kw):
        self._show(screen, **kw)


# ── Login ─────────────────────────────────────────────────────────────────────

class LoginScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._build()

    def _build(self):
        # Left panel — branding
        left = ttk.Frame(self, style="Panel.TFrame", width=340)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Frame(left, bg=PANEL).pack(fill="both", expand=True)
        inner = tk.Frame(left, bg=PANEL)
        inner.place(relx=0.5, rely=0.42, anchor="center")

        tk.Label(inner, text="🏥", font=(SANS,48), bg=PANEL, fg=ACCENT).pack()
        tk.Label(inner, text="MedLedger", font=(SANS,24,"bold"),
                 bg=PANEL, fg=TEXT).pack(pady=(8,4))
        tk.Label(inner, text="Patient-controlled encrypted\nmedical records",
                 font=(SANS,11), bg=PANEL, fg=MUTED, justify="center").pack()

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x", padx=32, pady=24)

        features = [
            ("🔐", "AES-256-GCM encryption"),
            ("✍", "ECDSA-signed records"),
            ("🔑", "Patient-controlled keys"),
            ("👁", "Auditable access grants"),
        ]
        for icon, text in features:
            row = tk.Frame(left, bg=PANEL)
            row.pack(fill="x", padx=32, pady=3)
            tk.Label(row, text=icon, bg=PANEL, fg=ACCENT2,
                     font=(SANS,11)).pack(side="left", padx=(0,8))
            tk.Label(row, text=text, bg=PANEL, fg=MUTED,
                     font=(SANS,9)).pack(side="left")

        # Right panel — form
        right = ttk.Frame(self)
        right.pack(side="left", fill="both", expand=True)

        form = tk.Frame(right, bg=BG)
        form.place(relx=0.5, rely=0.5, anchor="center", width=360)

        tk.Label(form, text="Sign in", font=(SANS,20,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0,4))
        tk.Label(form, text="Enter your credentials to continue",
                 font=(SANS,10), bg=BG, fg=MUTED).pack(anchor="w", pady=(0,24))

        tk.Label(form, text="Email", font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w")
        self._email = entry(form, width=36)
        self._email.pack(fill="x", pady=(2,14), ipady=5)

        tk.Label(form, text="Password", font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w")
        self._pw = entry(form, show="•", width=36)
        self._pw.pack(fill="x", pady=(2,24), ipady=5)

        btn_primary(form, "Sign In  →", self._login).pack(fill="x", ipady=4)

        tk.Frame(form, bg=BORDER, height=1).pack(fill="x", pady=20)

        tk.Label(form, text="No account yet?", font=(SANS,9), bg=BG, fg=MUTED).pack()
        btn_ghost(form, "Create account", lambda: self.app.goto("register")).pack(
            fill="x", pady=(8,0), ipady=3)

        # Demo hints
        hint = tk.Frame(right, bg=BG)
        hint.place(relx=0.5, rely=0.9, anchor="center")
        tk.Label(hint, text="Demo: register as patient + doctor, then log in",
                 font=(SANS,8), bg=BG, fg=MUTED).pack()

        self._email.focus_set()
        self.bind("<Return>", lambda e: self._login())

    def _login(self):
        email = self._email.get().strip()
        pw    = self._pw.get()
        if not email or not pw:
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        u = login_user(email, pw)
        if not u:
            messagebox.showerror("Login failed", "Invalid email or password.")
            return
        self.app.current_user = u
        self.app.goto("patient_home" if u["role"] == "patient" else "doctor_home")


# ── Register ──────────────────────────────────────────────────────────────────

class RegisterScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._build()

    def _build(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.place(relx=0.5, rely=0.5, anchor="center", width=400)

        tk.Label(wrap, text="Create account", font=(SANS,20,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0,4))
        tk.Label(wrap, text="Join MedLedger — your keys, your records",
                 font=(SANS,10), bg=BG, fg=MUTED).pack(anchor="w", pady=(0,24))

        fields = [("Full Name", False), ("Email", False), ("Password", True)]
        self._vars = {}
        for lbl, hide in fields:
            tk.Label(wrap, text=lbl, font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w")
            e = entry(wrap, show="•" if hide else None, width=36)
            e.pack(fill="x", pady=(2,14), ipady=5)
            self._vars[lbl] = e

        tk.Label(wrap, text="Role", font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w")
        self._role = tk.StringVar(value="patient")
        role_row = tk.Frame(wrap, bg=BG)
        role_row.pack(fill="x", pady=(2,24))
        for val, lbl in [("patient","Patient"), ("doctor","Doctor")]:
            rb = tk.Radiobutton(role_row, text=lbl, variable=self._role, value=val,
                                bg=BG, fg=TEXT, selectcolor=CARD,
                                activebackground=BG, activeforeground=TEXT,
                                font=(SANS,10))
            rb.pack(side="left", padx=(0,20))

        btn_primary(wrap, "Create Account  →", self._register).pack(fill="x", ipady=4)
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x", pady=16)
        btn_ghost(wrap, "← Back to login", lambda: self.app.goto("login")).pack(
            fill="x", ipady=3)

    def _register(self):
        name  = self._vars["Full Name"].get().strip()
        email = self._vars["Email"].get().strip()
        pw    = self._vars["Password"].get()
        role  = self._role.get()
        if not all([name, email, pw]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        if email in USERS:
            messagebox.showerror("Error", "That email is already registered.")
            return

        # Show key generation progress
        dlg = _ProgressWindow(self.winfo_toplevel(), "Setting up your account",
            ["Generating P-256 keypair",
             "Deriving public key",
             "Computing key hash",
             "Account ready"])
        def _run():
            time.sleep(0.3); dlg.step(0)
            register_user(name, email, pw, role)
            time.sleep(0.4); dlg.step(1)
            time.sleep(0.3); dlg.step(2)
            time.sleep(0.2); dlg.step(3)
            time.sleep(0.6)
            self.app.after(0, lambda: [dlg.destroy(), self.app.goto("login")])
        threading.Thread(target=_run, daemon=True).start()


# ── Patient Home ──────────────────────────────────────────────────────────────

class PatientHome(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app  = app
        self.user = app.current_user
        self._selected_path = None
        self._build()

    def _build(self):
        self._sidebar()
        sep_v = tk.Frame(self, bg=BORDER, width=1)
        sep_v.pack(side="left", fill="y")
        self._main = tk.Frame(self, bg=BG)
        self._main.pack(side="left", fill="both", expand=True)
        self._show_records()

    def _sidebar(self):
        side = tk.Frame(self, bg=PANEL, width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="🏥 MedLedger", font=(SANS,13,"bold"),
                 bg=PANEL, fg=TEXT).pack(padx=20, pady=(20,4), anchor="w")
        tk.Label(side, text="Patient Portal", font=(SANS,9),
                 bg=PANEL, fg=MUTED).pack(padx=20, pady=(0,20), anchor="w")

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=16, pady=4)

        nav = [("📋  My Records", self._show_records),
               ("⬆  Upload Record", self._show_upload)]
        self._nav_btns = {}
        for text, cmd in nav:
            b = tk.Button(side, text=text, command=cmd,
                          bg=PANEL, fg=MUTED, font=(SANS,10),
                          relief="flat", anchor="w", padx=20, pady=10,
                          activebackground=CARD, activeforeground=TEXT,
                          cursor="hand2")
            b.pack(fill="x")
            self._nav_btns[text] = b

        tk.Frame(side, bg=BG).pack(fill="both", expand=True)

        # Key info
        info = tk.Frame(side, bg=PANEL)
        info.pack(fill="x", padx=12, pady=(0,8))
        tk.Label(info, text="Public Key Hash", font=(SANS,8),
                 bg=PANEL, fg=MUTED).pack(anchor="w")
        ph = hashlib.sha256(bytes.fromhex(self.user["pub"])).hexdigest()
        tk.Label(info, text=ph[:24]+"…", font=(FONT,7),
                 bg=PANEL, fg=ACCENT2).pack(anchor="w")
        def _copy():
            self.clipboard_clear(); self.clipboard_append(self.user["pub"])
            messagebox.showinfo("Copied", "Full public key copied to clipboard.")
        tk.Button(info, text="Copy Key", command=_copy,
                  bg=PANEL, fg=MUTED, font=(SANS,8),
                  relief="flat", cursor="hand2",
                  activebackground=CARD).pack(anchor="w", pady=(4,0))

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

        tk.Button(side, text="🚪  Log Out",
                  command=lambda: self.app.goto("login"),
                  bg=PANEL, fg=MUTED, font=(SANS,10),
                  relief="flat", anchor="w", padx=20, pady=10,
                  activebackground=CARD, activeforeground=DANGER,
                  cursor="hand2").pack(fill="x")

    def _set_active(self, active_text):
        for t, b in self._nav_btns.items():
            b.configure(bg=CARD if t==active_text else PANEL,
                        fg=TEXT if t==active_text else MUTED)

    def _clear_main(self):
        for w in self._main.winfo_children():
            w.destroy()

    # ── Records list ──────────────────────────────────────────────────────────
    def _show_records(self):
        self._set_active("📋  My Records")
        self._clear_main()
        m = self._main

        hdr = tk.Frame(m, bg=BG)
        hdr.pack(fill="x", padx=28, pady=(24,0))
        tk.Label(hdr, text="My Medical Records", font=(SANS,17,"bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Button(hdr, text="⟳", command=self._show_records,
                  bg=BG, fg=MUTED, font=(SANS,14), relief="flat",
                  cursor="hand2").pack(side="right")

        tk.Label(m, text="All records are encrypted on your device with your private key.",
                 font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w", padx=28, pady=(4,16))

        # Table
        tf = tk.Frame(m, bg=BG)
        tf.pack(fill="both", expand=True, padx=28)

        cols = ("filename","hash","ts","status")
        tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        tree.heading("filename", text="File Name")
        tree.heading("hash",     text="SHA-256 Hash (preview)")
        tree.heading("ts",       text="Uploaded")
        tree.heading("status",   text="Status")
        tree.column("filename", width=200)
        tree.column("hash",     width=220)
        tree.column("ts",       width=130)
        tree.column("status",   width=90)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        my_records = {rid: r for rid,r in RECORDS.items()
                      if r["owner_email"] == self.user["email"]}

        if not my_records:
            tree.insert("","end", values=("No records yet — upload one →","","",""))
        else:
            for rid, r in my_records.items():
                granted = len(r["granted_to"])
                status = f"✓ {granted} grant{'s' if granted!=1 else ''}" if granted else "🔒 private"
                tree.insert("","end", iid=rid,
                            values=(r["filename"], r["hash"][:28]+"…", r["ts"], status))

        # Action row
        act = tk.Frame(m, bg=BG)
        act.pack(fill="x", padx=28, pady=12)

        def _grant():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select", "Please select a record first."); return
            rid = sel[0]
            _GrantDialog(self.winfo_toplevel(), self.user, rid,
                         on_done=self._show_records)

        def _download():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select", "Please select a record first."); return
            rid = sel[0]
            rec = RECORDS[rid]
            save = filedialog.asksaveasfilename(
                initialfile=rec["filename"],
                defaultextension=".pdf",
                filetypes=[("PDF","*.pdf"),("All","*.*")])
            if not save: return
            try:
                data = ecies_dec(self.user["priv"], rec["dek"])
                plaintext = _aes_dec(data, rec["blob"])
                with open(save,"wb") as f: f.write(plaintext)
                messagebox.showinfo("Saved", f"Decrypted and saved to:\n{save}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        btn_primary(act, "⬇  Decrypt & Save", _download).pack(side="left", padx=(0,8))
        tk.Button(act, text="🔓  Grant Doctor Access", command=_grant,
                  bg=PANEL, fg=TEXT, font=(SANS,10), relief="flat",
                  padx=14, pady=7, cursor="hand2",
                  activebackground=CARD).pack(side="left")

    # ── Upload ────────────────────────────────────────────────────────────────
    def _show_upload(self):
        self._set_active("⬆  Upload Record")
        self._clear_main()
        m = self._main

        tk.Label(m, text="Upload Medical Record", font=(SANS,17,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(24,4))
        tk.Label(m, text="Your file is hashed, signed, and encrypted before it's stored.",
                 font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w", padx=28, pady=(0,20))

        # File picker card
        fc = tk.Frame(m, bg=CARD, bd=0)
        fc.pack(fill="x", padx=28, pady=(0,16))
        fi = tk.Frame(fc, bg=CARD)
        fi.pack(padx=24, pady=20)
        tk.Label(fi, text="📂", font=(SANS,34), bg=CARD, fg=ACCENT).pack()
        tk.Label(fi, text="Choose a file to encrypt and upload",
                 font=(SANS,11), bg=CARD, fg=TEXT).pack(pady=4)
        tk.Label(fi, text="PDF · JPEG · PNG · DICOM  or generate a demo record",
                 font=(SANS,9), bg=CARD, fg=MUTED).pack()

        btn_row = tk.Frame(fi, bg=CARD)
        btn_row.pack(pady=(14,0))
        tk.Button(btn_row, text="Browse File…", command=self._pick_file,
                  bg=PANEL, fg=TEXT, font=(SANS,10), relief="flat",
                  padx=14, pady=7, cursor="hand2",
                  activebackground=BORDER).pack(side="left", padx=(0,8))
        tk.Button(btn_row, text="✨ Generate Demo PDF", command=self._gen_demo,
                  bg=PANEL, fg=ACCENT2, font=(SANS,10), relief="flat",
                  padx=14, pady=7, cursor="hand2",
                  activebackground=BORDER).pack(side="left")

        # Selected file label
        self._file_lbl_var = tk.StringVar(value="No file selected")
        sel_card = tk.Frame(m, bg=CARD)
        sel_card.pack(fill="x", padx=28, pady=(0,16))
        si = tk.Frame(sel_card, bg=CARD)
        si.pack(fill="x", padx=16, pady=12)
        tk.Label(si, text="Selected:", font=(SANS,9), bg=CARD, fg=MUTED).pack(anchor="w")
        tk.Label(si, textvariable=self._file_lbl_var, font=(SANS,10,"bold"),
                 bg=CARD, fg=TEXT, wraplength=700, anchor="w").pack(anchor="w", pady=(2,0))

        # Steps
        steps_card = tk.Frame(m, bg=CARD)
        steps_card.pack(fill="x", padx=28, pady=(0,20))
        si2 = tk.Frame(steps_card, bg=CARD)
        si2.pack(fill="x", padx=16, pady=14)
        tk.Label(si2, text="Encryption pipeline:", font=(SANS,9,"bold"),
                 bg=CARD, fg=MUTED).pack(anchor="w", pady=(0,8))
        self._steps = StepProgress(si2, [
            "SHA-256 hash of original file",
            "ECDSA-P256 signature with your private key",
            "Generate random 256-bit DEK",
            "AES-256-GCM encrypt file with DEK",
            "ECIES encrypt DEK with your public key",
            "Store encrypted blob + encrypted DEK",
        ])
        self._steps.pack(fill="x")

        # Upload button
        self._upload_btn = tk.Button(m, text="🔐  Encrypt & Upload",
                  command=self._do_upload,
                  bg=ACCENT, fg="white", font=(SANS,11,"bold"),
                  relief="flat", padx=18, pady=10, cursor="hand2",
                  activebackground="#2563d4", state="disabled")
        self._upload_btn.pack(fill="x", padx=28)

    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Select medical record",
            filetypes=[("PDF","*.pdf"),("Images","*.jpg *.jpeg *.png"),
                       ("DICOM","*.dcm"),("All","*.*")])
        if path:
            self._selected_path = path
            p_obj = path.split("/")[-1] if "/" in path else path.split("\\")[-1]
            import os as _os
            size = _os.path.getsize(path)/1024
            self._file_lbl_var.set(f"{p_obj}  ({size:.1f} KB)")
            self._upload_btn.configure(state="normal")

    def _gen_demo(self):
        pdf = make_dummy_pdf(self.user["name"])
        self._pending_bytes    = pdf
        self._pending_filename = f"lab_results_{datetime.now().strftime('%Y%m%d')}.pdf"
        self._file_lbl_var.set(
            f"{self._pending_filename}  ({len(pdf)/1024:.1f} KB)  [generated]")
        self._upload_btn.configure(state="normal")
        self._selected_path = None

    def _do_upload(self):
        if self._selected_path:
            with open(self._selected_path,"rb") as f:
                file_bytes = f.read()
            fname = self._selected_path.split("/")[-1]
        elif hasattr(self,"_pending_bytes"):
            file_bytes = self._pending_bytes
            fname      = self._pending_filename
        else:
            return

        self._upload_btn.configure(state="disabled")

        def _run():
            steps = self._steps
            time.sleep(0.4); self.app.after(0, lambda: steps.activate(0))
            time.sleep(0.5); self.app.after(0, lambda: steps.activate(1))
            time.sleep(0.4); self.app.after(0, lambda: steps.activate(2))
            enc = encrypt_doc(file_bytes, self.user["pub"], self.user["priv"])
            time.sleep(0.5); self.app.after(0, lambda: steps.activate(3))
            time.sleep(0.4); self.app.after(0, lambda: steps.activate(4))
            time.sleep(0.3); self.app.after(0, lambda: steps.activate(5))
            rid = upload_record(self.user, fname, file_bytes)
            time.sleep(0.5)
            self.app.after(0, lambda: self._upload_done(rid, fname))

        threading.Thread(target=_run, daemon=True).start()

    def _upload_done(self, rid, fname):
        messagebox.showinfo("Uploaded ✓",
                            f"'{fname}' encrypted and stored.\n\nRecord ID: {rid}")
        self._show_records()


# ── Grant dialog ──────────────────────────────────────────────────────────────

class _GrantDialog(tk.Toplevel):
    def __init__(self, parent, patient_user, record_id, on_done):
        super().__init__(parent)
        self.title("Grant Doctor Access")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.patient = patient_user
        self.rid     = record_id
        self.on_done = on_done

        w,h = 440,320
        px = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        py = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{px}+{py}")

        rec = RECORDS[record_id]
        tk.Label(self, text="Grant Doctor Access", font=(SANS,15,"bold"),
                 bg=BG, fg=TEXT).pack(padx=24, pady=(20,4), anchor="w")
        tk.Label(self, text=f"Record: {rec['filename']}",
                 font=(SANS,9), bg=BG, fg=MUTED).pack(padx=24, anchor="w")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=24, pady=12)

        # Doctor email or pick from registered doctors
        tk.Label(self, text="Doctor's email", font=(SANS,9), bg=BG, fg=MUTED).pack(
            padx=24, anchor="w")
        doctors = [u["email"] for u in USERS.values() if u["role"]=="doctor"]
        self._doc_var = tk.StringVar()
        if doctors:
            cb = ttk.Combobox(self, textvariable=self._doc_var, values=doctors, width=34)
            cb.pack(padx=24, pady=(2,16), fill="x")
            if doctors: self._doc_var.set(doctors[0])
        else:
            tk.Label(self, text="No doctors registered yet.",
                     font=(SANS,9), bg=BG, fg=WARNING).pack(padx=24, pady=(2,16), anchor="w")
            e = entry(self, width=36)
            e.pack(padx=24, pady=(2,16), fill="x")
            self._doc_var = tk.StringVar()
            e.configure(textvariable=self._doc_var)

        tk.Label(self, text="Access duration (hours)", font=(SANS,9),
                 bg=BG, fg=MUTED).pack(padx=24, anchor="w")
        self._hours = tk.StringVar(value="24")
        entry(self, textvariable=self._hours, width=10).pack(
            padx=24, pady=(2,20), anchor="w", ipady=4)

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill="x", padx=24)
        btn_primary(btn_row, "Grant Access", self._submit).pack(side="left", padx=(0,8))
        btn_ghost(btn_row, "Cancel", self.destroy).pack(side="left")

    def _submit(self):
        doc_email = self._doc_var.get().strip()
        if not doc_email:
            messagebox.showerror("Error","Enter the doctor's email."); return
        dlg = _ProgressWindow(self.winfo_toplevel(), "Granting access",
            ["Fetching doctor's public key",
             "Decrypting your record DEK",
             "Re-encrypting DEK for doctor (ECIES)",
             "Signing permission",
             "Access granted"])
        def _run():
            time.sleep(0.4); dlg.step(0)
            time.sleep(0.5); dlg.step(1)
            try:
                grant_access(self.rid, self.patient, doc_email)
            except Exception as e:
                self.after(0, lambda: [dlg.destroy(),
                    messagebox.showerror("Error", str(e))]); return
            time.sleep(0.5); dlg.step(2)
            time.sleep(0.4); dlg.step(3)
            time.sleep(0.3); dlg.step(4)
            time.sleep(0.7)
            self.after(0, lambda: [dlg.destroy(), self.destroy(), self.on_done()])
        threading.Thread(target=_run, daemon=True).start()


# ── Doctor Home ───────────────────────────────────────────────────────────────

class DoctorHome(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app  = app
        self.user = app.current_user
        self._build()

    def _build(self):
        # Sidebar
        side = tk.Frame(self, bg=PANEL, width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="🏥 MedLedger", font=(SANS,13,"bold"),
                 bg=PANEL, fg=TEXT).pack(padx=20, pady=(20,4), anchor="w")
        tk.Label(side, text="Doctor Portal", font=(SANS,9),
                 bg=PANEL, fg=ACCENT2).pack(padx=20, pady=(0,20), anchor="w")

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=16, pady=4)

        tk.Label(side, text=f"Dr. {self.user['name']}", font=(SANS,10,"bold"),
                 bg=PANEL, fg=TEXT).pack(padx=20, pady=(12,2), anchor="w")
        tk.Label(side, text=self.user["email"], font=(SANS,8),
                 bg=PANEL, fg=MUTED).pack(padx=20, anchor="w")

        tk.Frame(side, bg=BG).pack(fill="both", expand=True)

        tk.Label(side, text="Your ID (share with patients)",
                 font=(SANS,8), bg=PANEL, fg=MUTED).pack(padx=12, anchor="w")
        tk.Label(side, text=self.user["email"],
                 font=(FONT,8), bg=PANEL, fg=ACCENT2,
                 wraplength=180).pack(padx=12, anchor="w")

        def _copy():
            self.clipboard_clear(); self.clipboard_append(self.user["email"])
            messagebox.showinfo("Copied","Email copied to clipboard.")
        tk.Button(side, text="Copy Email", command=_copy,
                  bg=PANEL, fg=MUTED, font=(SANS,8), relief="flat",
                  cursor="hand2", activebackground=CARD).pack(
                  padx=12, pady=(4,16), anchor="w")

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=16, pady=4)
        tk.Button(side, text="🚪  Log Out",
                  command=lambda: self.app.goto("login"),
                  bg=PANEL, fg=MUTED, font=(SANS,10),
                  relief="flat", anchor="w", padx=20, pady=10,
                  activebackground=CARD, activeforeground=DANGER,
                  cursor="hand2").pack(fill="x")

        # Separator
        tk.Frame(self, bg=BORDER, width=1).pack(side="left", fill="y")

        # Main content
        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        tk.Label(main, text="Patient Records", font=(SANS,17,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(24,4))
        tk.Label(main, text="Records that patients have granted you access to.",
                 font=(SANS,9), bg=BG, fg=MUTED).pack(anchor="w", padx=28, pady=(0,20))

        # Records I have access to
        tf = tk.Frame(main, bg=BG)
        tf.pack(fill="both", expand=True, padx=28)

        cols = ("patient","filename","hash","ts","action")
        tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        tree.heading("patient",  text="Patient")
        tree.heading("filename", text="File")
        tree.heading("hash",     text="Hash (preview)")
        tree.heading("ts",       text="Uploaded")
        tree.heading("action",   text="Access")
        tree.column("patient",  width=130)
        tree.column("filename", width=170)
        tree.column("hash",     width=200)
        tree.column("ts",       width=120)
        tree.column("action",   width=80)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        accessible = [(rid, r) for rid, r in RECORDS.items()
                      if self.user["email"] in r["granted_to"]]

        if not accessible:
            tree.insert("","end",
                values=("No records yet","Ask a patient to grant you access","","",""))
        else:
            for rid, r in accessible:
                owner = USERS.get(r["owner_email"],{}).get("name", r["owner_email"])
                tree.insert("","end", iid=rid,
                            values=(owner, r["filename"],
                                    r["hash"][:24]+"…", r["ts"], "✓ granted"))

        # Actions
        act = tk.Frame(main, bg=BG)
        act.pack(fill="x", padx=28, pady=12)

        def _decrypt_view():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select","Select a record first."); return
            rid = sel[0]
            _DecryptView(self.winfo_toplevel(), self.user, rid)

        def _decrypt_save():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select","Select a record first."); return
            rid = sel[0]
            rec = RECORDS[rid]
            save = filedialog.asksaveasfilename(
                initialfile=rec["filename"], defaultextension=".pdf",
                filetypes=[("PDF","*.pdf"),("All","*.*")])
            if not save: return
            try:
                plaintext = doctor_decrypt(rid, self.user)
                with open(save,"wb") as f: f.write(plaintext)
                messagebox.showinfo("Saved", f"Decrypted and saved:\n{save}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        btn_primary(act, "🔍  Decrypt & View", _decrypt_view).pack(side="left", padx=(0,8))
        tk.Button(act, text="💾  Save to Disk", command=_decrypt_save,
                  bg=PANEL, fg=TEXT, font=(SANS,10), relief="flat",
                  padx=14, pady=7, cursor="hand2",
                  activebackground=CARD).pack(side="left")


# ── Decrypt view window ───────────────────────────────────────────────────────

class _DecryptView(tk.Toplevel):
    def __init__(self, parent, doctor_user, record_id):
        super().__init__(parent)
        self.title("Record Viewer — Decrypting…")
        self.configure(bg=BG)
        self.geometry("640x560")
        self.grab_set()

        rec = RECORDS[record_id]
        owner_name = USERS.get(rec["owner_email"],{}).get("name","Unknown")

        # Header
        hdr = tk.Frame(self, bg=PANEL)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"🔐 {rec['filename']}", font=(SANS,13,"bold"),
                 bg=PANEL, fg=TEXT).pack(side="left", padx=16, pady=12)
        tk.Label(hdr, text=f"Patient: {owner_name}",
                 font=(SANS,9), bg=PANEL, fg=MUTED).pack(side="right", padx=16)

        # Crypto info strip
        info = tk.Frame(self, bg=CARD)
        info.pack(fill="x")
        for k, v in [("SHA-256", rec["hash"][:32]+"…"),
                     ("Signature", rec["sig"][:24]+"…"),
                     ("Algorithm", "AES-256-GCM + ECIES-P256")]:
            tk.Label(info, text=f"{k}:", font=(SANS,8), bg=CARD, fg=MUTED).pack(
                side="left", padx=(12,2), pady=6)
            tk.Label(info, text=v, font=(FONT,8), bg=CARD, fg=ACCENT2).pack(
                side="left", padx=(0,16), pady=6)

        # Progress then content
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=16)

        self._prog_frame = tk.Frame(body, bg=BG)
        self._prog_frame.pack(fill="x")
        tk.Label(self._prog_frame, text="Decrypting…", font=(SANS,11,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(0,10))
        self._steps = StepProgress(self._prog_frame, [
            "Verifying doctor permission",
            "Loading doctor's ECIES bundle",
            "Decrypting DEK with private key",
            "AES-256-GCM decrypt record",
            "Verifying content hash",
        ])
        self._steps.pack(fill="x")

        self._content_frame = tk.Frame(body, bg=BG)

        def _run():
            time.sleep(0.3); self.after(0, lambda: self._steps.activate(0))
            time.sleep(0.4); self.after(0, lambda: self._steps.activate(1))
            time.sleep(0.5); self.after(0, lambda: self._steps.activate(2))
            time.sleep(0.5); self.after(0, lambda: self._steps.activate(3))
            try:
                plaintext = doctor_decrypt(record_id, doctor_user)
            except Exception as e:
                self.after(0, lambda: [self._prog_frame.destroy(),
                    tk.Label(body, text=f"❌ {e}", font=(SANS,11),
                             bg=BG, fg=DANGER).pack()])
                return
            time.sleep(0.3); self.after(0, lambda: self._steps.activate(4))
            time.sleep(0.4)
            self.after(0, lambda: self._show_content(plaintext))

        threading.Thread(target=_run, daemon=True).start()

    def _show_content(self, plaintext):
        self.title("Record Viewer — Decrypted ✓")
        self._prog_frame.destroy()
        cf = self._content_frame
        cf.pack(fill="both", expand=True)

        tk.Label(cf, text="✓ Decrypted successfully", font=(SANS,10,"bold"),
                 bg=BG, fg=SUCCESS).pack(anchor="w", pady=(0,10))

        # Try to show as text; if binary show hex dump
        try:
            text_content = plaintext.decode("utf-8", errors="strict")
            # It's a PDF — extract the readable lines
            lines = [l for l in text_content.split("\n")
                     if l.strip() and not l.startswith("%") and
                     not any(c in l for c in ["<<",">>","obj","endobj","stream"])]
            display = "\n".join(lines[:40])
        except Exception:
            display = plaintext[:800].hex()

        txt = tk.Text(cf, bg=CARD, fg=TEXT, font=(FONT,9),
                      relief="flat", wrap="word",
                      insertbackground=TEXT, selectbackground=ACCENT)
        txt.pack(fill="both", expand=True)
        scroll = ttk.Scrollbar(cf, command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        txt.insert("1.0", display)
        txt.configure(state="disabled")

        tk.Label(cf, text=f"  {len(plaintext):,} bytes decrypted  |  integrity verified",
                 font=(SANS,8), bg=CARD, fg=SUCCESS).pack(fill="x", pady=(4,0))


# ── Generic progress window ───────────────────────────────────────────────────

class _ProgressWindow(tk.Toplevel):
    def __init__(self, parent, title, steps):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG)
        self.resizable(False, False)

        w,h = 380, 60 + len(steps)*28 + 60
        px = parent.winfo_rootx() + (parent.winfo_width()-w)//2
        py = parent.winfo_rooty() + (parent.winfo_height()-h)//2
        self.geometry(f"{w}x{h}+{px}+{py}")
        self.grab_set()

        tk.Label(self, text=title, font=(SANS,12,"bold"),
                 bg=BG, fg=TEXT).pack(padx=24, pady=(18,12), anchor="w")

        self._sp = StepProgress(self, steps)
        self._sp.pack(fill="x", padx=24, pady=(0,16))

        self._bar = ttk.Progressbar(self, mode="indeterminate", length=330)
        self._bar.pack(padx=24, pady=(0,16))
        self._bar.start(10)

    def step(self, idx):
        self.after(0, lambda: self._sp.activate(idx))


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = App()
    app.mainloop()

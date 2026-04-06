"""
MedLedger CLI Client
────────────────────
A terminal app for interacting with a running MedLedger / CypherAegis server.

Features
  - Register as PATIENT or DOCTOR (auto-verifies, saves private key to .env/<username>.pem)
  - Login (JWT stored in memory for the session)
  - Upload a file (encrypted on server, stored in vault)
  - Download a file (decrypted on server with your private key)
  - List your vault records
  - Grant access to someone by their public key hex
  - Revoke a grant
  - View your outbox (grants you gave) and inbox (grants you received)
  - Look up a registered user's public key by username (via /api/auth/me workaround)

Usage
  python medledger_client.py [--base-url http://localhost:8000]
"""

import os
import sys
import json
import argparse
import getpass
import textwrap
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("requests is not installed. Run: pip install requests")

# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_BASE = "http://localhost:8000"
KEY_DIR      = Path(".env")   # .env/<username>.pem  (gitignored)

# ── ANSI colours ──────────────────────────────────────────────────────────────

R  = "\033[0m"
B  = "\033[1m"
DIM = "\033[2m"
CY = "\033[36m"
GR = "\033[32m"
YL = "\033[33m"
RD = "\033[31m"
MG = "\033[35m"

def ok(msg):    print(f"{GR}✓{R}  {msg}")
def err(msg):   print(f"{RD}✗{R}  {msg}")
def info(msg):  print(f"{CY}·{R}  {msg}")
def warn(msg):  print(f"{YL}!{R}  {msg}")
def hdr(msg):   print(f"\n{B}{MG}{'─'*50}{R}\n{B}{MG}  {msg}{R}\n{B}{MG}{'─'*50}{R}")
def dim(msg):   print(f"{DIM}{msg}{R}")

# ── Key helpers ───────────────────────────────────────────────────────────────

def key_path(username: str) -> Path:
    return KEY_DIR / f"{username}.pem"

def save_key(username: str, pem: str):
    KEY_DIR.mkdir(exist_ok=True)
    p = key_path(username)
    p.write_text(pem)
    p.chmod(0o600)
    ok(f"Private key saved → {p}")

def load_key(username: str) -> str | None:
    p = key_path(username)
    if p.exists():
        return p.read_text().strip()
    return None

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def post(base: str, path: str, body: dict, token: str = None) -> dict | None:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.post(f"{base}{path}", json=body, headers=headers, timeout=30)
    except requests.ConnectionError:
        err(f"Cannot reach server at {base}")
        return None
    if r.ok:
        return r.json()
    err(f"HTTP {r.status_code}: {r.json().get('detail', r.text)}")
    return None

def get(base: str, path: str, token: str = None) -> dict | list | None:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get(f"{base}{path}", headers=headers, timeout=30)
    except requests.ConnectionError:
        err(f"Cannot reach server at {base}")
        return None
    if r.ok:
        return r.json()
    err(f"HTTP {r.status_code}: {r.json().get('detail', r.text)}")
    return None

# ── Auth flows ────────────────────────────────────────────────────────────────

def cmd_register(base: str):
    hdr("Register new account")
    email    = input("  Email      : ").strip()
    username = input("  Username   : ").strip()
    full_name= input("  Full name  : ").strip()
    role     = input("  Role [PATIENT/DOCTOR] (default PATIENT): ").strip().upper() or "PATIENT"
    if role not in ("PATIENT", "DOCTOR"):
        err("Role must be PATIENT or DOCTOR"); return
    password = getpass.getpass("  Password   : ")
    if len(password) < 8:
        err("Password must be at least 8 characters"); return
    confirm  = getpass.getpass("  Confirm    : ")
    if password != confirm:
        err("Passwords do not match"); return

    info("Registering…")
    res = post(base, "/api/auth/register", {
        "email": email, "password": password,
        "username": username, "full_name": full_name, "role": role,
    })
    if not res:
        return

    token = res.get("verification_token")
    if not token:
        err("Server did not return a verification token"); return

    info(f"Account created (pending). Auto-verifying with token…")
    vres = post(base, "/api/auth/verify", {"token": token})
    if not vres:
        return

    private_key_pem = vres.get("private_key_pem")
    if not private_key_pem:
        err("Server did not return a private key"); return

    save_key(username, private_key_pem)
    ok(f"Account active! Role: {role}")
    info(f"Public key hash : {vres.get('public_key_hash', '?')}")
    warn("Your private key was returned ONCE and saved locally. Back it up.")

def cmd_login(base: str) -> tuple[str, str, dict] | tuple[None, None, None]:
    """Returns (token, username, profile) or (None, None, None)."""
    hdr("Login")
    email    = input("  Email    : ").strip()
    password = getpass.getpass("  Password : ")
    res = post(base, "/api/auth/login", {"email": email, "password": password})
    if not res:
        return None, None, None
    token    = res["access_token"]
    username = res["username"]
    ok(f"Logged in as {B}{username}{R} ({res.get('role', '?')})")
    return token, username, res

def require_login():
    err("You must be logged in to do this.")

# ── Vault flows ───────────────────────────────────────────────────────────────

def cmd_upload(base: str, token: str, username: str):
    hdr("Upload file to vault")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    filepath = input("  File path  : ").strip()
    p = Path(filepath)
    if not p.exists():
        err(f"File not found: {filepath}"); return

    raw = p.read_bytes()
    tags_raw = input("  Tags (comma-separated, optional): ").strip()
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    info(f"Uploading {p.name} ({len(raw)} bytes)…")
    res = post(base, "/api/vault/upload", {
        "private_key_pem": pem,
        "filename":        p.name,
        "plaintext_hex":   raw.hex(),
        "tags":            tags,
    }, token=token)
    if not res:
        return
    ok(f"Uploaded. Record ID: {B}{res['record_id']}{R}")
    info(f"Filename : {res.get('filename')}")
    info(f"Size     : {res.get('size_bytes')} bytes")
    info(f"Tags     : {res.get('tags', [])}")

def cmd_download(base: str, token: str, username: str):
    hdr("Download file from vault")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    record_id = input("  Record ID  : ").strip()
    out_dir   = input("  Save to dir (default: current): ").strip() or "."

    res = post(base, f"/api/vault/download/{record_id}", {
        "private_key_pem": pem,
    }, token=token)
    if not res:
        return

    raw     = bytes.fromhex(res["plaintext_hex"])
    outpath = Path(out_dir) / res["filename"]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    outpath.write_bytes(raw)
    ok(f"Saved → {outpath}  ({res['size_bytes']} bytes)")

def cmd_list_records(base: str, token: str):
    hdr("Your vault records")
    records = get(base, "/api/vault/records", token=token)
    if records is None:
        return
    if not records:
        info("No records yet."); return
    for r in records:
        print(f"  {B}{r['record_id']}{R}")
        print(f"    {DIM}filename : {r['filename']}{R}")
        print(f"    {DIM}size     : {r['size_bytes']} bytes{R}")
        print(f"    {DIM}tags     : {r.get('tags', [])}{R}")
        print(f"    {DIM}created  : {r['created_at']}{R}")
        print()

def cmd_grant(base: str, token: str, username: str):
    hdr("Grant access to a record")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    record_id       = input("  Record ID                         : ").strip()
    grantee_pub_hex = input("  Grantee public key hex (130 chars) : ").strip()
    perm            = input("  Permission [view_only/view_download] (default view_only): ").strip() or "view_only"
    hours_raw       = input("  Duration hours (default 24)        : ").strip()
    hours           = float(hours_raw) if hours_raw else 24.0

    res = post(base, "/api/vault/grant", {
        "private_key_pem":       pem,
        "record_id":             record_id,
        "grantee_public_key_hex": grantee_pub_hex,
        "permission_level":      perm,
        "duration_hours":        hours,
    }, token=token)
    if not res:
        return
    ok(f"Grant created. Grant ID: {B}{res['grant_id']}{R}")
    info(f"Expires: {res.get('time_end')}")

def cmd_revoke(base: str, token: str, username: str):
    hdr("Revoke a grant")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    grant_id = input("  Grant ID : ").strip()
    res = post(base, "/api/vault/revoke", {
        "private_key_pem": pem,
        "grant_id":        grant_id,
    }, token=token)
    if not res:
        return
    ok("Grant revoked.")

def cmd_outbox(base: str, token: str, username: str):
    hdr("Your outbox — grants you issued")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    grants = post(base, "/api/vault/permissions", {"private_key_pem": pem}, token=token)
    if grants is None:
        return
    if not grants:
        info("No grants issued yet."); return
    for g in grants:
        status = f"{RD}REVOKED{R}" if g.get("revoked") else f"{GR}active{R}"
        print(f"  {B}{g['grant_id']}{R}  [{status}]")
        print(f"    {DIM}record   : {g['record_id']}{R}")
        print(f"    {DIM}perm     : {g['permission_level']}{R}")
        print(f"    {DIM}expires  : {g['time_end']}{R}")
        print()

def cmd_inbox(base: str, token: str, username: str):
    hdr("Your inbox — grants you received")
    pem = load_key(username)
    if not pem:
        err(f"Private key not found at {key_path(username)}"); return

    grants = post(base, "/api/vault/inbox", {"private_key_pem": pem}, token=token)
    if grants is None:
        return
    if not grants:
        info("No grants received yet."); return
    for g in grants:
        status = f"{RD}REVOKED{R}" if g.get("revoked") else f"{GR}active{R}"
        print(f"  {B}{g['grant_id']}{R}  [{status}]")
        print(f"    {DIM}record   : {g['record_id']}{R}")
        print(f"    {DIM}perm     : {g['permission_level']}{R}")
        print(f"    {DIM}expires  : {g['time_end']}{R}")
        print()

def cmd_whoami(base: str, token: str):
    hdr("Your profile")
    res = get(base, "/api/auth/me", token=token)
    if not res:
        return
    for k, v in res.items():
        print(f"  {DIM}{k:<24}{R}{v}")

def cmd_show_pubkey(username: str):
    """Print own public key hex so friends can copy it for granting."""
    hdr("Your public key")
    pem = load_key(username)
    if not pem:
        err(f"No private key found at {key_path(username)}"); return
    # derive the public key from the PEM using cryptography lib if available
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        privkey = load_pem_private_key(pem.encode(), password=None)
        pub = privkey.public_key()
        raw = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        print(f"\n  {B}{raw.hex()}{R}\n")
        info("Share this with friends so they can grant you access to their records.")
    except ImportError:
        warn("cryptography library not available; log in and check /api/auth/me for your public_key_hex")

def cmd_rotate_key(base: str, token: str, username: str):
    hdr("Rotate keypair")
    warn("This re-encrypts all your DEKs under a new key and revokes all existing grants.")
    confirm = input("  Type YES to confirm: ").strip()
    if confirm != "YES":
        info("Aborted."); return

    old_pem = load_key(username)
    if not old_pem:
        err(f"Old private key not found at {key_path(username)}"); return

    # generate new keypair client-side
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption
        )
        new_privkey = ec.generate_private_key(ec.SECP256R1())
        new_pem     = new_privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        pub_raw     = new_privkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        new_pub_hex = pub_raw.hex()
    except Exception as e:
        err(f"Could not generate new keypair: {e}"); return

    res = post(base, "/api/vault/rotate-key", {
        "old_private_key_pem": old_pem,
        "new_private_key_pem": new_pem,
        "new_public_key_hex":  new_pub_hex,
    }, token=token)
    if not res:
        return

    save_key(username, new_pem)
    ok("Key rotated successfully. Old grants have been revoked.")

# ── Main REPL ─────────────────────────────────────────────────────────────────

MENU_LOGGED_OUT = """\
  {B}1{R}  Register
  {B}2{R}  Login
  {B}q{R}  Quit
""".format(B=B, R=R)

MENU_LOGGED_IN = """\
  {B}1{R}  Upload file
  {B}2{R}  Download file
  {B}3{R}  List my records
  {B}4{R}  Grant access
  {B}5{R}  Revoke grant
  {B}6{R}  Outbox  (grants I gave)
  {B}7{R}  Inbox   (grants I received)
  {B}8{R}  Show my public key
  {B}9{R}  Who am I
  {B}r{R}  Rotate keypair
  {B}l{R}  Logout
  {B}q{R}  Quit
""".format(B=B, R=R)

def main():
    parser = argparse.ArgumentParser(description="MedLedger CLI")
    parser.add_argument("--base-url", default=DEFAULT_BASE, help=f"Server base URL (default: {DEFAULT_BASE})")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    print(f"\n{B}{MG}  ███╗   ███╗███████╗██████╗ {R}")
    print(f"{B}{MG}  ████╗ ████║██╔════╝██╔══██╗{R}")
    print(f"{B}{MG}  ██╔████╔██║█████╗  ██║  ██║{R}")
    print(f"{B}{MG}  ██║╚██╔╝██║██╔══╝  ██║  ██║{R}")
    print(f"{B}{MG}  ██║ ╚═╝ ██║███████╗██████╔╝{R}")
    print(f"{B}{MG}  ╚═╝     ╚═╝╚══════╝╚═════╝ {R}")
    print(f"{DIM}  Patient-controlled health vault{R}")
    print(f"{DIM}  Server: {base}{R}\n")

    token    = None
    username = None
    profile  = None

    while True:
        if token:
            print(f"\n{DIM}Logged in as {B}{username}{R}{DIM} ({profile.get('role','?')}){R}")
            print(MENU_LOGGED_IN)
            choice = input("  → ").strip().lower()

            if   choice == "1": cmd_upload(base, token, username)
            elif choice == "2": cmd_download(base, token, username)
            elif choice == "3": cmd_list_records(base, token)
            elif choice == "4": cmd_grant(base, token, username)
            elif choice == "5": cmd_revoke(base, token, username)
            elif choice == "6": cmd_outbox(base, token, username)
            elif choice == "7": cmd_inbox(base, token, username)
            elif choice == "8": cmd_show_pubkey(username)
            elif choice == "9": cmd_whoami(base, token)
            elif choice == "r": cmd_rotate_key(base, token, username)
            elif choice == "l":
                token = username = profile = None
                ok("Logged out.")
            elif choice == "q":
                print(f"\n{DIM}Bye.{R}\n"); sys.exit(0)
            else:
                warn("Unknown option.")
        else:
            print(MENU_LOGGED_OUT)
            choice = input("  → ").strip().lower()

            if   choice == "1": cmd_register(base)
            elif choice == "2":
                token, username, profile = cmd_login(base)
            elif choice == "q":
                print(f"\n{DIM}Bye.{R}\n"); sys.exit(0)
            else:
                warn("Unknown option.")

if __name__ == "__main__":
    main()

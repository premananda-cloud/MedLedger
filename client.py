#!/usr/bin/env python3
"""
MedLedger CLI Client
Location: client.py

A command-line app that exercises every MedLedger API endpoint.
Stores session state (JWT, private key) in a local .session.json file
so you don't have to re-login between commands.

Usage
─────
    python client.py register --email alice@example.com --password pass1234 --username alice
    python client.py verify   --token <token_from_email>
    python client.py login    --email alice@example.com --password pass1234

    python client.py upload   --file /path/to/report.pdf
    python client.py download --record-id <uuid>  [--out ./report.pdf]
    python client.py records

    python client.py grant   --record-id <uuid> --grantee-key <hex> [--hours 48]
    python client.py revoke  --grant-id <uuid>
    python client.py perms
    python client.py inbox

    python client.py rotate-key

    python client.py whoami
    python client.py logout
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

BASE_URL   = os.environ.get("MEDLEDGER_URL", "http://localhost:8000")
SESSION_FILE = Path(".session.json")


# ── Session helpers ───────────────────────────────────────────────────────────

def _load_session() -> dict:
    if SESSION_FILE.exists():
        return json.loads(SESSION_FILE.read_text())
    return {}


def _save_session(data: dict):
    SESSION_FILE.write_text(json.dumps(data, indent=2))
    SESSION_FILE.chmod(0o600)


def _require_session() -> dict:
    s = _load_session()
    if not s.get("token"):
        print("Not logged in. Run: python client.py login")
        sys.exit(1)
    if not s.get("private_key_pem"):
        print("No private key in session. Re-login after verify.")
        sys.exit(1)
    return s


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _post(path: str, body: dict, token: str | None = None) -> dict:
    h = _headers(token) if token else {}
    r = requests.post(f"{BASE_URL}{path}", json=body, headers=h)
    if not r.ok:
        print(f"Error {r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()


def _get(path: str, token: str) -> dict | list:
    r = requests.get(f"{BASE_URL}{path}", headers=_headers(token))
    if not r.ok:
        print(f"Error {r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_register(args):
    body = {
        "email":     args.email,
        "password":  args.password,
        "username":  args.username,
        "full_name": args.full_name or "",
        "role":      args.role or "PATIENT",
    }
    resp = _post("/api/auth/register", body)
    print(f"Registration pending.")
    print(f"  user_id           : {resp['user_id']}")
    print(f"  email             : {resp['email']}")
    print(f"  token_expires_at  : {resp['token_expires_at']}")
    print()
    print(f"Verification token  : {resp['verification_token']}")
    print("Run: python client.py verify --token <token>")


def cmd_verify(args):
    resp = _post("/api/auth/verify", {"token": args.token})
    # Save private key + public key hash to session (no login needed separately)
    session = _load_session()
    session["private_key_pem"]  = resp["private_key_pem"]
    session["public_key_hash"]  = resp["public_key_hash"]
    session["public_key_hex"]   = resp["public_key_hex"]
    session["email"]            = resp["email"]
    session["user_id"]          = resp["user_id"]
    _save_session(session)

    print(f"Email verified. Account active.")
    print(f"  user_id         : {resp['user_id']}")
    print(f"  public_key_hash : {resp['public_key_hash'][:16]}...")
    print()
    print("Private key saved to .session.json — keep this file safe!")
    print("Now login to get a JWT: python client.py login")


def cmd_login(args):
    resp = _post("/api/auth/login", {"email": args.email, "password": args.password})
    session = _load_session()
    session["token"]            = resp["access_token"]
    session["email"]            = resp["email"]
    session["user_id"]          = resp["user_id"]
    session["public_key_hash"]  = resp["public_key_hash"]
    session["public_key_compressed"] = resp.get("public_key_compressed", "")
    _save_session(session)
    print(f"Logged in as {resp['email']}  (role: {resp['role']})")
    print(f"  public_key_hash : {resp['public_key_hash'][:16]}...")


def cmd_whoami(args):
    s = _require_session()
    resp = _get("/api/auth/me", s["token"])
    print(f"  user_id         : {resp['user_id']}")
    print(f"  email           : {resp['email']}")
    print(f"  username        : {resp['username']}")
    print(f"  role            : {resp['role']}")
    print(f"  public_key_hash : {resp['public_key_hash'][:16]}...")
    print(f"  is_active       : {resp['is_active']}")
    print(f"  last_login      : {resp.get('last_login')}")


def cmd_upload(args):
    s = _require_session()
    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {args.file}")
        sys.exit(1)

    raw      = path.read_bytes()
    tags     = args.tags.split(",") if args.tags else []
    body = {
        "private_key_pem": s["private_key_pem"],
        "filename":        path.name,
        "plaintext_hex":   raw.hex(),
        "tags":            tags,
    }
    resp = _post("/api/vault/upload", body, s["token"])
    print(f"Uploaded.")
    print(f"  record_id  : {resp['record_id']}")
    print(f"  filename   : {resp['filename']}")
    print(f"  size_bytes : {resp['size_bytes']}")
    print(f"  created_at : {resp['created_at']}")


def cmd_download(args):
    s = _require_session()
    body = {"private_key_pem": s["private_key_pem"]}
    resp = _post(f"/api/vault/download/{args.record_id}", body, s["token"])

    raw = bytes.fromhex(resp["plaintext_hex"])
    out = Path(args.out) if args.out else Path(resp["filename"])
    out.write_bytes(raw)
    print(f"Downloaded {resp['filename']} ({resp['size_bytes']} bytes) → {out}")


def cmd_records(args):
    s = _require_session()
    records = _get("/api/vault/records", s["token"])
    if not records:
        print("No records.")
        return
    for r in records:
        print(f"  {r['record_id'][:8]}...  {r['filename']:30s}  {r['size_bytes']:>8} bytes  {r['created_at'][:19]}")


def cmd_grant(args):
    s = _require_session()
    body = {
        "private_key_pem":       s["private_key_pem"],
        "record_id":             args.record_id,
        "grantee_public_key_hex": args.grantee_key,
        "permission_level":      args.level or "view_only",
        "duration_hours":        float(args.hours or 24),
    }
    resp = _post("/api/vault/grant", body, s["token"])
    print(f"Grant created.")
    print(f"  grant_id         : {resp['grant_id']}")
    print(f"  grantee_key_hash : {resp['grantee_key_hash'][:16]}...")
    print(f"  permission_level : {resp['permission_level']}")
    print(f"  time_end         : {resp['time_end'][:19]}")


def cmd_revoke(args):
    s = _require_session()
    body = {"private_key_pem": s["private_key_pem"], "grant_id": args.grant_id}
    resp = _post("/api/vault/revoke", body, s["token"])
    print(f"Grant {resp['grant_id'][:8]}... status: {resp['status']}")


def cmd_perms(args):
    s = _require_session()
    body = {"private_key_pem": s["private_key_pem"]}
    perms = _post("/api/vault/permissions", body, s["token"])
    _print_perms(perms, "Permissions issued (outbox)")


def cmd_inbox(args):
    s = _require_session()
    body = {"private_key_pem": s["private_key_pem"]}
    perms = _post("/api/vault/inbox", body, s["token"])
    _print_perms(perms, "Permissions received (inbox)")


def _print_perms(perms: list, title: str):
    print(f"\n{title}:")
    if not perms:
        print("  (none)")
        return
    for p in perms:
        status = "REVOKED" if p["revoked"] else ("ACTIVE" if p["time_valid"] else "EXPIRED")
        print(
            f"  [{status:7s}] {p['grant_id'][:8]}...  "
            f"file={p['filename']:20s}  "
            f"level={p['permission_level']:14s}  "
            f"sig={'OK' if p['signature_valid'] else 'BAD'}"
        )


def cmd_rotate_key(args):
    s = _require_session()
    # Generate a new keypair client-side
    from src.crypto.key_manager import KeyManager
    km   = KeyManager()
    new_kp = km.generate_keypair()

    body = {
        "old_private_key_pem": s["private_key_pem"],
        "new_private_key_pem": new_kp.private_key_pem,
        "new_public_key_hex":  new_kp.public_key_hex,
    }
    resp = _post("/api/vault/rotate-key", body, s["token"])

    # Update session with new key
    s["private_key_pem"] = new_kp.private_key_pem
    s["public_key_hash"] = new_kp.public_key_hash
    s["public_key_hex"]  = new_kp.public_key_hex
    _save_session(s)

    print(f"Key rotated.")
    print(f"  records re-wrapped : {resp['rotated_records']}")
    print(f"  grants revoked     : {resp['revoked_grants']}")
    print(f"  new_key_hash       : {resp['new_key_hash'][:16]}...")
    print("New private key saved to .session.json.")


def cmd_logout(args):
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    print("Logged out. Session file deleted.")


# ── Parser ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="client.py",
        description="MedLedger CLI — patient-controlled healthcare vault",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # register
    p = sub.add_parser("register", help="Create a new account")
    p.add_argument("--email",     required=True)
    p.add_argument("--password",  required=True)
    p.add_argument("--username",  required=True)
    p.add_argument("--full-name", dest="full_name", default="")
    p.add_argument("--role",      default="PATIENT")

    # verify
    p = sub.add_parser("verify", help="Verify email with token")
    p.add_argument("--token", required=True)

    # login
    p = sub.add_parser("login", help="Login and save JWT")
    p.add_argument("--email",    required=True)
    p.add_argument("--password", required=True)

    # whoami
    sub.add_parser("whoami", help="Show current user profile")

    # upload
    p = sub.add_parser("upload", help="Encrypt and upload a file")
    p.add_argument("--file", required=True, help="Path to file")
    p.add_argument("--tags", default="",   help="Comma-separated tags")

    # download
    p = sub.add_parser("download", help="Download and decrypt a file")
    p.add_argument("--record-id", required=True)
    p.add_argument("--out", default=None, help="Output path (default: original filename)")

    # records
    sub.add_parser("records", help="List your records")

    # grant
    p = sub.add_parser("grant", help="Grant access to a record")
    p.add_argument("--record-id",   required=True)
    p.add_argument("--grantee-key", required=True, help="Grantee's public_key_hex")
    p.add_argument("--level",       default="view_only", choices=["view_only", "view_download"])
    p.add_argument("--hours",       default=24, type=float)

    # revoke
    p = sub.add_parser("revoke", help="Revoke a grant")
    p.add_argument("--grant-id", required=True)

    # perms / inbox
    sub.add_parser("perms",  help="List grants you have issued")
    sub.add_parser("inbox",  help="List grants you have received")

    # rotate-key
    sub.add_parser("rotate-key", help="Generate new keypair and re-wrap all DEKs")

    # logout
    sub.add_parser("logout", help="Clear local session")

    args = parser.parse_args()

    cmds = {
        "register":   cmd_register,
        "verify":     cmd_verify,
        "login":      cmd_login,
        "whoami":     cmd_whoami,
        "upload":     cmd_upload,
        "download":   cmd_download,
        "records":    cmd_records,
        "grant":      cmd_grant,
        "revoke":     cmd_revoke,
        "perms":      cmd_perms,
        "inbox":      cmd_inbox,
        "rotate-key": cmd_rotate_key,
        "logout":     cmd_logout,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()

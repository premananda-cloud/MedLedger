# MedLedger Architecture

**Version:** 2.1 | **Date:** June 2026 | **Status:** Current — Reflects Deployed System

---

## 1. Executive Summary

MedLedger is a **low-trust, ephemeral sharing conduit** for patient-controlled medical records. The patient holds their physical records. MedLedger provides the cryptographic infrastructure to share them securely with doctors, specialists, or family — without ever seeing the plaintext, without holding the keys, and without storing data permanently.

**Core Principle:** *We are a means, not a vault. We store ciphertext we cannot read, for a limited time, at the patient's discretion. We cannot be compelled to decrypt what we do not possess.*

The system splits into two independent domains:
- **Auth Domain** (`auth/`, `services/`): Multi-step registration (PoW, email verification, TOTP, password). Python/FastAPI, PostgreSQL, Argon2id.
- **Crypto Domain** (`key_manager/`): libsodium-based key operations (Ed25519, X25519, sealed-box encryption). Runs entirely in the browser.

These domains meet at registration: the auth system creates the user account while the crypto system generates the keypair, and the public keys are stored together in one request.

---

## 2. Two-Layer Access Model

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: GATE (Server-Managed, Anti-Spam)                      │
│  ─────────────────────────────────────────────────────────────  │
│  • Email (verified via 6-digit code)                            │
│  • Proof-of-work (CPU cost to deter automation)                 │
│  • Rate limiting (per-IP, per-email lockout)                    │
│  • TOTP optional second factor                                  │
│  • JWT access token + opaque refresh token (Bearer header)      │
│  • Purpose: Filter noise. Attach a human to a public key.       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ (decoupled — Layer 1 does not grant vault access)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2: KEYSET (Patient-Sovereign, Non-Recoverable)           │
│  ─────────────────────────────────────────────────────────────  │
│  • Ed25519/X25519 keypair generated in browser (libsodium.js)   │
│  • Private key held client-side only (memory or keypair file)   │
│  • Public keys stored server-side as cryptographic anchor       │
│  • Server knows: signing_public_key, exchange_public_key        │
│  • Server never knows: private key, plaintext DEK               │
│  • Lost keyset = locked forever. No recovery. Delete & restart. │
└─────────────────────────────────────────────────────────────────┘
```

### Why Two Layers?

| Concern | Layer 1 (Gate) | Layer 2 (Keyset) |
|---------|---------------|------------------|
| **Purpose** | Anti-spam, session identity | Cryptographic identity, encryption, signing |
| **Who controls** | Server + User | User only |
| **Recovery** | Password reset via email code | None — delete account and start over |
| **Server knowledge** | Email, password hash (Argon2id) | Public keys only |
| **Compromise impact** | Account access — no data decryption | Nothing — private key never transmitted |
| **HIPAA posture** | Minimal data (no PHI) | Zero-knowledge — server cannot decrypt |

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         BROWSER (Client)                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │  React + Vite   │  │  Key Manager    │  │  libsodium.js       │  │
│  │  UI Layer       │  │  (JS Module)    │  │  (Ed25519/X25519)   │  │
│  │                 │  │                 │  │                     │  │
│  │  • Login Page   │  │  • createUser() │  │  • Ed25519 keygen   │  │
│  │  • Share UI     │  │  • loginUser()  │  │  • X25519 keygen    │  │
│  │  • Inbox/Outbox │  │  • signPayload()│  │  • Sealed boxes     │  │
│  │  • Keypair Modal│  │  • encryptRecord│  │  • XSalsa20-Poly1305│  │
│  │  • Download Flow│  │  • decryptShare │  │  • BLAKE2b hashing  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│                              │                                        │
│              HTTPS + Authorization: Bearer <access_token>            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│              SERVER (Python 3.11 / FastAPI / PostgreSQL)            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │  routes/        │  │  services/      │  │  database/          │  │
│  │  auth.py        │  │  auth_service   │  │  repository.py      │  │
│  │  keys.py        │  │  key_service    │  │                     │  │
│  │  vault.py       │  │  grant_service  │  │  PostgreSQL via     │  │
│  │  grants.py      │  │  audit_service  │  │  SQLAlchemy async   │  │
│  │  shares.py      │  │  relay_service  │  │                     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  auth/ (pure Python modules — no I/O, no DB access)            │ │
│  │  password.py  — Argon2id hashing; PBKDF2 verify for migration  │ │
│  │  pow.py       — PoW challenge/verify                            │ │
│  │  email.py     — 6-digit code generation + Gmail delivery        │ │
│  │  totp.py      — TOTP enrollment and verification                │ │
│  │  token.py     — JWT creation and verification                   │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Definitions

### 4.1 Frontend

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **React SPA** | Vite + React | UI rendering, routing, state management |
| **Keyset Manager** | libsodium.js module | All crypto operations, key lifecycle, memory management |
| **API client** | fetch wrapper | JWT header injection, 401 refresh retry, error handling |

The Keyset Manager is encapsulated. The React layer calls it via a defined API — never directly manipulates `Uint8Array` key material.

### 4.2 Auth Domain (`auth/`)

| Module | Tech | Responsibility |
|--------|------|----------------|
| **PasswordModule** | argon2-cffi | Hash passwords (Argon2id). Verify legacy PBKDF2 hashes and rehash on login. |
| **POWModule** | hashlib SHA-256 | Challenge generation and verification |
| **EmailAuthModule** | Gmail SMTP | 6-digit code generation and delivery |
| **TOTPModule** | pyotp | TOTP secret generation, backup codes, verification |
| **TokenModule** | PyJWT | JWT creation and verification |

All modules are stateless pure functions. No DB access. No I/O except EmailAuthModule. Orchestration is in `services/auth_service.py`.

### 4.3 Services Layer (`services/`)

| Service | Responsibility |
|---------|----------------|
| **AuthService** | Registration, login, email verify, TOTP, password management, token lifecycle |
| **KeyService** | Public key storage and lookup — keys arrive from frontend, server stores and serves |
| **GrantService** | Access grant creation, revocation, lookup, DEK bundle distribution |
| **AuditService** | Append-only auth and vault event logging |
| **RelayService** | Zero-knowledge share relay — stores ciphertext, never reads it |

### 4.4 Database Layer (`database/`)

Single `DatabaseRepository` class wrapping all PostgreSQL operations via SQLAlchemy async. Services import only the repository — no raw SQL anywhere else in the codebase.

---

## 5. Data Flows

### 5.1 Registration

```
Browser → User fills form (email, username, password, full_name)
       → GET /auth/pow/challenge → solve PoW
       → KeysetManager.createUser(username)
           → Ed25519 + X25519 keypairs generated
           → Returns public keys + private keys
       → Prompt user to download .medledger-key.json
       → POST /auth/register with:
           { email, username, password, full_name,
             signing_public_key, exchange_public_key }

Server → Validate password strength
       → Check email + username availability
       → Hash password (Argon2id — single self-contained string)
       → Create user row (password_hash + public keys in one INSERT)
       → Send 6-digit code to email (store SHA-256 hash, not code)
       → Return 202 + message

Browser → User enters the 6-digit code
       → POST /auth/verify-email { email, code }

Server → Verify code hash + expiry (timing-safe comparison)
       → Mark is_verified = 1
       → Issue JWT access token + opaque refresh token
       → Return 200 + { tokens, user }

Browser → Vault unlocked (keypair already in KeysetManager from generation)
```

### 5.2 Login

```
Browser → POST /auth/login { email, password }

Server → _check_login_lockout() FIRST (prevents timing oracle for locked accounts)
       → get_user_by_email()
       → verify_password(password, stored_hash) — always runs, dummy hash if no user
       → On failure: increment failure counter, raise 401
       → On TOTP enabled: return { requires_totp: true, user_id_hex }
       → On success: issue tokens, reset rate limit, audit log
       → Return { tokens, user }

Browser → Vault shows "Locked" until user supplies keypair file
       → User uploads .medledger-key.json
       → KeysetManager.loginUser(username, keypair)
       → Vault unlocked — no server call (Layer 2 is client-side only)
```

### 5.3 Share Creation

```
Browser → Fetch recipient exchange key: GET /keys/{user_id_hex}/exchange
       → KeysetManager.encryptRecord(fileBytes, recipientExchangePublicKey)
           1. Random 256-bit DEK
           2. XSalsa20-Poly1305: encrypt file → { encryptedRecord, nonce }
           3. crypto_box_seal(DEK, recipientPublicKey) → dekBundle
           4. memzero(DEK)
       → KeysetManager.signPayload(grantMetadata)
       → POST to vault/grant endpoint with ciphertext + dekBundle + signature

Server → Verify JWT
       → Store ciphertext + dekBundle (cannot read either)
       → Return record/grant ID
```

### 5.4 Share Retrieval (Client-Side Decryption)

```
Browser → Fetch ciphertext from server
       → KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle)
           1. crypto_box_seal_open(dekBundle, myPublicKey, myPrivateKey) → DEK
           2. crypto_secretbox_open_easy(ciphertext, nonce, DEK) → plaintext
           3. memzero(DEK) in finally block
       → Browser download of plaintext

Server never sees plaintext. Decryption is entirely in the browser.
```

---

## 6. Vault State Machine

```
                    ┌─────────────┐
                    │  NO ACCOUNT  │
                    └──────┬──────┘
                           │ Register (PoW + keygen + email verify)
                           ▼
                    ┌──────────────┐
                    │  LOGGED IN   │
                    │  Vault: LOCKED
                    └──────┬──────┘
                           │ Upload Keypair File (client-side only)
                           ▼
                    ┌──────────────┐
                    │  LOGGED IN   │
                    │ Vault: UNLOCKED
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌──────────┐
        │ Create  │  │ Retrieve│  │ Lock /   │
        │ Grants  │  │ Shares  │  │ Logout   │
        └─────────┘  └─────────┘  └────┬─────┘
                                        │
                                 ┌──────┴──────┐
                                 │ LOCKED or   │
                                 │ LOGGED OUT  │
                                 └─────────────┘
```

**State transitions:**
- `NO ACCOUNT → LOCKED`: Register (PoW + keys + email verify → tokens)
- `LOGGED OUT → LOCKED`: Login with email + password
- `LOCKED → UNLOCKED`: Client-side keypair load (KeysetManager.loginUser)
- `UNLOCKED → LOCKED`: Lock vault (memzero private keys) — still logged in
- `UNLOCKED → LOGGED OUT`: Full logout (revoke tokens + memzero keys)

---

## 7. Database Schema (Actual)

### 7.1 users

| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER | PK, autoincrement |
| user_id_hex | TEXT UNIQUE | Identity anchor |
| username | TEXT UNIQUE | Case-insensitive |
| email | TEXT UNIQUE | |
| full_name | TEXT | |
| role | TEXT | Default 'PATIENT' |
| password_hash | TEXT | Argon2id string (salt embedded — no separate salt column) |
| signing_public_key | TEXT | Ed25519, base64url |
| exchange_public_key | TEXT | X25519, base64url |
| is_verified | INTEGER | 0/1 |
| totp_enabled | INTEGER | 0/1 |
| totp_secret | TEXT | base32 |
| is_active | INTEGER | 0/1 |
| account_deleted | INTEGER | 0/1 |
| verification_token | TEXT | SHA-256 of email code — not the code itself |
| token_expires_at | TEXT | ISO timestamp |
| last_login_at | TEXT | |
| created_at | TEXT | |

### 7.2 active_shares

| Column | Notes |
|--------|-------|
| share_id | UNIQUE UUID |
| short_code | Human-readable retrieval code |
| owner_user_id_hex, grantee_user_id_hex | Identity anchors |
| ciphertext | Encrypted file (BLOB) |
| dek_bundle | DEK sealed for grantee — server cannot open |
| nonce | XSalsa20 nonce |
| filename, mime_type, size_bytes | Plaintext metadata |
| status | 'active', 'retrieved', 'expired', 'revoked' |
| expires_at | TTL deadline |
| delete_on_download | Default 1 |

### 7.3 grants

| Column | Notes |
|--------|-------|
| grant_id | UNIQUE |
| record_id | FK → vault_records |
| grantor_key_hash, grantee_key_hash | Crypto identity (not user_id_hex) |
| grantee_user_id_hex | Human identity anchor |
| grantee_public_key_hex | For DEK re-encryption if needed |
| permission_level | 'view_only' or 'view_download' |
| time_start, time_end | Access window |
| dek_bundle_grantee | DEK sealed for grantee — server cannot open |
| signature_hex | Ed25519 signature over grant payload |
| revoked | 0/1 |

### 7.4 vault_records

| Column | Notes |
|--------|-------|
| record_id | UNIQUE |
| owner_key_hash, owner_user_id_hex | Owner identity |
| owner_public_key_hex | Owner's encryption key at time of upload |
| filename, mime_type, size_bytes, iv_hex | Plaintext metadata |
| tags | JSON array |

### 7.5 audit_log

| Column | Notes |
|--------|-------|
| actor_user_id_hex | Who performed the action |
| action | Event type (login, register, share_created, etc.) |
| ip_address, user_agent | Request context |
| detail | JSON — no PHI |
| timestamp | UTC |

---

## 8. API Endpoint Map

### 8.1 Auth (`/auth/*`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/pow/challenge | None | Issue PoW challenge |
| POST | /auth/pow/verify | None | Verify PoW solution |
| POST | /auth/register | None | Register + store public keys (single request) |
| POST | /auth/verify-email | None | Verify email code → issue tokens |
| POST | /auth/resend-verification | None | Resend verification code |
| POST | /auth/login | None | Password login |
| POST | /auth/verify-totp-login | None | Complete TOTP second factor |
| POST | /auth/refresh | None | Rotate refresh token |
| POST | /auth/logout | JWT | Revoke current session |
| POST | /auth/logout-all | JWT | Revoke all sessions |
| POST | /auth/change-password | JWT | Change password, revoke all tokens |
| POST | /auth/request-password-reset | None | Send reset code to email |
| POST | /auth/confirm-password-reset | None | Verify code + set new password |
| POST | /auth/totp/setup | JWT | Begin TOTP enrollment |
| POST | /auth/totp/confirm | JWT | Confirm with live code |
| POST | /auth/totp/disable | JWT | Disable TOTP |
| GET  | /auth/me | JWT | Current user profile |

### 8.2 Keys (`/keys/*`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /keys/my | JWT | Own public keys |
| GET | /keys/{user_id_hex} | JWT | Both keys for a user |
| GET | /keys/{user_id_hex}/exchange | JWT | X25519 key only |
| GET | /keys/{user_id_hex}/signing | JWT | Ed25519 key only |
| PUT | /keys/update | JWT | Update own public keys |

---

## 9. Keypair File Format (v1)

```json
{
  "version": "medledger-keypair-v1",
  "username": "alice",
  "user_id_hex": "a1b2c3d4...",
  "signing_public_key": "base64url...",
  "exchange_public_key": "base64url...",
  "signing_private_key": "base64url...",
  "exchange_private_key": "base64url...",
  "created_at": "2026-06-07T23:10:00Z"
}
```

Key sizes: Ed25519 public 32 bytes, private 64 bytes. X25519 public and private 32 bytes each. All base64url without padding.

Private keys are unencrypted in v1. Password-encryption is planned for v1.1.

---

## 10. Deployment Topology

```
┌─────────────────┐         ┌─────────────────┐
│   Vercel        │         │   Railway         │
│   (Frontend)    │         │   (Backend)       │
│                 │         │                   │
│  React SPA      │◄──────►│  FastAPI          │
│  Static build   │  HTTPS  │  PostgreSQL       │
└─────────────────┘         └─────────────────┘
```

- Frontend: `app.medledger.com` → Vercel
- Backend: `api.medledger.com` → Railway
- Auth: `Authorization: Bearer <access_token>` header on all protected routes
- CORS: backend allows frontend origin with credentials

---

## 11. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.** Not in headers, not in logs, not in storage.
2. **Server stores only public material and ciphertext.** Never plaintext, never private keys.
3. **We cannot decrypt medical data.** Mathematical guarantee, not policy.
4. **Every share is cryptographically targeted.** DEK sealed for a specific recipient key.
5. **Argon2id for all new password hashes.** PBKDF2 hashes rehashed on first login.
6. **Lockout check before password verification.** Prevents timing oracle on locked accounts.
7. **Verification tokens stored as SHA-256 hashes.** Plain codes never persisted.
8. **Audit everything.** Every auth event logged with actor, IP, and timestamp.
9. **No private keys in API responses.** Key endpoints return public keys only.
10. **Honest UI.** "We cannot recover your keypair. We cannot read your data."

---

*Document: 01-ARCHITECTURE.md | Version: 2.1 | June 2026*
*Reflects deployed system: Python/FastAPI, PostgreSQL, Argon2id, Bearer JWT*

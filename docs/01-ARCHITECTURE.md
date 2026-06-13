# MedLedger Architecture

**Version:** 2.0 | **Date:** June 2026 | **Status:** Draft — Production Architecture

---

## 1. Executive Summary

MedLedger is a **low-trust, ephemeral sharing conduit** for patient-controlled medical records. The patient holds their physical records. MedLedger provides the cryptographic infrastructure to share them securely with doctors, specialists, or family — without ever seeing the plaintext, without holding the keys, and without storing data permanently.

**Core Principle:** *We are a means, not a vault. We store ciphertext we cannot read, for a limited time, at the patient's discretion. We cannot be compelled to decrypt what we do not possess.*

**Implementation Reality:** The system is split into two independent domains that communicate through a thin integration layer:
- **Auth Domain** (`auth/`): Traditional multi-step registration (POW, email, TOTP, username/password)
- **Crypto Domain** (`key_manager/`): libsodium-based key operations (Ed25519, X25519, sealed-box encryption)

These domains are bridged at registration time: the auth system creates the user account, then the crypto system generates a keypair that becomes the user's cryptographic identity.

---

## 2. Two-Layer Access Model

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: GATE (Server-Managed, Anti-Spam)                      │
│  ───────────────────────────────────────────────────────          │
│  • Email (verified, disposable-allowed, spam-filtered)            │
│  • Human verification (CAPTCHA / Turnstile)                     │
│  • Proof-of-work (CPU cost to deter automation)                 │
│  • Rate limiting (IP, domain, temporal)                         │
│  • JWT session (short-lived, HttpOnly cookie)                   │
│  • Purpose: Filter noise. Attach a human to a public key.       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ (decoupled — Layer 1 does not grant vault access)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2: KEYSET (Patient-Sovereign, Non-Recoverable)           │
│  ───────────────────────────────────────────────────────          │
│  • Ed25519/X25519 Keypair generated in browser (libsodium.js)   │
│  • Private key held client-side only (memory, or keypair file)  │
│  • Public key hash = identity anchor for all server interactions  │
│  • Server knows: public key hash, encrypted blob (optional)     │
│  • Server never knows: private key, password, plaintext DEK     │
│  • Lost keyset = locked forever. No recovery. Delete & restart.  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Two Layers?

| Concern | Layer 1 (Gate) | Layer 2 (Keyset) |
|---------|---------------|------------------|
| **Purpose** | Anti-spam, session identity | Cryptographic identity, encryption, signing |
| **Who controls** | Server + User | User only |
| **Recovery** | None. Delete account, start over. | None. Delete account, start over. |
| **Server knowledge** | Email hash, CAPTCHA token, PoW nonce | Public key hash, encrypted blob (if stored) |
| **Compromise impact** | Spam, noise — no data access | Nothing — private key never transmitted |
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
│           │                    │                    │               │
│           └────────────────────┴────────────────────┘               │
│                              │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │  Integration Layer (shared/)                                     ││
│  │  • registerBridge.js — wires auth → key_manager                ││
│  │  • loginBridge.js — loads keypair, unlocks vault              ││
│  │  • apiClient.js — JWT cookie handling, fetch wrapper           ││
│  └─────────────────────────────────────────────────────────────────┘│
│                              │                                      │
│                         HTTPS / JSON                                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│                         SERVER (FastAPI / Node.js)                  │
│  ┌─────────────────┐  ┌──────┴──────────┐  ┌─────────────────────┐  │
│  │  API Router     │  │  Gate Service   │  │  Share Service      │  │
│  │  (Endpoints)    │  │  (Layer 1)      │  │  (Layer 2 aware)    │  │
│  │                 │  │                 │  │                     │  │
│  │  /api/register  │  │  • CAPTCHA      │  │  • Store ciphertext │  │
│  │  /api/login     │  │  • PoW verify   │  │  • Store DEK bundle │  │
│  │  /api/share/*   │  │  • Rate limit   │  │  • TTL enforcement  │  │
│  │  /api/account   │  │  • JWT issue    │  │  • Delete on fetch  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│           │                    │                    │               │
│           └────────────────────┴────────────────────┘               │
│                              │                                      │
│  ┌───────────────────────────────────────────────────────────────── │
│  │  Store Layer (PostgreSQL / JSON file)                            │
│  │  • users (email, public_key_hash, password_hash, pubkeys, ts)     │
│  │  • active_shares (ciphertext, DEK bundle, TTL, expiry)          │
│  │  • audit_log (immutable, 7-year retention)                       │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Definitions

### 4.1 Frontend

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **React SPA** | Vite + TanStack Router | UI rendering, routing, state management |
| **TanStack Query** | React hooks | API calls, caching, background refresh |
| **Keyset Manager** | libsodium.js module | All crypto operations, key lifecycle, memory management |
| **Integration Layer** | Vanilla JS | Bridges auth state and crypto state |

The Keyset Manager is **encapsulated**. The React layer calls it via a defined API — never directly manipulates Uint8Array key material.

### 4.2 Auth Domain (`auth/`)

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **Auth Flow** | Node.js orchestrator | Multi-step registration: POW → Email → TOTP → User/Pass |
| **POW Module** | SHA-256 | Anti-spam challenge generation/verification |
| **Email Module** | crypto.randomInt | 6-digit code generation (currently used for verification) |
| **TOTP Module** | speakeasy + qrcode | 2FA enrollment and verification |
| **User Module** | PBKDF2-SHA512 | Password validation and hashing |
| **Storage** | JSON file | User record persistence |

**Note:** The auth domain is a standalone system. It knows nothing about cryptography. It produces a user record that the integration layer then extends with cryptographic identity.

### 4.3 Crypto Domain (`key_manager/`)

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **make_key.js** | libsodium.js | Pure key derivation/generation function |
| **key_manager.js** | libsodium.js | Session state machine, all crypto operations |
| **Tests** | Vitest | Unit tests for key derivation, encryption, signing |

**Key design principle:** Keys are randomly generated — not derived from a password. The user receives their private keypair once at registration and must store it securely. Lost keys mean lost access to past shares.

### 4.4 Integration Layer (`shared/`)

| Component | Responsibility |
|-----------|-------------|
| **registerBridge.js** | Calls authFlow.createAccount() → KeysetManager.createUser() → prompts keypair download → stores public keys server-side |
| **loginBridge.js** | Loads keypair file → KeysetManager.loginUser() → verifies against server public keys → unlocks vault |
| **apiClient.js** | fetch wrapper with credentials: 'include', JWT refresh logic, CSRF token handling |

---

## 5. Data Flows

### 5.1 Registration (Layer 1 + Keypair Generation)

```
Browser → User enters email + password
       → Completes CAPTCHA (Turnstile)
       → Browser solves PoW (~1 second, background)
       → Browser calls authFlow.createAccount(username, password)
           1. Auth domain validates username uniqueness
           2. PBKDF2: hash password with random salt (600k iter)
           3. Store user record in data/users.json
           4. Return { userId, username }

       → Integration layer calls KeysetManager.createUser(username)
           1. libsodium.js: crypto_sign_keypair() → Ed25519 keypair
           2. libsodium.js: crypto_box_keypair() → X25519 keypair
           3. Return: { signingPublicKey, exchangePublicKey, userIdHex,
                        signingPrivateKey, exchangePrivateKey }

       → Browser triggers download: "alice.medledger-key.json"
           { version, username, userIdHex, publicKeys, privateKeys }

       → Browser calls POST /api/register/keys
           Headers: Bearer <JWT>
           Body: { username, userIdHex, signingPublicKey, exchangePublicKey }

Server → Verify JWT
       → Store public keys in user record
       → Return: { registered: true }

→ User is now logged in (Layer 1). Vault shows "Locked" until keypair is loaded.
```

### 5.2 Keypair Loading (Unlocking Layer 2)

```
Browser → User clicks "Unlock Vault"
       → Uploads .medledger-key.json file + enters password (if encrypted)
       → Integration layer reads file, reconstructs keypair
       → KeysetManager.loginUser(username, keypair)
           1. Validate keypair format (correct lengths, valid base64)
           2. Derive userIdHex from signingPublicKey (BLAKE2b)
           3. Verify userIdHex matches server-stored value
           4. Store private keys in module memory (Uint8Array)
           5. Mark session as unlocked
       → Dashboard shows "Unlocked"
       → Share / download operations now available
```

### 5.3 Share Creation (Upload & Encrypt)

```
Browser → User selects file
       → User enters recipient's username (or scans QR)
       → Server lookup: recipient username → exchangePublicKey
       → KeysetManager.encryptRecord(fileBytes, recipientExchangePublicKey)
           1. Generate random 256-bit DEK (libsodium randombytes_buf)
           2. XSalsa20-Poly1305 encrypt file → { nonce, ciphertext }
           3. crypto_box_seal: encrypt DEK with recipient's X25519 public key
           4. Wipe DEK from memory (sodium.memzero)
           5. Return: { encryptedRecord, nonce, dekBundle, fileHash }

       → KeysetManager.signPayload(grantMetadata)
           1. Canonical-JSON serialize payload
           2. Ed25519 sign with sender's private key
           3. Return: { payloadCanon, signature }

Browser → POST /api/share
       Headers: Bearer <JWT>
       Body: { encryptedRecord, nonce, dekBundle, recipientUserIdHex,
               filename, mime_type, size_bytes, ttl_days, signature, payloadCanon }

Server → Verify JWT, extract user_id
       → Verify Ed25519 signature against sender's public key
       → Store in active_shares table
       → Set expires_at = NOW() + ttl_days (max 90, default 30)
       → Return: { share_id, short_url, expires_at }

→ User sends short_url to recipient (out of band: SMS, email, QR)
```

### 5.4 Recipient Download (Decrypt & Delete)

```
Browser → Recipient clicks short_url
       → Prompted to upload .medledger-key.json file
       → Integration layer loads keypair → KeysetManager.loginUser()
       → Browser calls POST /api/share/:id/retrieve
           Headers: Bearer <JWT>
           Body: { signature: Ed25519(retrievalPayload) }

Server → Verify JWT, check if recipient matches share.grantee
       → Verify Ed25519 signature
       → Return: { encryptedRecord, nonce, dekBundle, filename, mime_type }
       → If delete_on_download: mark row for deletion (or hard delete)

Browser → KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle)
           1. crypto_box_seal_open: decrypt DEK with recipient's X25519 private key
           2. crypto_secretbox_open_easy: decrypt file with DEK
           3. Wipe DEK from memory (sodium.memzero)
           4. Trigger browser download of decrypted file

→ Server never sees plaintext. Decryption happens entirely in browser.
```

### 5.5 Account Deletion (Absolute Destruction)

```
Browser → User clicks "Delete My Account"
       → Type "DELETE" to confirm
       → Browser calls DELETE /api/account
           Headers: Bearer <JWT>
           Body: { password_confirmation }

Server → Verify JWT, verify password (Argon2id or PBKDF2)
       → Hard delete: user record, all active_shares, keypair data
       → Audit logs: anonymize (strip email, keep action type)
       → Invalidate JWT cookie

Browser → Clear JWT, clear keypair from memory, redirect to landing page

→ Old recipients lose access immediately. Patient can register again with new keypair.
```

---

## 6. State Machine: Vault Lifecycle

```
                    ┌─────────────┐
                    │   NO ACCOUNT │
                    └──────┬──────┘
                           │ Register (CAPTCHA + PoW + keygen)
                           ▼
                    ┌─────────────┐
                    │  ACCOUNT +  │
                    │  KEYPAIR    │
                    │  Vault: LOCKED│
                    └──────┬──────┘
                           │ Upload Keypair File
                           ▼
                    ┌─────────────┐
                    │  KEYPAIR    │
                    │  Vault: UNLOCKED│
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ Share   │  │ Retrieve│  │ Delete  │
        │ File    │  │ Inbox   │  │ Account │
        └─────────┘  └─────────┘  └─────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  ACCOUNT    │
                    │  DELETED    │
                    │  (absolute) │
                    └─────────────┘
```

---

## 7. Database Schema

### 7.1 users (Layer 1 + Layer 2 Anchor)

| Column | Type | Notes |
|--------|------|-------|
| user_id | UUID | PK |
| username | VARCHAR(30) | UNIQUE, case-insensitive, no recovery |
| email | VARCHAR(255) | For rate-limiting, not verification |
| email_hash | VARCHAR(64) | SHA-256 of email (for lookups) |
| password_hash | VARCHAR(255) | PBKDF2-SHA512 (current) or Argon2id (target) |
| salt | VARCHAR(64) | 16 random bytes, hex |
| signing_public_key | VARCHAR(64) | Ed25519 public key, base64url |
| exchange_public_key | VARCHAR(64) | X25519 public key, base64url |
| user_id_hex | VARCHAR(32) | BLAKE2b(signingPublicKey, 16), identity anchor |
| created_at | TIMESTAMP | UTC |
| last_login | TIMESTAMP | UTC |
| deleted_at | TIMESTAMP | NULL if active |

### 7.2 active_shares (Ephemeral Storage)

| Column | Type | Notes |
|--------|------|-------|
| share_id | UUID | PK |
| owner_user_id_hex | VARCHAR(32) | FK → users.user_id_hex |
| grantee_user_id_hex | VARCHAR(32) | FK → users.user_id_hex |
| ciphertext | BYTEA | XSalsa20-Poly1305 encrypted file |
| dek_bundle | TEXT | crypto_box_seal encrypted DEK |
| nonce | TEXT | XSalsa20 nonce, base64url |
| filename | VARCHAR(255) | Original filename |
| mime_type | VARCHAR(100) | File type |
| size_bytes | INTEGER | Original size |
| file_hash | VARCHAR(64) | BLAKE2b-256 of plaintext (integrity) |
| signature | TEXT | Ed25519 signature of grant metadata |
| payload_canon | TEXT | Canonical JSON that was signed |
| created_at | TIMESTAMP | UTC |
| expires_at | TIMESTAMP | UTC. NOW() + ttl_days. |
| downloaded_at | TIMESTAMP | NULL if not yet downloaded |
| delete_on_download | BOOLEAN | Default true |
| deleted_at | TIMESTAMP | NULL if active |

### 7.3 audit_log (Immutable, 7-Year Retention)

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| actor_user_id_hex | VARCHAR(32) | Who did it (anonymized if account deleted) |
| action | VARCHAR(50) | register, login, share, retrieve, delete_account |
| share_id | UUID | FK, nullable |
| detail | JSONB | Contextual data (no PHI, no emails) |
| ip_address | INET | Request source |
| timestamp | TIMESTAMP | UTC |

---

## 8. API Endpoint Map

### 8.1 Gate (Layer 1)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/pow-challenge | None | Generate SHA-256 PoW challenge |
| POST | /api/register | None | CAPTCHA + PoW + auth registration |
| POST | /api/register/keys | Bearer | Store public keys after registration |
| POST | /api/login | None | Username + password → JWT |
| POST | /api/logout | Bearer | Invalidate session |
| GET | /api/me | Bearer | Current user profile + public keys |
| DELETE | /api/account | Bearer | Absolute deletion |
| GET | /api/health | None | Health check |

### 8.2 Share (Layer 2)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/share | Bearer + Keyset | Create encrypted share |
| POST | /api/share/:id/retrieve | Bearer + Keyset | Download and decrypt |
| GET | /api/shares/outbox | Bearer | Shares I created |
| GET | /api/shares/inbox | Bearer | Shares sent to me |
| DELETE | /api/share/:id | Bearer + Keyset | Revoke/cancel share |

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
  "created_at": "2026-06-07T23:10:00Z",
  "metadata": {
    "generated_by": "MedLedger Keyset Manager",
    "generator_version": "2.0"
  }
}
```

**Constraints:**
- `signing_public_key` is Ed25519, 32 bytes (43 chars base64url)
- `exchange_public_key` is X25519, 32 bytes (43 chars base64url)
- `user_id_hex` is BLAKE2b-128 of signingPublicKey, 16 bytes (32 hex chars)
- Private keys are base64url-encoded raw bytes (not encrypted in v1)
- File extension: `.medledger-key.json`

**Security note:** In a future version, the private keys may be encrypted with a user password before storage. For now, the user is responsible for securing the file.

---

## 10. Deployment Topology

```
┌─────────────────┐         ┌─────────────────┐
│   Vercel        │         │   Railway         │
│   (Frontend)    │         │   (Backend)       │
│                 │         │                 │
│  React SPA      │◄──────►│  FastAPI/Node.js  │
│  Static build   │  HTTPS  │  PostgreSQL       │
│  Edge CDN       │         │  Redis (sessions) │
└─────────────────┘         └─────────────────┘
         │                           │
         │    ┌─────────────────┐   │
         └───►│  Cloudflare DNS   │◄──┘
              │  + SSL + DDoS     │
              └─────────────────┘
```

**Domains:**
- `app.medledger.com` → Vercel (frontend)
- `api.medledger.com` → Railway (backend)
- CORS: `api.medledger.com` allows `app.medledger.com` with credentials

**Cookies:**
- JWT stored in HttpOnly, SameSite=Strict, Secure cookie
- Domain: `api.medledger.com`
- Keypair state: NOT in cookies — purely client-side memory or file

---

## 11. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.** Not in cookies, not in storage, not in logs.
2. **Server stores only public material and ciphertext.** Public keys, ciphertext, encrypted DEK bundles, signatures.
3. **We cannot decrypt medical data.** Mathematical guarantee, not policy.
4. **Every share is cryptographically targeted.** DEK is sealed for a specific recipient public key.
5. **DEKs are always sealed.** Plaintext DEK never exists server-side.
6. **No account recovery.** Lost email, password, or keypair = delete account and start over. We cannot help.
7. **Email is anti-spam only.** Used for rate-limiting, not for recovery. Disposable emails allowed.
8. **All shares have TTL.** Maximum 90 days, default 30 days. After expiry, server deletes.
9. **Account deletion is absolute.** Hard delete all shares, anonymize audit logs.
10. **Audit everything.** Every share, every retrieve, every registration logged.
11. **Honest UI.** "We cannot recover your keypair. We cannot read your data. We are not a storage company."

---

*Document: 01-ARCHITECTURE.md | Author: Premananda (Team Praxis) | Status: Draft v2.0*
*Updated: June 2026 to reflect actual two-domain implementation*

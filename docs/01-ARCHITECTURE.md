# MedLedger Architecture

**Version:** 1.0 | **Date:** June 2026 | **Status:** Draft — Production Architecture

---

## 1. Executive Summary

MedLedger is a **low-trust, ephemeral sharing conduit** for patient-controlled medical records. The patient holds their physical records. MedLedger provides the cryptographic infrastructure to share them securely with doctors, specialists, or family — without ever seeing the plaintext, without holding the keys, and without storing data permanently.

**Core Principle:** *We are a means, not a vault. We store ciphertext we cannot read, for a limited time, at the patient's discretion. We cannot be compelled to decrypt what we do not possess.*

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
│  • P-256 Keypair generated in browser (Web Crypto API)            │
│  • Private key encrypted with patient password, held client-side  │
│  • Public key hash = identity anchor for all server interactions  │
│  • Server knows: public key hash, encrypted blob (optional)     │
│  • Server never knows: private key, password, plaintext DEK      │
│  • Lost keyset = locked forever. No recovery. Delete & restart. │
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
│  │  React + Vite   │  │  Keyset Manager │  │  Web Crypto API     │  │
│  │  UI Layer       │  │  (JS Module)    │  │  (SubtleCrypto)     │  │
│  │                 │  │                 │  │                     │  │
│  │  • Login Page   │  │  • generate()   │  │  • P-256 keygen     │  │
│  │  • Share UI     │  │  • load()       │  │  • ECDH / ECIES     │  │
│  │  • Inbox/Outbox │  │  • sign()       │  │  • ECDSA sign       │  │
│  │  • Keyset Modal │  │  • encrypt()    │  │  • AES-256-GCM      │  │
│  │  • Download Flow│  │  • decrypt()    │  │  • PBKDF2           │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│           │                    │                    │               │
│           └────────────────────┴────────────────────┘               │
│                              │                                      │
│                         HTTPS / JSON                                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│                         SERVER (FastAPI)                            │
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
│  │  Store Layer (PostgreSQL)                                        │ │
│  │  • users (email, public_key_hash, encrypted_blob, timestamps)    │ │
│  │  • active_shares (ciphertext, DEK bundle, TTL, expiry)         │ │
│  │  • audit_log (immutable, 7-year retention)                       │ │
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
| **Keyset Manager** | Vanilla JS module | All crypto operations, key lifecycle, memory management |
| **Web Crypto API** | Browser native | P-256, ECDH, ECDSA, AES-GCM, PBKDF2 |

The Keyset Manager is **encapsulated**. The React layer calls it via a defined API — never directly manipulates CryptoKey objects or raw buffers.

### 4.2 Backend

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **FastAPI** | Python 3.12+ | HTTP routing, dependency injection, OpenAPI docs |
| **Gate Service** | JWT + CAPTCHA + PoW | Layer 1: anti-spam, rate limiting, session management |
| **Share Service** | PostgreSQL | Layer 2: ciphertext storage, TTL enforcement, deletion |
| **Store Layer** | psycopg2 / asyncpg | Typed dataclasses, atomic writes, query interface |

### 4.3 CLI Companion

| Component | Tech | Responsibility |
|-----------|------|----------------|
| **client.py** | Python + requests | Standalone CLI for power users, same keyset format, same API |

---

## 5. Data Flows

### 5.1 Registration (Layer 1 + Keyset Generation)

```
Browser → User enters email + password
       → Completes CAPTCHA (Turnstile)
       → Browser solves PoW (~1 second, background)
       → Browser calls Keyset Manager.generate(password)
           1. Web Crypto API: generateKey(ECDSA, P-256) → keypair
           2. Export private key as JWK
           3. PBKDF2: derive AES key from password + random salt (310k+ iter)
           4. AES-256-GCM: encrypt private key JWK
           5. Package: { version, public_key_hex, public_key_hash, encrypted_private_key, created_at }
       → Browser triggers download: "medledger-keyset-2026.json"
       → Browser calls POST /api/register
           Body: { email, password_hash, public_key_hash, encrypted_blob, captcha_token, pow_nonce, pow_solution }

Server → Validate CAPTCHA token
       → Validate PoW solution
       → Check rate limits (IP + email domain)
       → Hash password (Argon2id)
       → Create user record
       → Return JWT (HttpOnly, SameSite=Strict, Secure cookie)

→ User is now logged in. Vault shows "Locked" until keyset is loaded.
```

### 5.2 Keyset Loading (Unlocking Layer 2)

```
Browser → User clicks "Unlock Vault"
       → Uploads keyset file + enters password
       → Keyset Manager.load(keysetFile, password)
           1. Read JSON package
           2. PBKDF2 with stored salt → derive AES key
           3. AES-256-GCM decrypt → private key JWK
           4. Import into Web Crypto API → CryptoKey object (non-extractable)
           5. Hold in memory only
       → Dashboard shows "Unlocked"
       → Share / download operations now available
```

### 5.3 Share Creation (Upload & Encrypt)

```
Browser → User selects file
       → User enters recipient's public key (or scans QR)
       → Keyset Manager.encryptFor(file, recipient_public_key_hex)
           1. Generate random 256-bit DEK (CryptoKey, extractable=false)
           2. AES-256-GCM encrypt file → { iv, ciphertext }
           3. ECDH: derive shared secret from ephemeral_private + recipient_public
           4. HKDF-SHA256(shared_secret, "MedLedger-DEK-v1") → wrap key
           5. AES-256-GCM encrypt DEK with wrap key → dek_bundle
           6. Return: { ciphertext_hex, iv_hex, dek_bundle, filename, tags }

Browser → POST /api/share
       Headers: Bearer <JWT>
       Body: { ciphertext_hex, iv_hex, dek_bundle, recipient_public_key_hash, filename, mime_type, size_bytes, ttl_days, delete_on_download }

Server → Verify JWT, extract public_key_hash
       → Store in active_shares table
       → Set expires_at = NOW() + ttl_days (max 90, default 30)
       → Return: { share_id, short_url, expires_at }

→ User sends short_url to recipient (out of band: SMS, email, QR)
```

### 5.4 Recipient Download (Decrypt & Delete)

```
Browser → Recipient clicks short_url
       → Prompted to upload keyset file + password
       → Keyset Manager.load(keysetFile, password)
       → Browser calls POST /api/share/:id/retrieve
           Headers: Bearer <JWT>

Server → Verify JWT, check if recipient_public_key_hash matches share
       → Return: { ciphertext_hex, iv_hex, dek_bundle, filename, mime_type }
       → If delete_on_download: mark row for deletion (or hard delete)

Browser → Keyset Manager.decrypt(ciphertext_hex, iv_hex, dek_bundle)
           1. ECDH: derive shared secret from recipient_private + ephemeral_public (from dek_bundle)
           2. HKDF-SHA256 → unwrap key
           3. AES-256-GCM decrypt DEK bundle → DEK (CryptoKey)
           4. AES-256-GCM decrypt ciphertext with DEK → plaintext
           5. Zero DEK from memory
           6. Trigger browser download of decrypted file

→ Server never sees plaintext. Decryption happens entirely in browser.
```

### 5.5 Account Deletion (Absolute Destruction)

```
Browser → User clicks "Delete My Account"
       → Type "DELETE" to confirm
       → Browser calls DELETE /api/account
           Headers: Bearer <JWT>

Server → Verify JWT
       → Hard delete: user record, all active_shares, encrypted blobs
       → Audit logs: anonymize (strip email, keep action type for compliance)
       → Invalidate JWT cookie

Browser → Clear JWT, clear keyset from memory, redirect to landing page

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
                    │  KEYSET     │
                    │  Vault: LOCKED│
                    └──────┬──────┘
                           │ Upload Keyset + Password
                           ▼
                    ┌─────────────┐
                    │  KEYSET     │
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
| email | VARCHAR(255) | Verified, rate-limiting key, no recovery |
| email_hash | VARCHAR(64) | SHA-256 of email (for lookups without exposing plaintext) |
| password_hash | VARCHAR(255) | Argon2id |
| public_key_hash | VARCHAR(64) | UNIQUE. Identity anchor. SHA-256 of public_key_hex. |
| encrypted_private_key_blob | JSONB | Optional. Encrypted private key for re-download. |
| captcha_token_used | TEXT | Prevent replay |
| pow_nonce | VARCHAR(64) | Proof-of-work nonce |
| created_at | TIMESTAMP | UTC |
| last_login | TIMESTAMP | UTC |
| deleted_at | TIMESTAMP | NULL if active |

### 7.2 active_shares (Ephemeral Storage)

| Column | Type | Notes |
|--------|------|-------|
| share_id | UUID | PK |
| owner_key_hash | VARCHAR(64) | FK → users.public_key_hash |
| grantee_key_hash | VARCHAR(64) | FK → users.public_key_hash |
| ciphertext | BYTEA | AES-256-GCM encrypted file |
| dek_bundle | JSONB | ECIES-wrapped DEK for grantee |
| filename | VARCHAR(255) | Original filename |
| mime_type | VARCHAR(100) | File type |
| size_bytes | INTEGER | Original size |
| created_at | TIMESTAMP | UTC |
| expires_at | TIMESTAMP | UTC. NOW() + ttl_days. |
| downloaded_at | TIMESTAMP | NULL if not yet downloaded |
| delete_on_download | BOOLEAN | Default true |
| deleted_at | TIMESTAMP | NULL if active |

### 7.3 audit_log (Immutable, 7-Year Retention)

| Column | Type | Notes |
|--------|------|-------|
| id | UUID | PK |
| actor_key_hash | VARCHAR(64) | Who did it (anonymized if account deleted) |
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
| POST | /api/register | None | CAPTCHA + PoW + keyset registration |
| POST | /api/login | None | Email + password → JWT |
| POST | /api/logout | Bearer | Invalidate session |
| GET | /api/me | Bearer | Current user profile |
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

## 9. Keyset Package Format (v1)

```json
{
  "version": "medledger-keyset-v1",
  "public_key_hex": "04a1b2c3...",
  "public_key_hash": "sha256:abc123...",
  "encrypted_private_key": {
    "algorithm": "AES-256-GCM",
    "key_derivation": "PBKDF2",
    "pbkdf2_iterations": 310000,
    "salt": "base64_or_hex",
    "iv": "base64_or_hex",
    "ciphertext": "base64_or_hex",
    "tag": "base64_or_hex"
  },
  "key_algorithm": "ECDSA-P256",
  "created_at": "2026-06-07T23:10:00Z",
  "metadata": {
    "generated_by": "MedLedger Keyset Manager",
    "generator_version": "1.0"
  }
}
```

**Constraints:**
- `public_key_hex` is always uncompressed (65 bytes = 130 hex chars)
- `public_key_hash` is SHA-256 of `public_key_hex`
- `encrypted_private_key` uses AES-256-GCM with 12-byte IV, 16-byte tag
- PBKDF2 iterations: minimum 310,000 (OWASP 2023)
- Salt: 32 bytes (256 bits), random per keyset
- File extension: `.medledger-keyset.json` or `.mlk`

---

## 10. Deployment Topology

```
┌─────────────────┐         ┌─────────────────┐
│   Vercel        │         │   Railway         │
│   (Frontend)    │         │   (Backend)       │
│                 │         │                 │
│  React SPA      │◄──────►│  FastAPI          │
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
- Keyset state: NOT in cookies — purely client-side memory

---

## 11. Invariants (Non-Negotiable)

1. **Private keys never leave the browser.** Generated in Web Crypto API, exported only as encrypted blob.
2. **Server stores only public material and ciphertext.** Public keys, ciphertext, encrypted DEK bundles, signatures.
3. **We cannot decrypt medical data.** Mathematical guarantee, not policy.
4. **Every share is cryptographically targeted.** DEK is ECIES-wrapped for a specific recipient public key.
5. **DEKs are always ECIES-wrapped.** Plaintext DEK never exists server-side.
6. **No account recovery.** Lost email, password, or keyset = delete account and start over. We cannot help.
7. **Email is anti-spam only.** Verified for filtering, not for recovery. Disposable emails allowed.
8. **All shares have TTL.** Maximum 90 days, default 30 days. After expiry, server deletes.
9. **Account deletion is absolute.** Hard delete all shares, anonymize audit logs.
10. **Audit everything.** Every share, every retrieve, every registration logged.
11. **Honest UI.** "We cannot recover your keyset. We cannot read your data. We are not a storage company."

---

*Document: 01-ARCHITECTURE.md | Author: Premananda (Team Praxis) | Status: Draft v1.0*

# MedLedger

A low-trust, ephemeral sharing conduit for patient-controlled medical records.

MedLedger doesn't store your medical history. It gives you a way to encrypt a record in your browser and hand a decryptable copy to a specific doctor, specialist, or family member — without ever putting the server in a position to read it. See **[`PHILOSOPHY.md`](./PHILOSOPHY.md)** for the reasoning behind that design; this README covers what exists and how it fits together.

> **We are a means, not a vault.** We store ciphertext we cannot read, for a limited time, at the patient's discretion.

---

## How it works, in one paragraph

You register and verify your account through a normal auth flow (proof-of-work → email code → optional TOTP) — that's the **gate**, and it's fully recoverable if you forget a password. Separately, your browser generates an Ed25519/X25519 keypair that never leaves it — that's your **keyset**, and it's *not* recoverable if lost. The two meet exactly once, at registration, when your public keys are sent alongside your account details. From then on, anyone can look up your public keys through the API (that's not a secret — it's how sharing works), but only your browser, holding your private keys, can decrypt anything sealed to you or sign anything on your behalf. When you share a record, your browser encrypts it with a one-time key and seals that key specifically to the recipient's public key — the server just relays the sealed package.

---

## Two-layer access model

| | **Layer 1 — Gate** | **Layer 2 — Keyset** |
|---|---|---|
| What it is | Email + password + PoW + optional TOTP | Ed25519 (signing) + X25519 (encryption) keypair |
| Where it lives | Server (PostgreSQL) | Browser only |
| Purpose | Anti-spam, session identity | Cryptographic identity, encryption, signing |
| Recoverable? | Yes — password reset via email code | **No** — lost keypair = start over |
| Server ever sees plaintext of it? | Password hash only (Argon2id) | Public keys only, never private keys |

These layers are intentionally decoupled: being logged in (Layer 1) does not mean your vault is unlocked (Layer 2). You unlock the vault client-side by loading your `.medledger-key.json` keypair file — no server call involved.

---

## Architecture

```
BROWSER                                    SERVER (FastAPI + PostgreSQL)
┌──────────────────────────┐               ┌──────────────────────────────┐
│ React SPA (UI)            │  HTTPS +      │ routes/  auth.py, keys.py,   │
│ Keyset Manager (JS)        │─ Bearer JWT ─▶│           vault.py, grants.py│
│ libsodium.js (crypto)      │◀──────────────│ services/ auth, key, grant,  │
└──────────────────────────┘               │           audit, relay        │
                                             │ auth/    password, pow,       │
                                             │          email, totp, token   │
                                             │ database/ repository.py       │
                                             └──────────────────────────────┘
```

- **Frontend**: React + Vite. Owns the UI and the Keyset Manager, the only module allowed to touch raw key material. Talks to the backend exclusively over `Authorization: Bearer <token>`.
- **Backend — Auth domain**: Python/FastAPI + PostgreSQL. Multi-step registration (PoW → email verification → optional TOTP), Argon2id password hashing, JWT + opaque refresh tokens.
- **Backend — Crypto domain**: doesn't exist server-side. All key generation, encryption, and decryption happens in the browser via libsodium.js. The server's crypto domain is limited to *storing and serving public keys and ciphertext*.

The two domains meet at one point: registration, where the account is created and the freshly-generated public keys are stored in the same request.

---

## Request lifecycle: joining the system

```
1. GET  /auth/pow/challenge         → solve proof-of-work
2. POST /auth/pow/verify            → PoW accepted
3. [browser generates Ed25519 + X25519 keypair — KeysetManager.createUser()]
4. [user downloads .medledger-key.json — this file is never recoverable if lost]
5. POST /auth/register              → account + public keys created in one request
6. [user receives 6-digit email code]
7. POST /auth/verify-email          → account verified, JWT + refresh token issued
8. Vault is already unlocked — keypair is still in browser memory from step 3
```

Returning users log in (Layer 1), then separately re-upload their keypair file to unlock the vault (Layer 2) — the server is not involved in that second step at all.

---

## Sharing a record (how the keys get used)

1. Requester looks up the owner's exchange public key: `GET /keys/{user_id_hex}/exchange`.
2. Owner's browser generates a random one-time key (DEK), encrypts the file with it, and seals the DEK specifically to the requester's exchange public key (`crypto_box_seal`) — the server cannot open a sealed DEK.
3. Ciphertext + sealed DEK bundle are sent to the server, which stores and relays them without ever holding a usable decryption key.
4. Requester's browser opens the sealed DEK with *their* private key and decrypts the file locally.

If the owner rotates their exchange key, any DEK bundles sealed to the *old* key are discarded, not migrated — see `PHILOSOPHY.md` for why that's a deliberate trade-off rather than an oversight.

---

## API surface (implemented)

Full request/response shapes: **[`06-API_REFERENCE.md`](./06-API_REFERENCE.md)**.

| Area | Endpoints |
|---|---|
| Proof-of-work | `POST /auth/pow/challenge`, `POST /auth/pow/verify` |
| Registration & verification | `POST /auth/register`, `POST /auth/verify-email`, `POST /auth/resend-verification` |
| Login & 2FA | `POST /auth/login`, `POST /auth/verify-totp-login` |
| Tokens | `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all` |
| Password | `POST /auth/change-password`, `POST /auth/request-password-reset`, `POST /auth/confirm-password-reset` |
| TOTP | `POST /auth/totp/setup`, `/confirm`, `/disable` |
| Profile | `GET /auth/me` |
| Keys | `GET /keys/my`, `GET /keys/{user_id_hex}`, `GET /keys/{user_id_hex}/exchange`, `GET /keys/{user_id_hex}/signing`, `PUT /keys/update` |

Vault, grant, and share endpoints (`routes/vault.py`, `routes/grants.py`) are designed at the schema level but not yet documented in the API reference — see that document's closing note.

---

## Tech stack

| Layer | Choice |
|---|---|
| Frontend | React + Vite, libsodium.js |
| Backend | Python 3.11, FastAPI |
| Database | PostgreSQL (SQLAlchemy async) |
| Password hashing | Argon2id (PBKDF2 legacy verify + rehash) |
| Signing / encryption | Ed25519 / X25519 via libsodium |
| Symmetric encryption | XSalsa20-Poly1305 |
| Sessions | JWT access token (15 min) + opaque refresh token (30 days) |
| Deployment | Frontend on Vercel, backend + Postgres on Railway |

---

## Documentation index

| Doc | Covers |
|---|---|
| **`PHILOSOPHY.md`** | Why the system is shaped this way — the design rationale behind the architecture |
| `01-ARCHITECTURE.md` | Full system architecture, data flows, database schema, invariants |
| `02-SECURITY_SPEC.md` | Threat model, cryptographic parameters, known limitations, compliance posture |
| `03-AUTH_SPEC.md` | Auth flows in detail — what's implemented vs. originally planned |
| `04-CRYPTO_SPEC.md` | Cryptographic primitives and their usage |
| `05-KEYSET_MANAGER.md` | Client-side key manager module API |
| `06-API_REFERENCE.md` | Practical request/response reference for frontend integration |

---

## Known limitations (current phase)

Tracked in detail in `02-SECURITY_SPEC.md §4`. Highlights:

- Access tokens are Bearer tokens managed by JS (XSS risk for their 15-minute lifetime) — HttpOnly cookie migration is planned, not yet implemented.
- Keypair files are unencrypted at rest on the user's disk — password-encryption of the file is planned for v1.1.
- No CAPTCHA on registration yet; registration and password-reset requests aren't rate-limited (only login is).
- Refresh token reuse detection needs verification that it's fully wired end-to-end.

---

*This README summarizes the numbered specs above. Where this document and a numbered spec disagree, the numbered spec is authoritative.*

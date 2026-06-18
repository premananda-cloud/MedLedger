# MedLedger API — Backend Documentation

**Version:** 1.0.0  
**Base URL:** `https://<host>/api`  
**Framework:** FastAPI (Python) + asyncpg + PostgreSQL

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Authentication Model](#2-authentication-model)
3. [Environment & Configuration](#3-environment--configuration)
4. [Registration Flow](#4-registration-flow)
5. [Auth Endpoints](#5-auth-endpoints)
6. [User Endpoints](#6-user-endpoints)
7. [Shares Endpoints](#7-shares-endpoints)
8. [Vault Endpoints](#8-vault-endpoints)
9. [Error Responses](#9-error-responses)
10. [Security Notes](#10-security-notes)
11. [Rate Limiting](#11-rate-limiting)
12. [Database Pool](#12-database-pool)

---

## 1. Architecture Overview

```
main.py
  ├── lifespan: init_pool() / close_pool()
  ├── CORSMiddleware
  ├── global_exception_handler
  ├── /api  → auth.router
  ├── /api  → shares.router
  ├── /api  → vault.router
  └── /      → StaticFiles("static", html=True)   # frontend SPA
```

The backend is split into three route modules:

| Module | File | Responsibility |
|---|---|---|
| `auth` | `src/routes/auth.py` | Registration, login, logout, token refresh, user keys |
| `shares` | `src/routes/shares.py` | End-to-end encrypted file shares between users |
| `vault` | `src/routes/vault.py` | Personal encrypted file store with time-bounded grants |

All data access goes through `src/services/database.py`, which exposes an asyncpg connection pool and an `async with DB() as conn:` context manager.

---

## 2. Authentication Model

### Tokens

MedLedger uses a **dual-token HttpOnly cookie** scheme — no bearer tokens in headers.

| Cookie | Content | Lifetime | Flags |
|---|---|---|---|
| `access_token` | Signed JWT (HS256) | 30 minutes | HttpOnly, configurable Secure/SameSite |
| `refresh_token` | Opaque random hex (64 chars) | 7 days | HttpOnly, configurable Secure/SameSite |

The JWT payload contains:

```json
{
  "sub":      "<user_id_hex>",
  "username": "<username>",
  "jti":      "<16-byte random hex>",
  "iat":      "<unix timestamp>",
  "exp":      "<unix timestamp>"
}
```

### Token Revocation

Access tokens are revoked on logout by inserting their `jti` into the `token_revocations` table. Every authenticated request checks this table via `is_token_revoked(jti)`.

Refresh tokens use **family-based rotation**. Each token belongs to a family. When a refresh token is used it is immediately revoked and replaced with a new one. If a revoked or expired refresh token is presented, the **entire family** is revoked to neutralise replay after theft.

### The `get_current_user` Dependency

Protected routes use `Depends(get_current_user)`. It:

1. Reads the `access_token` cookie.
2. Decodes and validates the JWT signature and expiry.
3. Checks `token_revocations` for the `jti`.
4. Queries the `users` table to confirm `is_active = TRUE` and `account_deleted = FALSE`.
5. Returns a `CurrentUser(user_id_hex, username, jti, db_id)` object.

An optional variant `get_current_user_optional` returns `None` instead of raising 401.

---

## 3. Environment & Configuration

Settings are read by `src/services/config.py` via `pydantic-settings`. Defaults are shown below. Override any value in `.env` or as an environment variable.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/medledger_db` | asyncpg DSN |
| `JWT_SECRET` | `CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING` | **Must be overridden in production** |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `COOKIE_SECURE` | `False` | Set `True` in production (HTTPS only) |
| `COOKIE_SAMESITE` | `lax` | Cookie SameSite policy |
| `COOKIE_DOMAIN` | `None` | Cookie domain restriction |
| `CORS_ORIGINS` | `["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"]` | Allowed CORS origins |
| `RATE_LIMIT_LOGIN` | `10/minute` | Login rate limit (requires slowapi wiring) |
| `RATE_LIMIT_REGISTER` | `5/minute` | Registration rate limit (requires slowapi wiring) |
| `HOST` | `0.0.0.0` | Uvicorn bind address |
| `PORT` | `8000` | Uvicorn port |
| `DEBUG` | `False` | Enables `/api/docs` and `/api/redoc`, enables uvicorn reload |
| `APP_NAME` | `MedLedger API` | FastAPI title |
| `APP_VERSION` | `1.0.0` | FastAPI version |

> `load_env.py` must be imported before any `src.*` module so `DATABASE_URL` is set before the connection pool is configured.

---

## 4. Registration Flow

Registration is a **5-step server-side session** stored in memory (`_sessions` dict). All steps use a `session_token` to link them.

```
Step 1  POST /api/auth/pow              Client solves PoW challenge
Step 2  POST /api/auth/verify-pow       Server verifies PoW, issues session_token
Step 3  POST /api/auth/submit-email     Client submits email; server sends 6-digit code
Step 4  POST /api/auth/verify-email     Client verifies code; server issues TOTP secret + QR
Step 5  POST /api/auth/verify-totp      Client verifies first TOTP token
Step 6  POST /api/auth/create-account   Client submits username + password; account created
```

**Proof-of-Work:** The client must find a `nonce` such that:

```
SHA-256(challenge + nonce)
```

starts with **4 leading hex zeros** (difficulty 4). Challenges expire after **5 minutes** and are single-use.

**Email code:** A random 6-digit code, valid for **10 minutes**, maximum **3 verification attempts**.

**TOTP:** Uses `pyotp`. The server returns the provisioning URI and a base64-encoded QR code PNG. TOTP verification uses `valid_window=1` (±1 time step).

**Session expiry:** Sessions are in-memory only. A server restart invalidates all pending registrations. This is a known limitation — see [Security Notes](#10-security-notes).

---

## 5. Auth Endpoints

### `POST /api/auth/pow`

Generates a new Proof-of-Work challenge.

**Request:** No body.

**Response `200`:**
```json
{
  "challenge_id": "a1b2c3...",
  "challenge":    "d4e5f6...",
  "difficulty":   4
}
```

---

### `POST /api/auth/verify-pow`

Verifies a PoW solution and opens a registration session.

**Request body:**
```json
{
  "challenge_id": "a1b2c3...",
  "nonce":        "42"
}
```

**Response `200`:**
```json
{
  "session_token": "f7a8b9...",
  "message":       "PoW verified"
}
```

**Errors:** `400` invalid/expired/already-used challenge, invalid PoW solution.

---

### `POST /api/auth/submit-email`

Submits an email address for verification. Sends a 6-digit code (logged to console in dev).

**Request body:**
```json
{
  "session_token": "f7a8b9...",
  "email":         "user@example.com"
}
```

**Response `200`:**
```json
{
  "message":    "Code sent to use***@example.com",
  "expires_in": 600,
  "email":      "use***@example.com"
}
```

**Errors:** `400` invalid session, `409` email already registered.

---

### `POST /api/auth/verify-email`

Verifies the 6-digit email code. Returns a TOTP secret and QR code for authenticator app setup.

**Request body:**
```json
{
  "session_token": "f7a8b9...",
  "code":          "123456"
}
```

**Response `200`:**
```json
{
  "message": "Email verified",
  "totp": {
    "qr_code_uri":  "otpauth://totp/MedLedger:user@example.com?...",
    "manual_key":   "BASE32SECRET",
    "qr_code":      "data:image/png;base64,..."
  }
}
```

**Errors:** `400` invalid session/no code/expired code/invalid code, `429` too many attempts.

---

### `POST /api/auth/verify-totp`

Verifies the first TOTP token from the authenticator app.

**Request body:**
```json
{
  "session_token": "f7a8b9...",
  "totp_token":    "654321"
}
```

**Response `200`:**
```json
{ "message": "TOTP verified" }
```

**Errors:** `400` invalid session or invalid TOTP token.

---

### `POST /api/auth/create-account`

Final registration step. Creates the user account.

**Request body:**
```json
{
  "session_token": "f7a8b9...",
  "username":      "alice",
  "password":      "securepassword"
}
```

Username rules: 3–30 characters, `[a-zA-Z0-9_]` only. Stored lowercase.  
Password rules: minimum 8 characters. Hashed with Argon2id (time=3, mem=64MB, par=4).

**Response `200`:**
```json
{
  "message":  "Account created",
  "user_id":  "abc123...",
  "username": "alice"
}
```

**Errors:** `400` incomplete verification steps, `409` username already taken.

---

### `POST /api/login`

Password login. Sets `access_token` and `refresh_token` cookies. Failed attempts are written to `user_audit`.

**Request body:**
```json
{
  "username": "alice",
  "password": "securepassword"
}
```

**Response `200`:**
```json
{
  "username":    "alice",
  "user_id_hex": "abc123...",
  "full_name":   "Alice Smith",
  "role":        "patient",
  "public_keys": {
    "signing_public_key":  "hex...",
    "exchange_public_key": "hex..."
  }
}
```

Sets cookies:
- `access_token` — JWT, max-age 1800s
- `refresh_token` — opaque token, max-age 604800s

**Errors:** `401` invalid credentials, inactive/deleted account.

---

### `POST /api/auth/logout`

Revokes the current access token (by `jti`) and all active refresh tokens for the user. Clears both cookies.

**Auth:** Required (`access_token` cookie).

**Request:** No body.

**Response `200`:**
```json
{ "message": "Logged out" }
```

---

### `POST /api/auth/refresh`

Rotates the refresh token. Issues a new `access_token` and `refresh_token` pair.

If a revoked refresh token is presented, **all refresh tokens for that user are invalidated** (theft detection).

**Auth:** Reads `refresh_token` cookie directly (no access token required).

**Request:** No body.

**Response `200`:**
```json
{ "message": "Token refreshed" }
```

Sets new `access_token` and `refresh_token` cookies.

**Errors:** `401` missing/invalid/expired/revoked refresh token.

---

### `GET /api/me`

Returns the current authenticated user's profile.

**Auth:** Required.

**Response `200`:**
```json
{
  "username":    "alice",
  "user_id_hex": "abc123...",
  "full_name":   "Alice Smith",
  "role":        "patient",
  "public_keys": {
    "signing_public_key":  "hex...",
    "exchange_public_key": "hex..."
  },
  "is_verified": true
}
```

**Errors:** `401` unauthenticated, `404` user not found.

---

## 6. User Endpoints

### `POST /api/users/keys`

Uploads the authenticated user's Ed25519 signing key and X25519 exchange key. These are required before creating vault records.

**Auth:** Required. The update is always scoped to the authenticated user — the body fields `username` and `user_id_hex` are informational only and are not used as the WHERE condition.

**Request body:**
```json
{
  "signing_public_key":  "hex...",
  "exchange_public_key": "hex...",
  "user_id_hex":         "abc123...",
  "username":            "alice"
}
```

**Response `200`:**
```json
{ "message": "Public keys stored" }
```

**Errors:** `401` unauthenticated, `404` user not found.

---

### `GET /api/users/{username}/keys`

Returns the public keys for any active, non-deleted user. Used when preparing an encrypted share for a recipient.

**Auth:** Required.

**Path param:** `username` — case-insensitive.

**Response `200`:**
```json
{
  "signing_public_key":  "hex...",
  "exchange_public_key": "hex..."
}
```

**Errors:** `401` unauthenticated, `404` user not found or inactive.

---

### `GET /api/users/search?q=<query>`

Searches users by username prefix (case-insensitive). Excludes the calling user from results.

**Auth:** Required.

**Query params:**

| Param | Required | Description |
|---|---|---|
| `q` | Yes | Prefix to search. Minimum 2 characters. |

**Response `200`:**
```json
[
  {
    "username":            "alice",
    "user_id_hex":         "abc123...",
    "signing_public_key":  "hex...",
    "exchange_public_key": "hex..."
  }
]
```

Maximum 10 results.

**Errors:** `400` query too short, `401` unauthenticated.

---

## 7. Shares Endpoints

Shares are the primary mechanism for sending an encrypted file from one user to another. The ciphertext (XSalsa20) and DEK (sealed box, encrypted to recipient's X25519 key) are stored server-side. The server never sees plaintext.

### Share Object

| Field | Type | Description |
|---|---|---|
| `share_id` | UUID string | Unique share identifier |
| `short_code` | string \| null | Short human-readable code (DB-generated) |
| `filename` | string | Original filename |
| `mime_type` | string \| null | MIME type |
| `size_bytes` | integer | File size |
| `owner_username` | string | Sender |
| `grantee_username` | string | Recipient |
| `created_at` | ISO 8601 | Creation time |
| `expires_at` | ISO 8601 | Expiry time |
| `delete_on_download` | boolean | If true, status → `retrieved` after first grantee download |
| `status` | string | `active`, `retrieved`, or `revoked` |
| `permission_level` | string | `view_download` (default) |

`ShareDetail` extends the above with:

| Field | Type | Description |
|---|---|---|
| `dek_bundle` | string | Base64url sealed box (DEK encrypted to grantee) |
| `nonce` | string | Base64url XSalsa20 nonce |
| `signature` | string | Base64url Ed25519 signature (owner signs payload) |
| `ciphertext_url` | string | Relative URL to stream the ciphertext |

---

### `POST /api/shares`

Creates a new share. Stores the ciphertext bytes (decoded from `ciphertext_b64`) and associated metadata.

**Auth:** Required.

**Request body:**
```json
{
  "grantee_user_id_hex": "def456...",
  "filename":            "report.pdf",
  "mime_type":           "application/pdf",
  "size_bytes":          102400,
  "ciphertext_b64":      "<base64url-encoded XSalsa20 ciphertext>",
  "dek_bundle":          "<base64url sealed box>",
  "nonce":               "<base64url XSalsa20 nonce>",
  "signature":           "<base64url Ed25519 signature>",
  "payload_canon":       "<canonical payload string — optional>",
  "file_hash":           "<hex SHA-256 of plaintext — optional>",
  "expires_hours":       24,
  "delete_on_download":  true,
  "permission_level":    "view_download"
}
```

`expires_hours`: 1–2160 (1 hour to 90 days). Default 24.

**Response `200`:** `ShareDetail` object.

**Errors:** `401` unauthenticated, `404` grantee not found, `422` validation error.

---

### `GET /api/shares/sent`

Lists all shares sent by the authenticated user, newest first. Maximum 100 results.

**Auth:** Required.

**Response `200`:** Array of `ShareSummary` objects.

---

### `GET /api/shares/received`

Lists all **active** shares received by the authenticated user, newest first. Maximum 100 results.

**Auth:** Required.

**Response `200`:** Array of `ShareSummary` objects.

---

### `GET /api/shares/{share_id}`

Returns full share detail including `dek_bundle`, `nonce`, and `signature`. Only accessible by the owner or the grantee.

**Auth:** Required.

**Response `200`:** `ShareDetail` object.

**Errors:** `401`, `404` not found or access denied, `410` share is not active (includes current status in message).

---

### `GET /api/shares/{share_id}/ciphertext`

Streams the raw encrypted ciphertext bytes. Only accessible by owner or grantee.

When the **grantee** downloads and `delete_on_download` is `true`, the share status is set to `retrieved`. If `delete_on_download` is `false`, `retrieved_at` is set on the first download only.

The download is logged to `audit_log`.

**Auth:** Required.

**Response `200`:**

Headers:
```
Content-Type:        application/octet-stream
Content-Disposition: attachment; filename="<filename>.enc"
Content-Length:      <bytes>
X-Mime-Type:         <original mime type>
```

**Errors:** `401`, `403`, `404`, `410`.

---

### `DELETE /api/shares/{share_id}`

Revokes an active share. Only the owner can revoke. Sets status → `revoked`. Logged to `audit_log`.

**Auth:** Required.

**Response `200`:**
```json
{ "message": "Share revoked" }
```

**Errors:** `401`, `404` not found or already revoked.

---

### `GET /api/shares/code/{code}`

Resolves a short code to a `share_id`. Only resolves active shares.

**Auth:** Required.

**Response `200`:**
```json
{ "share_id": "<uuid>" }
```

**Errors:** `401`, `404` not found or expired.

---

## 8. Vault Endpoints

The vault is a personal encrypted file store. Each record is owned by one user. Access can be delegated to other users via time-bounded **grants**.

### `POST /api/vault/records`

Uploads a new encrypted vault record. The owner must have uploaded public keys first (`POST /api/users/keys`).

**Auth:** Required.

**Request body:**
```json
{
  "record_id":     "<client-generated UUID string>",
  "filename":      "xray.dcm",
  "mime_type":     "application/dicom",
  "size_bytes":    204800,
  "iv_hex":        "<AES IV as hex>",
  "tags":          ["radiology", "2024"],
  "ciphertext_b64":"<base64url ciphertext>",
  "dek_bundle":    { "wrapped_key": "...", "..." : "..." }
}
```

**Response `200`:** `VaultRecordMeta` object:
```json
{
  "record_id":  "<uuid string>",
  "filename":   "xray.dcm",
  "mime_type":  "application/dicom",
  "size_bytes": 204800,
  "iv_hex":     "<hex>",
  "tags":       ["radiology", "2024"],
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Errors:** `400` public keys not uploaded yet, `401`.

---

### `GET /api/vault/records`

Lists all vault records owned by the authenticated user, newest first. Maximum 200 results.

**Auth:** Required.

**Response `200`:** Array of `VaultRecordMeta` objects.

---

### `GET /api/vault/records/{record_id}`

Returns metadata for a single vault record. Owner only.

**Auth:** Required.

**Response `200`:** `VaultRecordMeta` object.

**Errors:** `401`, `404`.

---

### `GET /api/vault/records/{record_id}/ciphertext`

Streams the raw ciphertext bytes for a vault record.

Accessible by the **owner** or any user with an **active, non-revoked grant** where `time_start <= NOW() <= time_end`.

**Auth:** Required.

**Response `200`:**
```
Content-Type:        application/octet-stream
Content-Disposition: attachment; filename="<filename>.enc"
Content-Length:      <bytes>
```

**Errors:** `401`, `403` access denied (no active grant), `404`.

---

### `DELETE /api/vault/records/{record_id}`

Deletes a vault record and its ciphertext. Owner only. Cascades to `vault_ciphertext`.

**Auth:** Required.

**Response `200`:**
```json
{ "message": "Record deleted" }
```

**Errors:** `401`, `404`.

---

### `POST /api/vault/grants`

Creates a time-bounded access grant on a vault record. Only the record owner can create grants.

**Auth:** Required.

**Request body:**
```json
{
  "record_id":            "<uuid string>",
  "grantee_user_id_hex":  "def456...",
  "grantee_public_key_hex": "hex...",
  "permission_level":     "view_only",
  "time_start":           "2024-01-15T00:00:00Z",
  "time_end":             "2024-01-22T00:00:00Z",
  "dek_bundle_grantee":   { "wrapped_key": "..." },
  "signature_hex":        "hex..."
}
```

**Response `200`:**
```json
{
  "grant_id": "abc123...",
  "message":  "Grant created"
}
```

**Errors:** `401`, `404` record not found or not owned by caller.

---

### `GET /api/vault/grants/{record_id}`

Lists all active (non-revoked) grants for a record. Owner only.

**Auth:** Required.

**Response `200`:**
```json
[
  {
    "grant_id":            "abc123...",
    "grantee_user_id_hex": "def456...",
    "grantee_username":    "bob",
    "permission_level":    "view_only",
    "time_start":          "2024-01-15T00:00:00Z",
    "time_end":            "2024-01-22T00:00:00Z",
    "revoked":             false,
    "created_at":          "2024-01-14T12:00:00Z"
  }
]
```

**Errors:** `401`, `403` not the record owner.

---

### `DELETE /api/vault/grants/{grant_id}`

Revokes a grant. Only the owner of the underlying record can revoke.

**Auth:** Required.

**Response `200`:**
```json
{ "message": "Grant revoked" }
```

**Errors:** `401`, `404` grant not found or already revoked.

---

## 9. Error Responses

All errors follow FastAPI's standard format:

```json
{ "detail": "Human-readable error message" }
```

Unhandled exceptions are caught by the global exception handler and return:

```json
{ "detail": "Internal server error" }
```

with status `500`. The full exception is logged server-side.

Common status codes:

| Code | Meaning |
|---|---|
| `400` | Bad request — missing/invalid input, business rule violation |
| `401` | Unauthenticated — missing, expired, or revoked token |
| `403` | Forbidden — authenticated but not authorised for this resource |
| `404` | Resource not found |
| `409` | Conflict — username or email already exists |
| `410` | Gone — share is no longer active (retrieved or revoked) |
| `422` | Validation error — Pydantic schema violation |
| `429` | Rate limit exceeded (email code attempts; full rate limiting requires slowapi) |
| `500` | Internal server error |

---

## 10. Security Notes

### What the server stores

The server stores ciphertext and key bundles but **never sees plaintext**. Encryption and key wrapping happen entirely on the client. The server enforces access control only.

### In-memory registration sessions

`_sessions`, `_pow_challenges`, and `_email_codes` are Python dicts in process memory. Consequences:

- A server restart clears all pending registrations.
- Multi-worker deployments (e.g. `uvicorn --workers 4`) will break the registration flow because requests may be routed to different workers.
- For production: migrate sessions to Redis or PostgreSQL.

### `user_id_hex` is trusted from the JWT

`user_id_hex` in the JWT `sub` claim is the primary identity used for all authorisation checks. The `username` claim is informational. Always scope database writes to `user_id_hex`, never to user-supplied body fields.

### Argon2id parameters

```
time_cost=3, memory_cost=65536 (64 MB), parallelism=4, hash_len=32, salt_len=16
```

These meet current OWASP recommendations. Increase `memory_cost` for higher-security deployments.

### Cookie security in production

Set these in `.env` for production:

```
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
```

### Audit log IP

Shares routes capture `request.client.host`. This is the direct TCP peer address. If the app runs behind a reverse proxy, configure the proxy to set `X-Forwarded-For` and use a middleware (e.g. `uvicorn --proxy-headers`) to trust it, or extract it explicitly from headers in each route handler.

---

## 11. Rate Limiting

The config exposes `rate_limit_login` (`10/minute`) and `rate_limit_register` (`5/minute`) but **slowapi is not yet wired up**. See `rate_limiting_patch.md` for the integration steps.

Until that is done, the only in-app rate limiting is:

- Email code: max **3 attempts** per code before the session must restart.
- PoW challenge: single-use, 5-minute expiry.

---

## 12. Database Pool

Configured in `src/services/database.py`:

| Parameter | Value |
|---|---|
| `min_size` | 2 connections |
| `max_size` | 20 connections |
| `command_timeout` | 60 seconds |

The pool is initialised in the FastAPI `lifespan` startup hook and closed on shutdown. All route handlers acquire a connection via:

```python
async with DB() as conn:
    row = await conn.fetchrow("SELECT ...")
```

`DB` is a thin wrapper around `get_pool().acquire()` / `release()`. Never share a connection across `async with` blocks — each block is an independent acquisition.

---

## Health Check

```
GET /api/health
```

No auth required.

```json
{ "status": "ok", "version": "1.0.0" }
```

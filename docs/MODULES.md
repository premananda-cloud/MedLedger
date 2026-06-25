# MedLedger — Source Module Reference

## Overview

MedLedger is a FastAPI application for encrypted medical record storage and controlled sharing. All cryptography happens on the frontend; the backend stores, routes, and enforces access policy — it never sees plaintext.

The codebase is divided into five layers. Each layer has a strict contract about what it may and may not do, which is documented at the top of every `__init__.py`.

```
config.py
    ↓
auth/           ← pure stateless workers (no I/O, no DB)
    ↓
database/       ← data access only (no business logic)
    ↓
services/       ← orchestration (business logic, calls auth/ and database/)
    ↓
middleware/     ← session (JWT validation per request)
    ↓
routes/         ← API endpoints (thin: parse, call service, return response)
```

---

## `config.py`

**What it is:** Application settings loaded from environment variables or a `.env` file, via `pydantic-settings`.

**Why it exists:** Centralises every tuneable value — secrets, feature flags, rate limits, email credentials — in one place. Routes and services never hard-code values; they import from here.

**Key settings groups:**

| Group | Settings |
|---|---|
| App | `app_name`, `debug`, `api_prefix` |
| Database | `database_url` (asyncpg) |
| JWT | `jwt_secret`, `jwt_expiry_seconds`, `refresh_expiry_days` |
| Email | `gmail_user`, `gmail_app_password` |
| Proof-of-Work | `pow_difficulty`, `pow_expiry_seconds` |
| Rate limiting | `max_login_attempts`, `login_lockout_minutes`, etc. |
| TOTP | `totp_issuer`, `totp_window` |
| Email templates | `company_name`, logo/website/support links |

**Usage:**
```python
from config import settings
settings.jwt_secret
settings.pow_difficulty
```

A module-level singleton `settings` is provided for convenience. `get_settings()` is cached with `lru_cache` so the file is only parsed once.

---

## `auth/`

**What it is:** A collection of pure, stateless worker modules. Each one does exactly one cryptographic or validation job and returns a result. None of them touch the database, hold state, or know about users.

**Why it exists:** Separating the crypto primitives from the orchestration layer makes each piece independently testable and swappable. The orchestrator (`AuthService`) decides *when* and *why* to call them; these modules only handle *how*.

**Layer contract:**
- ✅ External crypto libraries (`pyotp`, `PyJWT`, etc.) are fine
- ❌ No database access
- ❌ No user IDs or session state
- ❌ No config lookups — callers pass in credentials

### `auth/email.py` — `EmailAuthModule`

Validates an email address and sends a 6-digit verification code via Gmail.

**Does:**
- Format validation (regex + disposable-domain blocklist via `disposable-email-domains`)
- Cryptographically secure code generation (`secrets.randbelow`)
- Email delivery via `wholemail` / Gmail App Password

**Does not:** Store the code. It returns the plain code to the caller, which is responsible for hashing and persisting it.

```python
module = EmailAuthModule(company_name="MyApp")
result = module.validate_and_send_code(email, gmail_user, gmail_app_password)
if result.success:
    db.store(email=result.email, code_hash=sha256(result.code))
```

### `auth/email_verification.py` — `EmailVerification`

Pure email classification and code lifecycle logic with zero I/O.

**Does:**
- Extended disposable/spam domain detection (built-in sets + optional JSON blocklist)
- Suspicious plus-addressing heuristic (`user+random123@domain.com`)
- Code generation returning `(plain_code, sha256_hash, expires_at)`
- Timing-safe code verification against a stored hash

This is a more complete alternative to `EmailAuthModule` — use it when you want fine-grained control over each step independently.

### `auth/password.py` — `PasswordModule`

PBKDF2-SHA512 password hashing with strength scoring.

**Does:**
- Hashing: PBKDF2-HMAC-SHA512, 600 000 iterations (OWASP 2023), 16-byte random salt
- Timing-safe verification: always runs the full hash to prevent user-enumeration via timing
- Strength scoring: 0–5 scale (uppercase, lowercase, digit, special char, length ≥ 12), returns actionable issues

Test environments automatically use 1 000 iterations (`APP_ENV=test`).

```python
ph = module.hash_password("MyP@ssw0rd!")
# Store ph.hash_hex, ph.salt_hex, ph.iterations

ok = module.verify_password(submitted, ph.hash_hex, ph.salt_hex, ph.iterations)
```

### `auth/pow.py` — `POWModule`

SHA-256 proof-of-work challenge generation and verification, compatible with the `capjs` client protocol.

**Why PoW exists:** Makes automated account creation and credential stuffing expensive. A client must find a nonce such that `SHA256(challenge + nonce)` starts with N zero hex digits before it can register or attempt login.

**Does:**
- `new_challenge()` → random challenge string + ID
- `verify_solution(challenge, nonce)` → checks leading-zero constraint
- `is_expired(challenge)` → convenience helper for orchestrators
- `solve(challenge, difficulty)` → brute-force solver for tests and CLI

The orchestrator stores the challenge and checks expiry; this module only handles the math.

### `auth/token.py` — `TokenService`

Stateless JWT creation and verification (HS256).

**Does:**
- `create(sub, username, email, extra)` → signed JWT with `jti` (unique token ID)
- `verify(token)` → validates signature + expiry, returns `TokenPayload`
- `decode_unverified(token)` → inspection only, never trust for auth

The `jti` is included in every token for revocation support. Actual revocation checks (DB lookup) are the caller's responsibility.

### `auth/totp.py` — `TOTPModule`

TOTP secret generation and 6-digit code verification via `pyotp`.

**Does:**
- `generate_secret(email)` → base32 secret + `otpauth://` provisioning URI (for QR)
- `verify_code(secret, code)` → verifies with configurable clock-skew window
- `generate_backup_codes(count)` → one-time codes in `XXXX-XXXX` format (plain — caller hashes and stores)

Secrets are never stored here. The orchestrator fetches the secret from the database and passes it in on every call.

### `auth/models.py`

Pydantic models for the data contracts between auth modules and their callers.

| Model | Used for |
|---|---|
| `EmailSendResult` | Return value of `EmailAuthModule.validate_and_send_code` |
| `EmailValidationResult` | Return value of format/domain checks |
| `TOTPSecret` | Return value of `TOTPModule.generate_secret` |
| `POWChallenge` / `POWVerifyResult` | PoW module inputs and outputs |
| `PasswordHashResult` | Return value of `PasswordModule.hash_password` |
| `PasswordStrengthResult` | Return value of strength scoring |

---

## `database/`

**What it is:** A single `DatabaseRepository` class that handles every SQL operation in the application.

**Why it exists:** Centralising all SQL in one place means no raw queries leak into services, no business logic creeps into data access, and all error handling is uniform. Services call named methods; they never write SQL.

**Layer contract:**
- ✅ Pure data access — reads and writes
- ✅ Raises only exceptions from `database/exceptions.py`
- ❌ No business logic
- ❌ No validation
- ❌ No auth decisions ("is this user allowed to…")
- ❌ No imports from `auth/` or `services/`

### `database/repository.py` — `DatabaseRepository`

Receives an `AsyncSession` in `__init__`. All methods are grouped by table.

**Tables and key operations:**

| Table | Notable methods |
|---|---|
| `users` | `create_user`, `get_user_by_email`, `get_user_by_id_hex`, `update_user`, `soft_delete_user` |
| `user_audit` | `append_user_audit`, `get_user_audit` |
| `pow_challenges` | `create_pow_challenge`, `get_pow_challenge`, `mark_pow_solved`, `delete_pow_challenge` |
| `refresh_tokens` | `store_refresh_token`, `get_refresh_token`, `revoke_refresh_token`, `revoke_token_family` |
| `token_revocations` | `revoke_token_jti`, `is_token_revoked` (called by middleware) |
| `rate_limit` | `get_rate_limit`, `upsert_rate_limit`, `set_rate_limit_block`, `reset_rate_limit` |
| `active_shares` | `create_share`, `get_share_by_id`, `mark_share_retrieved`, `get_shares_by_owner/grantee` |
| `share_access_log` | `append_share_access`, `get_share_access_log` |
| `vault_records` | `create_vault_record`, `get_vault_record`, `list_vault_records`, `delete_vault_record` |
| `vault_ciphertext` | `create_vault_ciphertext`, `get_vault_ciphertext` |
| `grants` | `create_grant`, `revoke_grant`, `get_grants_for_record`, `get_grants_by_grantor/grantee` |
| `audit_log` | `append_audit_log`, `get_audit_log` |
| `vault_audit` | `append_vault_audit`, `get_vault_audit` |

`run_full_cleanup()` batches all expiry cleanup in one call.

**Error handling:** SQLAlchemy `IntegrityError` is caught and re-raised as either `DuplicateError` (unique constraint, with `field` attribute) or `IntegrityError` (other constraint). `get_*` methods return `None` for missing records; `update_*` and `delete_*` methods raise `RecordNotFoundError`.

### `database/exceptions.py`

```
DatabaseError          ← base
├── RecordNotFoundError    update/delete targets a non-existent row
├── DuplicateError         unique constraint; .field = "email" | "username" | …
└── IntegrityError         any other constraint violation
```

---

## `services/`

**What it is:** The orchestration layer. Services wire together auth modules and the database repository to implement the application's actual behaviour. All business logic and flow decisions live here.

**Layer contract:**
- ✅ Imports from `auth/` and `database/`
- ✅ All business decisions
- ❌ No crypto operations (frontend does all crypto)
- ❌ No raw SQL (all SQL goes through `DatabaseRepository`)
- ❌ No plaintext payload storage

**Dependency order (also the injection order in `deps.py`):**
1. `AuditService(db_repo)`
2. `KeyService(db_repo, audit_service)`
3. `GrantService(db_repo, audit_service)`
4. `RelayService(db_repo, key_service, grant_service, audit_service)`
5. `AuthService(db_repo, email_module, totp_module, password_module, token_module, pow_module, audit_service, config)`

### `services/audit_service.py` — `AuditService`

Centralised audit logging. Every significant action in the system goes through here so log entries are uniform.

**Methods by domain:**

| Method | Events logged |
|---|---|
| `log_auth_event` | register, login_success/failure, logout, verify_email, totp_setup/verify, password_change/reset |
| `log_key_event` | keys_stored, keys_updated, keys_accessed |
| `log_relay_event` | payload_sent/received, share_requested/rejected |
| `log_grant_event` | grant_create, grant_revoke, grant_accessed |
| `log_vault_event` | record_created/deleted, vault_unlock/lock |

Audit failures are logged but never bubble up — a failing audit write should not abort the user's operation.

### `services/auth_service.py` — `AuthService`

The most complex service. Orchestrates the complete user authentication lifecycle.

**Registration flow:**
1. Validate password strength (`PasswordModule`)
2. Check email/username availability (`DatabaseRepository`)
3. Hash password (`PasswordModule`)
4. Create user + store public keys (`DatabaseRepository`)
5. Send verification code via email, store only the hash (`EmailAuthModule`)
6. Audit log

**Login flow:**
1. Fetch user; always run password hash to prevent timing attacks
2. Check account status (deleted, inactive)
3. Check rate-limit lockout
4. If TOTP enabled → return `requires_totp` signal, stop
5. Issue access + refresh tokens, store refresh hash
6. Record login, clear rate-limit counter, audit log

**Other operations:** email verification, resend, TOTP setup/confirm/disable, token refresh (with family-based reuse detection), logout (single device or all devices), password change, password reset request/confirm.

All token operations use `TokenModule`; all password operations use `PasswordModule`; all email operations use `EmailAuthModule`; PoW challenge issue and verify use `POWModule`.

### `services/token.py` — `TokenModule`

Stateless JWT helper living in `services/` (rather than `auth/`) because it is also used directly by middleware.

- `create_access_token(sub, username, email)` → signed HS256 JWT with `jti`
- `verify_token(token)` → returns `TokenVerifyResult` (does not check revocation list)
- `hash_refresh_token(token)` / `generate_refresh_token()` → SHA-256 hex hash and secure random token

### `services/key_service.py` — `KeyService`

Public key storage and lookup. The backend is a dumb store — all key generation happens on the frontend. No private keys ever arrive here.

- `store_initial_keys(user_id_hex, signing_key, exchange_key)` — called during registration
- `update_keys(user_id_hex, …)` — update one or both keys; logs audit event
- `get_public_keys(target, requester, ip)` — both keys; logged
- `get_exchange_key(target, requester, ip)` — X25519 key for encrypting data to this user
- `get_signing_key(target, requester, ip)` — Ed25519 key for verifying signatures from this user
- `get_my_keys(user_id_hex)` — own keys; not logged (not a sensitive access)

### `services/grant_service.py` — `GrantService`

Time-bounded, revocable access grants on vault records. The grantor's frontend encrypts the DEK for the grantee; the backend stores the bundle and enforces the time window.

- `create_grant(grantor, grantee, record, permission_level, time_start, time_end, dek_bundle, signature)` — validates ownership, time window, and grantee existence
- `revoke_grant(grant_id, revoker)` — only the record owner may revoke
- `check_access(user_id_hex, record_id)` → `{has_access, grant, permission_level}` — checks active, non-revoked, within time window
- `list_grants_for_record(record_id, owner)` — only callable by the record owner
- `list_my_grants(user_id_hex, as_grantor)` — grants created by or received by the user
- `get_grant_details(grant_id, user_id_hex)` — full details including DEK bundle; only grantor or grantee may access; marks retrieved on first grantee access

### `services/relay_service.py` — `RelayService`

Zero-knowledge encrypted payload relay. The backend routes payloads between users without ever storing or inspecting them.

**Flow:**
1. Grantee calls `request_share(requester, owner, record_id, requester_public_key)` — stored as a pending stub (no real ciphertext)
2. Owner fetches pending requests via `get_pending_requests(owner_id_hex)`
3. Owner's frontend encrypts the DEK for the grantee and calls `send_encrypted_payload(sender, recipient, record_id, encrypted_payload, signature)`
4. Payload is returned directly in the API response — it is **never persisted**

`notify_payload_ready` and `fetch_notifications` support async delivery: the owner pushes a notification, and the recipient polls to discover that a payload is ready. The notification contains a reference ID, not the payload itself.

---

## `middleware/`

**What it is:** FastAPI/Starlette middleware that validates JWTs on every protected request and attaches identity to `request.state`.

### `middleware/auth.py` — `AuthMiddleware`

A `BaseHTTPMiddleware` subclass added to the FastAPI app at startup.

**On each request:**
1. If path matches a public prefix (auth endpoints, docs, `/health`) → pass through immediately
2. Extract `Authorization: Bearer <token>` header
3. Verify JWT via `TokenModule.verify_token` (signature + expiry)
4. Check JTI against `token_revocations` table via `DatabaseRepository`
5. Attach `user_id_hex`, `username`, `email`, `jti` to `request.state`

If the JTI revocation check fails due to a database error, the middleware **fails open** (lets the request through) to avoid blocking users during DB downtime. Change to fail-closed if your threat model requires it.

**Public route prefixes** (no JWT required):
```
/api/auth/pow/
/api/auth/register
/api/auth/login
/api/auth/verify-email
/api/auth/refresh
/api/auth/request-password-reset
/api/auth/confirm-password-reset
/docs  /redoc  /openapi.json  /health
```

**`get_current_user(request)`** is a FastAPI dependency that reads `request.state` and raises `HTTP 401` if the middleware hasn't run or the token was invalid. Routes import this from `routes/deps.py`.

---

## `models/`

**What it is:** Pydantic models for all API request and response shapes. No SQLAlchemy, no database imports.

### `models/schemas.py`

All request bodies, response bodies, and internal DTOs are defined here. Key groups:

| Group | Models |
|---|---|
| Generic | `MessageResponse`, `ErrorResponse` |
| Auth requests | `RegisterRequest`, `LoginRequest`, `VerifyEmailRequest`, `ChangePasswordRequest`, `POWVerifyRequest`, `VerifyTOTPLoginRequest`, … |
| Auth responses | `UserResponse`, `TokenResponse`, `LoginResponse`, `TOTPSetupResponse`, `RegisterResponse` |
| Key management | `UpdateKeysRequest`, `PublicKeysResponse`, `ExchangeKeyResponse`, `SigningKeyResponse` |
| Shares / relay | `RequestShareRequest`, `SendEncryptedPayloadRequest`, `EncryptedPayloadResponse`, `PendingRequestsResponse`, `NotificationResponse` |
| Vault | `CreateVaultRecordRequest`, `VaultRecordResponse`, `VaultRecordMeta` |
| Grants | `CreateGrantRequest`, `GrantResponse`, `GrantDetailsResponse`, `AccessCheckResponse`, `GrantListResponse` |

Field validators on request models enforce format constraints (username 3–30 chars alphanumeric, TOTP codes exactly 6 digits, etc.) before the request reaches a service.

---

## `routes/`

**What it is:** FastAPI routers — thin API endpoint handlers. Each handler parses the request, calls the relevant service, maps the result to a response model, and maps exceptions to HTTP status codes.

**Dependency injection** is centralised in `routes/deps.py`. Auth modules are singletons (`lru_cache`); services are created per-request sharing the per-request DB session.

### `routes/auth.py` — `/api/auth/…`

| Endpoint | Auth | Description |
|---|---|---|
| `POST /auth/pow/challenge` | Public | Issue PoW challenge |
| `POST /auth/pow/verify` | Public | Verify PoW solution |
| `POST /auth/register` | Public | Register new user |
| `POST /auth/verify-email` | Public | Submit 6-digit email code |
| `POST /auth/resend-verification` | Public | Resend email code |
| `POST /auth/login` | Public | Login (returns tokens or `requires_totp`) |
| `POST /auth/verify-totp-login` | Public | Complete TOTP second factor |
| `POST /auth/refresh` | Public | Rotate refresh token |
| `POST /auth/request-password-reset` | Public | Send reset code to email |
| `POST /auth/confirm-password-reset` | Public | Verify code + set new password |
| `POST /auth/logout` | JWT | Revoke current device |
| `POST /auth/logout-all` | JWT | Revoke all devices |
| `POST /auth/change-password` | JWT | Change password (revokes all sessions) |
| `POST /auth/totp/setup` | JWT | Begin TOTP setup, get URI + backup codes |
| `POST /auth/totp/confirm` | JWT | Activate TOTP with live code |
| `POST /auth/totp/disable` | JWT | Disable TOTP (requires password + code) |
| `GET /auth/me` | JWT | Current user profile |

### `routes/keys.py` — `/api/keys/…`

All endpoints require JWT.

| Endpoint | Description |
|---|---|
| `GET /keys/my` | Own public keys (no audit) |
| `GET /keys/{user_id_hex}` | Both keys for any user (audited) |
| `GET /keys/{user_id_hex}/exchange` | X25519 exchange key only |
| `GET /keys/{user_id_hex}/signing` | Ed25519 signing key only |
| `PUT /keys/update` | Update own keys |

### `routes/vault.py` — `/api/vault/…`

All endpoints require JWT. Ciphertext is stored server-side; owners must hold the DEK client-side.

| Endpoint | Description |
|---|---|
| `POST /vault/records` | Upload encrypted record (metadata + ciphertext) |
| `GET /vault/records` | List own records |
| `GET /vault/records/{record_id}` | Get record metadata |
| `GET /vault/records/{record_id}/ciphertext` | Stream ciphertext (owner or active grantee) |
| `DELETE /vault/records/{record_id}` | Delete record + ciphertext (CASCADE) |

### `routes/grants.py` — `/api/grants/…`

All endpoints require JWT.

| Endpoint | Description |
|---|---|
| `POST /grants` | Create time-bounded access grant |
| `DELETE /grants/{grant_id}` | Revoke grant (grantor only) |
| `GET /grants/{grant_id}` | Get grant details + DEK bundle (grantor or grantee) |
| `GET /grants/record/{record_id}` | List grants for a record (owner only) |
| `GET /grants/my` | My grants as grantor or grantee (`?as_grantor=true/false`) |
| `GET /grants/check/{record_id}` | Check if I have active access |

### `routes/shares.py` — `/api/shares/…`

All endpoints require JWT. Contains both the new relay flow and the legacy direct-share flow.

**Relay endpoints (new):**

| Endpoint | Description |
|---|---|
| `POST /shares/request` | Grantee requests encrypted payload from owner |
| `POST /shares/send` | Owner sends encrypted payload (never stored) |
| `POST /shares/reject` | Owner rejects a pending request |
| `GET /shares/pending` | Owner views pending requests |
| `GET /shares/notifications` | Recipient polls for ready payloads |

**Legacy direct-share endpoints:**

| Endpoint | Description |
|---|---|
| `POST /shares` | Create direct share (ciphertext stored in DB) |
| `GET /shares/sent` | Shares created by me |
| `GET /shares/received` | Active shares received by me |
| `GET /shares/{share_id}` | Share detail + keys (owner or grantee) |
| `GET /shares/{share_id}/ciphertext` | Stream ciphertext (marks retrieved on download) |
| `DELETE /shares/{share_id}` | Revoke share (owner only) |
| `GET /shares/code/{code}` | Resolve short code to share_id |
| `GET /users/search?q=` | Search users by username prefix |

### `routes/deps.py`

FastAPI dependency factory. Centralises all wiring so routes stay clean.

- `get_session()` — yields a fresh `AsyncSession` per request
- `get_db_repo()` — wraps session in `DatabaseRepository`
- `db_repo_factory()` — standalone factory for middleware (no FastAPI DI)
- `get_auth_service()`, `get_key_service()`, `get_grant_service()`, `get_relay_service()`, `get_audit_service()` — service constructors with correct dependency injection
- Auth modules (`EmailAuthModule`, `TOTPModule`, `PasswordModule`, `POWModule`, `TokenModule`) are singletons via `lru_cache`

---

## Adding a new feature

1. **Data** — add methods to `DatabaseRepository` (raw SQL, raise only `database/exceptions.py` types)
2. **Logic** — add methods to the relevant service, or create a new service following the dependency order
3. **API** — add a route handler; use `Depends(get_<service>)` for injection
4. **Models** — add request/response models to `models/schemas.py`
5. If new cryptographic primitives are needed, add a module under `auth/` and wire it in via `deps.py`

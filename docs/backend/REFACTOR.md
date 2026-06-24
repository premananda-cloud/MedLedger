# Backend Refactor — Working Document

> Reference doc for systematic refactoring. Not a spec — a map.
> Update as decisions are made.

---

## Project Structure (target)

```
src/
├── auth/           ✅ done
├── database/       ✅ done
├── models/         ⬜ pending
├── services/       ⬜ pending
├── routes/         ⬜ pending
└── __init__.py
```

---

## Layer Rules (the one rule per layer)

| Layer | Job | Can import | Cannot import |
|---|---|---|---|
| `auth/` | Does auth work, returns results | domain libs (`pyotp`, `wholemail`, etc), stdlib | database, models, services |
| `database/` | All data operations, session management | SQLAlchemy, stdlib | auth, services |
| `models/` | DB schemas + Pydantic shapes | database | auth, services |
| `services/` | Orchestrates flows, owns business logic | auth, database, models | routes |
| `routes/` | Parses requests, calls services | services, models | auth, database directly |

---

## Status

### ✅ `auth/` — Complete

Self-contained auth workers. No DB. No user context. Each module does one job and returns results to whoever called it.

```
auth/
├── __init__.py
├── models.py
├── email.py
├── totp.py
├── pow.py
└── password.py
```

---

### ✅ `database/` — Complete

All data operations in one `DatabaseRepository` class. Receives an `AsyncSession`, returns dicts. No business logic, no auth decisions.

```
database/
├── __init__.py
├── exceptions.py
└── repository.py
```

Key decisions made:
- `user_id_hex` (BLAKE2b of signing key) is the app-level user handle — not the internal `SERIAL id`
- Login locking goes through `rate_limit` table, not `users` (no `locked_until` column on users)
- `verification_token` / `token_expires_at` on users are legacy columns — kept but noted
- Refresh token families tracked via `family_id` — revoke whole family on reuse detection
- All get_* methods return `None` for missing records; update/delete raise `RecordNotFoundError`

---

### ⬜ `models/` — Pending

SQLAlchemy table definitions + Pydantic request/response shapes.

---

### ✅ `services/` — Complete

Integrates auth modules + database repository. Business logic lives here.
Needs detailed assessment before starting.

---

### ⬜ `routes/` — Pending

Thin handlers. Parse request → call service → return response.

---

### 🔮 Future modules (not started)

- Key handling
- *(add more as assessed)*

---

---

# `auth/` — Module Reference

> Read this instead of the code.

---

## `EmailAuthModule` — `auth/email.py`

Validates an email address, generates a verification code, sends it via Gmail, and returns the plain code to the caller.

**The caller stores the code. This module never sees it again.**

```python
from auth import EmailAuthModule

module = EmailAuthModule(company_name="MyApp")
```

### `validate_email(email)`

Check format and disposable domain blocklist without sending anything.

```python
result = module.validate_email("user@example.com")
# result.valid      → bool
# result.email      → normalized email
# result.reason     → why it failed (if valid=False)
```

Rejects: bad format, 7500+ disposable/temp domains (mailinator, guerrillamail, etc).

### `validate_and_send_code(email, gmail_user, gmail_app_password)`

Validate → generate code → send via Gmail → return plain code.

```python
result = module.validate_and_send_code(
    email="user@example.com",
    gmail_user="noreply@myapp.com",
    gmail_app_password="xxxx xxxx xxxx xxxx",
)

# result.success  → bool
# result.email    → normalized email
# result.code     → plain code — store this, then discard
# result.error    → reason if success=False
```

**Caller responsibility:** store `result.code` (with TTL), compare on submit, delete after use.

---

## `TOTPModule` — `auth/totp.py`

Generates TOTP secrets and verifies codes. Never stores anything. Caller always supplies the secret.

```python
from auth import TOTPModule

module = TOTPModule(issuer="MyApp")
```

### `generate_secret(email)`

```python
result = module.generate_secret("user@example.com")
# result.secret  → base32 secret — store this (encrypted)
# result.uri     → otpauth:// URI — send to frontend for QR display
# result.issuer  → issuer name
# result.email   → account name shown in authenticator app
```

**Caller responsibility:** persist `result.secret` encrypted. Return `result.uri` to the frontend.

### `verify_code(secret, code)`

```python
ok = module.verify_code(secret=stored_secret, code="123456")
# → bool
```

Caller fetches the secret from DB, passes it in. Accepts ±1 time-step for clock skew.

### `generate_backup_codes(count=8)`

```python
codes = module.generate_backup_codes(count=8)
# → ["A1B2C3D4-E5F6A7B8", ...]
```

**Caller responsibility:** hash and store each code. Shown once, never stored here.

---

## `POWModule` — `auth/pow.py`

Generates proof-of-work challenges and verifies solutions. Caller owns storage and expiry.

```python
from auth import POWModule

module = POWModule(difficulty=4, expiry_seconds=300)
```

### `new_challenge()`

```python
challenge = module.new_challenge()
# challenge.challenge_id  → unique ID — use as cache key
# challenge.challenge     → random string sent to client
# challenge.difficulty    → leading zeros required
# challenge.timestamp     → unix time issued
# challenge.to_dict()     → serialize to send to client
```

**Caller responsibility:** persist via `repo.create_pow_challenge()` before returning to client.

### `verify_solution(challenge, solution)`

```python
result = module.verify_solution(challenge=stored_challenge, solution=nonce)
# result.success  → bool
# result.message  → human-readable outcome
```

**Caller responsibility:** check expiry before calling. Call `repo.delete_pow_challenge()` on success.

### `is_expired(challenge)`

```python
expired = module.is_expired(challenge)  # → bool
```

---

## `PasswordModule` — `auth/password.py`

Hashes passwords, verifies them, and scores strength. Caller stores the hash fields.

```python
from auth import PasswordModule

module = PasswordModule()   # auto-selects iterations: 600k prod, 1k test
```

### `validate_strength(password)`

```python
result = module.validate_strength("MyP@ssw0rd!")
# result.valid     → bool  (score ≥ 3 and length ≥ min_length)
# result.score     → int 0-5
# result.strength  → "weak" | "fair" | "good" | "strong" | "very_strong"
# result.issues    → ["Add at least one uppercase letter.", ...]
```

### `hash_password(password)`

```python
ph = module.hash_password("MyP@ssw0rd!")
# ph.hash_hex    → store this
# ph.salt_hex    → store this
# ph.iterations  → store this
```

### `verify_password(password, hash_hex, salt_hex, iterations)`

```python
ok = module.verify_password("MyP@ssw0rd!", ph.hash_hex, ph.salt_hex, ph.iterations)
# → bool (timing-safe)
```

Pass dummy values for non-existent users to prevent timing-based enumeration.

---

## `auth/` Dependencies

```
pyotp                     # TOTP
wholemail                 # Gmail sending
disposable-email-domains  # Blocklist (7500+ domains)
pydantic                  # Models
```

---

---

# `database/` — Module Reference

> Read this instead of the code.

---

## `DatabaseRepository` — `database/repository.py`

Single class. All DB operations. Inject an `AsyncSession` on construction.

```python
from database import DatabaseRepository

async with get_session() as session:
    repo = DatabaseRepository(session)
```

---

## Users

```python
# Create
user = await repo.create_user(username, email, full_name, password_hash, role="PATIENT")
# → dict (full row). Raises DuplicateError on email/username conflict.

# Fetch
user = await repo.get_user_by_id_hex(user_id_hex)   # → dict | None
user = await repo.get_user_by_email(email)           # → dict | None
user = await repo.get_user_by_username(username)     # → dict | None

# Existence checks (cheap, no full row fetch)
exists = await repo.email_exists(email)       # → bool
exists = await repo.username_exists(username) # → bool

# Updates (only pass fields you want to change)
user = await repo.update_user(user_id_hex, is_active=False)
await repo.set_public_keys(user_id_hex, signing_public_key, exchange_public_key)
await repo.set_password_hash(user_id_hex, new_hash)
await repo.mark_email_verified(user_id_hex)
await repo.record_successful_login(user_id_hex, ip_address)

# Soft delete / restore
await repo.soft_delete_user(user_id_hex)
await repo.restore_user(user_id_hex)

# List
users = await repo.list_users(skip=0, limit=100, active_only=True)  # → list[dict]
count = await repo.count_users(active_only=True)                     # → int
```

**Note:** account locking is via `rate_limit` table, not a `locked_until` column on users.

---

## PoW Challenges

```python
row    = await repo.create_pow_challenge(challenge_id, nonce_prefix, difficulty, target_hash, expires_at)
ch     = await repo.get_pow_challenge(challenge_id)       # → dict | None
await    repo.mark_pow_solved(challenge_id, solved_nonce, solver_ip)
await    repo.delete_pow_challenge(challenge_id)          # call after verify — replay protection
count  = await repo.cleanup_expired_pow()                 # → int
```

---

## Refresh Tokens

```python
token  = await repo.store_refresh_token(token_hash, user_id_hex, family_id, expires_at)
token  = await repo.get_refresh_token(token_hash)         # → dict | None (None if revoked/expired)
await    repo.revoke_refresh_token(token_hash, replaced_by_token_hash=new_hash)
count  = await repo.revoke_token_family(family_id)        # revoke whole chain on reuse — → int
count  = await repo.revoke_all_user_refresh_tokens(user_id_hex)  # → int
count  = await repo.cleanup_expired_refresh_tokens()      # → int
```

---

## Token Revocations (JWT JTI blocklist)

```python
await    repo.revoke_token_jti(token_jti, user_id_hex, expires_at)
revoked = await repo.is_token_revoked(token_jti)          # → bool  (called by middleware)
count  = await repo.cleanup_expired_jtis()                # → int
```

---

## Rate Limiting

```python
record = await repo.get_rate_limit(key_hash, action)      # → dict | None
record = await repo.upsert_rate_limit(key_hash, action)   # increment or create → dict
await    repo.set_rate_limit_block(key_hash, action, blocked_until)
await    repo.reset_rate_limit(key_hash, action)          # clear after success
```

`key_hash` is SHA-256 of the email or IP — computed by the caller, never raw PII in this table.

---

## Active Shares

```python
share  = await repo.create_share(owner_user_id_hex, grantee_user_id_hex, ciphertext, ...)
share  = await repo.get_share_by_id(share_id)             # → dict | None
share  = await repo.get_share_by_short_code(short_code)   # → dict | None
await    repo.mark_share_retrieved(share_id)
await    repo.update_share_status(share_id, "revoked")    # active|retrieved|expired|revoked|deleted
shares = await repo.get_shares_by_owner(owner_user_id_hex, status=None, skip=0, limit=50)
shares = await repo.get_shares_by_grantee(grantee_user_id_hex, status=None)
count  = await repo.expire_old_shares()                   # → int
```

---

## Vault Records + Ciphertext

```python
# Always create record first, then ciphertext
record = await repo.create_vault_record(record_id, owner_key_hash, owner_user_id_hex, ...)
await    repo.create_vault_ciphertext(record_id, ciphertext_bytes, dek_bundle_dict)

record = await repo.get_vault_record(record_id)           # → dict | None
ct     = await repo.get_vault_ciphertext(record_id)       # → dict | None
records = await repo.list_vault_records(owner_user_id_hex, skip=0, limit=50)
await    repo.delete_vault_record(record_id)              # cascades to ciphertext
```

---

## Grants

```python
grant  = await repo.create_grant(grant_id, record_id, grantor_key_hash, grantee_key_hash, ...)
grant  = await repo.get_grant(grant_id)                   # → dict | None
await    repo.revoke_grant(grant_id)
await    repo.mark_grant_retrieved(grant_id)
grants = await repo.get_grants_for_record(record_id, active_only=True)
grants = await repo.get_grants_by_grantor(grantor_key_hash, active_only=True)
grants = await repo.get_grants_by_grantee(grantee_key_hash, active_only=True)
```

---

## Audit Logs (append-only)

```python
# Compliance audit log
await repo.append_audit_log(action, ip_address, actor_user_id_hex=None, share_id=None, detail={})
rows  = await repo.get_audit_log(actor_user_id_hex=None, action=None, skip=0, limit=100)

# Vault audit log
await repo.append_vault_audit(action, actor_key_hash, record_id, detail, ...)
rows  = await repo.get_vault_audit(actor_key_hash=None, record_id=None, skip=0, limit=100)

# User audit log
await repo.append_user_audit(user_id, action, description, ip_address, user_agent)
rows  = await repo.get_user_audit(user_id, limit=100, skip=0)
```

---

## Maintenance

```python
# Run all cleanup in one call
results = await repo.run_full_cleanup()
# → {
#     "expired_shares": int,
#     "expired_pow": int,
#     "expired_refresh_tokens": int,
#     "expired_jtis": int,
#   }
```

---

## Exceptions

```python
from database.exceptions import (
    DatabaseError,        # base — catch this for any DB error
    RecordNotFoundError,  # update/delete on missing row
    DuplicateError,       # unique constraint violated; .field tells you which column
    IntegrityError,       # other constraint violations
)
```

---

## `database/` Dependencies

```
sqlalchemy[asyncio]   # async ORM + core
asyncpg               # PostgreSQL async driver
```

---

---

# `services/` — Module Reference

> Read this instead of the code.

---

## Dependency injection order

Build and inject in this order — each service only depends on what's above it:

```python
audit_svc  = AuditService(db_repo)
key_svc    = KeyService(db_repo, audit_svc)
grant_svc  = GrantService(db_repo, audit_svc)
relay_svc  = RelayService(db_repo, key_svc, grant_svc, audit_svc)
auth_svc   = AuthService(db_repo, email_module, totp_module, password_module,
                         token_module, pow_module, audit_svc, config)
```

`TokenModule` lives in `services/token.py` (not `auth/`) because it needs
`config.jwt_secret` at construction time.

---

## `AuditService` — `services/audit_service.py`

Centralized audit logging. All other services call this — never write audit
rows directly. Swallows exceptions internally so a logging failure never
breaks a user-facing flow.

```python
await audit.log_auth_event(action, actor_user_id_hex, ip, detail={}, user_agent=None)
await audit.log_key_event(action, actor_user_id_hex, ip, detail={})
await audit.log_relay_event(action, recipient_id_hex, ip, sender_id_hex=None, detail={})
await audit.log_grant_event(action, actor_user_id_hex, ip, grant_id=None, record_id=None, detail={})
await audit.log_vault_event(action, actor_user_id_hex, ip, record_id=None, detail={})
```

Valid action strings match the `audit_action` enum in the schema:
`register`, `login_success`, `login_failure`, `logout`, `share_create`,
`share_retrieve`, `share_revoke`, `grant_create`, `grant_revoke`, `vault_unlock`, etc.

---

## `TokenModule` — `services/token.py`

JWT creation and verification. Lives in services (not auth/) because it
needs the JWT secret from config.

```python
module = TokenModule(secret=config.jwt_secret, expiry_seconds=3600)

token  = module.create_access_token(sub=user_id_hex, username, email, extra={})
result = module.verify_token(token)
# result.valid, result.payload.sub / .username / .email / .jti, result.error

plain_refresh = TokenModule.generate_refresh_token()   # static
hash_hex      = TokenModule.hash_refresh_token(plain)  # store this, not plain
```

Caller (middleware) checks JTI revocation after `verify_token()` — the module
doesn't know about the revocation list.

---

## `AuthService` — `services/auth_service.py`

Full user lifecycle. The largest service — coordinates all auth modules + DB.

### PoW (call before registration or login)
```python
challenge = await auth_svc.issue_pow_challenge(ip)
# → {challenge_id, challenge, difficulty, timestamp}  (send to client)

ok = await auth_svc.verify_pow_challenge(challenge_id, solution, ip)
# → bool
```

### Registration
```python
user = await auth_svc.register_user(
    email, username, password, full_name,
    signing_public_key, exchange_public_key, ip
)
# Raises: ValueError (weak password), DuplicateError (email/username taken)
# Returns: safe user dict (no password_hash, no salt)
```

### Email verification
```python
result = await auth_svc.verify_email(user_id_hex, code, ip)
# Raises: ValueError (wrong/expired code)

result = await auth_svc.resend_verification_code(user_id_hex, ip)
```

### Login
```python
result = await auth_svc.login(email, password, ip, user_agent=None)
# If TOTP enabled → {"requires_totp": True, "user_id_hex": ...}
# Otherwise     → {"access_token", "refresh_token", "token_type", "expires_in", "user"}
# Raises: ValueError (bad credentials, locked, inactive/deleted)

# Second factor (only when requires_totp=True):
result = await auth_svc.verify_totp_login(user_id_hex, totp_code, ip)
# → same token response as login
```

### TOTP setup
```python
setup  = await auth_svc.setup_totp(user_id_hex, ip)
# → {"uri": "otpauth://...", "backup_codes": [...]}  — show backup_codes ONCE

result = await auth_svc.confirm_totp(user_id_hex, totp_code, ip)
# Raises: ValueError (bad code)

result = await auth_svc.disable_totp(user_id_hex, password, totp_code, ip)
# Requires both password + current TOTP code. Revokes all refresh tokens.
```

### Token management
```python
result = await auth_svc.refresh_access_token(refresh_token, ip)
# → {"access_token", "refresh_token", ...}  (old token is revoked)
# Raises: ValueError (invalid/expired/reused token)

await auth_svc.logout(user_id_hex, refresh_token=None, ip="")
await auth_svc.logout_all_devices(user_id_hex, ip)
```

### Password management
```python
result = await auth_svc.change_password(user_id_hex, old_password, new_password, ip)
# Revokes all refresh tokens after change.

result = await auth_svc.request_password_reset(email, ip)
# Always returns success — never reveals if email exists.

result = await auth_svc.confirm_password_reset(email, code, new_password, ip)
```

---

## `KeyService` — `services/key_service.py`

Public key storage and retrieval. No crypto.

```python
# Called by AuthService during registration:
await key_svc.store_initial_keys(user_id_hex, signing_public_key, exchange_public_key, ip)

# Update one or both keys (frontend generates new pair):
await key_svc.update_keys(user_id_hex, ip, signing_public_key=None, exchange_public_key=None)

# Lookup (logs key access event):
keys = await key_svc.get_public_keys(user_id_hex, requester_id_hex, ip)
# → {user_id_hex, signing_public_key, exchange_public_key}

key = await key_svc.get_exchange_key(user_id_hex, requester_id_hex, ip)
# → {user_id_hex, exchange_public_key}  — use to encrypt data FOR this user

key = await key_svc.get_signing_key(user_id_hex, requester_id_hex, ip)
# → {user_id_hex, signing_public_key}  — use to verify signatures FROM this user

keys = await key_svc.get_my_keys(user_id_hex)
# → own keys, no audit log
```

---

## `GrantService` — `services/grant_service.py`

Time-bound, revocable access grants. Frontend encrypts the DEK for the
grantee — backend only stores the bundle and enforces time windows.

```python
grant = await grant_svc.create_grant(
    grantor_id_hex, grantee_id_hex, record_id,
    permission_level,       # "view_only" | "view_download"
    time_start, time_end,
    dek_bundle_grantee,     # DEK encrypted for grantee by frontend
    signature_hex,          # Ed25519 signature by grantor (frontend)
    ip_address,
)
# Raises: RecordNotFoundError (record/grantee not found)
#         ValueError (grantor doesn't own record, bad time window, bad permission)

result = await grant_svc.revoke_grant(grant_id, revoker_id_hex, ip)
# Only grantor may revoke.

access = await grant_svc.check_access(user_id_hex, record_id)
# → {"has_access": bool, "grant": dict|None, "permission_level": str|None}

grants = await grant_svc.list_grants_for_record(record_id, owner_id_hex)
grants = await grant_svc.list_my_grants(user_id_hex, as_grantor=True)

grant  = await grant_svc.get_grant_details(grant_id, user_id_hex)
# Only callable by grantor or grantee. Returns full row incl. dek_bundle_grantee.
# Marks retrieved_at on first grantee access.
```

---

## `RelayService` — `services/relay_service.py`

Zero-knowledge payload relay. Never stores ciphertext.

```python
# Grantee requests a record from its owner:
result = await relay_svc.request_share(
    requester_id_hex, owner_id_hex, record_id,
    requester_public_key,   # so owner can encrypt DEK for requester
    ip_address,
)
# → {"status": "pending", "share_id": ..., "message": ...}
# Raises: ValueError (no active grant)

# Owner sees pending requests:
requests = await relay_svc.get_pending_requests(owner_id_hex)
# → [{share_id, requester_id_hex, record_id, requester_public_key, requested_at}]

# Owner rejects a request:
await relay_svc.reject_share_request(owner_id_hex, share_id, ip)

# Owner sends encrypted payload (NEVER stored — returned directly):
result = await relay_svc.send_encrypted_payload(
    sender_id_hex, recipient_id_hex, record_id,
    encrypted_payload,      # already encrypted by frontend
    signature,              # signed by sender's private key (frontend)
    ip_address,
)
# → {"encrypted_payload", "signature", "sender_signing_key", "record_id", "sender_id_hex"}
# Route handler forwards this directly to the recipient.
# Raises: ValueError (sender doesn't own record, no active grant)

# Async notification (when recipient isn't polling):
await relay_svc.notify_payload_ready(recipient_id_hex, payload_reference, sender_id_hex, record_id)
notifications = await relay_svc.fetch_notifications(user_id_hex)
# → [{type, from_user, record_id, payload_reference, timestamp, share_id}]
```

---

## What services never do

```
✗ Generate key pairs          — frontend
✗ Encrypt or decrypt          — frontend
✗ Sign anything               — frontend
✗ Store private keys          — impossible, never arrive
✗ Store plaintext payloads    — zero-knowledge relay
✗ Write raw SQL               — DatabaseRepository
✗ Validate JWT tokens         — middleware (calls token_module.verify_token)
✗ Check JTI revocation        — middleware (calls db.is_token_revoked)
```

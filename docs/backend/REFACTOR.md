# Backend Refactor — Working Document

> Reference doc for systematic refactoring. Not a spec — a map.
> Update as decisions are made.

---

## Project Structure (target)

```
src/
├── auth/           ✅ done
├── database/       ⬜ next
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
| `database/` | DB connection + session management | ORM, config | auth, services |
| `models/` | DB schemas + Pydantic shapes | database | auth, services |
| `services/` | Orchestrates flows, owns business logic | auth, database, models | routes |
| `routes/` | Parses requests, calls services | services, models | auth, database directly |

---

## Status

### ✅ `auth/` — Complete

Self-contained auth workers. No DB. No user context. Each module does one job and returns results to whoever called it.

**Files:**

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

### ⬜ `database/` — Next

Similar structure to `auth/`. Connection management and session handling only. No business logic.

---

### ⬜ `models/` — Pending

---

### ⬜ `services/` — Pending

Integrates auth modules + database. Business logic lives here.

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

**Caller responsibility:** hash and store each code. These are shown once and never stored here.

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

**Caller responsibility:** persist `challenge` keyed by `challenge_id` before returning it to the client.

### `verify_solution(challenge, solution)`

```python
result = module.verify_solution(challenge=stored_challenge, solution=nonce)
# result.success  → bool
# result.message  → human-readable outcome
```

**Caller responsibility:** check expiry before calling this. Delete the challenge from storage on success (replay protection).

### `is_expired(challenge)`

```python
expired = module.is_expired(challenge)
# → bool
```

Convenience helper so the orchestrator doesn't do the timestamp math itself.

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

Catches: common passwords, keyboard patterns (qwerty, 123456), missing character classes.

### `hash_password(password)`

```python
ph = module.hash_password("MyP@ssw0rd!")
# ph.hash_hex    → store this
# ph.salt_hex    → store this
# ph.iterations  → store this (needed for future verification)
```

PBKDF2-HMAC-SHA512 with a random 16-byte salt.

### `verify_password(password, hash_hex, salt_hex, iterations)`

```python
ok = module.verify_password(
    password="MyP@ssw0rd!",
    hash_hex=row.hash_hex,
    salt_hex=row.salt_hex,
    iterations=row.iterations,
)
# → bool (timing-safe)
```

Always runs the full hash — pass dummy values for non-existent users to avoid timing-based user enumeration.

---

## Dependencies

```
pyotp                     # TOTP
wholemail                 # Gmail sending
disposable-email-domains  # Blocklist (7500+ domains)
pydantic                  # Models
```

---

## What goes where — quick reference

```
auth/email.py    →  "I validate, send, and return the code. You store it."
auth/totp.py     →  "Give me the secret, I'll generate or verify. You store it."
auth/pow.py      →  "I make challenges and check solutions. You store and expire them."
auth/password.py →  "I hash and verify. You store hash + salt + iterations."

services/        →  coordinates all of the above + talks to database
```

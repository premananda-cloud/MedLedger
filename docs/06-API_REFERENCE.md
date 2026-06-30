# MedLedger API Reference

**Version:** 1.0 | **Date:** June 2026 | **Status:** Current — Generated from `routes/auth.py` + `models/schemas.py`

This is the practical reference for frontend integration. For design rationale, see `03-AUTH_SPEC.md`. For crypto operations referenced here, see `05-KEYSET_MANAGER.md`.

---

## Base URL & Auth

```
Base URL: https://api.medledger.com   (or http://localhost:8000 in dev)
Auth header on protected routes: Authorization: Bearer <access_token>
```

All request and response bodies are JSON. All endpoints return Pydantic-validated shapes — a 422 response means the request body failed validation (see field-level error detail).

---

## Error Response Format

```json
{
  "detail": "Human-readable error message"
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request — validation failed at the business logic level (e.g. weak password, expired code) |
| 401 | Unauthorized — invalid credentials, expired/invalid token |
| 404 | Not found — user or resource doesn't exist |
| 409 | Conflict — duplicate email or username |
| 422 | Unprocessable entity — request body failed Pydantic schema validation |
| 500 | Internal server error |

---

## 1. Proof of Work

### `POST /auth/pow/challenge`

No auth required.

**Response 200:**
```json
{
  "challenge_id": "uuid-string",
  "challenge": "random-string-to-hash",
  "difficulty": 4,
  "timestamp": 1717800000.123
}
```

### `POST /auth/pow/verify`

**Request:**
```json
{
  "challenge_id": "uuid-string",
  "solution": "client-computed-solution"
}
```

**Response 200:** `{ "message": "Proof of work verified." }`
**Response 400:** Invalid solution.

---

## 2. Registration

### `POST /auth/register`

No auth required. Call this after PoW is verified and keys are generated client-side (see `05-KEYSET_MANAGER.md` → `createUser()`).

**Request:**
```json
{
  "email": "alice@example.com",
  "username": "alice",
  "password": "correct horse battery staple 1!",
  "full_name": "Alice Smith",
  "signing_public_key": "base64url-encoded-32-bytes",
  "exchange_public_key": "base64url-encoded-32-bytes"
}
```

| Field | Validation |
|-------|-----------|
| `email` | Valid email format |
| `username` | 3–30 chars, `[a-zA-Z0-9_]` only, lowercased server-side |
| `password` | Minimum 8 chars at schema level (full strength check server-side) |
| `full_name` | 1–100 chars, trimmed |
| `signing_public_key`, `exchange_public_key` | Required strings, no format validation at schema level |

**Response 202:**
```json
{ "message": "Registration complete. A verification code has been sent to your email." }
```

**Response 409:** Email or username already taken.
**Response 400:** Password too weak (message includes specific issues).

---

## 3. Email Verification

### `POST /auth/verify-email`

No auth required. On success, the user is immediately authenticated.

**Request:**
```json
{ "email": "alice@example.com", "code": "123456" }
```

**Response 200 (normal):**
```json
{
  "requires_totp": false,
  "user_id_hex": null,
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "opaque-string",
    "token_type": "bearer",
    "expires_in": 900
  },
  "user": {
    "user_id_hex": "a1b2c3...",
    "username": "alice",
    "email": "alice@example.com",
    "full_name": "Alice Smith",
    "role": "PATIENT",
    "is_verified": true,
    "totp_enabled": false,
    "created_at": "2026-06-09T10:00:00Z",
    "last_login_at": null
  }
}
```

**Response 400:** Code invalid or expired.
**Response 404:** User not found.

### `POST /auth/resend-verification`

**Request:** `{ "email": "alice@example.com" }`
**Response 200:** `{ "message": "Verification code sent." }`

---

## 4. Login

### `POST /auth/login`

No auth required.

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "correct horse battery staple 1!",
  "totp_code": null
}
```

**Response 200 (no TOTP):**
```json
{
  "requires_totp": false,
  "user_id_hex": null,
  "tokens": { "access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 900 },
  "user": { "user_id_hex": "...", "username": "alice", "...": "..." }
}
```

**Response 200 (TOTP required):**
```json
{
  "requires_totp": true,
  "user_id_hex": "a1b2c3...",
  "tokens": null,
  "user": null
}
```

**Response 401:** Invalid credentials, account locked, or account inactive/deleted.

### `POST /auth/verify-totp-login`

Call this when login returns `requires_totp: true`.

**Request:** `{ "user_id_hex": "a1b2c3...", "totp_code": "123456" }`
**Response 200:** Same shape as a normal login success (`requires_totp: false`, tokens, user).
**Response 401:** Invalid TOTP code.

---

## 5. Token Management

### `POST /auth/refresh`

No auth header required — refresh token is in the body.

**Request:** `{ "refresh_token": "opaque-string" }`
**Response 200:** `{ "access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 900 }`
**Response 401:** Invalid or expired refresh token.

**Frontend pattern:** intercept any 401 from a protected route, call this endpoint, retry the original request with the new access token. If refresh also fails, clear local state and redirect to login.

### `POST /auth/logout` 🔒

**Request:** `{ "refresh_token": "opaque-string" }` (optional — omit to only clear client state)
**Response 200:** `{ "message": "Logged out successfully." }`

### `POST /auth/logout-all` 🔒

No body. Revokes every refresh token for the user.
**Response 200:** `{ "message": "Logged out from all devices." }`

---

## 6. Password Management

### `POST /auth/change-password` 🔒

**Request:** `{ "old_password": "...", "new_password": "..." }`
**Response 200:** `{ "message": "Password changed. Please log in again." }`
**Response 400:** Wrong old password, or new password too weak.

All sessions are revoked — frontend must redirect to login after this call.

### `POST /auth/request-password-reset`

No auth required.

**Request:** `{ "email": "alice@example.com" }`
**Response 200:** Always the same message regardless of whether the email exists (prevents enumeration):
```json
{ "message": "If that email is registered, a reset code has been sent." }
```

### `POST /auth/confirm-password-reset`

**Request:**
```json
{ "email": "alice@example.com", "code": "123456", "new_password": "..." }
```

**Response 200:** `{ "message": "Password reset successfully. Please log in." }`
**Response 400:** Invalid/expired code, or weak password.

**Important for frontend UX:** Resetting the password restores account login only. If the user has also lost their `.medledger-key.json` file, the vault remains permanently locked. Display this clearly — do not imply password reset restores data access.

---

## 7. TOTP (Two-Factor Authentication)

### `POST /auth/totp/setup` 🔒

No body. Begins enrollment.

**Response 200:**
```json
{
  "uri": "otpauth://totp/MedLedger:alice?secret=...",
  "backup_codes": ["abc123", "def456", "..."],
  "message": "Store backup codes safely. They will never be shown again."
}
```

Render `uri` as a QR code for the user to scan. Show `backup_codes` once — they cannot be retrieved again.

### `POST /auth/totp/confirm` 🔒

**Request:** `{ "user_id_hex": "...", "totp_code": "123456" }`
**Response 200:** `{ "message": "TOTP enabled successfully." }`

### `POST /auth/totp/disable` 🔒

**Request:** `{ "user_id_hex": "...", "password": "...", "totp_code": "123456" }`
**Response 200:** `{ "message": "TOTP disabled. All sessions have been revoked." }`

Requires both password and a live TOTP code — disabling 2FA is a sensitive action.

---

## 8. Profile

### `GET /auth/me` 🔒

**Response 200:**
```json
{
  "user_id_hex": "a1b2c3...",
  "username": "alice",
  "email": "alice@example.com",
  "full_name": "Alice Smith",
  "role": "PATIENT",
  "is_verified": true,
  "totp_enabled": false,
  "created_at": "2026-06-09T10:00:00Z",
  "last_login_at": "2026-06-29T08:15:00Z"
}
```

Call this on app mount to check session validity and populate user state. Does not reveal vault lock state — that is purely client-side (see `05-KEYSET_MANAGER.md`).

---

## 9. Keys

🔒 = JWT required on all key endpoints.

### `GET /keys/my` 🔒

Own public keys, no audit log (not a sensitive lookup).

**Response 200:**
```json
{
  "user_id_hex": "a1b2c3...",
  "signing_public_key": "base64url...",
  "exchange_public_key": "base64url..."
}
```

### `GET /keys/{user_id_hex}` 🔒

Both keys for another user. Logged as a key access event.

**Response 200:** Same shape as `/keys/my`.
**Response 404:** User not found.

### `GET /keys/{user_id_hex}/exchange` 🔒

Use this before encrypting a file for someone (see `05-KEYSET_MANAGER.md` → `encryptRecord()`).

**Response 200:**
```json
{ "user_id_hex": "a1b2c3...", "exchange_public_key": "base64url..." }
```

### `GET /keys/{user_id_hex}/signing` 🔒

Use this before verifying a signature from someone.

**Response 200:**
```json
{ "user_id_hex": "a1b2c3...", "signing_public_key": "base64url..." }
```

### `PUT /keys/update` 🔒

Update one or both of your own public keys. At least one required.

**Request:**
```json
{
  "signing_public_key": "base64url...",
  "exchange_public_key": null
}
```

**Response 200:** `{ "message": "Public keys updated." }`
**Response 400:** Neither key provided.

**Warning:** Rotating keys invalidates all existing grants encrypted to the old key. The frontend should warn the user clearly before calling this — anyone who received a share encrypted to the old exchange key will no longer be able to decrypt it via re-fetch (already-downloaded plaintext is unaffected).

---

## 10. Full Auth Flow (Frontend Sequence)

This is the recommended call sequence for a complete registration → unlocked-vault flow.

```
1.  GET  /auth/pow/challenge
2.  [client solves PoW]
3.  POST /auth/pow/verify
4.  [client: KeysetManager.createUser(username) → keypair generated]
5.  [client: prompt user to download .medledger-key.json]
6.  POST /auth/register   (includes signing_public_key, exchange_public_key)
7.  [user receives email, enters 6-digit code]
8.  POST /auth/verify-email   → tokens + user returned, client now authenticated
9.  [vault already unlocked — keypair is in KeysetManager memory from step 4]
```

For returning users:

```
1.  POST /auth/login
2a. If requires_totp: POST /auth/verify-totp-login
2b. Else: tokens returned directly
3.  [vault shows "Locked"]
4.  [user uploads .medledger-key.json]
5.  [client: KeysetManager.loginUser(username, keypair)]
6.  [vault shows "Unlocked" — no server call for this step]
```

---

## 11. Pydantic Field Reference

Quick lookup for request/response field types — generated from `models/schemas.py`.

| Schema | Fields |
|--------|--------|
| `RegisterRequest` | email, username, password, full_name, signing_public_key, exchange_public_key |
| `LoginRequest` | email, password, totp_code? |
| `VerifyEmailRequest` | email, code (6 chars) |
| `ResendVerificationRequest` | email |
| `SetupTOTPRequest` | user_id_hex |
| `ConfirmTOTPRequest` | user_id_hex, totp_code (6 digits) |
| `DisableTOTPRequest` | user_id_hex, password, totp_code (6 digits) |
| `ChangePasswordRequest` | old_password, new_password (min 8 chars) |
| `RequestPasswordResetRequest` | email |
| `ConfirmPasswordResetRequest` | email, code (6 chars), new_password (min 8 chars) |
| `RefreshTokenRequest` | refresh_token |
| `LogoutRequest` | refresh_token? |
| `POWVerifyRequest` | challenge_id, solution |
| `VerifyTOTPLoginRequest` | user_id_hex, totp_code (6 digits) |
| `UserResponse` | user_id_hex, username, email, full_name, role, is_verified, totp_enabled, created_at?, last_login_at? |
| `TokenResponse` | access_token, refresh_token, token_type, expires_in |
| `LoginResponse` | requires_totp, user_id_hex?, tokens?, user? |
| `TOTPSetupResponse` | uri, backup_codes[], message |
| `UpdateKeysRequest` | signing_public_key?, exchange_public_key? (at least one required) |
| `PublicKeysResponse` | user_id_hex, signing_public_key?, exchange_public_key? |
| `ExchangeKeyResponse` | user_id_hex, exchange_public_key? |
| `SigningKeyResponse` | user_id_hex, signing_public_key? |

Vault, grant, and share schemas exist in `models/schemas.py` (`CreateVaultRecordRequest`, `CreateGrantRequest`, `GrantResponse`, etc.) — document these once `routes/vault.py` and `routes/grants.py` are finalized, since those routes weren't included in this review.

---

*Document: 06-API_REFERENCE.md | Version: 1.0 | June 2026*
*Generated from routes/auth.py and models/schemas.py — covers /auth/* and /keys/* only.*
*Vault, grant, and share endpoints to be added once those route files are reviewed.*

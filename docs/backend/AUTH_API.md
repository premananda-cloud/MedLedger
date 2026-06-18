# MedLedger — Auth API Reference

> Base URL: `http://localhost:8000`  
> All requests and responses are `application/json`.  
> Authenticated endpoints require `Authorization: Bearer <access_token>`.

---

## Overview

Authentication is split into three flows:

- **Registration** — 4-step state machine (PoW → Email → TOTP → Create account)
- **Login** — single call; returns JWT access + refresh tokens
- **Password reset** — 2-step (request code → verify + set new password)

The registration flow is stateful. Each step returns a `session_token` that must be forwarded to the next step. Steps cannot be skipped.

---

## Registration Flow

```
POST /auth/pow/init
        ↓  challenge_id, challenge, difficulty
POST /auth/pow/verify
        ↓  session_token
POST /auth/email/submit
        ↓  session_token (same)
POST /auth/email/verify
        ↓  session_token + TOTP QR URI
POST /auth/totp/verify
        ↓  session_token (same)
POST /auth/register
        ↓  user_id, username, created_at
```

---

### Step 1a — Get PoW Challenge

```
POST /auth/pow/init
```

No request body needed.

**Response `200`**
```json
{
  "step": "pow_challenge",
  "data": {
    "challenge_id": "a3f9c2...",
    "challenge": "Kx2bZ9...",
    "difficulty": 4,
    "timestamp": 1719000000.0
  },
  "next_action": "solve_pow"
}
```

**What to do:** Find a `nonce` (integer, starting from 0) such that:

```
SHA-256(challenge + nonce).startsWith("0".repeat(difficulty))
```

JavaScript example:

```js
async function solvePoW(challenge, difficulty) {
  const prefix = "0".repeat(difficulty);
  let nonce = 0;
  while (true) {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(challenge + nonce)
    );
    const hex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
    if (hex.startsWith(prefix)) return nonce;
    nonce++;
  }
}
```

Difficulty 4 takes ~300 ms on average. Run this in a Web Worker to avoid blocking the UI.

---

### Step 1b — Submit PoW Solution

```
POST /auth/pow/verify
```

**Request body**
```json
{
  "challenge_id": "a3f9c2...",
  "nonce": "31274"
}
```

> `nonce` is sent as a string.

**Response `200`**
```json
{
  "step": "pow_verified",
  "data": {},
  "next_action": "submit_email",
  "session_token": "c8f2e1a0...64-char hex..."
}
```

Save `session_token` — you'll pass it to every subsequent registration step.

---

### Step 2a — Submit Email

```
POST /auth/email/submit
```

**Request body**
```json
{
  "session_token": "c8f2e1a0...",
  "email": "alice@example.com"
}
```

**Response `200`**
```json
{
  "step": "email_code_sent",
  "data": {
    "message": "Verification code sent",
    "email": "ali***@example.com",
    "expires_in_seconds": 600,
    "expires_at": "2026-06-18T10:10:00+00:00"
  },
  "next_action": "verify_email_code"
}
```

The user receives a 6-digit code by email. It expires in 10 minutes. After 3 wrong attempts the code is invalidated and the user must restart from step 1.

**Error `400`** — invalid or disposable email domain:
```json
{ "detail": "Email address is not accepted" }
```

---

### Step 2b — Verify Email Code

```
POST /auth/email/verify
```

**Request body**
```json
{
  "session_token": "c8f2e1a0...",
  "code": "483920"
}
```

**Response `200`**
```json
{
  "step": "email_verified",
  "data": {
    "totp": {
      "qr_code_uri": "otpauth://totp/MedLedger:alice%40example.com?secret=JBSWY3...&issuer=MedLedger",
      "manual_key": "JBSWY3DPEHPK3PXP"
    }
  },
  "next_action": "verify_totp"
}
```

Display `qr_code_uri` as a QR code (use any QR library). Also show `manual_key` as a fallback for users who can't scan. The user scans with Google Authenticator, Authy, etc. and then submits their first 6-digit token.

> The raw TOTP secret is intentionally not exposed — only the provisioning URI and manual key.

---

### Step 3 — Confirm TOTP

```
POST /auth/totp/verify
```

**Request body**
```json
{
  "session_token": "c8f2e1a0...",
  "token": "123456"
}
```

**Response `200`**
```json
{
  "step": "totp_verified",
  "data": {
    "ready_for_registration": true
  },
  "next_action": "create_account"
}
```

**Error `400`** — wrong token (clock drift > ±30 s, or user scanned wrong QR):
```json
{ "detail": "Invalid TOTP token" }
```

---

### Step 4 — Create Account

```
POST /auth/register
```

**Request body**
```json
{
  "session_token": "c8f2e1a0...",
  "username": "alice",
  "password": "SecurePass123!",
  "signing_public_key": "04a1b2c3...",
  "exchange_public_key": "04d4e5f6...",
  "encrypted_private_key_bundle": "base64encodedciphertext..."
}
```

| Field | Required | Notes |
|---|---|---|
| `session_token` | ✅ | From step 1b, must have passed all 3 prior steps |
| `username` | ✅ | 1–32 chars, alphanumeric + underscores |
| `password` | ✅ | Must meet complexity rules (see below) |
| `signing_public_key` | ✅ | Client-generated; hex or base64 |
| `exchange_public_key` | ✅ | Client-generated; hex or base64 |
| `encrypted_private_key_bundle` | ⬜ | Recommended — ciphertext from your client-side key gen |

**Password rules** — must satisfy ≥ 3 of these 5:
- At least 8 characters
- Contains uppercase letter
- Contains lowercase letter
- Contains digit
- Contains special character

**Response `201`**
```json
{
  "step": "account_created",
  "user_id": "sha256hexofyoursigningkey...",
  "username": "alice",
  "email": "ali***@example.com",
  "created_at": "2026-06-18T10:05:00+00:00"
}
```

**Error `409`** — username taken:
```json
{ "detail": "Username already taken" }
```

After this response the session is destroyed. Redirect the user to login.

---

## Login

```
POST /auth/login
```

**Request body**
```json
{
  "username": "alice",
  "password": "SecurePass123!",
  "totp_token": ""
}
```

If the user has TOTP enabled and you don't include the token (or send `""`), you'll get a `400` with `step: totp_required`. Prompt for the token and retry with the same credentials.

**Response `200` — success**
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "a1b2c3d4...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

`expires_in` is in seconds (default 30 minutes for access token).

**Response `400` — TOTP required**
```json
{
  "detail": {
    "step": "totp_required",
    "message": "TOTP token required"
  }
}
```

Retry with the 6-digit code from the user's authenticator app:
```json
{
  "username": "alice",
  "password": "SecurePass123!",
  "totp_token": "847291"
}
```

**Response `401` — wrong credentials**
```json
{ "detail": "Invalid username or password" }
```

---

## Token Usage

Include the access token on every authenticated request:

```
Authorization: Bearer eyJhbGci...
```

Access tokens expire after 30 minutes (configurable). When one expires you'll get `401 Token expired` — use the refresh endpoint to get a new pair without asking the user to log in again.

---

## Refresh Token

```
POST /auth/refresh
```

**Request body**
```json
{
  "refresh_token": "a1b2c3d4..."
}
```

**Response `200`**
```json
{
  "access_token": "eyJhbGci...(new)...",
  "refresh_token": "e5f6g7h8...(new)...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

Refresh tokens **rotate** on every use — you get a new one each time. Store the new refresh token and discard the old one. If you try to reuse an old refresh token, all sessions for that user are immediately revoked (token theft detection).

Refresh tokens expire after 7 days of inactivity.

---

## Logout

```
POST /auth/logout
Authorization: Bearer <access_token>
```

**Request body**
```json
{
  "refresh_token": "a1b2c3d4..."
}
```

Send both the `Authorization` header (to revoke the access token) and the refresh token in the body (to revoke the refresh token). Both are optional but send both when you have them.

**Response `200`**
```json
{ "message": "Logged out" }
```

---

## Password Reset

### Step 1 — Request Reset Code

```
POST /auth/password-reset/init
```

**Request body**
```json
{ "email": "alice@example.com" }
```

**Response `200`** — always succeeds regardless of whether the email is registered (prevents user enumeration):
```json
{
  "step": "reset_code_sent",
  "data": { "message": "If an account exists, a reset code has been sent." },
  "next_action": "complete_password_reset"
}
```

---

### Step 2 — Complete Reset

```
POST /auth/password-reset/complete
```

**Request body**
```json
{
  "email": "alice@example.com",
  "code": "748291",
  "new_password": "NewSecure!456"
}
```

**Response `200`**
```json
{
  "step": "password_reset_complete",
  "data": { "message": "Password updated successfully" },
  "next_action": null
}
```

After a successful reset, all existing sessions for that user are revoked. They must log in again.

**Error `400`** — wrong or expired code:
```json
{ "detail": "Invalid or expired reset code" }
```

---

## Get Current User

```
GET /auth/me
Authorization: Bearer <access_token>
```

**Response `200`**
```json
{
  "user_id": "a1b2c3...",
  "username": "alice",
  "email": "alice@example.com",
  "role": "PATIENT",
  "is_verified": true,
  "created_at": "2026-06-18T10:05:00+00:00"
}
```

---

## Registration Session Status (debug / polling)

```
GET /auth/session/{session_token}
```

Returns the current state of a registration session. Useful for debugging or resuming an interrupted flow.

**Response `200`**
```json
{
  "step": "email_verified",
  "pow_verified": true,
  "email_verified": true,
  "totp_verified": false,
  "email": "ali***@example.com"
}
```

**Error `404`** — session expired or not found.

Sessions expire after 30 minutes of inactivity.

---

## Error Format

All errors follow this shape:

```json
{ "detail": "Human-readable message" }
```

Or for structured errors (e.g. TOTP required):

```json
{
  "detail": {
    "step": "totp_required",
    "message": "TOTP token required"
  }
}
```

| Status | Meaning |
|---|---|
| `400` | Bad request — invalid input, wrong code, step out of order |
| `401` | Unauthenticated — missing/expired/revoked token |
| `404` | Resource not found |
| `409` | Conflict — e.g. username already taken |
| `500` | Server error — report to backend team |

---

## Recommended Client Implementation

```
localStorage / sessionStorage:
  access_token   → in memory only (never persist to localStorage)
  refresh_token  → httpOnly cookie or sessionStorage

On every request:
  1. Attach Authorization: Bearer <access_token>
  2. On 401 → call POST /auth/refresh
  3. If refresh also fails → redirect to login

On app load:
  1. Try to refresh to get a fresh access token
  2. If refresh fails → user is logged out
```

---

## Key Generation (frontend responsibility)

The server stores your public keys but never sees your private keys. Before calling `POST /auth/register` you must:

1. Generate a signing keypair (e.g. Ed25519)
2. Generate an exchange keypair (e.g. X25519)
3. Encrypt your private keys with a key derived from the user's password
4. Send the public keys and the encrypted private key bundle to `/auth/register`

The server cannot recover your private keys. If the user forgets their password, private key material is lost.

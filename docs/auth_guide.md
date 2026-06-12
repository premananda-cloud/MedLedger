# Auth System — Usage Guide & Documentation

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Modules](#modules)
   - [POW (pow.js)](#pow-module)
   - [Email Verifier (email.js)](#email-module)
   - [TOTP Manager (totp.js)](#totp-module)
   - [User Manager (user.js)](#user-module)
   - [Storage (storage.js)](#storage-module)
4. [Authentication Flow](#authentication-flow)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Running Tests](#running-tests)
8. [Security Notes](#security-notes)

---

## Overview

This is a multi-step user registration and authentication system built in Node.js. It chains five verification stages before an account is created:

1. **Proof of Work** — bot/spam deterrent
2. **Email verification** — confirms ownership of a real email address
3. **TOTP 2FA setup** — enrolls the user in time-based one-time passwords
4. **Username/password creation** — sets credentials
5. **Account persistence** — saves the verified user to disk

All state between steps is held in a server-side session map keyed by a cryptographically random session token.

---

## Architecture

```
auth/
├── orchestrator/
│   └── authFlow.js       # Coordinates all steps; holds session state
├── modules/
│   ├── pow.js            # Proof-of-work challenge/verification
│   ├── email.js          # Email verification code generation/validation
│   ├── totp.js           # TOTP secret generation, QR code, token verification
│   ├── user.js           # Username/password validation and account creation
│   └── storage.js        # File-based user persistence (data/users.json)
├── tests/
│   └── authTest.js       # End-to-end integration test
└── data/
    └── users.json        # Persisted user records
```

The orchestrator (`authFlow.js`) is the only public-facing interface. Modules are internal and should not be called directly by application code.

---

## Modules

### POW Module

**File:** `modules/pow.js`  
**Purpose:** Generates and verifies SHA-256 proof-of-work challenges to deter automated registrations.

Each challenge requires the client to find a `nonce` such that:

```
SHA-256(challenge + nonce)  starts with  "0000"  (difficulty = 4)
```

**Key methods:**

| Method | Description |
|---|---|
| `generateChallenge()` | Returns a new `{ challengeId, challenge, difficulty, timestamp }`. Challenges older than 5 minutes are auto-purged. |
| `verify(challengeId, nonce)` | Returns `{ success, message, sessionToken }`. Each challenge can only be used once. |
| `getStatus()` | Returns `{ activeChallenges, difficulty }` for diagnostics. |

**Defaults:**

| Parameter | Value |
|---|---|
| Difficulty (leading zeros) | `4` |
| Challenge expiry | 5 minutes |
| Challenge bytes | 32 (base64 encoded) |

---

### Email Module

**File:** `modules/email.js`  
**Purpose:** Generates a one-time 6-digit verification code for a given email address and validates it.

Codes are generated using `crypto.randomInt` (cryptographically secure). They expire after 10 minutes and are invalidated after 3 failed attempts.

**Key methods:**

| Method | Description |
|---|---|
| `generateCode(email)` | Generates and stores a code for the email. Returns `{ code, expiresIn, timestamp }`. |
| `verifyCode(email, code)` | Returns `{ verified, message, attemptsLeft }`. |
| `isVerified(email)` | Returns `true` if the email has a verified code in memory. |
| `getCodeForTesting(email)` | **Test-only.** Returns the stored code. Throws if `NODE_ENV !== 'test'`. |
| `getStatus()` | Returns `{ activeCodes, expiryTime }`. |

**Defaults:**

| Parameter | Value |
|---|---|
| Code length | 6 digits |
| Expiry | 10 minutes |
| Max attempts | 3 |

> **Note:** The `generateCode` return value includes the raw code. Callers should handle this carefully and not log or serialize it in production.

---

### TOTP Module

**File:** `modules/totp.js`  
**Purpose:** Generates TOTP secrets, produces `otpauth://` URIs for QR code enrollment, and verifies 6-digit tokens.

Uses `speakeasy` for TOTP operations and `qrcode` for QR image generation.

**Key methods:**

| Method | Description |
|---|---|
| `generateSecret(email)` | Returns `{ secret, qrCodeUri, manualKey }`. Stores the secret keyed by email. |
| `generateQRCode(otpauthUrl)` | Async. Returns a base64 data URL of the QR code image. |
| `verifyToken(email, token)` | Returns `{ verified, remaining, message }`. Accepts tokens within ±1 window (30 seconds). |
| `getCurrentToken(email)` | **Test/debug only.** Returns the currently valid token for the stored secret. |
| `hasSecret(email)` | Returns `true` if a secret is stored for this email. |

**Defaults:**

| Parameter | Value |
|---|---|
| Secret length | 20 bytes |
| Issuer name | `"AuthSystem"` |
| TOTP window | 1 (±30 seconds tolerance) |

---

### User Module

**File:** `modules/user.js`  
**Purpose:** Validates username and password, hashes passwords, and creates user accounts.

Passwords are hashed with PBKDF2-SHA512, 600,000 iterations, with a 16-byte random salt (OWASP 2023 recommended).

**Key methods:**

| Method | Description |
|---|---|
| `validateUsername(username)` | Returns `{ valid, message }`. Checks length, character set, and uniqueness (case-insensitive). |
| `validatePassword(password)` | Returns `{ valid, message, strength, strengthLabel }`. Requires 3 of 5 complexity criteria. |
| `hashPassword(password, salt)` | Async. Returns the hex-encoded PBKDF2 hash. |
| `createUser(username, password, email)` | Async. Validates, hashes, and persists the user. Returns `{ created, message, userId }`. |
| `verifyPassword(username, password)` | Async. Returns `true` if the password matches the stored hash. |
| `getUserInfo(username)` | Returns safe user info (no hash, no salt). |

**Username rules:**

| Rule | Value |
|---|---|
| Min length | 3 characters |
| Max length | 30 characters |
| Allowed characters | Letters, numbers, underscores |
| Case sensitivity | Stored and compared in lowercase |

**Password strength criteria (need 3 of 5):**

- Uppercase letter
- Lowercase letter
- Number
- Special character (`!@#$%^&*(),.?":{}|<>`)
- 12+ characters

**Password hashing:**

| Parameter | Value |
|---|---|
| Algorithm | PBKDF2 |
| Hash function | SHA-512 |
| Iterations | 600,000 |
| Key length | 64 bytes |
| Salt | 16 random bytes (hex) |

---

### Storage Module

**File:** `modules/storage.js`  
**Purpose:** Reads and writes user records to `data/users.json`. Loaded as a singleton at startup.

**Key methods:**

| Method | Description |
|---|---|
| `saveUser(user)` | Appends a user record. Returns `false` if username or email already exists. |
| `getUserByUsername(username)` | Case-insensitive lookup. Returns the full user object or `null`. |
| `getUserByEmail(email)` | Returns the full user object or `null`. |
| `usernameExists(username)` | Case-insensitive. Returns `boolean`. |
| `emailExists(email)` | Returns `boolean`. |
| `getUserCount()` | Returns total number of registered users. |
| `getAllUsers()` | Returns an array of `{ username, email, createdAt }` (no secrets). |

**Stored user record shape:**

```json
{
  "userId": "<32-char hex>",
  "username": "<lowercase>",
  "email": "user@example.com",
  "passwordHash": "<128-char hex>",
  "salt": "<32-char hex>",
  "createdAt": 1700000000000,
  "totpEnabled": true,
  "verified": true
}
```

---

## Authentication Flow

The complete registration flow is orchestrated by `authFlow.js`. All calls go through this single interface.

```
Client                          AuthFlow
  │                                │
  │──── initPOW() ────────────────▶│  Generate SHA-256 challenge
  │◀─── { challengeId, challenge } │
  │                                │
  │  [Client solves POW]           │
  │                                │
  │──── verifyPOW(id, nonce) ─────▶│  Validate hash, create session
  │◀─── { sessionToken }           │
  │                                │
  │──── submitEmail(token, email) ─▶│  Send 6-digit code to email
  │◀─── { maskedEmail, expiresIn } │
  │                                │
  │──── verifyEmailCode(token, code)▶│  Validate code, generate TOTP secret
  │◀─── { qrCodeUri, manualKey }   │
  │                                │
  │  [User scans QR in auth app]   │
  │                                │
  │──── verifyTOTP(token, totpCode)▶│  Verify 6-digit TOTP token
  │◀─── { qrCode (data URL) }      │
  │                                │
  │──── createAccount(token, u, p) ▶│  Validate creds, hash password, save user
  │◀─── { userId, username }       │  Session is deleted
```

### Step-by-step

**Step 1 — Init POW**
```js
const step1 = authFlow.initPOW();
// Returns: { step: "pow_challenge", data: { challengeId, challenge, difficulty, timestamp } }
```

**Step 2 — Verify POW**
```js
const step2 = authFlow.verifyPOW(challengeId, nonce);
// Returns: { step: "pow_verified", data: { sessionToken, message } }
const { sessionToken } = step2.data;
```

**Step 3 — Submit email**
```js
const step3 = authFlow.submitEmail(sessionToken, "user@example.com");
// Returns: { step: "email_code_sent", data: { message, expiresIn, email } }
// An email with the 6-digit code is sent to the user at this point.
```

**Step 4 — Verify email code**
```js
const step4 = authFlow.verifyEmailCode(sessionToken, "483920");
// Returns: { step: "email_verified", data: { message, totp: { qrCodeUri, manualKey } } }
```

**Step 5 — Verify TOTP**
```js
const step5 = await authFlow.verifyTOTP(sessionToken, "123456");
// Returns: { step: "totp_verified", data: { message, qrCode } }
```

**Step 6 — Create account**
```js
const step6 = await authFlow.createAccount(sessionToken, "myusername", "SecureP@ss123");
// Returns: { step: "account_created", data: { message, userId, username } }
// Session is destroyed on success.
```

### Error responses

Every step returns a consistent envelope. On failure:

```json
{
  "step": "error",
  "data": { "message": "Reason for failure" },
  "next": null
}
```

The `next` field indicates what the client should do next (e.g. `"retry_code"`, `"restart"`, or `null` to abort).

### Session status (debug)

```js
authFlow.getSessionStatus(sessionToken);
// Returns: { exists, powVerified, emailVerified, totpVerified, email }
// Email is masked: "tes***@example.com"
```

---

## Configuration

Configuration is currently hardcoded in each module. The relevant values and their locations:

| Setting | Default | Location |
|---|---|---|
| POW difficulty | `4` leading zeros | `pow.js` constructor |
| Challenge expiry | 5 minutes | `pow.js → cleanupOldChallenges` |
| Email code length | 6 digits | `email.js` constructor |
| Email code expiry | 10 minutes | `email.js` constructor |
| Email max attempts | 3 | `email.js → generateCode` |
| TOTP issuer name | `"AuthSystem"` | `totp.js` constructor |
| TOTP window | 1 (±30s) | `totp.js → verifyToken` |
| Username min length | 3 | `user.js` constructor |
| Username max length | 30 | `user.js` constructor |
| Password min length | 8 | `user.js` constructor |
| PBKDF2 iterations | 600,000 | `user.js → hashPassword` |
| PBKDF2 key length | 64 bytes | `user.js → hashPassword` |
| Storage file path | `data/users.json` | `storage.js` constructor |

---

## Running Tests

The test script runs a full end-to-end registration flow against the live modules.

**Requirements:** `NODE_ENV=test` must be set so that `getCodeForTesting()` is accessible.

```bash
cd auth
NODE_ENV=test node tests/authTest.js
```

Expected output:

```
=== Auth Flow Test ===

1. Getting POW challenge...
2. Verifying POW...
3. Submitting email...
4. Verifying email code...
5. Setting up TOTP...
6. Creating account...
7. Testing case-insensitive username (Bug 6 fix)...
8. Session status...

=== Test Complete ===

✅ All fixes verified:
   Bug 1: TOTP secret not regenerated
   Bug 2: CSPRNG used for email codes
   Bug 3: PBKDF2 with 600,000 iterations
   Bug 4: Correct require path
   Bug 5: No plaintext code leakage
   Bug 6: Case-insensitive usernames
```

**Installing dependencies** (if not already installed):

```bash
npm install speakeasy qrcode
```

---

## Security Notes

### What's implemented correctly

- Cryptographically secure random number generation throughout (`crypto.randomBytes`, `crypto.randomInt`)
- PBKDF2 password hashing at OWASP-recommended iteration count (600,000 × SHA-512)
- Email codes are invalidated after 3 failed attempts
- POW challenges are single-use (replay protection)
- Test-only code paths are gated behind `NODE_ENV === 'test'`
- Usernames are normalized to lowercase to prevent `Admin` / `admin` conflicts
- Session is destroyed immediately after account creation

### Known limitations to address before production

| Issue | Recommendation |
|---|---|
| Email code comparison uses `===` (timing-unsafe) | Replace with `crypto.timingSafeEqual` |
| Sessions have no expiry check | Add a TTL check in each `verifyXxx` method |
| No rate limiting on `initPOW` | Cap challenges per IP; limit map size |
| `generateCode` returns the plaintext code | Remove `code` from the return value; use `getCodeForTesting` in tests only |
| `users.json` is unencrypted on disk | Use a proper database with appropriate access controls |
| `getSessionStatus` and `getCurrentToken` are unauthenticated | Remove or protect these endpoints in production |
| No binding of session token to client fingerprint | Consider binding to IP/user-agent |

# Auth System — Usage Guide & Documentation

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Modules](#modules)
   - [PoW (pow.js)](#pow-module)
   - [Email Verifier (email.js)](#email-module)
   - [TOTP Manager (totp.js)](#totp-module)
   - [User Manager (user.js)](#user-module)
   - [Storage (storage.js)](#storage-module)
5. [Authentication Flow](#authentication-flow)
   - [Step-by-step API](#step-by-step-api)
   - [Error Responses](#error-responses)
   - [Session Status](#session-status)
6. [API Reference](#api-reference)
7. [Configuration](#configuration)
8. [Running Tests](#running-tests)
   - [Test Setup](#test-setup)
   - [Coverage](#coverage)
9. [Security Notes](#security-notes)
10. [Changelog](#changelog)

---

## Overview

This is a multi-step user registration and authentication system built in Node.js with ESM modules. It chains five verification stages before an account is created:

1. **Proof of Work (PoW)** — bot/spam deterrent via SHA-256 computational challenge
2. **Email verification** — confirms ownership of a real email address via 6-digit code
3. **TOTP 2FA setup** — enrolls the user in time-based one-time passwords
4. **Username/password creation** — sets credentials with strength validation
5. **Account persistence** — saves the verified user to disk (`data/users.json`)

All state between steps is held in a server-side session map keyed by a cryptographically random session token.

---

## Architecture

The system uses a **singleton-per-module** pattern with explicit reset functions for testability. Each module exposes:

- A class with configurable constructor parameters
- A `getXxx()` factory that returns a cached singleton instance
- A `resetXxx()` function that clears the singleton (and internal state)

The orchestrator (`authFlow.js`) is the only public-facing interface. Individual modules should not be called directly by application code.

---

## Project Structure

```
auth/
├── coverage/              # Vitest coverage reports
├── data/
│   └── users.json         # Persisted user records (auto-created)
├── modules/
│   ├── pow.js             # Proof-of-work challenge/verification
│   ├── email.js           # Email verification code generation/validation
│   ├── totp.js            # TOTP secret generation, QR code, token verification
│   ├── user.js            # Username/password validation and account creation
│   └── storage.js         # File-based user persistence
├── orchestrator/
│   └── authFlow.js        # Coordinates all steps; holds session state
├── tests/
│   └── auth.test.js       # End-to-end integration tests (Vitest)
├── index.js               # Entry point / server (if applicable)
├── package.json           # Dependencies: speakeasy, qrcode, vitest
├── vitest.config.js       # Vitest configuration
└── run_test.sh            # Convenience test runner script
```

### Dependencies

| Package | Purpose |
|---|---|
| `speakeasy` | TOTP secret generation and token verification |
| `qrcode` | QR code generation for TOTP enrollment |
| `vitest` | Test framework (dev dependency) |

All other APIs (`crypto`, `fs/promises`, `path`) are Node.js built-ins.

---

## Modules

### PoW Module

**File:** `modules/pow.js`  
**Purpose:** Generates and verifies SHA-256 proof-of-work challenges to deter automated registrations.

Each challenge requires the client to find a `nonce` such that:

```
SHA-256(challenge + nonce) starts with "0000" (difficulty = 4)
```

**Key methods:**

| Method | Description |
|---|---|
| `generateChallenge()` | Returns a new `{ challenge_id, challenge, difficulty, timestamp }`. Challenges older than 5 minutes are auto-purged. |
| `verify(challengeId, nonce)` | Returns `{ success, message, sessionToken }`. Each challenge can only be used once. |
| `cleanup()` | Removes expired challenges (called automatically every 60s). |
| `getStatus()` | Returns `{ activeChallenges, difficulty }` for diagnostics. |
| `destroy()` | Clears the auto-purge interval (call on shutdown). |
| `reset()` | Clears all in-memory challenges. |

**Singleton exports:**

```js
import { getPoW, resetPoW } from "./modules/pow.js";
```

**Defaults:**

| Parameter | Value |
|---|---|
| Difficulty (leading zeros) | `4` |
| Challenge expiry | 5 minutes |
| Challenge bytes | 32 (base64 encoded) |
| Challenge ID bytes | 16 (hex encoded) |
| Auto-cleanup interval | 60 seconds |

---

### Email Module

**File:** `modules/email.js`  
**Purpose:** Generates a one-time 6-digit verification code for a given email address and validates it.

Codes are generated using `crypto.randomInt` (cryptographically secure). They expire after 10 minutes and are invalidated after 3 failed attempts.

**Key methods:**

| Method | Description |
|---|---|
| `generateCode(email)` | Generates and stores a code for the email. Returns `{ code, expiresIn, timestamp }`. In non-test environments, logs the code to stdout. |
| `verifyCode(email, code)` | Returns `{ verified, message, attemptsLeft }`. |
| `isVerified(email)` | Returns `true` if the email has a verified code in memory. |
| `getCodeForTesting(email)` | **Test-only.** Returns the stored code. Throws if `NODE_ENV !== 'test'`. |
| `getStatus()` | Returns `{ activeCodes, expiryTime }`. |
| `reset()` | Clears all in-memory codes. |

**Singleton exports:**

```js
import { getEmailVerifier, resetEmailVerifier } from "./modules/email.js";
```

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
| `generateSecret(email)` | Returns `{ secret, qrCodeUri, manualKey }`. Stores the secret keyed by normalized email. |
| `generateQRCode(otpauthUrl)` | Async. Returns a base64 data URL of the QR code image. |
| `verifyToken(email, token)` | Returns `{ verified, remaining, message }`. Accepts tokens within ±1 window (30 seconds). |
| `getCurrentToken(email)` | **Test/debug only.** Returns the currently valid token for the stored secret. |
| `hasSecret(email)` | Returns `true` if a secret is stored for this email. |
| `reset()` | Clears all in-memory secrets. |

**Singleton exports:**

```js
import { getTOTPManager, resetTOTPManager } from "./modules/totp.js";
```

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
| `hashPassword(password, salt)` | Async. Returns `{ hash, salt }` with hex-encoded PBKDF2 hash. |
| `createUser(username, password, email)` | Async. Validates, hashes, and persists the user. Returns `{ created, message, userId }`. |
| `verifyPassword(username, password)` | Async. Returns `true` if the password matches the stored hash (timing-safe). |
| `getUserInfo(username)` | Returns safe user info (no hash, no salt). |
| `reset()` | Async. Clears storage (delegates to `storage.reset()`). |

**Singleton exports:**

```js
import { getUserManager, resetUserManager } from "./modules/user.js";
```

**Username rules:**

| Rule | Value |
|---|---|
| Min length | 3 characters |
| Max length | 30 characters |
| Allowed characters | Letters, numbers, underscores (`a-zA-Z0-9_`) |
| Case sensitivity | Stored and compared in lowercase |
| Uniqueness | Checked against both username and email |

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
| `init()` | Async. Creates `data/` directory and loads `users.json` into memory. Called automatically by `saveUser()`. |
| `saveUser(user)` | Async. Appends a user record. Returns `false` if username or email already exists. |
| `getUserByUsername(username)` | Case-insensitive lookup. Returns the full user object or `null`. |
| `getUserByEmail(email)` | Returns the full user object or `null`. |
| `usernameExists(username)` | Case-insensitive. Returns `boolean`. |
| `emailExists(email)` | Returns `boolean`. |
| `getUserCount()` | Returns total number of registered users. |
| `getAllUsers()` | Returns an array of `{ username, email, createdAt }` (no secrets). |
| `reset()` | Async. Clears in-memory users, resets initialization flag, and writes `"[]"` to disk. |

**Singleton exports:**

```js
import { getStorage, resetStorage } from "./modules/storage.js";
```

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
  │◀─── { challenge_id, challenge } │
  │                                │
  │  [Client solves PoW]           │
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

### Step-by-step API

**Step 1 — Init PoW**
```js
const step1 = authFlow.initPOW();
// Returns: { step: "pow_challenge", data: { challenge_id, challenge, difficulty, timestamp } }
```

**Step 2 — Verify PoW**
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

### Error Responses

Every step returns a consistent envelope. On failure:

```json
{
  "step": "error",
  "data": { "message": "Reason for failure" },
  "next": "retry" | "retry_code" | "retry_totp" | "restart" | null
}
```

The `next` field indicates what the client should do next:

| Value | Meaning |
|---|---|
| `"retry"` | Retry the same step (e.g., invalid email format) |
| `"retry_code"` | Retry with a new email code |
| `"retry_totp"` | Retry with a new TOTP token |
| `"restart"` | Start over from Step 1 (session invalid/expired) |
| `null` | Abort (fatal error) |

### Session Status

```js
authFlow.getSessionStatus(sessionToken);
// Returns: { exists, powVerified, emailVerified, totpVerified, email }
// Email is masked: "tes***@example.com"
```

---

## API Reference

### `AuthFlow` Class (`orchestrator/authFlow.js`)

| Method | Async | Parameters | Returns | Description |
|---|---|---|---|---|
| `initPOW()` | No | — | `{ step, data }` | Generates a new PoW challenge. |
| `verifyPOW(challengeId, nonce)` | No | `challengeId: string`, `nonce: string` | `{ step, data, next? }` | Verifies PoW, creates session. |
| `submitEmail(sessionToken, email)` | No | `sessionToken: string`, `email: string` | `{ step, data, next? }` | Generates and sends email code. |
| `verifyEmailCode(sessionToken, code)` | No | `sessionToken: string`, `code: string` | `{ step, data, next? }` | Verifies email code, generates TOTP secret. |
| `verifyTOTP(sessionToken, totpToken)` | **Yes** | `sessionToken: string`, `totpToken: string` | `{ step, data, next? }` | Verifies TOTP token, generates QR code. |
| `createAccount(sessionToken, username, password)` | **Yes** | `sessionToken: string`, `username: string`, `password: string` | `{ step, data, next? }` | Validates credentials, hashes password, saves user. Destroys session on success. |
| `getSessionStatus(sessionToken)` | No | `sessionToken: string` | `{ exists, powVerified?, emailVerified?, totpVerified?, email? }` | Returns current session state with masked email. |
| `reset()` | No | — | `void` | Clears all sessions and resets all module singletons. |

### Singleton Exports

```js
// Get the orchestrator instance
import { getAuthFlow } from "./orchestrator/authFlow.js";

// Reset everything (useful for testing)
import { resetAuthFlow } from "./orchestrator/authFlow.js";
```

---

## Configuration

Configuration is currently hardcoded in each module constructor. The relevant values and their locations:

| Setting | Default | Module | Parameter |
|---|---|---|---|
| PoW difficulty | `4` leading zeros | `pow.js` | `difficulty` |
| Challenge expiry | 5 minutes | `pow.js` | `expiryMs` |
| Challenge bytes | 32 (base64) | `pow.js` | `crypto.randomBytes(32)` |
| Email code length | 6 digits | `email.js` | `codeLength` |
| Email code expiry | 10 minutes | `email.js` | `expiryMs` |
| Email max attempts | 3 | `email.js` | `maxAttempts` |
| TOTP issuer name | `"AuthSystem"` | `totp.js` | `issuer` |
| TOTP window | 1 (±30s) | `totp.js` | `window` |
| Username min length | 3 | `user.js` | `minUsername` |
| Username max length | 30 | `user.js` | `maxUsername` |
| Password min length | 8 | `user.js` | `minPassword` |
| PBKDF2 iterations | 600,000 | `user.js` | `pbkdf2Iterations` |
| PBKDF2 key length | 64 bytes | `user.js` | `pbkdf2KeyLength` |
| Storage file path | `data/users.json` | `storage.js` | `dataDir`, `fileName` |

---

## Running Tests

Tests are written with **Vitest** and located in `tests/auth.test.js`.

### Test Setup

```bash
cd auth
npm install        # if not already installed
npm test           # or: npx vitest
```

Or use the convenience script:

```bash
bash run_test.sh
```

### Test Configuration

`vitest.config.js` (example):

```js
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    coverage: {
      reporter: ["text", "html"],
      reportsDirectory: "./coverage",
    },
  },
});
```

### Coverage

```bash
npx vitest --coverage
```

Reports are written to `./coverage/` in both text and HTML formats.

### Test Structure

| Suite | Tests |
|---|---|
| `Auth Flow` | Full registration flow, invalid PoW rejection, invalid email code rejection |
| `User Validation` | Username validation rules, password strength criteria |

### Test Environment

`NODE_ENV=test` must be set so that `getCodeForTesting()` is accessible. The `beforeEach`/`afterEach` hooks reset all singletons to ensure test isolation.

---

## Security Notes

### What's implemented correctly

- Cryptographically secure random number generation throughout (`crypto.randomBytes`, `crypto.randomInt`)
- PBKDF2 password hashing at OWASP-recommended iteration count (600,000 × SHA-512)
- Timing-safe password comparison via `crypto.timingSafeEqual`
- Email codes are invalidated after 3 failed attempts
- PoW challenges are single-use (replay protection)
- Test-only code paths are gated behind `NODE_ENV === 'test'`
- Usernames and emails are normalized to lowercase to prevent `Admin` / `admin` conflicts
- Session is destroyed immediately after account creation
- Email addresses are masked in API responses (e.g., `tes***@example.com`)

### Known limitations to address before production

| Issue | Recommendation |
|---|---|
| Email code comparison uses `===` (timing-unsafe) | Replace with `crypto.timingSafeEqual` or constant-time comparison |
| Sessions have no expiry check | Add a TTL check in each `verifyXxx` method (e.g., 30-minute session expiry) |
| No rate limiting on `initPOW` | Cap challenges per IP; limit map size to prevent memory exhaustion |
| `generateCode` returns the plaintext code | Remove `code` from the return value; use `getCodeForTesting` in tests only |
| `users.json` is unencrypted on disk | Use a proper database (PostgreSQL, MongoDB) with appropriate access controls |
| `getSessionStatus` and `getCurrentToken` are unauthenticated | Remove or protect these endpoints behind admin/auth in production |
| No binding of session token to client fingerprint | Consider binding to IP/user-agent to prevent token theft/replay |
| No HTTPS enforcement | All endpoints must run over TLS in production |
| No audit logging | Log security events (failed logins, code attempts, account creation) |

---

## Changelog

### Current Version

- **ESM modules** — All files use `import`/`export` syntax with `.js` extensions
- **Singleton reset functions** — Added `resetXxx()` to all modules for clean test isolation
- **Vitest test suite** — Replaced ad-hoc test runner with structured Vitest tests
- **Coverage reporting** — Added `coverage/` output via Vitest
- **Project structure** — Added `orchestrator/`, `tests/`, `coverage/`, config files
- **PoW destroy method** — Added `destroy()` to clear cleanup intervals on shutdown
- **Storage reset** — Added `reset()` that clears memory and writes `"[]"` to disk

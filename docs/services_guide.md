# MedLedger Services Guide

## Overview

The `services/` directory contains the core HTTP and authentication coordination layer for the MedLedger UI. These modules bridge the React component layer with the backend API and cryptographic key management systems.

**Design Philosophy:**
- **Separation of concerns**: API transport, auth orchestration, and crypto operations are kept in distinct files
- **No DOM access**: These modules never touch the browser DOM or React state directly
- **No persistent storage**: JWTs and private keys are held in memory only; storage decisions live in the component/hook layer
- **Error uniformity**: All modules throw `ApiError` (network/server) or `KeysetError` (crypto) for consistent upstream handling

---

## File Reference

| File | Responsibility | Depends On |
|------|----------------|------------|
| `apiClient.js` | Base HTTP client, JWT attachment, JSON envelope parsing | None (pure transport) |
| `loginBridge.js` | Signature-based login flow for returning users | `apiClient.js`, `key_manager/key_manager.js` |
| `registerBridge.js` | Six-step registration flow (PoW → Email → TOTP → Account) | `apiClient.js`, `key_manager/key_manager.js` |
| `authKeyBridge.js` | High-level coordinator that merges auth flow with key lifecycle | `auth/orchestrator/authFlow.js`, `key_manager/key_manager.js` |

---

## `apiClient.js` — Base HTTP Client

### Purpose
Low-level fetch wrapper that handles JWT injection, JSON envelope parsing (`{ ok, data, error }`), and uniform error throwing.

### Token Management (In-Memory Only)

| Function | Signature | Description |
|----------|-----------|-------------|
| `setToken(token)` | `setToken(string): void` | Stores JWT in module-scoped memory after login/registration. Throws if token is empty. |
| `clearToken()` | `clearToken(): void` | Wipes the in-memory JWT. Call alongside `KeysetManager.logoutUser()`. |
| `hasToken()` | `hasToken(): boolean` | Returns `true` if a JWT is currently held. |

> **Security note:** The token is never written to `localStorage` or `sessionStorage`. The caller (typically `useAuth.js`) must decide how to handle token persistence across page reloads.

### Error Type

```js
class ApiError extends Error {
  name = "ApiError";
  status;   // HTTP status code (0 for network failure)
  code;     // Server-side error code string, e.g. "INVALID_SIGNATURE"
}
```

### Core API Object

```js
import { api } from "./apiClient.js";

// All methods return the parsed `data` field from the server envelope
await api.get("/records");                    // GET
await api.post("/records", { title: "x" });   // POST with body
await api.put("/records/1", { title: "y" }); // PUT
await api.patch("/records/1", { title: "z" }); // PATCH
await api.delete("/records/1");                // DELETE
```

All methods accept an optional `opts` object forwarded to `fetch()` (e.g., `signal` for `AbortController`).

### Envelope Handling

The server returns JSON envelopes in the shape `{ ok, data, error }`. The client treats the response as an error if **either**:
- The HTTP status is non-2xx (`!response.ok`), **or**
- The envelope explicitly indicates failure (`envelope.ok === false`)

This catches logical errors that the server may return with HTTP 200 (e.g., rate limits, validation failures).

### Auth-Specific Endpoints (`authApi`)

Thin wrappers around the six-step registration flow and login endpoint. The business logic lives in `registerBridge.js` and `loginBridge.js`.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `authApi.initPoW()` | `GET /auth/pow/init` | Fetch a PoW challenge |
| `authApi.verifyPoW(challengeId, nonce)` | `POST /auth/pow/verify` | Submit solved nonce, receive `sessionToken` |
| `authApi.submitEmail(sessionToken, email)` | `POST /auth/email/submit` | Submit email for verification |
| `authApi.verifyEmailCode(sessionToken, code)` | `POST /auth/email/verify` | Submit 6-digit email code |
| `authApi.verifyTOTP(sessionToken, totpToken)` | `POST /auth/totp/verify` | Submit TOTP token |
| `authApi.createAccount(sessionToken, username, password, publicKeys)` | `POST /auth/account/create` | Final registration step; sends credentials + public keys |
| `authApi.login(payloadCanon, signature, username)` | `POST /auth/login` | Signature-based login; returns JWT |
| `authApi.logout()` | `POST /auth/logout` | Server-side JWT invalidation |
| `authApi.getUserKeys(username)` | `GET /users/{username}/keys` | Fetch another user's public keys (for encryption) |

---

## `loginBridge.js` — Signature-Based Login

### Purpose
Authenticates returning users without ever sending their password over the wire. The server verifies an Ed25519 signature on a timestamped payload.

### Flow
1. Validate inputs (username length, keypair shape)
2. Load the user's saved keypair into `KeysetManager`
3. Build a canonical login payload: `{ action: "login", username, issuedAt: ISOString }`
4. Sign the payload with `KeysetManager.signPayload()`
5. Self-verify the signature locally (catches corrupt keypairs early)
6. POST `{ payloadCanon, signature, username }` to `/auth/login`
7. Server verifies signature against stored public key → returns JWT
8. Store JWT via `apiClient.setToken()`

### Exported Functions

#### `login(username, keypair)`
```js
import { login } from "./loginBridge.js";

const { publicKeys } = await login("alice", {
  signing: { publicKey: Uint8Array(32), privateKey: Uint8Array(64) },
  exchange: { publicKey: Uint8Array(32), privateKey: Uint8Array(32) }
});
```
- **Parameters:**
  - `username` — string, minimum 2 characters
  - `keypair` — object with `signing` and `exchange` key objects (each containing `publicKey` and `privateKey` as `Uint8Array`s)
- **Returns:** `{ publicKeys: { signingPublicKey, exchangePublicKey, userIdHex, username } }`
- **Throws:** `Error` (invalid username or keypair shape), `KeysetError` (bad key format from KeysetManager), `ApiError` (server rejection), or generic `Error` (self-verification failure)

#### `logout()`
```js
import { logout } from "./loginBridge.js";
await logout();
```
- Clears the JWT **first** (resilient even if KeysetManager throws), then wipes private keys from `KeysetManager`
- Calls `authApi.logout()` best-effort; ignores network failures (local session is already destroyed)

#### `isSessionActive()`
```js
const active = isSessionActive(); // boolean
```
Returns `true` if `KeysetManager` currently holds an unlocked keypair.

#### `getSessionPublicKeys()`
```js
const keys = getSessionPublicKeys(); // null | { signingPublicKey, exchangePublicKey, userIdHex, username }
```
Returns public keys for the current session, or `null` if locked.

---

## `registerBridge.js` — Six-Step Registration

### Purpose
Guides new users through the full registration pipeline: PoW → Email → TOTP → Account creation. Generates a fresh Ed25519 + X25519 keypair and surfaces the private keys **exactly once** for the user to save.

### Input Validation

All steps perform client-side validation before forwarding to the API:

| Step | Validation Rule |
|------|-----------------|
| `startPoW()` | Server difficulty clamped to `[1, 6]`; rejects higher values to prevent main-thread DoS |
| `submitEmail(email)` | Must be non-empty and match `user@domain.tld` format |
| `verifyEmailCode(code)` | Must be exactly 6 digits (`/^\d{6}$/`) |
| `verifyTOTP(totpToken)` | Must be exactly 6 digits (`/^\d{6}$/`) |
| `createAccount(username, password)` | Username ≥ 2 characters; password ≥ 8 characters |

### Class: `RegisterBridge`

Instantiate once per registration attempt:
```js
import { RegisterBridge } from "./registerBridge.js";
const bridge = new RegisterBridge();
```

#### Step 1+2: `startPoW(opts?)`
```js
const { sessionToken } = await bridge.startPoW();
// or with cancellation:
const { sessionToken } = await bridge.startPoW({ signal: controller.signal });
```
- Fetches a PoW challenge from the server
- Solves it client-side using Web Crypto SHA-256 (finds nonce with required leading zeros)
- Difficulty is clamped to a maximum of 6 to prevent main-thread blocking
- Verifies with server → returns `sessionToken` that must be passed to subsequent steps
- **Parameters:**
  - `opts.signal` — optional `AbortSignal` to cancel PoW solving
- **Returns:** `{ sessionToken: string }`

#### Step 3: `submitEmail(email)`
```js
const { message, expiresIn, email } = await bridge.submitEmail("user@example.com");
```
- Validates email format before sending
- Server dispatches a 6-digit code
- **Returns:** `{ message, expiresIn, email }`

#### Step 4: `verifyEmailCode(code)`
```js
const result = await bridge.verifyEmailCode("483920");
// result.totp.qrCodeUri  — URI for QR code rendering
// result.totp.manualKey  — manual entry key for authenticator apps
```
- Validates that `code` is exactly 6 digits
- On success, server returns TOTP enrollment info (QR URI + manual key)
- The bridge caches this info internally for `getTotpInfo()`

#### `getTotpInfo()`
```js
const { qrCodeUri, manualKey } = bridge.getTotpInfo();
```
- Returns cached TOTP enrollment data after `verifyEmailCode()` succeeds
- Returns `null` if called before step 4

#### Step 5: `verifyTOTP(totpToken)`
```js
await bridge.verifyTOTP("123456");
```
- Validates that `totpToken` is exactly 6 digits
- Verifies the TOTP token from the user's authenticator app

#### Step 6: `createAccount(username, password)`
```js
const { keypair, publicKeys, userId } = await bridge.createAccount("alice", "SecureP@ss!");
```
- Validates `username` (≥ 2 chars) and `password` (≥ 8 chars)
- Generates Ed25519 + X25519 keypair via `KeysetManager.createUser()`
- Normalizes all key material to `Uint8Array` via an internal `base64ToUint8Array` helper (handles both base64 strings and raw `Uint8Array`s returned by KeysetManager)
- Surfaces the **raw private keys** in `keypair` for the caller to persist
- Registers public keys + credentials with the server (server receives keys in their original format)
- **Automatically stores a JWT** if the server returns one at this step
- **Automatically clears the session token** after successful creation (security cleanup)
- **Returns:**
  - `keypair` — `{ signing: { publicKey, privateKey }, exchange: { publicKey, privateKey } }` (all `Uint8Array`s)
  - `publicKeys` — `{ signingPublicKey, exchangePublicKey, userIdHex, username }` (all `Uint8Array`s except `userIdHex` and `username`)
  - `userId` — server-assigned user ID
- **⚠️ Critical:** The caller must immediately render a `<KeypairDownload>` component or equivalent. Private keys are never recoverable.

#### `clearKeypair()`
```js
bridge.clearKeypair();
```
- Releases the bridge's reference to the raw keypair so GC can reclaim it
- Call after the user confirms they have saved their keys
- Note: `KeysetManager` still holds the keys in module memory until `logoutUser()` is called

#### `reset()`
```js
bridge.reset();
```
- Clears session token, TOTP info, and keypair reference
- Use if the user wants to restart registration from scratch

---

## `authKeyBridge.js` — High-Level Auth + Crypto Coordinator

### Purpose
A singleton bridge that coordinates the entire authentication lifecycle with the cryptographic key management system. It wraps both the `authFlow` orchestrator and `KeysetManager`, providing a unified interface for registration, login, key unlock, and crypto operations.

> **Note:** This module is currently a demo/prototype. `verifyAuthCredentials()` is a placeholder, and `storeKeyMapping()` / `getKeyMapping()` use `localStorage`. Replace with real database calls before production use.

### Singleton Access
```js
import { getAuthKeyBridge, resetAuthKeyBridge } from "./authKeyBridge.js";

const bridge = getAuthKeyBridge(); // creates on first call, returns same instance thereafter
await bridge.init();               // initialize libsodium and auth system (call once at app startup)

// Reset everything (for testing)
resetAuthKeyBridge();
```

### Registration Flow (via `authKeyBridge`)

The bridge exposes the same six-step registration API as `registerBridge.js`, but adds automatic key generation at the final step.

| Method | Description |
|--------|-------------|
| `initRegistration()` | Step 1: Initialize PoW challenge |
| `verifyPoW(challengeId, nonce)` | Step 2: Verify PoW, get `sessionToken` |
| `submitEmail(sessionToken, email)` | Step 3: Submit email |
| `verifyEmailCode(sessionToken, code)` | Step 4: Verify email code, get TOTP setup |
| `verifyTOTP(sessionToken, totpToken)` | Step 5: Verify TOTP token |
| `createAccountWithKeys(sessionToken, username, password)` | Step 6: Create account + generate crypto keys |

#### `createAccountWithKeys(sessionToken, username, password)`
```js
const result = await bridge.createAccountWithKeys(token, "alice", "pass");
// result.account   — { userId, username, message }
// result.cryptoKeys — { signingPublicKey, exchangePublicKey, userIdHex, signingPrivateKey, exchangePrivateKey }
// result.warning   — "SAVE THESE PRIVATE KEYS IMMEDIATELY..."
```
- Creates the auth account via `authFlow.createAccount()`
- Generates crypto keys via `KeysetManager.createUser()`
- Stores a mapping between `username` and public keys (demo: `localStorage`; production: database)
- Returns both auth account info and the raw crypto keys (including private keys)

### Login Flow (via `authKeyBridge`)

| Method | Description |
|--------|-------------|
| `login(username, password, totpToken)` | Verify credentials, return public keys (crypto session remains locked) |
| `unlockCryptoSession(username, savedKeypair)` | Unlock crypto features with user's saved keypair |

#### `login(username, password, totpToken)`
```js
const result = await bridge.login("alice", "pass", "123456");
// result.authenticated   — true
// result.publicKeys      — { signingPublicKey, exchangePublicKey, userIdHex }
// result.requiresKeyUnlock — true
// result.message         — "Authentication successful. Please provide your crypto keypair..."
```
- Verifies username/password + TOTP against the auth system
- Retrieves the user's stored public key mapping
- Returns auth success but **does not unlock the crypto session**

#### `unlockCryptoSession(username, savedKeypair)`
```js
const result = await bridge.unlockCryptoSession("alice", savedKeypair);
// result.unlocked   — true
// result.publicKeys — { signingPublicKey, exchangePublicKey, userIdHex }
// result.message    — "Crypto session unlocked. You can now encrypt/decrypt files."
```
- Loads the saved keypair into `KeysetManager.loginUser()`
- Unlocks encryption/decryption/signing capabilities
- Throws if keypair format is invalid or no session exists

### Crypto Operations (Unlocked Session Required)

| Method | Signature | Description |
|--------|-----------|-------------|
| `encryptRecord(fileBytes, recipientPublicKey)` | `(Uint8Array, string) => object` | Encrypt a file for a recipient |
| `decryptShare(encryptedRecord, nonce, dekBundle)` | `(Uint8Array, Uint8Array, object) => Uint8Array` | Decrypt a received share |
| `signPayload(payload)` | `(object) => { payloadCanon, signature }` | Sign a payload with the user's private key |
| `verifySignature(payload, signature, signerPublicKey)` | `(string, string, string) => boolean` | Verify a signature (no unlock required) |

### Session & Utility Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `logout()` | `void` | Clears crypto session via `KeysetManager.logoutUser()` |
| `isCryptoLocked()` | `boolean` | Check if crypto session is locked |
| `getPublicKeys()` | `object` | Get current public keys (throws if locked) |
| `reset()` | `void` | Reset auth flow, crypto session, and pending registrations |

### Key Mapping Storage (Demo vs Production)

The bridge includes `storeKeyMapping()` and `getKeyMapping()` helpers that map usernames to their public keys.

- **Current implementation:** Stores in `localStorage` under key `crypto_key_mapping` (for demo only)
- **Production:** Replace with database calls to your users table

```js
// Production structure:
{
  username: "alice",
  userIdHex: "abc123...",
  signingPublicKey: "base64...",
  exchangePublicKey: "base64...",
  createdAt: 1234567890
}
```

---

## Cross-Module Dependencies

```
services/
├── apiClient.js          ← no internal deps (pure fetch wrapper)
├── loginBridge.js        ← apiClient.js, key_manager/key_manager.js
├── registerBridge.js     ← apiClient.js, key_manager/key_manager.js
└── authKeyBridge.js      ← auth/orchestrator/authFlow.js, key_manager/key_manager.js
```

> **Note:** `authKeyBridge.js` imports `generateKeypair` from `key_manager/make_key.js` but does not currently use it. This import can be removed.

---

## Error Handling Quick Reference

| Scenario | Error Type | Properties | Typical Handler |
|----------|-----------|------------|-----------------|
| Network offline / DNS failure | `ApiError` | `status: 0`, `code: "NETWORK_ERROR"` | Show "Check connection" toast |
| Server returned non-JSON | `ApiError` | `status: HTTP code`, `code: "PARSE_ERROR"` | Show "Server error" toast |
| Server rejected request (HTTP or logical) | `ApiError` | `status: 4xx/5xx/200`, `code: server code` | Show server message or generic error |
| Invalid username or keypair shape | `Error` | `message: "loginBridge: ..."` | Prompt user to correct input |
| Invalid email format | `Error` | `message: "registerBridge: email format..."` | Show inline validation error |
| Invalid code/TOTP format | `Error` | `message: "registerBridge: ... must be exactly 6 digits"` | Show inline validation error |
| Invalid keypair format | `KeysetError` | `code: "BAD_KEY_FORMAT"` | Prompt user to re-upload keys |
| Crypto session locked | `KeysetError` | `code: "SESSION_LOCKED"` | Redirect to unlock screen |
| Missing key mapping | `Error` (generic) | `message: "No crypto keys found..."` | Prompt user to check saved keys |

---

## Usage Patterns

### Pattern 1: Simple Login (via `loginBridge.js`)
```js
import { login, logout } from "./services/loginBridge.js";

// In your login form handler:
const keypair = await loadKeypairFromFileUpload(); // your UI logic
const { publicKeys } = await login(username, keypair);
// → JWT is now stored in apiClient; user is authenticated

// On logout button:
await logout();
// → JWT cleared first, then private keys wiped (resilient to KeysetManager errors)
```

### Pattern 2: Registration with Key Download (via `registerBridge.js`)
```js
import { RegisterBridge } from "./services/registerBridge.js";

const bridge = new RegisterBridge();
await bridge.startPoW();
await bridge.submitEmail("user@example.com");
await bridge.verifyEmailCode("123456");

const totpInfo = bridge.getTotpInfo();
// → Render QR code from totpInfo.qrCodeUri

await bridge.verifyTOTP("123456");
const { keypair, publicKeys } = await bridge.createAccount("alice", "SecureP@ss!");
// → Immediately show download prompt for keypair
bridge.clearKeypair(); // after user confirms save
```

### Pattern 3: Full Auth + Crypto Coordination (via `authKeyBridge.js`)
```js
import { getAuthKeyBridge } from "./services/authKeyBridge.js";

const bridge = getAuthKeyBridge();
await bridge.init();

// Registration
const result = await bridge.createAccountWithKeys(token, "alice", "SecureP@ss!");
await saveToSecureStorage(result.cryptoKeys); // your secure storage logic

// Login
await bridge.login("alice", "SecureP@ss!", "123456");
const savedKeys = await loadFromSecureStorage("alice");
await bridge.unlockCryptoSession("alice", savedKeys);

// Now encrypt/decrypt
const encrypted = bridge.encryptRecord(fileBytes, recipientPublicKey);
```

---

## Security Checklist for Developers

1. **Never log private keys** — The `keypair` objects returned by `createAccount()` and `createAccountWithKeys()` contain raw `Uint8Array` private keys. Do not `console.log()` them.
2. **Clear keypair references promptly** — Call `bridge.clearKeypair()` or set the variable to `null` after the user confirms storage.
3. **Logout clears token first** — `clearToken()` is called before `KeysetManager.logoutUser()` so the JWT is wiped even if the crypto layer throws.
4. **Self-verify before sending** — `loginBridge.js` verifies its own signature locally before transmitting. If this fails, the keypair is likely corrupt.
5. **Timestamp validation** — Login payloads include `issuedAt`. The server should reject timestamps older than ~2 minutes to prevent replay attacks.
6. **No localStorage for JWT** — `apiClient.js` does not persist the JWT. If you need persistence across reloads, implement it in your hook layer with appropriate security measures (e.g., `httpOnly` cookies, or encrypted localStorage with a user password).
7. **Validate on the client** — `registerBridge.js` enforces minimum lengths and formats before hitting the API, but always re-validate server-side as well.

# MedLedger UI — Current State

> Last updated after Phase 1 + 2 completion (state, services, crypto layer).
> All 41 tests passing. No components written yet.

---

## What exists

```
src/
├── key_manager/
│   ├── key_backup.js          ← written this session, 220 lines
│   ├── key_backup.test.js     ← pre-existing, 211 lines
│   ├── key_manager.js         ← pre-existing, 585 lines
│   ├── key_manager.test.js    ← pre-existing, 408 lines
│   ├── key_manager_worker.js  ← pre-existing, 286 lines
│   ├── make_key.js            ← pre-existing, 54 lines
│   └── make_key.test.js       ← pre-existing, 93 lines
├── services/
│   ├── auth.js                ← 238 lines
│   ├── bundle.js              ← 78 lines
│   ├── crypto.js              ← 268 lines
│   ├── http.js                ← 198 lines
│   ├── pow.js                 ← 71 lines
│   ├── pow_worker.js          ← 60 lines
│   ├── shares.js              ← 148 lines
│   ├── user.js                ← 40 lines
│   └── vault.js               ← 80 lines
├── state/
│   ├── authStore.js           ← 22 lines
│   ├── cryptoStore.js         ← 21 lines
│   └── store.js               ← 38 lines
├── main.js                    ← 61 lines
└── router.js                  ← 154 lines
```

**3,334 lines total across 21 source files. 41 tests, 0 failures.**

---

## Layer 1 — State (`src/state/`)

### `store.js` — Observable base class

```js
export class Store {
  #state;            // private field — not accessible from outside
  #listeners = new Set();

  constructor(initialState) { ... }
  getState()          // returns current state snapshot
  setState(partial)   // shallow merge, notifies all listeners
  subscribe(listener) // calls listener immediately, returns unsub fn
}
```

Design rules:
- `subscribe()` fires immediately with the current state — components don't need to call `getState()` separately on mount.
- Returns an unsubscribe function. Components **must** call it in `disconnectedCallback` (or equivalent teardown) or they will leak.
- `setState` is a shallow merge, not a replace. Pass only the fields that changed.

### `authStore.js` — Server session

Shape at any given moment:
```js
{
  status: 'unauthenticated' | 'authenticated',
  user: null | {
    user_id_hex, username, email,
    full_name, role, is_verified, totp_enabled
  },
  accessToken: null | string,   // Bearer token, memory-only
  _refreshToken: null | string  // internal field — http.js reads this, nothing else should
}
```

**Write rules:** Only `services/auth.js` and `services/http.js` write to this store. Components are read-only subscribers.

### `cryptoStore.js` — Crypto session

Shape:
```js
{
  status: 'locked' | 'unlocked',
  publicKeys: null | {
    signingPublicKey,   // Ed25519 public key, base64url
    exchangePublicKey,  // X25519 public key, base64url
    userIdHex,          // BLAKE2b(sigPub, 16 bytes) as hex
    username
  },
  lockReason: null | 'inactivity' | 'manual'
}
```

**Write rules:** Only `services/crypto.js` writes to this store. `lockReason` is always set **before** any navigation on lock events, so the unlock screen can read it synchronously on mount.

---

## Layer 2 — Key manager (`src/key_manager/`)

These files were pre-existing (already passing tests) with the exception of `key_backup.js` which was written this session.

### `make_key.js`

Single export: `generateKeypair()`. Returns fresh random Ed25519 (signing) + X25519 (exchange) keypairs. No state, no side effects. Caller owns the returned `Uint8Array` private keys and must `memzero()` them when done.

### `key_manager.js` — `KeysetManager`

The only module where private keys ever exist in the browser's main thread. Exports a named object with:

| Method | Requires session | Notes |
|--------|-----------------|-------|
| `init()` | — | Idempotent. Must be awaited before anything else. |
| `createUser(username)` | init | Generates keys, stores them internally, returns public keys + raw private keys as `.slice()` copies. Session becomes unlocked. |
| `loginUser(username, keypair)` | init | Accepts full keypair object, stores internally. Session becomes unlocked. |
| `logoutUser()` | — | **Synchronous.** Calls `sodium.memzero()` on private keys. |
| `encryptRecord(fileBytes, recipientPubKeyB64)` | init only | Sealed-box DEK for recipient. Does not require unlock. |
| `decryptShare(encRecordB64, nonceB64, dekBundleB64)` | unlocked | Opens DEK with exchange private key, decrypts record. |
| `signPayload(payloadObject)` | unlocked | Canonical JSON (recursive key sort) → Ed25519 detached signature. |
| `verifySignature(payloadOrCanon, sigB64, pubKeyB64)` | init | Returns boolean. |
| `getPublicKeys()` | unlocked | Returns base64url public keys + userIdHex. |
| `isLocked()` | — | Synchronous boolean. |

Critical design point: `createUser` returns `.slice()` copies of private keys — not references to the internal buffers. This matters because `logoutUser()` calls `memzero()` on the internal buffers in-place; if the caller held the same reference, their copy would be silently zeroed.

### `key_manager_worker.js` — SharedWorker

Wraps `KeysetManager` behind a message protocol so private keys never cross to the main thread. One SharedWorker instance is shared across all tabs of the same origin — locking in one tab locks all.

**Message protocol:**
```
Main → Worker:  { id: string, cmd: string, args: object }
Worker → Main:  { id: string, result: any }      ← success
                { id: string, error: { code, message } }  ← failure
Worker push:    { event: 'locked', reason: string }  ← no id, broadcast to all ports
```

**Commands:**

| Command | Args | Returns |
|---------|------|---------|
| `init` | — | null |
| `createUser` | `{ username, passphrase }` | `{ signingPublicKey, exchangePublicKey, userIdHex, username, bundleB64 }` |
| `loadAndUnlock` | `{ username, bundleB64, passphrase }` | publicKeys object |
| `logout` | — | null |
| `isLocked` | — | boolean |
| `getPublicKeys` | — | publicKeys object |
| `encryptRecord` | `{ fileBytesB64, recipientExchangePubKeyB64 }` | `{ encryptedRecord, nonce, dekBundle, fileHash }` |
| `decryptShare` | `{ encryptedRecordB64, nonceB64, dekBundleB64 }` | `{ fileBytesB64 }` |
| `signPayload` | `{ payloadObject }` | `{ payload, payloadCanon, signature }` |
| `verifySignature` | `{ payloadOrCanon, signatureB64, signerPubKeyB64 }` | boolean |
| `setAutoLockMs` | `{ ms }` | null |

The worker holds an auto-lock timer (default 15 minutes). Any crypto operation resets it. On timeout it calls `KeysetManager.logoutUser()` and broadcasts `{ event: 'locked', reason: 'inactivity' }` to all connected ports.

### `key_backup.js` — `.mledger` bundle format

Written this session. Verified by 14 passing tests.

**Binary layout (189 bytes exactly):**

```
Offset  Len   Field
──────  ───   ─────────────────────────────────────────
0       4     Magic: 0x4d 0x4c 0x45 0x44 ('MLED')
4       1     Version: 0x01
5       16    Argon2id salt (random per bundle)
21      24    XSalsa20-Poly1305 nonce (random per bundle)
45      144   Ciphertext = encrypt(plaintext) + 16-byte MAC
```

**Plaintext layout (128 bytes):**
```
[0..63]    signing.privateKey   Ed25519, 64 bytes
[64..95]   signing.publicKey    Ed25519, 32 bytes  ← embedded for fast unlock
[96..127]  exchange.privateKey  X25519,  32 bytes
```

**Key derivation:** Argon2id with `OPSLIMIT_INTERACTIVE` + `MEMLIMIT_INTERACTIVE`. The salt is random per bundle, so two bundles from the same passphrase produce different ciphertexts.

**Error contract:**
- `INVALID_BUNDLE` — wrong length, wrong magic bytes, unsupported version
- `WRONG_PASSPHRASE` — MAC verification failed (wrong passphrase or tampered ciphertext)

All intermediate key material (`symKey`, `plaintext`) is wiped with `sodium.memzero()` in `finally` blocks before return.

The signing public key is embedded in the plaintext (not just the private key) so `decryptBundleToKeypair` can return it directly — avoiding an extra `crypto_sign_ed25519_sk_to_pk` call on the unlock path.

---

## Layer 3 — Services (`src/services/`)

Services are the only things that talk to the outside world (API, workers). Components call services; services never call components.

### `http.js`

Two exports:
- `http(path, options)` — authenticated fetch. Attaches `Authorization: Bearer <token>` from `authStore` automatically.
- `httpPublic(path, options)` — unauthenticated fetch. Used for login, register, PoW endpoints that don't need a token.

**401 handling with request queue:**

When a 401 occurs and a token refresh is in-flight, subsequent 401-triggering requests are queued in `_refreshWaiters`. Once the refresh completes, all queued requests drain and retry with the new token. This prevents race conditions when multiple requests fire simultaneously during a refresh cycle.

If the refresh itself fails, all queued callers receive a 401 rejection, `authStore` is wiped, and the user is redirected to `/login`.

**Token strategy (intentional limitation):** Tokens live in memory only. The server returns `refresh_token` in the JSON response body (not an httpOnly cookie). On a full page reload, memory is gone — re-login is required. This is a deliberate architectural choice documented in the build plan.

### `auth.js`

All authentication endpoints. Writes to `authStore`. Never touches `cryptoStore`.

| Export | Endpoint | Notes |
|--------|----------|-------|
| `login(email, password)` | `POST /api/auth/login` | Returns `{ done: true }` or `{ done: false, requiresTotp, userIdHex }` |
| `verifyTotpLogin(userIdHex, totpCode)` | `POST /api/auth/verify-totp-login` | Completes TOTP 2FA |
| `register(fields)` | `POST /api/auth/register` | Fields include PoW solution. Returns `{ user_id_hex }` |
| `verifyEmail(userIdHex, code)` | `POST /api/auth/verify-email` | — |
| `resendVerification(userIdHex)` | `POST /api/auth/resend-verification` | — |
| `logout()` | `POST /api/auth/logout` | Best-effort server call; wipes `authStore` regardless. Redirects to `/login`. |
| `refreshToken()` | `POST /api/auth/refresh` | Returns boolean. Will always return `false` after a page reload (no token in memory). |
| `changePassword(old, new)` | `POST /api/auth/change-password` | Requires auth |
| `requestPasswordReset(email)` | `POST /api/auth/forgot-password` | Public |
| `confirmPasswordReset(email, code, new)` | `POST /api/auth/reset-password` | Public |
| `requestPoWChallenge()` | `POST /api/auth/pow/challenge` | Returns `{ challenge_id, challenge, difficulty, timestamp }` |
| `verifyPoWSolution(challengeId, solution)` | `POST /api/auth/pow/verify` | — |
| `setupTotp()` | `POST /api/auth/totp/setup` | Returns `{ uri, backup_codes }` |
| `enableTotp(totpCode)` | `POST /api/auth/totp/enable` | — |
| `disableTotp(totpCode)` | `POST /api/auth/totp/disable` | — |

### `crypto.js` — SharedWorker bridge

Single point of contact with the key manager worker. No other file knows the worker exists.

**Startup:** `initWorker()` must be called once at boot (called in `main.js`). Safe to call multiple times (no-op).

**Push event handling:** The worker broadcasts `{ event: 'locked', reason }` on inactivity timeout. The handler in `crypto.js`:
1. Sets `cryptoStore.lockReason` first (before navigation)
2. Sets `cryptoStore.status = 'locked'`
3. Navigates to `/unlock` (not `/login` — server session remains alive)

**Exports:**

| Export | Worker command | Side effect on cryptoStore |
|--------|---------------|---------------------------|
| `createUser(username, passphrase)` | `createUser` | Sets status `'unlocked'`, populates `publicKeys` |
| `loadAndUnlock(username, bundleB64, passphrase)` | `loadAndUnlock` | Sets status `'unlocked'`, populates `publicKeys` |
| `lock()` | `logout` | Sets status `'locked'`, clears `publicKeys`, `lockReason = 'manual'` |
| `getPublicKeys()` | — | Reads from `cryptoStore` directly (no worker call) |
| `isLocked()` | — | Reads from `cryptoStore` directly |
| `encryptRecord(fileBytes, recipientPubKeyB64)` | `encryptRecord` | None |
| `decryptShare(encB64, nonceB64, dekB64)` | `decryptShare` | None |
| `signPayload(payloadObject)` | `signPayload` | None |
| `verifySignature(payloadOrCanon, sigB64, pubKeyB64)` | `verifySignature` | None |

Base64url encode/decode helpers are internal to this file — `_uint8ToBase64Url` and `_base64UrlToUint8`. They use `btoa`/`atob` with padding adjustment. Not exported.

### `pow.js` + `pow_worker.js`

`solvePoW()` is the only public export. It orchestrates the full PoW flow:

1. `POST /api/auth/pow/challenge` — get `{ challenge_id, challenge, difficulty }`
2. Spawn a dedicated `Worker` from `pow_worker.js`
3. Send `{ challenge, difficulty }` to the worker
4. Worker iterates nonces, computing `SHA-256(challenge + nonce)` until `difficulty` leading zeros are found
5. Worker posts back `{ solution: nonceHex }`
6. `POST /api/auth/pow/verify` with `{ challenge_id, solution }`
7. Worker is terminated in `finally` regardless of outcome
8. Returns `{ challengeId, solution }` for use in the register payload

**Critical:** `difficulty` is always read from the server response. It is never hardcoded. This allows the server to increase difficulty under load without a client deploy.

The worker uses `crypto.subtle.digest('SHA-256', ...)` which is async. It yields every 5000 iterations (`setTimeout(resolve, 0)`) to prevent the browser from flagging it as hung.

### `bundle.js`

`createBundleDownloader(bundleB64, username)` returns `{ download, wasTriggered }`.

- `download()` — converts base64url → `Uint8Array` → `Blob` → object URL → anchor click. Resolves after the download has been handed off to the browser.
- `wasTriggered()` — returns `true` if `download()` has been called at least once.

The registration component uses both conditions to gate the Continue button:
```js
if (downloader.wasTriggered() && checkboxChecked) {
  // allow Continue
}
```

Object URLs are revoked after 60 seconds (sufficient for the browser to pick up the download). Firefox requires the anchor to be appended to `document.body` before clicking.

### `vault.js`

CRUD for medical records. All encryption/decryption is the **caller's responsibility** — this service only handles HTTP. Components must call `crypto.encryptRecord()` before `uploadRecord()` and `crypto.decryptShare()` after `getRecord()`.

| Export | Method | Endpoint |
|--------|--------|----------|
| `listRecords()` | GET | `/api/vault/records` |
| `getRecord(id)` | GET | `/api/vault/records/:id` |
| `uploadRecord({...})` | POST | `/api/vault/records` |
| `updateRecord(id, {title, description})` | PUT | `/api/vault/records/:id` |
| `deleteRecord(id)` | DELETE | `/api/vault/records/:id` |

`uploadRecord` accepts camelCase fields and converts to snake_case for the server (`encryptedRecord` → `encrypted_record`, `dekBundle` → `dek_bundle`, etc.).

### `shares.js`

Share CRUD + notification polling.

| Export | Notes |
|--------|-------|
| `createShare({...})` | Caller must pre-compute `recipientEncryptedDek` via `crypto.encryptRecord()` and `signature` via `crypto.signPayload()` |
| `listSentShares()` | — |
| `listReceivedShares()` | — |
| `getShare(shareId)` | — |
| `revokeShare(shareId)` | DELETE |
| `lookupRecipient(username)` | Returns `{ username, exchangePublicKey, userIdHex }` — needed before creating a share |
| `startNotificationPolling(onNotifications, intervalMs)` | Recursive setTimeout, 30s default |
| `stopNotificationPolling()` | Must be called on logout |

**Notification polling design:**

Uses recursive `setTimeout` (not `setInterval`) so requests never overlap on slow networks. If a poll request takes longer than the interval, the next one waits until the current one finishes. Failures are silenced. 401s are handled by `http.js` (force logout). The polling module-level `_stopPolling` variable means only one poller can be active at a time — calling `start` while already polling logs a warning and does nothing.

### `user.js`

Profile management. Writes back to `authStore.user` after `getProfile()` and `updateProfile()` so the rest of the app sees the updated user immediately without a store refresh.

| Export | Method | Endpoint |
|--------|--------|----------|
| `getProfile()` | GET | `/api/users/me` |
| `updateProfile(fields)` | PUT | `/api/users/me` |
| `deleteAccount(password)` | DELETE | `/api/users/me` |

---

## Layer 4 — Routing (`src/router.js`)

Hash-based router (`window.location.hash`). No history API — keeps things simple and avoids server-side route configuration.

**Three built-in guards:**

| Guard | Condition | Redirects to |
|-------|-----------|-------------|
| `requireGuest` | Already authenticated + unlocked | `/vault` |
| `requireAuth` | Not authenticated | `/login` |
| `requireUnlocked` | Authenticated but crypto locked | `/unlock` |

`requireUnlocked` implies `requireAuth` — it calls `requireAuth()` first.

**Pattern matching:** Supports `:param` segments (e.g. `/vault/:recordId`). First match wins. 404 falls through to `/login`.

**Route registration (from `main.js`):**

```
/login              → med-login.js          (guard: requireGuest)
/register           → med-register.js       (guard: requireGuest)
/verify-email       → med-verify-email.js   (guard: requireGuest)
/forgot-password    → med-forgot-password.js (guard: requireGuest)
/unlock             → med-unlock.js         (guard: requireAuth)
/vault              → med-vault.js          (guard: requireUnlocked)
/vault/upload       → med-vault-upload.js   (guard: requireUnlocked)
/vault/:recordId    → med-vault-detail.js   (guard: requireUnlocked)
/shares             → med-shares.js         (guard: requireUnlocked)
/shares/new         → med-share-new.js      (guard: requireUnlocked)
/shares/:shareId    → med-share-detail.js   (guard: requireUnlocked)
/settings           → med-settings.js       (guard: requireUnlocked)
/settings/totp      → med-totp-setup.js     (guard: requireUnlocked)
/                   → redirect to /vault
```

All component imports are dynamic (`import(...)`) — zero upfront bundle, each route loads only what it needs.

---

## Layer 5 — Entry point (`src/main.js`)

Boot sequence, three steps:

```js
initWorker();      // 1. Start the SharedWorker
router.on(...)     // 2. Register all routes
router.start();    // 3. Resolve the current hash
```

No session restore on boot. Because tokens are memory-only, a page refresh always requires re-login. The router guards handle this automatically — the first resolution will hit `requireAuth`, find no token, and redirect to `/login`.

Notification polling is **not** started here. It is started by the app shell component (`med-app.js`, not yet written) after both `authStore.status === 'authenticated'` and `cryptoStore.status === 'unlocked'` are confirmed.

---

## Test suite

```
3 test files, 41 tests, 0 failures

src/key_manager/make_key.test.js      6 tests  — generateKeypair() length, uniqueness, sign/verify, encrypt/decrypt
src/key_manager/key_manager.test.js  21 tests  — full KeysetManager API including roundtrip
src/key_manager/key_backup.test.js   14 tests  — bundle format, roundtrip, error cases
```

**Test infrastructure note:** `libsodium-wrappers-sumo@0.7.15` ESM build references `libsodium-sumo.mjs` which is absent from the npm tarball (upstream packaging gap). `vitest.config.js` uses an absolute path alias to redirect the import to the CJS build (`dist/modules-sumo/libsodium-wrappers.js`). This only affects tests — the browser build via Vite uses the ESM path correctly because the WASM file is resolved differently in a browser context.

---

## What does not exist yet

**Components (Phase 3+) — none written:**

| Component | Route | Key dependency |
|-----------|-------|---------------|
| `med-login.js` | `/login` | `auth.login()`, TOTP branch |
| `med-register.js` | `/register` | `pow.solvePoW()`, `auth.register()`, `crypto.createUser()`, `bundle.createBundleDownloader()` — registration state machine with `downloadingBundle` state |
| `med-verify-email.js` | `/verify-email` | `auth.verifyEmail()` |
| `med-forgot-password.js` | `/forgot-password` | `auth.requestPasswordReset()`, `auth.confirmPasswordReset()` |
| `med-unlock.js` | `/unlock` | `crypto.loadAndUnlock()`, file picker, `cryptoStore.lockReason` |
| `med-vault.js` | `/vault` | `vault.listRecords()` |
| `med-vault-upload.js` | `/vault/upload` | `crypto.encryptRecord()`, `vault.uploadRecord()` |
| `med-vault-detail.js` | `/vault/:recordId` | `vault.getRecord()`, `crypto.decryptShare()` |
| `med-shares.js` | `/shares` | `shares.listSentShares()`, `shares.listReceivedShares()` |
| `med-share-new.js` | `/shares/new` | `shares.lookupRecipient()`, `crypto.encryptRecord()`, `crypto.signPayload()`, `shares.createShare()` |
| `med-share-detail.js` | `/shares/:shareId` | `shares.getShare()`, `shares.revokeShare()`, `crypto.decryptShare()` |
| `med-settings.js` | `/settings` | `user.getProfile()`, `user.updateProfile()`, `auth.changePassword()`, `user.deleteAccount()` |
| `med-totp-setup.js` | `/settings/totp` | `auth.setupTotp()`, `auth.enableTotp()`, `auth.disableTotp()` |

**Shared UI components (Phase 2, also not written):**
- `med-toast` — notification display
- `med-spinner` — loading state
- `med-modal` — modal wrapper
- `med-confirm` — confirmation dialog

**App shell:**
- `med-app.js` — top-level shell, nav, notification badge, starts/stops polling on auth state changes

---

## Key architectural constraints for component authors

**Reading store state in a component:**
```js
// connectedCallback
this._unsub = authStore.subscribe(state => this._render(state));

// disconnectedCallback — REQUIRED
this._unsub();
```

**Navigating:**
```js
import { navigate } from '../router.js';
navigate('/vault');
```

**The registration state machine** (`med-register.js`) must have these explicit states:
```
fillingForm → solvingPoW → submitting → verifyingEmail
  → generatingKeys → downloadingBundle → done
```

The `downloadingBundle` state holds the bundle in a closure variable (not in any store). It must:
- Block navigation with `beforeunload`
- Gate Continue on both: `downloader.wasTriggered()` AND checkbox checked
- Clear the bundle from memory only after both conditions are met

**Unlock screen** reads `cryptoStore.lockReason` on mount to show the correct message. The reason is always set before navigation by `services/crypto.js`, so it will be present synchronously.

**Notification polling lifecycle:**
```js
// Start after both sessions confirmed live
startNotificationPolling(notifications => updateBadge(notifications));

// Stop on logout — must be called before auth state is wiped
stopNotificationPolling();
```

**Never call `fetch()` directly** in a component or service. Always use `http()` or `httpPublic()` from `services/http.js`.

**Never store tokens, keys, or bundle bytes in `localStorage`** or `sessionStorage`. Memory only.

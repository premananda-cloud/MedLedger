# MedLedger UI — Build Plan

## Core Design Decisions (before any code)

### The Two-Session Problem

The single most important thing to get right architecturally.

A user has **two independent sessions** that must never be conflated:

1. **Server session** — authenticated via email + password → JWT access token + refresh token
2. **Crypto session** — unlocked via bundle file upload + passphrase → private keys live in SharedWorker

These can be in four states:

| Server | Crypto | What the user sees |
|--------|--------|--------------------|
| ✗ | ✗ | Login screen |
| ✓ | ✗ | Unlock screen (must upload bundle + passphrase) |
| ✓ | ✓ | Full app |
| ✗ | ✓ | Impossible — crypto session dies on page unload anyway |

The UI **must model both states explicitly**. A single `isAuthenticated` boolean is wrong. Every route guard checks both.

### The Lock Event

The SharedWorker broadcasts `{ event: "locked", reason: "inactivity" }` after 15 minutes of crypto inactivity. This is **not a logout**. The server session is still valid. The user should land on the Unlock screen, not the Login screen, with a message like "Your session locked after inactivity — upload your key file to continue."

This distinction matters for UX: the user does not have to re-enter their email and password.

### Token Storage

Access tokens live **in memory only** — never `localStorage`, never `sessionStorage`. A medical data app storing tokens in localStorage means any XSS attack on any script on the page can silently exfiltrate them.

The refresh token goes in an `httpOnly` cookie (set by the server). If the server does not support this today, use memory for both and accept that a page refresh requires re-login. Do not silently degrade to localStorage.

On page load, the first thing the app does is attempt a token refresh via the cookie. If it succeeds, the server session is restored. The crypto session is always gone on page load — the user always must unlock after a refresh.

---

## State Architecture

### Two stores, not one

**`authStore`** — server session only
```
{
  status: 'unauthenticated' | 'authenticated',
  user: null | { user_id_hex, username, email, full_name, role, is_verified, totp_enabled },
  accessToken: null | string,   // in memory only
}
```

**`cryptoStore`** — crypto session only
```
{
  status: 'locked' | 'unlocked',
  publicKeys: null | { signingPublicKey, exchangePublicKey, userIdHex, username },
  lockReason: null | 'inactivity' | 'manual',
}
```

Both are observable via a minimal `Store` class (subscribe/setState pattern). Components subscribe to whichever stores they need. No component writes to a store directly — they call service functions that write to stores as a side effect.

### Route guard logic

Every page component checks on `connectedCallback`:

```
if authStore.status !== 'authenticated' → navigate to /login
if cryptoStore.status !== 'unlocked'   → navigate to /unlock
```

The unlock screen additionally checks: if `cryptoStore.lockReason === 'inactivity'`, show the inactivity message.

---

## Services Layer (built from scratch)

Services are plain JS modules. No classes unless state genuinely requires encapsulation. Each service owns one concern.

### `services/http.js` — Authenticated fetch wrapper

Wraps `fetch`. Automatically attaches `Authorization: Bearer <token>` from `authStore`. On 401, attempts one token refresh, retries the request, and if that also fails, calls `authStore.logout()` and redirects to login. All other error handling is the caller's responsibility.

No service should call `fetch` directly — always goes through `http.js`.

### `services/auth.js` — Server authentication

Wraps the auth endpoints. Writes to `authStore` as a side effect. Never touches `cryptoStore`.

Functions:
- `login(email, password)` → handles `requires_totp` branching, stores token in memory
- `verifyTotpLogin(userIdHex, totpCode)` → completes TOTP flow
- `register(fields)` → calls PoW challenge/verify first, then register
- `verifyEmail(userIdHex, code)`
- `logout()` → calls server logout, wipes `authStore`, redirects
- `refreshToken()` → called on page load; silently restores server session or fails quietly
- `changePassword(oldPw, newPw)`
- `requestPasswordReset(email)`
- `confirmPasswordReset(email, code, newPw)`

### `services/crypto.js` — Bridge to the SharedWorker

Single point of contact with `key_manager_worker.js`. Wraps every worker command as an `async` function. Writes to `cryptoStore` as a side effect.

The worker client pattern (promise-per-message-id) is implemented here and only here. No other file knows the worker exists.

Functions:
- `initWorker()` → called once at app boot
- `createUser(username, passphrase)` → returns `{ publicKeys, bundleB64 }` for download
- `loadAndUnlock(username, bundleB64, passphrase)` → unlocks crypto session, writes to `cryptoStore`
- `lock()` → manual lock
- `getPublicKeys()` → returns from `cryptoStore` (no worker call needed if already unlocked)
- `encryptRecord(fileBytes, recipientExchangePubKeyB64)` → delegates to worker
- `decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)` → delegates to worker
- `signPayload(payloadObject)` → delegates to worker
- `verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64)` → delegates to worker
- `onLockEvent(callback)` → registers listener for the worker's `locked` broadcast

**Note on `onLockEvent`:** This must be called at app boot and wire up the lock event to update `cryptoStore` and redirect to `/unlock`. It must only be registered once, not per-component.

### `services/vault.js` — Vault record operations

All vault API calls. Does not touch crypto directly — receives already-encrypted data from the caller.

Functions:
- `listRecords()` → `GET /api/vault/records`
- `uploadRecord(payload)` → `POST /api/vault/records` (caller encrypts first)
- `getRecord(recordId)` → `GET /api/vault/records/{id}`
- `getRecordCiphertext(recordId)` → `GET /api/vault/records/{id}/ciphertext`
- `deleteRecord(recordId)` → `DELETE /api/vault/records/{id}`

### `services/shares.js` — Share operations

- `requestShare(ownerIdHex, recordId, requesterPublicKey)`
- `sendEncryptedPayload(recipientIdHex, recordId, encryptedPayload, signature)`
- `rejectShareRequest(shareId)`
- `getPendingRequests()`
- `getNotifications()`
- `createShare(payload)` — direct share flow
- `listSentShares()`
- `listReceivedShares()`
- `getShare(shareId)`
- `revokeShare(shareId)`
- `getShareCiphertext(shareId)`
- `searchUsers(q)`
- `resolveShortCode(code)`

### `services/grants.js` — Grant operations

- `createGrant(payload)`
- `revokeGrant(grantId)`
- `getGrant(grantId)`
- `listMyGrants(asGrantor)`
- `checkAccess(recordId)`
- `listGrantsForRecord(recordId)`

### `services/keys.js` — Public key lookup

- `getMyKeys()`
- `getUserKeys(userIdHex)`
- `getExchangeKey(userIdHex)`
- `getSigningKey(userIdHex)`
- `updateKeys(signingPublicKey, exchangePublicKey)`

---

## Component Architecture

Web Components (native `HTMLElement` subclasses). Shadow DOM is **not** used — global CSS is simpler at this scale and shadow DOM's style isolation causes more friction than it solves here.

### Event cleanup rule

Every component that subscribes to a store in `connectedCallback` must call the returned unsubscribe function in `disconnectedCallback`. No exceptions. This is the most common vanilla Web Component bug.

### Listener delegation rule

Event listeners on dynamic lists go on the container once, in `connectedCallback`, never inside render functions. The render function only produces HTML strings. The listener reads `event.target.closest('[data-id]')` to find the relevant item.

### Navigation

A single `router.js` module maps URL paths to component tag names. It renders into a `<main id="content">` container by setting `innerHTML`. Each navigation call disconnects the previous component (triggering cleanup) and connects the new one.

No hash routing — use `history.pushState`. On popstate, re-run the router.

---

## Screen Inventory

### Auth flow (no crypto required)

**`/login`** — `med-login`
- Email + password form
- On success: if `requires_totp`, navigate to `/login/totp`; else if crypto locked, navigate to `/unlock`; else navigate to `/vault`
- Links to `/register` and `/forgot-password`

**`/login/totp`** — `med-totp-login`
- 6-digit code input
- Back link returns to `/login` (clears partial auth state)

**`/register`** — `med-register`
- Multi-step: PoW solve (invisible to user) → fields → submit → email verification code
- On final success: worker `createUser()` → offer bundle download → navigate to `/unlock`
- Bundle download must be presented as a hard requirement, not optional

**`/verify-email`** — `med-verify-email`
- Code entry form
- Resend link

**`/forgot-password`** — `med-forgot-password`
- Email input → sends reset code

**`/reset-password`** — `med-reset-password`
- Code + new password form

### Crypto unlock (server session valid, crypto locked)

**`/unlock`** — `med-unlock`
- If `lockReason === 'inactivity'`: show "Your session locked after inactivity"
- If first login after register: show "Download your key file before continuing" (with re-download option)
- File picker for `.bundle` file + passphrase input
- On success: navigate to previous intended route or `/vault`

### Main app (both sessions required)

**`/vault`** — `med-vault`
- List of records: filename, type, size, date
- Upload button → file picker → encrypt (via crypto service) → upload
- Per-record: view (download + decrypt + display), delete, create share, create grant
- Empty state: "No records yet — upload your first file"

**`/vault/:recordId`** — `med-record-detail`
- Metadata display
- Download + decrypt action
- List of grants on this record
- Create grant form inline

**`/shares`** — `med-shares`
- Tabs: Sent / Received / Pending requests
- Pending: owner sees incoming requests with Accept / Reject actions
- Received: requester sees incoming encrypted payloads, can decrypt + download
- Sent: list with revoke action

**`/shares/new`** — `med-share-create`
- User search (by username prefix)
- Select record from vault
- Encrypt + sign → send

**`/grants`** — `med-grants`
- Tabs: Given / Received
- Per grant: record name, grantee/grantor, time window, permission level, revoke action

**`/settings`** — `med-settings`
- Sections: Profile, Security, Keys
- Security: change password, TOTP setup/disable, active sessions
- Keys: view current public keys, update keys

**`/notifications`** — polled silently, surfaced as a badge or toast not a full page

---

## Boot Sequence

This is the order things happen when the app loads. Get this right and everything else composes cleanly.

```
1. authStore and cryptoStore initialize to their default locked/unauthenticated states
2. crypto.initWorker() — start the SharedWorker
3. crypto.onLockEvent() — wire up the inactivity lock handler (once, globally)
4. auth.refreshToken() — attempt to restore server session from cookie
   → success: authStore becomes 'authenticated'
   → failure: authStore stays 'unauthenticated' (silent, no error shown)
5. router.init() — read current URL, render the appropriate screen
   → router checks both stores before rendering any protected route
6. If on a protected route and server session restored but crypto locked:
   → redirect to /unlock (not /login)
7. Notification polling starts only after both sessions are active
```

---

## File Structure

```
src/
├── main.js                    # Boot sequence only (steps 1-7 above)
├── index.css                  # Global styles, CSS custom properties
│
├── state/
│   ├── store.js               # Observable Store class
│   ├── authStore.js           # Server session state
│   └── cryptoStore.js         # Crypto session state
│
├── router.js                  # Path → component mapping, history API
│
├── services/
│   ├── http.js                # Authenticated fetch, 401 handling, token refresh
│   ├── auth.js                # Server auth operations → writes authStore
│   ├── crypto.js              # Worker bridge → writes cryptoStore
│   ├── vault.js               # Vault API calls
│   ├── shares.js              # Share API calls
│   ├── grants.js              # Grant API calls
│   └── keys.js                # Public key lookups
│
├── key_manager/               # UNTOUCHED
│   ├── key_manager.js
│   ├── key_manager_worker.js
│   ├── make_key.js
│   └── key_backup.js
│
└── components/
    ├── common/
    │   ├── med-modal.js       # Trap focus, close on Escape, backdrop click
    │   ├── med-toast.js       # Auto-dismiss, stacking, success/error/info variants
    │   ├── med-spinner.js     # Loading indicator
    │   └── med-confirm.js     # Confirmation dialog (used for destructive actions)
    │
    ├── med-app.js             # App shell: nav, content container, notification badge
    │
    ├── med-login.js
    ├── med-totp-login.js
    ├── med-register.js
    ├── med-verify-email.js
    ├── med-forgot-password.js
    ├── med-reset-password.js
    ├── med-unlock.js
    │
    ├── med-vault.js
    ├── med-record-detail.js
    ├── med-share-create.js
    ├── med-shares.js
    ├── med-grants.js
    └── med-settings.js
```

---

## Build Order

Build in dependency order. Never build a component before the things it depends on exist.

**Phase 1 — Foundation (no UI)**
1. `state/store.js`
2. `state/authStore.js`
3. `state/cryptoStore.js`
4. `services/http.js`
5. `services/crypto.js` (worker bridge)
6. `router.js`
7. `main.js` (boot sequence)

**Phase 2 — Common components**
8. `med-toast.js`
9. `med-spinner.js`
10. `med-modal.js`
11. `med-confirm.js`

**Phase 3 — Auth flow**
12. `med-login.js`
13. `med-register.js` (needs PoW + bundle download)
14. `med-unlock.js`
15. `med-totp-login.js`
16. `med-verify-email.js`
17. `med-forgot-password.js` + `med-reset-password.js`

**Phase 4 — Services (build alongside components that need them)**
18. `services/auth.js`
19. `services/vault.js`
20. `services/shares.js`
21. `services/grants.js`
22. `services/keys.js`

**Phase 5 — Main app**
23. `med-app.js` (shell + nav)
24. `med-vault.js`
25. `med-record-detail.js`
26. `med-share-create.js`
27. `med-shares.js`
28. `med-grants.js`
29. `med-settings.js`

---

## Things to Decide Before Phase 3

- **Does the server set the refresh token as an `httpOnly` cookie?** If not, the token strategy above needs to be revised explicitly — do not silently fall back to localStorage.
- **PoW on registration:** is the difficulty parameter fixed or returned per-challenge? The `POWChallengeResponse` schema returns `difficulty` dynamically, so the client solver must read it from the response, not hardcode it.
- **Bundle file format:** the tests confirm it's a `Uint8Array` of exactly 189 bytes. Offer it as a `.mledger` download with a clear filename like `medledger-keys-<username>.mledger`. Make the download step hard to skip.
- **Notification polling interval:** the `/api/shares/notifications` endpoint is polled, not streamed. Decide on an interval (suggest 30 seconds) and whether to use `setInterval` or recursive `setTimeout` (prefer recursive — avoids drift and pile-up if the request is slow).

# MedLedger Key Manager — Code Guide & Specification

**Files:** `make_key.js`, `key_manager.js`  
**Spec baseline:** `04-CRYPTO_SPEC-v2.md`  
**Implementation version:** 2.0  

---

## What Is In Each File

### `make_key.js` — Pure Key Generation

One job: generate a cryptographically random Ed25519 signing keypair and X25519 exchange keypair.

It knows nothing about sessions, UI, or the application. It holds no state between calls. It is a pure function that returns fresh random keys every time.

**What it does internally:**

1. Calls `sodium.crypto_sign_keypair()` → Ed25519 keypair
2. Calls `sodium.crypto_box_keypair()` → X25519 keypair
3. Returns both keypairs
4. Caller is responsible for wiping private keys when done

**Who calls it:** only `key_manager.js`. Nothing in the React layer touches it.

---

### `key_manager.js` — Session State Machine & Public API

Owns the `_state` object (locked/unlocked flag, live private key Uint8Arrays in memory, cached public keys, username). Exposes every method React calls.
All crypto goes through libsodium; the public API returns only base64 strings — no `Uint8Array` or raw key material ever leaves this module.

**State machine:**

```
UNINITIALIZED
    │ init()
    ▼
LOCKED  ◄─────────────────────────────────────────────┐
    │ createUser(username)                              │
    │ or loginUser(username, keypair)  ← returns       │
    │ public keys only, unlocks session                │
    ▼                                                  │
UNLOCKED                                              │
    │                                                  │
    ├── encryptRecord()    (no unlock needed — pub key op)
    ├── decryptShare()     (unlock required)
    ├── signPayload()      (unlock required)
    ├── verifySignature()  (no unlock needed — pub key op)
    ├── getPublicKeys()    (unlock required)
    │                                                  │
    └── logoutUser() ─────────────────────────────────►┘
        or 30-min idle (app layer)
        or beforeunload (app layer)
```

**Methods exposed:**

| Method | Needs unlock | What it does |
|---|---|---|
| `init()` | — | Awaits `sodium.ready`, sets `initialized = true`. No-op if called again. |
| `createUser(username)` | No | Generates keys, unlocks session, returns full keypair to caller. |
| `loginUser(username, keypair)` | No | Loads supplied keypair, validates format, unlocks session. |
| `logoutUser()` | — | Synchronously wipes all private material with `memzero`, resets state. |
| `encryptRecord(bytes, recipientExchangePublicKeyB64)` | No | Generates random DEK, encrypts file, seals DEK for recipient, wipes DEK. |
| `decryptShare(record, nonce, dekBundle)` | Yes | Opens sealed DEK, decrypts record, wipes DEK in `finally`. |
| `signPayload(object)` | Yes | Canonical-JSON-serialises payload, signs with Ed25519 private key. |
| `verifySignature(payload, sig, pubKey)` | No | Verifies Ed25519 signature against canonical JSON. |
| `getPublicKeys()` | Yes | Returns `{ signingPublicKey, exchangePublicKey, userIdHex, username }`. |
| `isLocked()` | — | Returns `_state.locked` boolean. |

---

## API Reference

### `init()`

```js
await KeysetManager.init();
```

Initializes libsodium. Call once at app startup before any other method. Safe to call multiple times — idempotent.

---

### `createUser(username)`

```js
const result = await KeysetManager.createUser(username);
```

Generates a random keypair, unlocks the session, and returns **both public and private keys**. The private keys are also held in module memory (session is now unlocked).

**The caller must store the returned private keypair.** This is the only time private keys are surfaced. If they are not persisted by the user, they cannot be recovered.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `username` | `string` | The new user's username |

**Returns**

```js
{
  signingPublicKey:      string,      // Base64url, Ed25519, 32 bytes
  exchangePublicKey:     string,      // Base64url, X25519, 32 bytes
  userIdHex:             string,      // BLAKE2b(signingPublicKey, 16) as hex — 32 chars
  username:              string,
  // Private keys for the caller to store:
  signingPrivateKey:     Uint8Array,  // Ed25519, 64 bytes — store this
  exchangePrivateKey:    Uint8Array,  // X25519, 32 bytes  — store this
}
```

**Registration flow**

```js
await KeysetManager.init();

// 1. Generate keys — session is now unlocked
const result = await KeysetManager.createUser('alice');

// 2. Prompt user to save their keypair NOW (download, password manager, etc.)
//    result.signingPrivateKey and result.exchangePrivateKey must be stored
//    by the user — they will be needed for every future login.
await promptUserToSaveKeypair(result);

// 3. Register public keys with the server
await api.registerPublicKeys({
  signingPublicKey:  result.signingPublicKey,
  exchangePublicKey: result.exchangePublicKey,
  userIdHex:         result.userIdHex,
  username:          result.username,
});

// Session is already unlocked — proceed directly to the app.
```

---

### `loginUser(username, keypair)`

```js
const publicKeys = await KeysetManager.loginUser(username, keypair);
```

Loads the supplied keypair into memory and unlocks the session. The caller is responsible for supplying the exact keypair generated at registration. There is no fallback — if `keypair` is missing or malformed, this throws `BAD_KEY_FORMAT` immediately.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `username` | `string` | The user's username |
| `keypair` | `object` | The keypair returned from `createUser()` — must include both `signing` and `exchange` with `publicKey` and `privateKey` |

`keypair` shape:

```js
{
  signing:  { publicKey: Uint8Array, privateKey: Uint8Array },
  exchange: { publicKey: Uint8Array, privateKey: Uint8Array },
}
```

**Returns** same shape as `createUser()` (public fields only).

**Throws** `KeysetError(BAD_KEY_FORMAT)` if `keypair` is null, missing fields, or any key is absent. This is always a caller error — there is no fallback.

```js
// Retrieve the keypair the user saved at registration
const keypair = await loadKeypairFromSecureStorage();

const session = await KeysetManager.loginUser('alice', keypair);
console.log(session.userIdHex);
console.log(KeysetManager.isLocked());  // false
```

---

### `logoutUser()`

```js
KeysetManager.logoutUser();
```

Synchronous. Wipes all private key material with `sodium.memzero()` and resets session state. `init()` does not need to be called again afterward.

Wire this to:
- User clicking "Lock" or "Logout"
- Inactivity timeout (30 minutes recommended — see React integration below)
- `window.addEventListener('beforeunload', () => KeysetManager.logoutUser())`

---

### `encryptRecord(fileBytes, recipientExchangePublicKeyB64)`

```js
const result = KeysetManager.encryptRecord(fileBytes, recipientExchangePublicKeyB64);
```

Encrypts a file for a recipient. Does **not** require an unlocked session — sealed boxes are public-key-only operations.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `fileBytes` | `Uint8Array` | Raw file content |
| `recipientExchangePublicKeyB64` | `string` | Recipient's X25519 public key, Base64url |

**Returns**

```js
{
  encryptedRecord: string,  // Base64url — XSalsa20-Poly1305 ciphertext
  nonce:           string,  // Base64url — 24-byte random nonce
  dekBundle:       string,  // Base64url — DEK sealed for recipient (only they can open)
  fileHash:        string,  // Hex       — BLAKE2b-256 of plaintext for integrity check
}
```

Internally: a random 256-bit DEK encrypts the file, the DEK is sealed for the recipient with `crypto_box_seal`, then wiped with `memzero` before return. The sender's identity is not embedded in the ciphertext.

**Share creation flow**

```js
// Fetch recipient's public key from server
const { exchangePublicKey } = await api.getUserKeys('dr_jones');

const { encryptedRecord, nonce, dekBundle, fileHash } =
  KeysetManager.encryptRecord(fileBytes, exchangePublicKey);

// Sign the grant — requires unlocked session
const { payloadCanon, signature } = KeysetManager.signPayload({
  action:             'create_share',
  ownerUsername:      'alice',
  recipientUsername:  'dr_jones',
  fileHash,
  expiresAt:          '2026-07-10T00:00:00Z',
});

await api.createShare({ encryptedRecord, nonce, dekBundle, payloadCanon, signature });
```

---

### `decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)`

```js
const plaintext = KeysetManager.decryptShare(encryptedRecordB64, nonceB64, dekBundleB64);
```

Decrypts a received share. **Requires an unlocked session.**

**Returns** `Uint8Array` — the raw decrypted file bytes.

**Throws** `KeysetError(DECRYPTION_FAILED)` if the DEK bundle is not addressed to the logged-in user or the ciphertext has been tampered with. The DEK is always wiped in a `finally` block regardless of outcome.

```js
const { encryptedRecord, nonce, dekBundle } = await api.retrieveShare(shareId);

let plaintext;
try {
  plaintext = KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle);
} catch (err) {
  if (err.code === ERRORS.DECRYPTION_FAILED) {
    // Wrong recipient key, tampered bundle, or mismatched nonce
  }
  throw err;
}

const blob = new Blob([plaintext]);
```

---

### `signPayload(payloadObject)`

```js
const result = KeysetManager.signPayload(payloadObject);
```

Signs a JSON-serializable object with the session's Ed25519 private key. **Requires an unlocked session.**

Object keys are sorted recursively before signing (canonical JSON), including keys inside nested arrays of objects, so the same data always produces the same signature regardless of property insertion order.

**Returns**

```js
{
  payload:      object,  // Original object (unchanged reference)
  payloadCanon: string,  // Canonical JSON string that was actually signed
  signature:    string,  // Base64url Ed25519 signature, 64 bytes
}
```

Send `payloadCanon` and `signature` to the server. The server verifies by re-canonicalizing the payload with the same key-sort logic and checking against the stored public key.

---

### `verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64)`

```js
const valid = KeysetManager.verifySignature(payload, signature, signerPublicKey);
```

Verifies an Ed25519 signature. Does **not** require an unlocked session.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `payloadOrCanon` | `object` or `string` | Original object, or the pre-canonicalized string from `signPayload` |
| `signatureB64` | `string` | Base64url signature |
| `signerPubKeyB64` | `string` | Base64url Ed25519 public key of the claimed signer |

**Returns** `boolean`.

Returns `false` for both cryptographically invalid signatures and malformed inputs (bad base64, wrong key length, etc.). This method never throws — all errors from libsodium are caught internally and collapsed to `false`.

```js
// Self-verify before sending to server
const { payloadCanon, signature } = KeysetManager.signPayload(grantPayload);
const mySigningPublicKey = KeysetManager.getPublicKeys().signingPublicKey;

const ok = KeysetManager.verifySignature(payloadCanon, signature, mySigningPublicKey);
if (!ok) throw new Error('Self-verification failed — do not send');
```

---

### `getPublicKeys()`

```js
const keys = KeysetManager.getPublicKeys();
```

Returns the current session's public keys. **Requires an unlocked session.**

**Returns**

```js
{
  signingPublicKey:  string,  // Base64url
  exchangePublicKey: string,  // Base64url
  userIdHex:         string,  // BLAKE2b hex
  username:          string,
}
```

---

### `isLocked()`

```js
const locked = KeysetManager.isLocked();  // boolean
```

`true` if no private keys are in memory. Does not require `init()`. Safe to call at any time.

---

## Error handling

All methods throw `KeysetError` on failure. Always wrap crypto calls in `try/catch`.

```js
import { KeysetManager, KeysetError, ERRORS } from './key_manager.js';

try {
  const plaintext = KeysetManager.decryptShare(record, nonce, dek);
} catch (err) {
  if (err instanceof KeysetError) {
    switch (err.code) {
      case ERRORS.SESSION_LOCKED:
        // Prompt user to log in and supply their keypair
        break;
      case ERRORS.DECRYPTION_FAILED:
        // Wrong recipient key or tampered data
        break;
      case ERRORS.BAD_KEY_FORMAT:
        // Keypair passed to loginUser() was missing or malformed
        break;
      case ERRORS.SIGNATURE_INVALID:
        // Bad base64 or wrong key length in verifySignature()
        break;
      default:
        throw err;
    }
  } else {
    throw err;
  }
}
```

**Error codes**

| Code | Constant | When thrown |
|------|----------|-------------|
| `KEYSET_NOT_INITIALIZED` | `ERRORS.NOT_INITIALIZED` | Any method called before `init()` |
| `KEYSET_SESSION_LOCKED` | `ERRORS.SESSION_LOCKED` | Private-key method called while locked |
| `KEYSET_DECRYPTION_FAILED` | `ERRORS.DECRYPTION_FAILED` | Wrong key, tampered ciphertext, or wrong nonce in `decryptShare` |
| `KEYSET_BAD_KEY_FORMAT` | `ERRORS.BAD_KEY_FORMAT` | Missing or malformed keypair passed to `loginUser` |

> `ERRORS.SIGNATURE_INVALID` is defined in the `ERRORS` object but is not currently thrown by any method. `verifySignature` returns `false` for all failure cases — including malformed inputs — rather than throwing.

---

## React integration

```js
// hooks/useKeyset.js
import { useState, useCallback, useEffect } from 'react';
import { KeysetManager, ERRORS } from '../crypto/key_manager';

export function useKeyset() {
  const [locked, setLocked] = useState(true);
  const [publicKeys, setPublicKeys] = useState(null);

  useEffect(() => {
    KeysetManager.init();

    // Wipe keys synchronously on tab close
    const onUnload = () => KeysetManager.logoutUser();
    window.addEventListener('beforeunload', onUnload);
    return () => window.removeEventListener('beforeunload', onUnload);
  }, []);

  const login = useCallback(async (username, keypair) => {
    const keys = await KeysetManager.loginUser(username, keypair);
    setLocked(false);
    setPublicKeys(keys);
    return keys;
  }, []);

  const logout = useCallback(() => {
    KeysetManager.logoutUser();
    setLocked(true);
    setPublicKeys(null);
  }, []);

  return { locked, publicKeys, login, logout };
}
```

**30-minute inactivity lock** — wire this in your root layout:

```js
useEffect(() => {
  let timer;
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (!KeysetManager.isLocked()) {
        KeysetManager.logoutUser();
        navigate('/lock');
      }
    }, 30 * 60 * 1000);
  };

  ['mousemove', 'keydown', 'click', 'touchstart']
    .forEach(e => window.addEventListener(e, reset));
  reset();

  return () => {
    clearTimeout(timer);
    ['mousemove', 'keydown', 'click', 'touchstart']
      .forEach(e => window.removeEventListener(e, reset));
  };
}, []);
```

---

## What these modules do not do

| Excluded | Where it belongs |
|----------|-----------------|
| HTTP requests | React / API layer |
| JWT handling | Server + HttpOnly cookie |
| Keypair persistence | App.js / caller — present a save/download prompt at registration |
| File reading (File API) | Caller passes `Uint8Array` to `encryptRecord` |
| DOM manipulation | React |
| Password change or key rotation | Delete account + re-register |
| Key recovery | Not possible by design — user is sole custodian |

---

## Vitest configuration

Tests that call `encryptRecord`, `decryptShare`, or `signPayload` in a loop may be slow due to libsodium initialization. Increase the default timeout in `vitest.config.js`:

```js
export default {
  test: {
    testTimeout: 15000,
  },
};
```

---

## Changes From v1.0 → v2.0

| Aspect | v1.0 (Old Spec) | v2.0 (This Document) |
|--------|-----------------|---------------------|
| Key derivation | Deterministic (Argon2id from username+password) | Random generation (libsodium keypair functions) |
| Keypair file | Eliminated (no file needed) | Required (user must save `.medledger-key.json`) |
| Library | Web Crypto API + libsodium hybrid | libsodium.js only |
| Curves | P-256 (NIST) | Ed25519/X25519 (djb) |
| DEK wrapping | ECIES (manual ECDH + HKDF + AES-GCM) | Sealed boxes (`crypto_box_seal`) |
| File encryption | AES-256-GCM | XSalsa20-Poly1305 (`crypto_secretbox_easy`) |
| Hashing | SHA-256 | BLAKE2b (`crypto_generichash`) |
| Identity | `public_key_hash` (SHA-256) | `user_id_hex` (BLAKE2b-128) |
| Memory zero | Manual buffer wipe | `sodium.memzero()` |

---

## Invariants (Still Non-Negotiable)

1. No network I/O in either file.
2. No private key leaves `key_manager.js` — public API returns base64 strings.
3. `sodium.memzero()` on every private key after use, including in `finally`.
4. `logoutUser()` is always synchronous.
5. `assertUnlocked()` on every method that uses private keys.
6. All file encryption uses `encryptRecord()`. No other path.
7. Random key generation — each keypair is independent.
8. Test vectors from `04-CRYPTO_SPEC-v2.md §10` must pass before any release.

---

*Document: 05-KEYSET_MANAGER.md | Author: Premananda (Team Praxis) | Status: Draft v2.0*
*Aligned with: 01-ARCHITECTURE-v2.md + 02-SECURITY_SPEC-v2.md + 03-AUTH_SPEC-v2.md + 04-CRYPTO_SPEC-v2.md*

# MedLedger Crypto Modules — Usage Guide

**Covers:** `make_key.js` · `key_manager.js`  
**Version:** 2.0 | **Date:** June 2026

---

## Overview

Two modules, one job each.

| Module | Responsibility |
|--------|---------------|
| `make_key.js` | Generates random Ed25519 + X25519 keypairs. Pure function, no state. |
| `key_manager.js` | Owns all crypto state and operations. The only place private keys ever live at runtime. |

**Key design principle:** Keys are randomly generated — not derived from a password. There is no server-side key storage. The user receives their private keypair once at registration and is responsible for storing it securely (e.g. encrypted download, hardware wallet). On subsequent logins they supply it back. Lost keys mean lost access to past shares — there is no recovery path.

**Rule:** Nothing outside `key_manager.js` should call `make_key.js` directly. The React layer calls `KeysetManager`. That is the entire public surface.

---

## Installation

```bash
npm install libsodium-wrappers-sumo
```

Both modules are ES modules. Your bundler or runtime must support top-level `await`.

---

## make_key.js

### What it does

Generates a cryptographically random Ed25519 signing keypair and X25519 exchange keypair. Non-deterministic — each call produces a fresh keypair with no relation to any credential or prior call.

### API

```js
import { generateKeypair } from './make_key.js';

const keypair = generateKeypair();
```

**Returns**

```js
{
  signing:  { publicKey: Uint8Array, privateKey: Uint8Array },  // Ed25519
  exchange: { publicKey: Uint8Array, privateKey: Uint8Array },  // X25519
}
```

**You own the returned private keys.** Call `sodium.memzero()` on them when done. If you go through `KeysetManager` (which you should), it manages this automatically.

### When you'd call it directly

You wouldn't — in normal use. `KeysetManager.createUser()` calls it internally. It is exported separately only for unit testing in isolation.

---

## key_manager.js

### What it does

The single stateful crypto module. Holds private keys in memory between operations, enforces a locked/unlocked session lifecycle, and exposes only base64 strings to callers — never raw `Uint8Array` key material.

### Imports

```js
import { KeysetManager, KeysetError, ERRORS } from './key_manager.js';
```

### Session lifecycle

```
init()
  └─► createUser()         — generates keys, unlocks session, returns full keypair to caller
        │
        └─► [caller stores keypair securely]
              │
              └─► logoutUser()      — wipes private keys from memory
                    │
                    └─► loginUser(keypair)   — caller supplies stored keypair, unlocks session
                          │
                          └─► [operations: encryptRecord, decryptShare, signPayload, ...]
                                │
                                └─► logoutUser()
```

`init()` only needs to be called once. After `logoutUser()`, call `loginUser()` directly — no need to re-run `init()`.

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
await api.register({
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

*Usage Guide v2.0 | MedLedger Team Praxis | June 2026*

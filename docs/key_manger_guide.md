# MedLedger Crypto Modules — Usage Guide

**Covers:** `make_key.js` · `key_manager.js`  
**Version:** 1.1 | **Date:** June 2026

---

## Overview

Two modules, one job each.

| Module | Responsibility |
|--------|---------------|
| `make_key.js` | Derives Ed25519 + X25519 keypairs from credentials. Pure function, no state. |
| `key_manager.js` | Owns all crypto state and operations. The only place private keys ever live. |

**Rule:** Nothing outside `key_manager.js` should ever call `make_key.js` directly. The React layer calls `KeysetManager`. That's the entire public surface.

---

## Installation

```bash
npm install libsodium-wrappers-sumo
```

Both modules are ES modules. Your bundler or runtime must support top-level `await`.

---

## make_key.js

### What it does

Derives a deterministic Ed25519 signing keypair and X25519 exchange keypair from a username and password using Argon2id (64 MB, 3 iterations). Same credentials on any device always produce the same keys.

### When you'd call it directly

You wouldn't — in normal use. `KeysetManager.createUser()` and `KeysetManager.loginUser()` call it internally. It is exported separately so it can be unit-tested in isolation and potentially reused in the CLI companion.

### API

```js
import { deriveKeys } from './make_key.js';

const keypairs = deriveKeys(username, password, serverSalt?);
```

**Parameters**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `username` | `string` | Yes | Trimmed and lowercased internally. |
| `password` | `string` | Yes | UTF-8. Not touched by this module beyond passing to Argon2id. |
| `serverSalt` | `Uint8Array` | No | 32-byte random salt from the server. If omitted, falls back to a deterministic BLAKE2b salt derived from the username. |

**Returns**

```js
{
  signing:  { publicKey: Uint8Array, privateKey: Uint8Array },  // Ed25519
  exchange: { publicKey: Uint8Array, privateKey: Uint8Array },  // X25519
}
```

**You own the returned private keys.** Call `sodium.memzero()` on them when done. `KeysetManager` does this automatically — another reason to go through it rather than calling `deriveKeys` directly.

### Salt behaviour

```
No serverSalt supplied:
  salt = BLAKE2b(username, 16 bytes)         ← deterministic, no entropy

serverSalt supplied (≥ 16 bytes, Uint8Array):
  salt = BLAKE2b(username, 16) XOR serverSalt[0..15]  ← real per-user entropy
```

The serverSalt is fetched from the server once at registration and stored in the `users` table. The same salt must be supplied at every subsequent login or the derived keys will differ.

### Example (direct use, e.g. CLI)

```js
import _sodium from 'libsodium-wrappers-sumo';
import { deriveKeys } from './make_key.js';

await _sodium.ready;
const sodium = _sodium;

const keys = deriveKeys('alice', 'correct-horse-battery-staple');

// Use keys...
const message = sodium.from_string('hello');
const sig = sodium.crypto_sign_detached(message, keys.signing.privateKey);

// Wipe when done — your responsibility
sodium.memzero(keys.signing.privateKey);
sodium.memzero(keys.exchange.privateKey);
```

---

## key_manager.js

### What it does

The single stateful crypto module. Holds private keys in memory between operations, enforces the locked/unlocked lifecycle, and exposes only base64 strings to callers — never raw `Uint8Array` key material.

### Imports

```js
import { KeysetManager, KeysetError, ERRORS } from './key_manager.js';
```

### Session lifecycle

```
init()  →  createUser() or loginUser()  →  [operations]  →  logoutUser()
                                                  ↑
                                          can call loginUser()
                                          again after logout
                                          without re-running init()
```

**`init()` must be called and awaited before anything else.** It is safe to call multiple times — subsequent calls are no-ops.

---

### API Reference

#### `init()`

```js
await KeysetManager.init();
```

Initializes libsodium. Call once at app startup (or before the first crypto operation). Safe to call again — idempotent.

---

#### `createUser(username, password, serverSalt?)`

```js
const publicKeys = await KeysetManager.createUser(username, password, serverSalt);
```

Derives keys and returns **public keys only**. Does **not** unlock the session. Call this during registration to get the keys to send to the server, then call `loginUser()` after the server confirms registration.

**Returns**

```js
{
  signingPublicKey:  string,  // Base64url, Ed25519, 32 bytes
  exchangePublicKey: string,  // Base64url, X25519, 32 bytes
  userIdHex:         string,  // BLAKE2b(signingPublicKey, 16) as hex — 32 chars
  username:          string,
}
```

**Registration flow**

```js
await KeysetManager.init();

// 1. Fetch serverSalt from server (once, store it server-side against the user)
const { serverSalt } = await api.getRegistrationSalt();   // your API call

// 2. Derive and return public keys — session stays locked
const { signingPublicKey, exchangePublicKey, userIdHex } =
  await KeysetManager.createUser('alice', 'passw0rd', serverSalt);

// 3. Register with server
await api.register({ signingPublicKey, exchangePublicKey, userIdHex, captchaToken, ... });

// 4. Now unlock the session
await KeysetManager.loginUser('alice', 'passw0rd', serverSalt);
```

---

#### `loginUser(username, password, serverSalt?)`

```js
const publicKeys = await KeysetManager.loginUser(username, password, serverSalt);
```

Derives keys and **unlocks the session**. Private keys are held in module memory from this point until `logoutUser()` is called.

**Returns** same shape as `createUser()`.

**Important:** Pass the same `serverSalt` that was used during `createUser()`. If the salt differs, different keys are derived and the server's stored public key will not match.

```js
// Fetch the stored serverSalt for this user from your server
const { serverSalt } = await api.getSalt(username);

const session = await KeysetManager.loginUser(username, password, serverSalt);
console.log(session.userIdHex);   // identity anchor
console.log(KeysetManager.isLocked());  // false
```

---

#### `logoutUser()`

```js
KeysetManager.logoutUser();
```

Synchronous. Wipes all private key material with `sodium.memzero()` and resets session state. `init()` does not need to be called again afterward — `loginUser()` can be called directly.

Wire this to:
- User clicking "Lock" or "Logout"
- 30-minute inactivity timer
- `window.addEventListener('beforeunload', () => KeysetManager.logoutUser())`

---

#### `encryptRecord(fileBytes, recipientExchangePublicKeyB64)`

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
  dekBundle:       string,  // Base64url — sealed DEK (only recipient can open)
  fileHash:        string,  // Hex       — BLAKE2b-256 of plaintext for integrity
}
```

**Internals (you don't need to manage these):** A random 256-bit DEK is generated, used to encrypt the file, sealed for the recipient with `crypto_box_seal`, then wiped with `memzero` before return. The sender's identity is not embedded in the ciphertext.

**Share creation flow**

```js
// Recipient's public key — fetched from server
const { exchangePublicKey } = await api.getUserKeys('dr_jones');

const { encryptedRecord, nonce, dekBundle, fileHash } =
  KeysetManager.encryptRecord(fileBytes, exchangePublicKey);

// Sign the grant so the server can verify it came from you
const { payloadCanon, signature } = KeysetManager.signPayload({
  action:               'create_share',
  owner_username:       'alice',
  recipient_username:   'dr_jones',
  file_hash:            fileHash,
  expires_at:           '2026-07-10T00:00:00Z',
});

await api.createShare({ encryptedRecord, nonce, dekBundle, payloadCanon, signature });
```

---

#### `decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)`

```js
const plaintext = KeysetManager.decryptShare(encryptedRecordB64, nonceB64, dekBundleB64);
```

Decrypts a received share. **Requires an unlocked session.**

**Returns** `Uint8Array` — the raw decrypted file bytes.

**Throws** `KeysetError` with code `KEYSET_DECRYPTION_FAILED` if the DEK bundle is not addressed to the logged-in user, or if the ciphertext has been tampered with. The DEK is always wiped in a `finally` block regardless of outcome.

**Retrieval flow**

```js
const { encryptedRecord, nonce, dekBundle } = await api.retrieveShare(shareId);

let plaintext;
try {
  plaintext = KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle);
} catch (err) {
  if (err.code === ERRORS.DECRYPTION_FAILED) {
    // Wrong recipient, tampered bundle, or mismatched nonce
  }
  throw err;
}

// plaintext is Uint8Array — convert or save as needed
const blob = new Blob([plaintext]);
```

---

#### `signPayload(payloadObject)`

```js
const result = KeysetManager.signPayload(payloadObject);
```

Signs a JSON-serializable object with the session's Ed25519 private key. **Requires an unlocked session.**

Keys in the payload are sorted recursively before signing (canonical JSON) so the same object always produces the same signature regardless of property insertion order.

**Returns**

```js
{
  payload:      object,  // Original object (unchanged reference)
  payloadCanon: string,  // The canonical JSON string that was signed
  signature:    string,  // Base64url Ed25519 signature, 64 bytes
}
```

Send `payloadCanon` and `signature` to the server. The server verifies by re-canonicalizing the same object and checking the signature against the stored public key.

---

#### `verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64)`

```js
const valid = KeysetManager.verifySignature(payload, signature, signerPublicKey);
```

Verifies an Ed25519 signature. Does **not** require an unlocked session.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `payloadOrCanon` | `object` or `string` | The original object, or the pre-canonicalized string from `signPayload` |
| `signatureB64` | `string` | Base64url signature |
| `signerPubKeyB64` | `string` | Base64url Ed25519 public key of the claimed signer |

**Returns** `boolean`. Never throws on a bad signature — returns `false`.

```js
// Client-side verification before sending to server
const { payload, payloadCanon, signature } = KeysetManager.signPayload(grantPayload);

const ok = KeysetManager.verifySignature(payloadCanon, signature, mySigningPublicKey);
if (!ok) throw new Error('Self-verification failed — do not send');
```

---

#### `getPublicKeys()`

```js
const keys = KeysetManager.getPublicKeys();
```

Returns the current session's public keys. **Requires an unlocked session.**

**Returns** same shape as `loginUser()`.

---

#### `isLocked()`

```js
const locked = KeysetManager.isLocked();  // boolean
```

Returns `true` if the session is locked (no private keys in memory). Does not require `init()`.

---

### Error handling

All methods throw `KeysetError` on failure. Always wrap crypto calls in `try/catch`.

```js
import { KeysetManager, KeysetError, ERRORS } from './key_manager.js';

try {
  const plaintext = KeysetManager.decryptShare(record, nonce, dek);
} catch (err) {
  if (err instanceof KeysetError) {
    switch (err.code) {
      case ERRORS.SESSION_LOCKED:
        // Prompt user to unlock
        break;
      case ERRORS.DECRYPTION_FAILED:
        // Wrong recipient or tampered data
        break;
      case ERRORS.DERIVATION_FAILED:
        // Argon2id failed (bad inputs or memory pressure)
        break;
      default:
        throw err;
    }
  } else {
    throw err;  // unexpected — rethrow
  }
}
```

**Error codes**

| Code | Constant | When thrown |
|------|----------|-------------|
| `KEYSET_NOT_INITIALIZED` | `ERRORS.NOT_INITIALIZED` | Any method called before `init()` |
| `KEYSET_SESSION_LOCKED` | `ERRORS.SESSION_LOCKED` | Private-key method called while locked |
| `KEYSET_DERIVATION_FAILED` | `ERRORS.DERIVATION_FAILED` | Argon2id fails inside `createUser` / `loginUser` |
| `KEYSET_DECRYPTION_FAILED` | `ERRORS.DECRYPTION_FAILED` | Wrong key, tampered ciphertext, or wrong nonce in `decryptShare` |
| `KEYSET_BAD_KEY_FORMAT` | `ERRORS.BAD_KEY_FORMAT` | Reserved — invalid base64 or key length |

---

### React integration

```js
// hooks/useKeyset.js
import { useState, useCallback, useEffect } from 'react';
import { KeysetManager, ERRORS } from '../crypto/key_manager';

export function useKeyset() {
  const [locked, setLocked] = useState(true);
  const [publicKeys, setPublicKeys] = useState(null);

  useEffect(() => {
    KeysetManager.init();

    // Lock on tab close — synchronous wipe
    const onUnload = () => KeysetManager.logoutUser();
    window.addEventListener('beforeunload', onUnload);
    return () => window.removeEventListener('beforeunload', onUnload);
  }, []);

  const login = useCallback(async (username, password, serverSalt) => {
    const keys = await KeysetManager.loginUser(username, password, serverSalt);
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
        navigate('/lock');  // or show lock screen
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
| File reading (File API) | Caller passes `Uint8Array` to `encryptRecord` |
| DOM manipulation | React |
| Password change or key rotation | Delete account + re-register |
| Session persistence across tab reloads | Optional IndexedDB wrap (not implemented in v1) |

---

## Vitest configuration

The Argon2id derivation takes ~1–2 seconds per call by design. The default 5-second test timeout is too short for tests that run multiple derivations. Add to `vitest.config.js`:

```js
export default {
  test: {
    testTimeout: 30000,
  },
};
```

---

*Usage Guide v1.1 | MedLedger Team Praxis | June 2026*

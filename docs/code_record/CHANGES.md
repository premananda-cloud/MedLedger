# MedLedger Key Manager — Code Guide & Change Log

**Files:** `make_key.js`, `key_manager.js`  
**Spec baseline:** `04-CRYPTO_SPEC.md`, `05-KEYSET_MANAGER.md` v1.0  
**Implementation version:** 1.1  

---

## What Is In Each File

### `make_key.js` — Pure Key Derivation

One job: given a username, password, and optional server salt, derive and
return an Ed25519 signing keypair and an X25519 exchange keypair.

It knows nothing about sessions, UI, or the application. It holds no state
between calls. It is a math function with a carefully managed side effect:
wiping all intermediate byte buffers with `sodium.memzero()` before it returns.

**What it does internally:**

1. Canonicalises the username (`toLowerCase().trim()`)
2. Hashes the username to 16 bytes via BLAKE2b — this is the base salt
3. If a `serverSalt` is provided, XORs it with the username hash to get the
   final 16-byte Argon2id salt (see salt improvement below)
4. Runs `crypto_pwhash` (Argon2id) to produce a 64-byte master seed
5. Slices the seed: bytes 0–31 → Ed25519 seed, bytes 32–63 → X25519 seed
6. Derives keypairs from each seed via `crypto_sign_seed_keypair` and
   `crypto_box_seed_keypair`
7. Wipes the 64-byte seed and both sub-seeds immediately
8. Returns the two keypairs (caller owns the returned private keys and must
   wipe them when done)

**Who calls it:** only `key_manager.js`. Nothing in the React layer touches it.

---

### `key_manager.js` — Session State Machine & Public API

Owns the `_state` object (locked/unlocked flag, live private key Uint8Arrays
in memory, cached public keys, username). Exposes every method React calls.
All crypto goes through libsodium; the public API returns only base64 strings —
no `Uint8Array` or `CryptoKey` objects ever leave this module.

**State machine:**

```
UNINITIALIZED
    │ init()
    ▼
LOCKED  ◄─────────────────────────────────────────────┐
    │ loginUser(u, p, [salt])                          │
    │ or createUser(u, p, [salt])  ← returns pub keys  │
    ▼                                 only, stays locked│
UNLOCKED                                               │
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
| `createUser(u, p, [salt])` | No | Derives keys, returns public keys only, wipes private keys. Does not unlock. |
| `loginUser(u, p, [salt])` | No | Derives keys, stores private keys in `_state`, unlocks session. |
| `logoutUser()` | — | Synchronously wipes all private material with `memzero`, resets state. |
| `encryptRecord(bytes, recipientPubKeyB64)` | No | Generates random DEK, encrypts file, seals DEK for recipient, wipes DEK. |
| `decryptShare(record, nonce, dekBundle)` | Yes | Opens sealed DEK, decrypts record, wipes DEK in `finally`. |
| `signPayload(object)` | Yes | Canonical-JSON-serialises payload, signs with Ed25519 private key. |
| `verifySignature(payload, sig, pubKey)` | No | Verifies Ed25519 signature against canonical JSON. |
| `getPublicKeys()` | Yes | Returns `{ signingPublicKey, exchangePublicKey, userIdHex, username }`. |
| `isLocked()` | — | Returns `_state.locked` boolean. |

---

## Changes From Spec v1.0

### 1. `encryptFor()` removed from public API

**Original:** The spec defined both `encryptFor(plaintext, recipientPubKeyB64)`
and `encryptRecord(fileBytes, recipientPubKeyB64)` as public methods.

**Problem:** `encryptFor` seals arbitrary bytes for a recipient. `encryptRecord`
does the same thing *plus* generates a DEK and encrypts the file. Exposing both
creates ambiguity — a caller could use `encryptFor` to encrypt a file directly
(bypassing the DEK layer) without realising the implications.

**Change:** `encryptFor` is gone from the public API. Its logic (sealed box)
is now an internal step inside `encryptRecord`. All share encryption goes
through `encryptRecord`. There is no other supported path.

---

### 2. `decryptShare()` — DEK always wiped, even on failure

**Original:**
```js
const dek = sodium.crypto_box_seal_open(...);
const plaintext = sodium.crypto_secretbox_open_easy(...);
if (!plaintext) throw new Error("tampered");
sodium.memzero(dek);  // ← never reached if the line above throws
```

**Problem:** If `crypto_secretbox_open_easy` throws or the `!plaintext` check
throws, `memzero` is skipped. The DEK Uint8Array stays in memory until GC runs
(whenever that is).

**Fix:** Wrapped in `try/finally`:
```js
const dek = ...open sealed box...;
try {
    plaintext = sodium.crypto_secretbox_open_easy(...);
    if (!plaintext) throw new KeysetError(...);
} finally {
    sodium.memzero(dek);   // always runs
}
```

---

### 3. `signPayload()` — canonical JSON serialisation

**Original:** `JSON.stringify(payloadObject)` was used directly.

**Problem:** `JSON.stringify` does not guarantee key order. If the server (or
another client) reconstructs the payload object and serialises it before
verifying, key order may differ, producing a different byte string and making
a valid signature fail verification.

**Fix:** `canonicalJSON()` — a small recursive function that sorts object keys
before serialising. Every object at every nesting level is sorted alphabetically.
Arrays are left in order (their order is meaningful).

```js
function canonicalJSON(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return JSON.stringify(value);
    }
    const sorted = Object.keys(value).sort().reduce((acc, k) => {
        acc[k] = value[k]; return acc;
    }, {});
    return JSON.stringify(sorted, (_, v) =>
        v !== null && typeof v === 'object' && !Array.isArray(v)
            ? Object.keys(v).sort().reduce((a, k) => { a[k] = v[k]; return a; }, {})
            : v
    );
}
```

`signPayload()` now returns `payloadCanon` (the string that was actually signed)
alongside `payload` and `signature`. The server should use `payloadCanon`
directly for verification rather than re-serialising the object.

`verifySignature()` accepts either a plain object (will be canonicalised) or a
pre-canonicalised string (used directly) so that the server can verify without
having to reconstruct the object at all.

---

### 4. Salt improvement in `make_key.js`

**Original:** `const salt = BLAKE2b(username)` — fully deterministic from the
username. Argon2id is still hard to brute-force, but a precomputed table of
`BLAKE2b(username)` → Argon2id outputs for common passwords is cheaper than
with a random salt.

**Change:** `deriveKeys()` accepts an optional `serverSalt` parameter (32
random bytes stored publicly in the `users` table, generated at registration).
When provided, it is XOR'd with the username hash to produce the final
Argon2id salt, adding real per-user entropy.

**Backward compatibility:** `serverSalt` is optional. If omitted (e.g. offline
tools, tests, CLI client), derivation falls back to the original
deterministic username hash — identical behaviour to spec v1.0. No existing
keys break.

**Server changes required:** The `users` table needs a `pwhash_salt` column
(32 bytes, hex or base64, generated at registration, returned by
`POST /api/register` and `GET /api/me`). The login flow must fetch this salt
before calling `loginUser()`.

---

### 5. `logoutUser()` — explicit reset instead of spread

**Original:**
```js
_state = { ..._state, locked: true, username: null, ... };
```

The spread was fine but implicit — it relied on `initialized` being part of
`_state` and surviving the spread.

**Change:** The reset is now written out explicitly, naming `initialized`
directly so the intent is clear and a future refactor cannot accidentally drop
the field:

```js
_state = {
    initialized:     _state.initialized,   // preserve — intentional
    locked:          true,
    username:        null,
    signingPrivKey:  null,
    exchangePrivKey: null,
    signingPubKey:   null,
    exchangePubKey:  null,
    userIdHex:       null,
};
```

Public keys (`signingPubKey`, `exchangePubKey`, `userIdHex`) are also cleared.
They are not secret, but clearing them prevents stale identity values from
persisting after logout in a shared-tab scenario.

---

### 6. Typed errors everywhere

**Original:** Some error paths used `new Error(...)` (plain Error), others were
implied to use `KeysetError`. Inconsistent.

**Change:** Every throw in `key_manager.js` uses `KeysetError` with a code from
the `ERRORS` constant object. React catch blocks can now switch on `err.code`
without string matching on `err.message`.

```js
try {
    await KeysetManager.decryptShare(...);
} catch (err) {
    if (err.code === ERRORS.DECRYPTION_FAILED) {
        // show "wrong key or tampered file" UI
    } else if (err.code === ERRORS.SESSION_LOCKED) {
        // redirect to unlock screen
    } else {
        throw err;  // unexpected, re-throw
    }
}
```

---

## What Did Not Change

- Argon2id parameters: `opslimit = 3`, `memlimit = 64 MB`. Unchanged.
- Ed25519 for signing, X25519 for key exchange. Unchanged.
- XSalsa20-Poly1305 (`crypto_secretbox_easy`) for file encryption. Unchanged.
- Sealed boxes (`crypto_box_seal`) for DEK wrapping. Unchanged.
- BLAKE2b for all hashing. Unchanged.
- `sodium.memzero()` on all private material after use. Unchanged (and now
  also guaranteed on failure paths — see change #2).
- `logoutUser()` is synchronous. Unchanged.
- Module closure — `_state` is inaccessible from outside. Unchanged.
- React integration pattern (`useKeyset` hook, idle timer). Unchanged — see
  `05-KEYSET_MANAGER.md §11` for the hook code; no changes needed there.
- The `createUser` / `loginUser` separation. Unchanged — registration derives
  keys and returns only public keys; login derives and holds them in memory.

---

## Invariants (Still Non-Negotiable)

1. No network I/O in either file.
2. No private key leaves `key_manager.js` — public API returns base64 strings.
3. `sodium.memzero()` on every private key after use, including in `finally`.
4. `logoutUser()` is always synchronous.
5. `assertUnlocked()` on every method that uses private keys.
6. All file encryption uses `encryptRecord()`. No other path.
7. Deterministic key derivation — same credentials → same keys.
8. Test vectors from `04-CRYPTO_SPEC.md §10` must pass before any release.

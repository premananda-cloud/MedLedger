# MedLedger Keyset Manager Specification

**Version:** 1.0 | **Date:** June 2026 | **Status:** Draft — Foundation Document

**Depends on:** 04-CRYPTO_SPEC.md, 03-AUTH_SPEC.md, 01-ARCHITECTURE.md

**What this is:** The Keyset Manager is the single client-side module that owns all cryptographic state and operations. It has no network I/O. It exposes a clean API to the React layer. It is the only place private keys ever exist in the application.

---

## 1. Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Single responsibility** | Keyset Manager does crypto. Nothing else. |
| **No network I/O** | The caller (React / API layer) handles all HTTP. |
| **Memory-only private keys** | `Uint8Array`, wiped with `sodium.memzero()` on lock. |
| **Opaque to callers** | React never sees raw keys or `Uint8Array` buffers. |
| **Fail closed** | Any operation requiring an unlocked session throws if locked. |
| **Deterministic** | Same credentials → same keys. No randomness in key derivation. |
| **Explicit lifecycle** | `init` → `unlock` → (operations) → `lock`. State machine, not implicit. |

---

## 2. Module Boundary

```
┌────────────────────────────────────────────────────────────────┐
│                    React Application                            │
│                                                                  │
│  KeysetManager.init()           ─────► Loads libsodium          │
│  KeysetManager.createUser()     ─────► Returns public keys only  │
│  KeysetManager.loginUser()      ─────► Derives + holds keys      │
│  KeysetManager.logoutUser()     ─────► Wipes keys, clears state  │
│  KeysetManager.encryptFor()     ─────► Returns ciphertext        │
│  KeysetManager.decryptShare()   ─────► Returns plaintext         │
│  KeysetManager.signPayload()    ─────► Returns base64 signature  │
│  KeysetManager.getPublicKeys()  ─────► Returns {sign, enc}       │
│  KeysetManager.isLocked()       ─────► Returns boolean           │
│                                                                  │
│              ▲  Never passes CryptoKey or Uint8Array out         │
│              ▲  Never receives private keys in                   │
└────────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────────────┐
│                    KeysetManager (Internal)                       │
│                                                                  │
│  State: { locked, signingPrivKey, exchangePrivKey, publicKeys } │
│  Crypto: libsodium.js (all ops) + Web Crypto (storage wrap)     │
│                                                                  │
└────────────────────────────────────────────────────────────────┘
```

---

## 3. Internal State

```javascript
// Private state — never exposed outside the module
let _state = {
    initialized:     false,
    locked:          true,
    username:        null,

    // Private keys — Uint8Array, wiped on lock
    signingPrivKey:  null,   // Ed25519, 64 bytes
    exchangePrivKey: null,   // X25519, 32 bytes

    // Public keys — safe to expose and cache
    signingPubKey:   null,   // Ed25519, 32 bytes
    exchangePubKey:  null,   // X25519, 32 bytes

    // Derived metadata
    userIdHex:       null,   // BLAKE2b(signingPubKey, 16) as hex
};

// No global references to private keys outside this object.
// Module closure ensures no external access.
```

---

## 4. State Machine

```
                    ┌────────────────┐
                    │   UNINITIALIZED │
                    └───────┬────────┘
                            │ init()
                            ▼
                    ┌────────────────┐
              ┌────►│    LOCKED       │◄─────────────────┐
              │     └───────┬────────┘                   │
              │             │ loginUser(u, p)             │
              │             │ or createUser(u, p)         │
              │             ▼                             │
              │     ┌────────────────┐                   │
              │     │   UNLOCKED      │                   │
              │     └───────┬────────┘                   │
              │             │                             │
              │     ┌───────┴───────────────────┐        │
              │     │                           │        │
              │  encryptFor()              decryptShare() │
              │  signPayload()             getPublicKeys() │
              │  verifySignature()         isLocked()      │
              │                                           │
              └──────────── logoutUser() ─────────────────┘
                         or 30-min idle
                         or beforeunload
```

---

## 5. API Reference

### 5.1 `init()`

Loads and initializes libsodium. Must be called before any other method. Safe to call multiple times.

```javascript
/**
 * Initialize libsodium. Must be called before any other method.
 * @returns {Promise<void>}
 * @throws if libsodium fails to load
 */
async function init()
```

**Implementation:**
```javascript
async function init() {
    if (_state.initialized) return;
    await sodium.ready;
    _state.initialized = true;
}
```

---

### 5.2 `createUser(username, password)`

Derives keys from credentials, returns only public keys. Called during registration. Does NOT unlock the session.

```javascript
/**
 * Derive keys for a new user. Returns public keys for server registration.
 * Does not unlock the session — call loginUser() after registration.
 *
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{
 *   signingPublicKey:  string,  // Base64url, 32 bytes
 *   exchangePublicKey: string,  // Base64url, 32 bytes
 *   userIdHex:         string,  // BLAKE2b hex, 16 bytes = 32 chars
 * }>}
 */
async function createUser(username, password)
```

**Implementation:**
```javascript
async function createUser(username, password) {
    assertInitialized();
    const keys = await _deriveKeys(username, password);

    // Public keys only — do NOT store private keys here
    const result = {
        signingPublicKey:  sodium.to_base64(keys.signing.publicKey,  sodium.base64_variants.URLSAFE_NO_PADDING),
        exchangePublicKey: sodium.to_base64(keys.exchange.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING),
        userIdHex:         sodium.to_hex(sodium.crypto_generichash(16, keys.signing.publicKey)),
    };

    // Wipe private material — caller will call loginUser() separately
    sodium.memzero(keys.signing.privateKey);
    sodium.memzero(keys.exchange.privateKey);

    return result;
}
```

---

### 5.3 `loginUser(username, password)`

Derives keys and loads them into session state. Unlocks the session.

```javascript
/**
 * Derive keys and unlock the session.
 *
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{
 *   signingPublicKey:  string,
 *   exchangePublicKey: string,
 *   userIdHex:         string,
 * }>}
 */
async function loginUser(username, password)
```

**Implementation:**
```javascript
async function loginUser(username, password) {
    assertInitialized();

    const keys = await _deriveKeys(username, password);

    _state.locked          = false;
    _state.username        = username;
    _state.signingPrivKey  = keys.signing.privateKey;   // held in memory
    _state.exchangePrivKey = keys.exchange.privateKey;  // held in memory
    _state.signingPubKey   = keys.signing.publicKey;
    _state.exchangePubKey  = keys.exchange.publicKey;
    _state.userIdHex       = sodium.to_hex(
        sodium.crypto_generichash(16, keys.signing.publicKey)
    );

    return {
        signingPublicKey:  sodium.to_base64(_state.signingPubKey,  sodium.base64_variants.URLSAFE_NO_PADDING),
        exchangePublicKey: sodium.to_base64(_state.exchangePubKey, sodium.base64_variants.URLSAFE_NO_PADDING),
        userIdHex:         _state.userIdHex,
    };
}
```

---

### 5.4 `logoutUser()`

Wipes all private key material and resets session state. Synchronous.

```javascript
/**
 * Wipe private keys and lock the session. Synchronous.
 * @returns {void}
 */
function logoutUser()
```

**Implementation:**
```javascript
function logoutUser() {
    if (_state.signingPrivKey)  sodium.memzero(_state.signingPrivKey);
    if (_state.exchangePrivKey) sodium.memzero(_state.exchangePrivKey);

    _state = {
        ..._state,
        locked:          true,
        username:        null,
        signingPrivKey:  null,
        exchangePrivKey: null,
        signingPubKey:   null,
        exchangePubKey:  null,
        userIdHex:       null,
    };
}
```

---

### 5.5 `encryptFor(plaintext, recipientExchangePublicKeyB64)`

Encrypts data for a recipient using their X25519 public key (sealed box).

```javascript
/**
 * Encrypt data for a recipient. Uses sealed box — anonymous sender.
 * Does NOT require an unlocked session (sealed box is public-key only).
 *
 * @param {Uint8Array|string} plaintext - Data to encrypt
 * @param {string} recipientExchangePublicKeyB64 - Recipient's X25519 public key (Base64url)
 * @returns {{
 *   ciphertext: string,  // Base64url — sealed box output
 * }}
 */
function encryptFor(plaintext, recipientExchangePublicKeyB64)
```

**Implementation:**
```javascript
function encryptFor(plaintext, recipientExchangePublicKeyB64) {
    assertInitialized();

    const recipientPubKey = sodium.from_base64(
        recipientExchangePublicKeyB64,
        sodium.base64_variants.URLSAFE_NO_PADDING
    );

    const data = typeof plaintext === 'string'
        ? sodium.from_string(plaintext)
        : plaintext;

    const ciphertext = sodium.crypto_box_seal(data, recipientPubKey);

    return {
        ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.URLSAFE_NO_PADDING),
    };
}
```

---

### 5.6 `encryptRecord(plaintext)`

Encrypts a medical record with a random DEK. Returns the encrypted record and sealed DEK bundle for a recipient. Full share creation helper.

```javascript
/**
 * Encrypt a medical record for sharing.
 * Generates a random DEK, encrypts the record, seals the DEK for recipient.
 *
 * @param {Uint8Array} fileBytes - Raw file content
 * @param {string} recipientExchangePublicKeyB64 - Recipient's X25519 public key
 * @returns {{
 *   encryptedRecord: string,  // Base64url — XSalsa20-Poly1305 ciphertext
 *   nonce:           string,  // Base64url — 24-byte nonce
 *   dekBundle:       string,  // Base64url — sealed DEK for recipient
 *   fileHash:        string,  // Hex — BLAKE2b(plaintext) for integrity
 * }}
 */
function encryptRecord(fileBytes, recipientExchangePublicKeyB64)
```

**Implementation:**
```javascript
function encryptRecord(fileBytes, recipientExchangePublicKeyB64) {
    assertInitialized();

    // 1. Generate random DEK
    const dek = sodium.randombytes_buf(32);

    // 2. Generate random nonce
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES); // 24 bytes

    // 3. Encrypt record with DEK
    const encrypted = sodium.crypto_secretbox_easy(fileBytes, nonce, dek);

    // 4. Hash plaintext for integrity verification
    const fileHash = sodium.to_hex(sodium.crypto_generichash(32, fileBytes));

    // 5. Seal DEK for recipient
    const recipientPubKey = sodium.from_base64(
        recipientExchangePublicKeyB64,
        sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const dekBundle = sodium.crypto_box_seal(dek, recipientPubKey);

    // 6. Wipe DEK
    sodium.memzero(dek);

    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    return {
        encryptedRecord: sodium.to_base64(encrypted, enc),
        nonce:           sodium.to_base64(nonce, enc),
        dekBundle:       sodium.to_base64(dekBundle, enc),
        fileHash,
    };
}
```

---

### 5.7 `decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)`

Decrypts a received share. Requires unlocked session.

```javascript
/**
 * Decrypt a received share. Session must be unlocked.
 *
 * @param {string} encryptedRecordB64 - Base64url ciphertext
 * @param {string} nonceB64           - Base64url nonce (24 bytes)
 * @param {string} dekBundleB64       - Base64url sealed DEK bundle
 * @returns {Uint8Array} - Decrypted plaintext bytes
 * @throws if session locked, DEK decryption fails, or record authentication fails
 */
function decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)
```

**Implementation:**
```javascript
function decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) {
    assertUnlocked();

    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    const encryptedRecord = sodium.from_base64(encryptedRecordB64, enc);
    const nonce           = sodium.from_base64(nonceB64,           enc);
    const dekBundle       = sodium.from_base64(dekBundleB64,       enc);

    // 1. Open sealed DEK
    const dek = sodium.crypto_box_seal_open(
        dekBundle,
        _state.exchangePubKey,
        _state.exchangePrivKey
    );
    if (!dek) throw new Error("DEK decryption failed — wrong recipient or tampered bundle");

    // 2. Decrypt record
    const plaintext = sodium.crypto_secretbox_open_easy(encryptedRecord, nonce, dek);
    if (!plaintext) throw new Error("Record decryption failed — tampered ciphertext");

    // 3. Wipe DEK
    sodium.memzero(dek);

    return plaintext;
}
```

---

### 5.8 `signPayload(payloadObject)`

Signs a JSON-serializable payload with the session's Ed25519 private key.

```javascript
/**
 * Sign a payload. Session must be unlocked.
 *
 * @param {object} payload - JSON-serializable object
 * @returns {{
 *   payload:   object,  // The original payload (unchanged)
 *   signature: string,  // Base64url Ed25519 signature
 * }}
 */
function signPayload(payloadObject)
```

**Implementation:**
```javascript
function signPayload(payloadObject) {
    assertUnlocked();

    const payloadStr = JSON.stringify(payloadObject);
    const payloadBytes = sodium.from_string(payloadStr);

    const signature = sodium.crypto_sign_detached(payloadBytes, _state.signingPrivKey);

    return {
        payload:   payloadObject,
        signature: sodium.to_base64(signature, sodium.base64_variants.URLSAFE_NO_PADDING),
    };
}
```

---

### 5.9 `verifySignature(payloadObject, signatureB64, signerPublicKeyB64)`

Verifies a signature. Does NOT require an unlocked session (public operation).

```javascript
/**
 * Verify a signature. Does not require unlocked session.
 *
 * @param {object} payloadObject      - The payload that was signed
 * @param {string} signatureB64       - Base64url signature
 * @param {string} signerPublicKeyB64 - Base64url Ed25519 public key
 * @returns {boolean}
 */
function verifySignature(payloadObject, signatureB64, signerPublicKeyB64)
```

**Implementation:**
```javascript
function verifySignature(payloadObject, signatureB64, signerPublicKeyB64) {
    assertInitialized();

    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    const payloadBytes = sodium.from_string(JSON.stringify(payloadObject));
    const signature    = sodium.from_base64(signatureB64,       enc);
    const pubKey       = sodium.from_base64(signerPublicKeyB64, enc);

    return sodium.crypto_sign_verify_detached(signature, payloadBytes, pubKey);
}
```

---

### 5.10 `getPublicKeys()`

Returns the current session's public keys. Requires unlocked session.

```javascript
/**
 * Get current session's public keys.
 *
 * @returns {{
 *   signingPublicKey:  string,  // Base64url
 *   exchangePublicKey: string,  // Base64url
 *   userIdHex:         string,  // BLAKE2b hex
 *   username:          string,
 * }}
 */
function getPublicKeys()
```

---

### 5.11 `isLocked()`

```javascript
/**
 * @returns {boolean} true if session is locked (no private keys in memory)
 */
function isLocked()
```

---

## 6. Full Share Protocol Flow

```
PATIENT (owner)                SERVER                  DOCTOR (recipient)
─────────────────              ──────────              ──────────────────

1. GET doctor's public key
   GET /api/user/:username/public-keys
                        ◄─────────────────
                        ← { exchangePublicKey, signingPublicKey }

2. Encrypt record for doctor
   encryptRecord(file, doctorEncPubKey)
   → { encryptedRecord, nonce, dekBundle, fileHash }

3. Sign the grant
   signPayload({
     action: "create_share",
     owner_username: "patient42",
     recipient_username: "dr_jones",
     share_id: "...",         ← server will assign, use placeholder or two-step
     expires_at: "...",
     file_hash: fileHash,
   })
   → { payload, signature }

4. POST /api/share
   { encryptedRecord, nonce, dekBundle,
     recipient_username, signature, ttl_days }
                        ──────────────────►
                        Server verifies signature
                        Stores ciphertext + dekBundle
                        Returns share_id

═══════════════ (Later — Doctor retrieves) ═══════════════

5. GET /api/shares/inbox
                        ◄─────────────────────────────────
                        ← [{ share_id, from: "patient42", expires_at, filename }]

6. Sign retrieval request
   signPayload({
     action: "retrieve_share",
     username: "dr_jones",
     share_id: "...",
     retrieved_at: "...",
     nonce: serverNonce,
   })

7. POST /api/share/:id/retrieve
   { signature }
                        ──────────────────►
                        Server verifies signature
                        Returns { encryptedRecord, nonce, dekBundle }
                        Marks as downloaded (delete_on_download if set)

8. decryptShare(encryptedRecord, nonce, dekBundle)
   → plaintext file bytes

9. Patient's data is now in doctor's browser — never on server in plaintext
```

---

## 7. Grant Revocation Flow

```
PATIENT                        SERVER
───────────                    ──────

1. signPayload({
     action: "revoke_share",
     owner_username: "patient42",
     share_id: "...",
     revoked_at: "...",
   })

2. DELETE /api/share/:id
   { signature }
                        ──────────────────►
                        Server verifies signature
                        Hard deletes ciphertext + dekBundle
                        Doctor can no longer retrieve

3. Revocation is IMMEDIATE — no key rotation needed
   (The server simply no longer serves the ciphertext)
```

---

## 8. Session Persistence (Optional)

For users who want keys to survive tab refresh without re-entering credentials, the session can optionally be persisted to IndexedDB using Web Crypto AES-GCM wrapping. This is **opt-in** and **off by default**.

```javascript
// OPTIONAL — only if user explicitly enables "Remember me"
async function persistSession(pinOrBrowserKey) {
    assertUnlocked();

    // Derive wrapping key from a browser-specific PIN or device key
    const wrapKey = await crypto.subtle.importKey(
        "raw",
        pinBytes,
        { name: "AES-GCM" },
        false,
        ["wrapKey"]
    );

    // Wrap private keys using Web Crypto (CryptoKey handles)
    // Store wrapped material in IndexedDB with short TTL
    // On next load: unwrap and restore session
}
```

**Security notes:**
- Persisted session is only as secure as the PIN or device credential protecting it
- Short TTL mandatory: max 8 hours
- On logout: `crypto.subtle` key handle is destroyed, IndexedDB entry deleted
- This feature is NOT required for v1.0. Implement only if UX demands it.

---

## 9. Error Handling

All methods throw typed errors. Callers MUST catch.

```javascript
class KeysetError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'KeysetError';
        this.code = code;
    }
}

// Error codes
const ERRORS = {
    NOT_INITIALIZED:    'KEYSET_NOT_INITIALIZED',
    SESSION_LOCKED:     'KEYSET_SESSION_LOCKED',
    DERIVATION_FAILED:  'KEYSET_DERIVATION_FAILED',
    DECRYPTION_FAILED:  'KEYSET_DECRYPTION_FAILED',
    SIGNATURE_INVALID:  'KEYSET_SIGNATURE_INVALID',
    BAD_KEY_FORMAT:     'KEYSET_BAD_KEY_FORMAT',
};
```

---

## 10. Complete Module Skeleton

```javascript
// keyset_manager.js
// MedLedger Keyset Manager v1.0
// No network I/O. No DOM access. No framework dependencies.
// Requires: libsodium-wrappers (npm install libsodium-wrappers)

import sodium from 'libsodium-wrappers';

let _state = {
    initialized:    false,
    locked:         true,
    username:       null,
    signingPrivKey: null,
    exchangePrivKey: null,
    signingPubKey:  null,
    exchangePubKey: null,
    userIdHex:      null,
};

// ─────────────────── INTERNAL HELPERS ───────────────────────────

function assertInitialized() {
    if (!_state.initialized) throw new KeysetError('KEYSET_NOT_INITIALIZED', 'Call init() first');
}

function assertUnlocked() {
    assertInitialized();
    if (_state.locked) throw new KeysetError('KEYSET_SESSION_LOCKED', 'Session is locked');
}

async function _deriveKeys(username, password) {
    const salt = sodium.crypto_generichash(
        16,
        sodium.from_string(username.toLowerCase().trim())
    );
    const seed = sodium.crypto_pwhash(
        64,
        sodium.from_string(password),
        salt,
        3,                // opslimit
        67108864,         // memlimit (64MB)
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const sigSeed  = seed.slice(0, 32);
    const encSeed  = seed.slice(32, 64);
    const sigKP    = sodium.crypto_sign_seed_keypair(sigSeed);
    const encKP    = sodium.crypto_box_seed_keypair(encSeed);
    sodium.memzero(seed);
    sodium.memzero(sigSeed);
    sodium.memzero(encSeed);
    return { signing: sigKP, exchange: encKP };
}

// ─────────────────── PUBLIC API ─────────────────────────────────

export const KeysetManager = {
    init,
    createUser,
    loginUser,
    logoutUser,
    encryptFor,
    encryptRecord,
    decryptShare,
    signPayload,
    verifySignature,
    getPublicKeys,
    isLocked: () => _state.locked,
};
```

---

## 11. React Integration Pattern

```javascript
// hooks/useKeyset.js
import { useState, useCallback, useEffect } from 'react';
import { KeysetManager } from '../crypto/keyset_manager';

export function useKeyset() {
    const [locked, setLocked] = useState(true);
    const [publicKeys, setPublicKeys] = useState(null);

    useEffect(() => {
        KeysetManager.init();

        // Auto-lock on tab close
        const handleUnload = () => KeysetManager.logoutUser();
        window.addEventListener('beforeunload', handleUnload);
        return () => window.removeEventListener('beforeunload', handleUnload);
    }, []);

    const login = useCallback(async (username, password) => {
        const keys = await KeysetManager.loginUser(username, password);
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

```javascript
// Inactivity timer — in App.jsx or layout component
useEffect(() => {
    let timer;
    const reset = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
            if (!KeysetManager.isLocked()) {
                KeysetManager.logoutUser();
                // Trigger UI state update — navigate to /login or show lock screen
            }
        }, 30 * 60 * 1000); // 30 minutes
    };

    ['mousemove', 'keydown', 'click', 'touchstart'].forEach(e =>
        window.addEventListener(e, reset)
    );
    reset();

    return () => {
        clearTimeout(timer);
        ['mousemove', 'keydown', 'click', 'touchstart'].forEach(e =>
            window.removeEventListener(e, reset)
        );
    };
}, []);
```

---

## 12. Security Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| Private keys never exposed to React | Module closure — only public API callable |
| Private keys never logged | No `console.log` of `_state` in any code path |
| Private keys wiped on logout | `sodium.memzero()` on all private material |
| Private keys wiped on tab close | `beforeunload` → `logoutUser()` |
| Session auto-lock on inactivity | 30-minute idle timer → `logoutUser()` |
| No keys in localStorage/IndexedDB (default) | Memory-only by design |
| Sealed box anonymous sender | `crypto_box_seal` — ephemeral key wiped by libsodium |
| AEAD encryption | XSalsa20-Poly1305 — authentication tag prevents tampering |
| Deterministic derivation | Same credentials → same keys, verified by test vectors |

---

## 13. What This Module Does NOT Do

| Excluded | Reason |
|----------|--------|
| HTTP requests | Not its job. React / API layer handles network. |
| DOM manipulation | Not its job. React handles UI. |
| JWT handling | Not its job. Auth layer handles JWT in HttpOnly cookie. |
| File reading (File API) | Caller passes bytes. Manager encrypts bytes. |
| Server-side key operations | All private key ops are client-side only. |
| Key rotation | Delete account + re-register. No rotation endpoint. |
| Password change | Delete account + re-register. Same design. |

---

## 14. Invariants (Non-Negotiable)

1. **No network I/O.** KeysetManager never calls `fetch`, `XMLHttpRequest`, or WebSocket.
2. **No private key leaves the module.** Public API returns base64 strings, not `Uint8Array` references to key material.
3. **`sodium.memzero()` on every private key after use.** Including intermediate seeds.
4. **`logoutUser()` is always synchronous.** Key wipe must not be async — no await, no promise.
5. **`assertUnlocked()` on every method that uses private keys.** No silent failures.
6. **Sealed boxes for all share encryption.** No manual ECDH in this module.
7. **Deterministic derivation only.** No `randombytes` in the key derivation path.
8. **Test vectors must pass before any release.** See 04-CRYPTO_SPEC.md §10.

---

## 15. Alignment with Other Documents

| Concept | This Doc | 04-CRYPTO_SPEC | 03-AUTH_SPEC |
|---------|----------|---------------|-------------|
| Key derivation | `_deriveKeys()` calls Argon2id | §3 (full spec) | Referenced |
| Sealed boxes | `encryptRecord()`, `decryptShare()` | §5 (sealed box spec) | N/A |
| Signatures | `signPayload()`, `verifySignature()` | §6 (signature spec) | §6 (server-side verify) |
| Session lifecycle | State machine §4 | §9 (memory management) | §3 (auth flows) |
| Lock triggers | `logoutUser()`, idle timer | §9 | §7 (session management) |
| Username as identity anchor | `_state.username`, `getPublicKeys()` | §4.3 note | §1 (JWT claims) |

---

*Document: 05-KEYSET_MANAGER.md | Author: Premananda (Team Praxis) | Status: Draft v1.0*
*Aligned with: 04-CRYPTO_SPEC.md + 03-AUTH_SPEC.md + 01-ARCHITECTURE.md*
*No network I/O. Memory-only private keys. Single-responsibility crypto module.*

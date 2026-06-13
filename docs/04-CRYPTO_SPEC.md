# MedLedger Cryptographic Specification

**Version:** 2.0 | **Date:** June 2026 | **Status:** Draft — Foundation Document

**Depends on:** 01-ARCHITECTURE-v2.md, 02-SECURITY_SPEC-v2.md, 03-AUTH_SPEC-v2.md

**WARNING:** This document defines the cryptographic layer for MedLedger. Any deviation from these specifications — including algorithm substitution, parameter changes, or library swaps — must be treated as a breaking change and requires full re-review.

---

## 1. Library Strategy: libsodium.js

MedLedger uses **libsodium.js** (specifically `libsodium-wrappers-sumo`) as the sole cryptographic library for all browser-side operations.

```
┌──────────────────────────────────────────────────────────────────┐
│                    CRYPTO LAYER (Browser)                         │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    libsodium.js (Sumo)                        │  │
│  │                                                             │  │
│  │  • Ed25519  (signing)           — crypto_sign_*             │  │
│  │  • X25519   (key exchange)      — crypto_box_*              │  │
│  │  • XSalsa20-Poly1305 (encrypt)  — crypto_secretbox_*        │  │
│  │  • Sealed boxes                 — crypto_box_seal*          │  │
│  │  • BLAKE2b  (hashing)           — crypto_generichash        │  │
│  │  • Argon2id (key derivation)    — crypto_pwhash*            │  │
│  │  • Random generation            — randombytes_buf           │  │
│  │  • Memory zeroing               — memzero                   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  RULE: libsodium.js for ALL crypto operations.                    │
│        No Web Crypto API, no custom implementations.              │
└──────────────────────────────────────────────────────────────────┘
```

### 1.1 Why libsodium.js

| Concern | libsodium Advantage |
|---------|-------------------|
| **Algorithm selection** | Opinionated — no footgun choices. Ed25519, X25519, Argon2id are the defaults. |
| **Nonce management** | Sealed boxes: no nonce. Secret boxes: nonce included in output. |
| **Side-channel resistance** | Constant-time implementations by design |
| **Key derivation** | Built-in Argon2id with sane defaults |
| **Hashing** | BLAKE2b: fast, keyed, variable-length output |
| **Memory zeroization** | `sodium.memzero()` for explicit wipe |

### 1.2 Why NOT Web Crypto API

The previous MedLedger spec (v1.0) used Web Crypto API with P-256 curves. This was changed because:

| Web Crypto Limitation | libsodium Solution |
|----------------------|-------------------|
| P-256 (NIST curve) | Ed25519/X25519 (djb curves, no NIST backdoor concerns) |
| Manual ECDH + HKDF + AES-GCM | Single `crypto_box_seal` call |
| No Argon2id | Built-in Argon2id |
| No BLAKE2b | Built-in BLAKE2b |
| Complex nonce management | Sealed boxes handle nonces automatically |
| No memory zeroization | `sodium.memzero()` |

---

## 2. Algorithm Registry

| Purpose | Algorithm | Parameters | Library | Status |
|---------|-----------|------------|---------|--------|
| Signing keypair | Ed25519 | 32-byte seed → 64-byte private, 32-byte public | libsodium.js | **Active** |
| Encryption keypair | X25519 | 32-byte seed → 32-byte private, 32-byte public | libsodium.js | **Active** |
| Symmetric file encryption | XSalsa20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag | libsodium.js | **Active** |
| Sealed-box encryption | X25519 + XSalsa20-Poly1305 | `crypto_box_seal` | libsodium.js | **Active** |
| Grant signing | Ed25519 | 64-byte signature | libsodium.js | **Active** |
| Content integrity | BLAKE2b | 256-bit output | libsodium.js | **Active** |
| Identity hashing | BLAKE2b | 128-bit output (user_id) | libsodium.js | **Active** |
| CSPRNG | `randombytes_buf` | — | libsodium.js | **Active** |
| Memory zeroing | `memzero` | — | libsodium.js | **Active** |

---

## 3. Key Generation (Current: Random)

### 3.1 Design Decision (v2.0)

**Random key generation.** Each call to `generateKeypair()` produces a fresh, cryptographically random keypair with no relation to any credential or prior call.

The user receives their private keypair once at registration and must store it securely (e.g., encrypted download, password manager, hardware wallet). On subsequent logins they supply it back. Lost keys mean lost access to past shares — there is no recovery path.

### 3.2 Trade-offs (Documented Explicitly)

| Benefit | Cost |
|---------|------|
| No password-derived key weakness | User must store a file |
| Keypair is independent of account password | Lost file = lost access |
| Simple generation (single libsodium call) | File management burden on user |
| Same keypair works across password changes | File theft = key theft (if unencrypted) |

**These trade-offs are accepted by design.** The system is honest about them in the UI.

### 3.3 Key Generation Function

```javascript
// make_key.js
import sodium from 'libsodium-wrappers-sumo';

export function generateKeypair() {
  // Ed25519 signing keypair
  const signingKeypair = sodium.crypto_sign_keypair();

  // X25519 exchange keypair
  const exchangeKeypair = sodium.crypto_box_keypair();

  return {
    signing: {
      publicKey:  signingKeypair.publicKey,   // Uint8Array, 32 bytes
      privateKey: signingKeypair.privateKey,  // Uint8Array, 64 bytes
    },
    exchange: {
      publicKey:  exchangeKeypair.publicKey,   // Uint8Array, 32 bytes
      privateKey: exchangeKeypair.privateKey,  // Uint8Array, 32 bytes
    },
  };
}
```

### 3.4 Future: Deterministic Key Derivation (Phase 3)

In a future version, keys may be derived deterministically from `username + password + serverSalt` using Argon2id. This would eliminate the keypair file entirely.

See MIGRATION_PLAN.md Phase 3 for details.

---

## 4. Key Types and Encoding

### 4.1 Key Sizes

| Key | Algorithm | Size |
|-----|-----------|------|
| Ed25519 signing public key | Ed25519 | 32 bytes |
| Ed25519 signing private key | Ed25519 | 64 bytes (seed + public key concatenated) |
| X25519 exchange public key | Curve25519 | 32 bytes |
| X25519 exchange private key | Curve25519 | 32 bytes |
| Symmetric file key (DEK) | XSalsa20 | 32 bytes |

### 4.2 Encoding

All keys transmitted or stored use **Base64url** encoding (no padding, URL-safe alphabet).

```javascript
// Encode
const encoded = sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);

// Decode
const decoded = sodium.from_base64(encoded, sodium.base64_variants.URLSAFE_NO_PADDING);
```

### 4.3 User Identity Hash

The server-side identity anchor is a BLAKE2b hash of the signing public key:

```javascript
// user_id_hex = BLAKE2b(signingPublicKey, outputLength=16)
// 16 bytes = 128-bit identifier
const userId = sodium.crypto_generichash(16, signingKeypair.publicKey);
const userIdHex = sodium.to_hex(userId);  // 32-char hex string
```

**Note:** The `username` is used for human-readable identification, but the `user_id_hex` is the canonical cryptographic identity anchor. All share operations reference `user_id_hex`.

---

## 5. Sealed Box Encryption (Share Encryption)

### 5.1 What Is a Sealed Box?

A sealed box is anonymous, forward-secure encryption using the recipient's public key:
- Sender generates an ephemeral X25519 keypair
- Derives a shared secret via X25519 ECDH
- Encrypts with XSalsa20-Poly1305
- Prepends ephemeral public key to ciphertext
- Wipes ephemeral private key

The recipient cannot tell who sent it. The sender cannot decrypt their own message.

```
libsodium: crypto_box_seal(message, recipientPublicKey) → ciphertext
libsodium: crypto_box_seal_open(ciphertext, recipientPublicKey, recipientPrivateKey) → message
```

### 5.2 Share Encryption Flow

```
Patient wants to share record with Doctor:

1. Generate a random 32-byte DEK (Data Encryption Key)
   const dek = sodium.randombytes_buf(32);

2. Encrypt the medical record with the DEK (symmetric)
   const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
   const encryptedRecord = sodium.crypto_secretbox_easy(record, nonce, dek);

3. Seal the DEK for the doctor's X25519 public key
   const encryptedDEK = sodium.crypto_box_seal(dek, doctorEncPublicKey);

4. Hash the plaintext for integrity verification
   const fileHash = sodium.crypto_generichash(32, record);
   const fileHashHex = sodium.to_hex(fileHash);

5. Wipe DEK from memory
   sodium.memzero(dek);

6. Send to server:
   {
     ciphertext: base64(encryptedRecord),
     nonce: base64(nonce),
     dek_bundle: base64(encryptedDEK),
     file_hash: fileHashHex,
     recipient_user_id_hex: "dr_jones_hex",
     ttl_days: 30
   }
```

### 5.3 Share Decryption Flow

```
Doctor retrieves share:

1. Fetch from server: { ciphertext, nonce, dek_bundle }

2. Open sealed DEK with doctor's X25519 private key
   const dek = sodium.crypto_box_seal_open(
       encryptedDEK,
       doctorEncPublicKey,
       doctorEncPrivateKey
   );

3. Decrypt the record with DEK
   const record = sodium.crypto_secretbox_open_easy(
       encryptedRecord,
       nonce,
       dek
   );

4. Verify integrity
   const computedHash = sodium.crypto_generichash(32, record);
   if (!sodium.memcmp(computedHash, expectedHash)) throw new Error("Tampered!");

5. Wipe DEK after use
   sodium.memzero(dek);
```

### 5.4 Why Sealed Boxes (vs ECIES from Old Spec)

| Old Design (ECIES + P-256) | New Design (Sealed Box + X25519) |
|---------------------------|----------------------------------|
| Web Crypto API only (P-256) | libsodium.js (Curve25519) |
| Manual ECDH + HKDF + AES-GCM | Single `crypto_box_seal` call |
| Nonce management required | No nonce management |
| Complex implementation | Cannot be misimplemented |
| NIST curves | Djb curves (no NIST backdoor concerns) |

---

## 6. Signatures

### 6.1 Purpose

Ed25519 signatures are used to:
1. Authenticate share creation (patient signs grant metadata)
2. Authenticate share retrieval (grantee signs fetch request)
3. Prevent forgery and replay attacks

### 6.2 What Gets Signed

```javascript
// Share creation — patient signs:
const grantPayload = {
    action:              "create_share",
    owner_user_id_hex:  userIdHex,
    recipient_user_id_hex: recipientIdHex,
    share_id:            shareId,          // server-assigned UUID
    expires_at:          expiryTimestamp,  // ISO 8601 UTC
    created_at:          nowTimestamp,     // ISO 8601 UTC
    file_hash:           fileHashHex,
};

// Canonical-JSON serialize (sorted keys, deterministic)
const payloadCanon = canonicalJSON(grantPayload);

const signature = sodium.crypto_sign_detached(
    sodium.from_string(payloadCanon),
    signingPrivateKey   // Ed25519, 64 bytes
);

// Send to server: { ...payload, signature: base64(signature), payloadCanon }
```

```javascript
// Share retrieval — grantee signs:
const retrievalPayload = {
    action:       "retrieve_share",
    user_id_hex:  recipientIdHex,
    share_id:     shareId,
    retrieved_at: nowTimestamp,
    nonce:        serverProvidedNonce,   // prevents replay
};

const payloadCanon = canonicalJSON(retrievalPayload);

const signature = sodium.crypto_sign_detached(
    sodium.from_string(payloadCanon),
    signingPrivateKey
);
```

### 6.3 Signature Verification (Server)

```python
# Server verifies using PyNaCl or libsodium Python bindings
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder

verify_key = VerifyKey(user.signing_public_key_bytes)
verify_key.verify(payload_bytes, signature_bytes)
# Raises BadSignatureError if forged
```

### 6.4 Canonical JSON

Object keys are sorted recursively before signing to ensure deterministic serialization:

```javascript
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

---

## 7. Symmetric Encryption (Local Records)

When a user stores a record locally (client-side only, not shared):

```javascript
// Encrypt local record with a password-derived key
// Uses the same keypair derivation or a separate password

const localKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const encrypted = sodium.crypto_secretbox_easy(plaintext, nonce, localKey);

// Store: { nonce: base64(nonce), ciphertext: base64(encrypted) }
// The nonce is not secret — store alongside ciphertext
```

---

## 8. Hashing

### 8.1 Content Integrity

```javascript
// Hash file content for integrity verification
// Sent with share, verified by recipient after decryption
const fileHash = sodium.crypto_generichash(32, fileBytes);  // 32-byte BLAKE2b
const fileHashHex = sodium.to_hex(fileHash);
```

### 8.2 Username Lookup Hash (Audit Logs)

```javascript
// Username hash used in audit logs only (additional privacy layer)
const usernameHash = sodium.crypto_generichash(
    16,
    sodium.from_string(username.toLowerCase().trim())
);
```

---

## 9. Memory Management

Private keys and DEKs MUST be zeroed after use.

```javascript
class CryptoSession {
    #signingPrivateKey = null;
    #exchangePrivateKey = null;

    async unlock(keypair) {
        this.#signingPrivateKey  = keypair.signing.privateKey;
        this.#exchangePrivateKey = keypair.exchange.privateKey;
        // Public keys can be stored normally
    }

    lock() {
        if (this.#signingPrivateKey)  sodium.memzero(this.#signingPrivateKey);
        if (this.#exchangePrivateKey) sodium.memzero(this.#exchangePrivateKey);
        this.#signingPrivateKey  = null;
        this.#exchangePrivateKey = null;
    }
}
```

**Triggers for `lock()`:**
- User clicks "Lock"
- 30-minute inactivity timer fires
- Browser tab closes (`beforeunload` event)
- `window.blur` (optional — aggressive)
- Logout

---

## 10. Test Vectors

These vectors MUST pass before any release. They verify the cryptographic chain.

### 10.1 Key Generation Vector

```javascript
// Test: generateKeypair() produces valid keys
const keypair = generateKeypair();

// Ed25519 public key: 32 bytes
assert(keypair.signing.publicKey.length === 32);
// Ed25519 private key: 64 bytes
assert(keypair.signing.privateKey.length === 64);
// X25519 public key: 32 bytes
assert(keypair.exchange.publicKey.length === 32);
// X25519 private key: 32 bytes
assert(keypair.exchange.privateKey.length === 32);

// user_id_hex: 32 hex chars (16 bytes)
const userId = sodium.crypto_generichash(16, keypair.signing.publicKey);
const userIdHex = sodium.to_hex(userId);
assert(userIdHex.length === 32);
```

### 10.2 Sealed Box Round-Trip Vector

```javascript
// Generate test keypair
const recipientKeys = generateKeypair();

// Known plaintext
const plaintext = sodium.from_string("Hello MedLedger");

// Seal
const ciphertext = sodium.crypto_box_seal(plaintext, recipientKeys.exchange.publicKey);

// Open
const decrypted = sodium.crypto_box_seal_open(
    ciphertext,
    recipientKeys.exchange.publicKey,
    recipientKeys.exchange.privateKey
);

// Verify
assert(sodium.to_string(decrypted) === "Hello MedLedger");
```

### 10.3 Signature Round-Trip Vector

```javascript
const keys = generateKeypair();

const message = sodium.from_string("MedLedger test payload 2026");

const sig = sodium.crypto_sign_detached(message, keys.signing.privateKey);

const valid = sodium.crypto_sign_verify_detached(sig, message, keys.signing.publicKey);

assert(valid === true);
```

### 10.4 XSalsa20-Poly1305 Round-Trip Vector

```javascript
const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const plaintext = sodium.from_string("Secret medical record");

const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);
const decrypted = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);

assert(sodium.to_string(decrypted) === "Secret medical record");
```

---

## 11. Security Properties

| Property | Guarantee |
|----------|-----------|
| **Forward secrecy (sealed box)** | Ephemeral sender key wiped — past messages safe even if long-term key compromised |
| **Anonymous sender** | Sealed box reveals no sender identity |
| **Key commitment** | XSalsa20-Poly1305 is an AEAD — tampered ciphertext fails authentication |
| **Random key generation** | Each keypair is independent, no credential correlation |
| **Memory safety** | `sodium.memzero()` for all private material after use |
| **No weak algorithms** | No RSA, no ECDSA-P256, no MD5, no SHA-1 |
| **No library footguns** | libsodium opinionated by design — no AES-ECB, no raw ECDH |

---

## 12. Invariants (Non-Negotiable)

1. **Private keys are randomly generated, never derived from passwords.** Each keypair is independent.
2. **libsodium.js for all crypto operations.** No Web Crypto API, no custom implementations.
3. **No P-256, no ECDSA-P256.** The previous spec used P-256; this spec uses Ed25519/X25519.
4. **`sodium.memzero()` on all private material after use.** No exceptions.
5. **Sealed boxes for share encryption.** No manual ECDH + HKDF + AES. Use `crypto_box_seal`.
6. **XSalsa20-Poly1305 for file encryption.** Not AES-GCM.
7. **BLAKE2b for all hashing.** Not SHA-256 for content hashes.
8. **Random DEK per share.** Never reuse a DEK across multiple shares.
9. **DEK wiped immediately after encryption/decryption.** Use `try/finally` to guarantee.
10. **Canonical JSON for all signed payloads.** Deterministic serialization prevents signature malleability.

---

## 13. Alignment with Previous Docs

The following items in 01-ARCHITECTURE.md (v1.0) and 02-SECURITY_SPEC.md (v1.0) are **superseded** by this document:

| Old Reference | Old Value | New Value (This Doc) |
|---------------|-----------|---------------------|
| Keypair algorithm | ECDSA P-256 | Ed25519 (signing), X25519 (encryption) |
| Key derivation | PBKDF2 + random salt | Random generation (no derivation) |
| DEK wrapping | ECIES (P-256) | `crypto_box_seal` (X25519 + XSalsa20-Poly1305) |
| Library | Web Crypto API (primary) | libsodium.js (sole library) |
| Key generation | Random (Web Crypto generateKey) | Random (libsodium crypto_sign_keypair) |
| Public key format | Uncompressed 65-byte P-256 | 32-byte Curve25519 |
| Identity hash | SHA-256 of public key | BLAKE2b-128 of signing public key |
| Identity anchor | public_key_hash | user_id_hex |

---

*Document: 04-CRYPTO_SPEC.md | Author: Premananda (Team Praxis) | Status: Draft v2.0*
*Aligned with: 01-ARCHITECTURE-v2.md + 02-SECURITY_SPEC-v2.md + 03-AUTH_SPEC-v2.md*
*Crypto model: libsodium.js (sole library) — Random key generation, sealed-box encryption*

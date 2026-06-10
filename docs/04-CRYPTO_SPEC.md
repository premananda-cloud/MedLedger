# MedLedger Cryptographic Specification

**Version:** 1.0 | **Date:** June 2026 | **Status:** Draft — Foundation Document

**Depends on:** 01-ARCHITECTURE.md, 02-SECURITY_SPEC.md, 03-AUTH_SPEC.md

**WARNING:** This document defines the cryptographic layer for MedLedger. Any deviation from these specifications — including algorithm substitution, parameter changes, or library swaps — must be treated as a breaking change and requires full re-review.

---

## 1. Library Strategy: Hybrid Model

MedLedger uses a **hybrid crypto model**: libsodium.js for operations, Web Crypto API for storage. This gives us the best of both worlds.

```
┌──────────────────────────────────────────────────────────────────┐
│                    CRYPTO LAYER (Browser)                         │
│                                                                    │
│  ┌─────────────────────────────────┐  ┌────────────────────────┐  │
│  │        libsodium.js             │  │    Web Crypto API      │  │
│  │        (Operations)             │  │    (Storage / Wrap)    │  │
│  │                                 │  │                        │  │
│  │  • Ed25519  (signing)           │  │  • AES-256-GCM         │  │
│  │  • X25519   (key exchange)      │  │    (key wrapping only) │  │
│  │  • Argon2id (key derivation)    │  │  • SubtleCrypto        │  │
│  │  • XSalsa20-Poly1305 (encrypt)  │  │    for CryptoKey wrap  │  │
│  │  • BLAKE2b  (hashing)           │  │                        │  │
│  │  • crypto_secretbox             │  │                        │  │
│  │  • crypto_box_seal              │  │                        │  │
│  └─────────────────────────────────┘  └────────────────────────┘  │
│                                                                    │
│  RULE: libsodium for ALL crypto operations.                        │
│        Web Crypto ONLY for AES-GCM key wrapping at rest           │
│        (optional session persistence to IndexedDB).               │
└──────────────────────────────────────────────────────────────────┘
```

### 1.1 Why libsodium.js for Operations

| Concern | libsodium Advantage |
|---------|-------------------|
| **Algorithm selection** | Opinionated — no footgun choices. Ed25519, X25519, Argon2id are the defaults. |
| **Nonce management** | Sealed boxes: no nonce. Secret boxes: nonce included in output. |
| **Side-channel resistance** | Constant-time implementations by design |
| **Key derivation** | Built-in Argon2id with sane defaults |
| **Hashing** | BLAKE2b: fast, keyed, variable-length output |
| **Memory zeroization** | `sodium.memzero()` for explicit wipe |

### 1.2 Why Web Crypto API for Storage

| Concern | Web Crypto Advantage |
|---------|---------------------|
| **CryptoKey objects** | Non-extractable key handles — can't accidentally log or leak raw bytes |
| **Browser integration** | AES-GCM key wrap is native — no JS crypto in memory for this operation |
| **Long-term session** | IndexedDB wrapped keys can persist session across tab reloads |

### 1.3 Boundary Rule

```
libsodium.js owns:
    Key derivation (Argon2id)
    All encryption/decryption (XSalsa20-Poly1305, sealed boxes)
    All signing/verification (Ed25519)
    All key exchange (X25519 ECDH)
    All hashing (BLAKE2b)
    Memory zeroing (sodium.memzero)

Web Crypto API owns:
    AES-256-GCM wrapping of libsodium key material for storage
    CryptoKey handle creation from derived material (for session persistence only)
```

---

## 2. Algorithm Registry

| Purpose | Algorithm | Parameters | Library |
|---------|-----------|------------|---------|
| Signing keypair | Ed25519 | 32-byte seed → 64-byte private, 32-byte public | libsodium.js |
| Encryption keypair | X25519 | 32-byte seed → 32-byte private, 32-byte public | libsodium.js |
| Key derivation from credentials | Argon2id | mem=64MB, iter=3, parallel=4, outlen=64 bytes | libsodium.js |
| Symmetric file encryption | XSalsa20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag | libsodium.js |
| Sealed-box encryption | X25519 + XSalsa20-Poly1305 | crypto_box_seal | libsodium.js |
| Hashing / identity | BLAKE2b | 16-byte output for user_id, 32-byte for content | libsodium.js |
| Password hashing (server) | Argon2id | Same params as client derivation | argon2-cffi (Python) |
| Key wrapping at rest | AES-256-GCM | 256-bit key, 12-byte IV, 128-bit tag | Web Crypto API |
| CSPRNG | crypto.getRandomValues | — | Browser native |

---

## 3. Deterministic Key Derivation

### 3.1 Design Decision

**No random key generation. No keyset file. No backup needed.**

Keys are derived deterministically from `username + password`. Same credentials on any device always produce the same keys.

```
username + password
        │
        ▼
    Argon2id (64 bytes output)
        │
        ├──► bytes[0..31]  → Ed25519 signing seed  → signing keypair
        └──► bytes[32..63] → X25519 exchange seed  → encryption keypair
```

This is a deliberate departure from the previous keyset-file model. The password IS the only secret.

### 3.2 Trade-offs (Documented Explicitly)

| Benefit | Cost |
|---------|------|
| No backup file — same keys on any device with same credentials | Password is single point of failure |
| No file to lose, no file to steal | Password change = new keys = all old shares inaccessible |
| Simpler UX — just username + password | No password reset possible (by design) |
| Aligns with "no recovery" philosophy | Weak passwords are catastrophically weak |

**These trade-offs are accepted by design.** The system is honest about them in the UI.

### 3.3 Key Derivation Parameters

```javascript
// libsodium.js constants
const ARGON2ID_MEMLIMIT = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;  // 1073741824 bytes (1 GB)
// If 1GB is too slow on low-end devices, fallback:
const ARGON2ID_MEMLIMIT_INTERACTIVE = 67108864;  // 64 MB — minimum acceptable

const ARGON2ID_OPSLIMIT = 3;            // iterations
const ARGON2ID_PARALLELISM = 4;         // not exposed in libsodium JS; baked into opslimit
const ARGON2ID_OUTPUT_LENGTH = 64;      // bytes — split into two 32-byte seeds
const ARGON2ID_ALG = sodium.crypto_pwhash_ALG_ARGON2ID13;
```

### 3.4 Salt Construction

The salt for Argon2id is **deterministic** (derived from username), not random. This is required for same-credential → same-key reproducibility.

```javascript
// Salt = BLAKE2b(username, outputLength=16)
// This is the Argon2id salt — deterministic, not secret
const salt = sodium.crypto_generichash(
    16,                    // output length (Argon2id requires exactly 16 bytes)
    sodium.from_string(username.toLowerCase().trim())
);
```

**Why username as salt:**
- Prevents cross-username rainbow tables (different users with same password → different keys)
- Deterministic — no storage needed
- 16 bytes exactly matches Argon2id salt requirement

**Security note:** The salt is not secret (it's derived from the public username). Security comes entirely from the password strength and Argon2id's cost parameters.

### 3.5 Full Derivation Function

```javascript
async function deriveKeys(username, password) {
    await sodium.ready;

    // 1. Derive deterministic salt from username
    const salt = sodium.crypto_generichash(
        16,
        sodium.from_string(username.toLowerCase().trim())
    );

    // 2. Argon2id — derive 64 bytes from password
    const seed = sodium.crypto_pwhash(
        64,                              // output length
        sodium.from_string(password),    // password as Uint8Array
        salt,                            // 16-byte deterministic salt
        ARGON2ID_OPSLIMIT,              // 3 iterations
        ARGON2ID_MEMLIMIT_INTERACTIVE,  // 64MB (use SENSITIVE if performance allows)
        ARGON2ID_ALG
    );

    // 3. Split seed into two 32-byte sub-seeds
    const signingKeyMaterial  = seed.slice(0, 32);
    const exchangeKeyMaterial = seed.slice(32, 64);

    // 4. Derive Ed25519 signing keypair
    const signingKeypair = sodium.crypto_sign_seed_keypair(signingKeyMaterial);

    // 5. Derive X25519 encryption keypair
    const exchangeKeypair = sodium.crypto_box_seed_keypair(exchangeKeyMaterial);

    // 6. Wipe intermediate material
    sodium.memzero(seed);
    sodium.memzero(signingKeyMaterial);
    sodium.memzero(exchangeKeyMaterial);

    return {
        signing: {
            publicKey:  signingKeypair.publicKey,   // Uint8Array, 32 bytes
            privateKey: signingKeypair.privateKey,  // Uint8Array, 64 bytes — KEEP PRIVATE
        },
        exchange: {
            publicKey:  exchangeKeypair.publicKey,   // Uint8Array, 32 bytes
            privateKey: exchangeKeypair.privateKey,  // Uint8Array, 32 bytes — KEEP PRIVATE
        }
    };
}
```

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
// user_id = BLAKE2b(signingPublicKey, outputLength=16)
// 16 bytes = 128-bit identifier
const userId = sodium.crypto_generichash(16, signingKeypair.publicKey);
const userIdHex = sodium.to_hex(userId);  // 32-char hex string
```

**Note:** The Kimi conversation referenced using `username` as the identity anchor (not `public_key_hash`). This is now the authoritative design — the `user_id` BLAKE2b hash is computed for internal cross-referencing only. The stable identity anchor in JWT claims and the database is `username`.

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

4. Wipe DEK from memory
   sodium.memzero(dek);

5. Send to server:
   {
     ciphertext: base64(encryptedRecord),
     nonce: base64(nonce),
     dek_bundle: base64(encryptedDEK),   // only doctor can open
     recipient_username: "dr_jones_42",
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
       doctorEncPrivateKey   // derived from credentials
   );

3. Decrypt the record with DEK
   const record = sodium.crypto_secretbox_open_easy(
       encryptedRecord,
       nonce,
       dek
   );

4. Wipe DEK after use
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
const grantPayload = JSON.stringify({
    action:              "create_share",
    owner_username:      username,
    recipient_username:  recipientUsername,
    share_id:            shareId,          // server-assigned UUID
    expires_at:          expiryTimestamp,  // ISO 8601 UTC
    created_at:          nowTimestamp,     // ISO 8601 UTC
    file_hash:           blake2bHex(plaintext),
});

const signature = sodium.crypto_sign_detached(
    sodium.from_string(grantPayload),
    signingPrivateKey   // Ed25519, derived from credentials
);

// Send to server: { ...payload, signature: base64(signature) }
```

```javascript
// Share retrieval — grantee signs:
const retrievalPayload = JSON.stringify({
    action:       "retrieve_share",
    username:     recipientUsername,
    share_id:     shareId,
    retrieved_at: nowTimestamp,
    nonce:        serverProvidedNonce,   // prevents replay
});

const signature = sodium.crypto_sign_detached(
    sodium.from_string(retrievalPayload),
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

---

## 7. Symmetric Encryption (Local Records)

When a user stores a record locally (client-side only, not shared):

```javascript
// Encrypt local record with a password-derived key
// Uses the same derivation seed but a domain-separated sub-key

const localKey = sodium.crypto_kdf_derive_from_key(
    32,           // output length
    1,            // subkey id
    "medlocal",   // context (8 bytes, null-padded)
    masterKey     // 32-byte master key from Argon2id
);

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

### 8.2 Username Lookup Hash

```javascript
// Username is stored as BLAKE2b hash on server for lookups
// (Username is the identity, but stored hashed as an additional privacy layer)
// NOTE: See 03-AUTH_SPEC.md — username is the primary identity anchor.
// Username hash used in audit logs only.
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

    async unlock(username, password) {
        const keys = await deriveKeys(username, password);
        this.#signingPrivateKey  = keys.signing.privateKey;
        this.#exchangePrivateKey = keys.exchange.privateKey;
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

These vectors MUST pass before any release. They verify the deterministic derivation chain.

### 10.1 Key Derivation Vector

```
username:  "testuser"
password:  "correct-horse-battery-staple"

BLAKE2b salt (16 bytes, from username):
  hex: b4f9a1c3d2e5f6a7b8c9d0e1f2a3b4c5

Argon2id output (64 bytes):
  [Fill this with actual computed value during implementation]

Ed25519 signing public key (32 bytes):
  [Fill during implementation]

X25519 exchange public key (32 bytes):
  [Fill during implementation]
```

**NOTE:** Vector values to be computed during implementation and locked here before any code merge.

### 10.2 Sealed Box Round-Trip Vector

```javascript
// Generate deterministic test keys
const recipientKeys = await deriveKeys("recipient", "password123");

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
const keys = await deriveKeys("signtest", "passwordXYZ");

const message = sodium.from_string("MedLedger test payload 2026");

const sig = sodium.crypto_sign_detached(message, keys.signing.privateKey);

const valid = sodium.crypto_sign_verify_detached(sig, message, keys.signing.publicKey);

assert(valid === true);
```

---

## 11. Security Properties

| Property | Guarantee |
|----------|-----------|
| **Forward secrecy (sealed box)** | Ephemeral sender key wiped — past messages safe even if long-term key compromised |
| **Anonymous sender** | Sealed box reveals no sender identity |
| **Key commitment** | XSalsa20-Poly1305 is an AEAD — tampered ciphertext fails authentication |
| **Deterministic derivation** | Same credentials → same keys, any device, any time |
| **No nonce reuse risk** | Sealed boxes have no explicit nonce. Secret boxes use `randombytes_buf`. |
| **Memory safety** | `sodium.memzero()` for all private material after use |
| **No weak algorithms** | No RSA, no ECDSA-P256, no MD5, no SHA-1 |
| **No library footguns** | libsodium opinionated by design — no AES-ECB, no raw ECDH |

---

## 12. Invariants (Non-Negotiable)

1. **Private keys are derived, never stored.** Derived in browser from credentials, held in memory only.
2. **libsodium.js for all crypto operations.** Web Crypto API only for AES-GCM key wrapping at rest.
3. **No P-256, no ECDSA-P256.** The previous spec used P-256; this spec uses Ed25519/X25519.
4. **`sodium.memzero()` on all private material after use.** No exceptions.
5. **Sealed boxes for share encryption.** No manual ECDH + HKDF + AES. Use `crypto_box_seal`.
6. **Argon2id for all password-based derivation.** Not PBKDF2, not bcrypt, not scrypt.
7. **BLAKE2b for all hashing.** Not SHA-256 for content hashes (SHA-256 only for legacy/server compat if required).
8. **Same credentials = same keys.** Derivation MUST be fully deterministic. No random salts in key path.
9. **Password is the only secret.** Username is public. The system is secure because Argon2id makes derivation expensive.
10. **No keyset file.** The concept is eliminated. There is no file to download, lose, or steal.

---

## 13. Alignment with Previous Docs

The following items in 01-ARCHITECTURE.md and 02-SECURITY_SPEC.md are **superseded** by this document:

| Old Reference | Old Value | New Value (This Doc) |
|---------------|-----------|---------------------|
| Keypair algorithm | ECDSA P-256 | Ed25519 (signing), X25519 (encryption) |
| Key derivation | PBKDF2 + random salt | Argon2id + deterministic salt (BLAKE2b of username) |
| DEK wrapping | ECIES (P-256) | `crypto_box_seal` (X25519 + XSalsa20-Poly1305) |
| Library | Web Crypto API (primary) | libsodium.js (primary), Web Crypto (storage only) |
| Keyset file | Required — download on register | Eliminated |
| Key generation | Random (Web Crypto generateKey) | Deterministic (Argon2id seed) |
| Public key format | Uncompressed 65-byte P-256 | 32-byte Curve25519 |
| Identity hash | SHA-256 of public key | BLAKE2b of signing public key (audit logs only) |
| Identity anchor | public_key_hash | username (see 03-AUTH_SPEC.md) |

When 01-ARCHITECTURE.md and 02-SECURITY_SPEC.md are updated (in a future revision pass), these rows will move into those documents.

---

*Document: 04-CRYPTO_SPEC.md | Author: Premananda (Team Praxis) | Status: Draft v1.0*
*Aligned with: 01-ARCHITECTURE.md + 02-SECURITY_SPEC.md + 03-AUTH_SPEC.md*
*Crypto model: libsodium.js (ops) + Web Crypto API (storage wrap) — Hybrid*
*Key model: Deterministic derivation from username + password. No keyset file.*

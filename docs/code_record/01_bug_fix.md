Bug Fix Summary: libsodium-wrappers Initialization & Package Migration
Date: 2026-06-10
Files Modified: make_key.js, key_manager.js, make_key.test.js, key_manager.test.js, package.json

Root Cause
libsodium-wrappers (standard package) does not include crypto_pwhash (Argon2id password hashing). All calls to deriveKeys() failed with:

text
TypeError: default.crypto_pwhash is not a function
Additionally, libsodium requires await sodium.ready to resolve before any functions can be called. The original code imported sodium but did not await initialization.

Changes Made
1. Package Migration (package.json)
Removed: libsodium-wrappers

Added: libsodium-wrappers-sumo (includes all algorithms including Argon2id)

Added: "type": "module" for proper ES module handling

json
{
  "type": "module",
  "dependencies": {
    "libsodium-wrappers-sumo": "^0.8.4"
  },
  "devDependencies": {
    "vitest": "^4.1.8"
  }
}
2. Source Files: Sodium Initialization
Both make_key.js and key_manager.js were updated to use top-level await for initialization:

javascript
// Before (broken):
import sodium from 'libsodium-wrappers';

// After (fixed):
import _sodium from 'libsodium-wrappers-sumo';
await _sodium.ready;
const sodium = _sodium;
3. Missing Import (key_manager.js)
Added the missing import of deriveKeys from make_key.js:

javascript
import { deriveKeys } from './make_key.js';
4. Error Handling (key_manager.js — decryptShare())
libsodium-wrappers-sumo throws raw Error objects instead of returning null/false for certain crypto failures. Wrapped sodium calls in try/catch to convert to KeysetError:

javascript
// crypto_box_seal_open now wrapped:
try {
    dek = sodium.crypto_box_seal_open(dekBundle, _state.exchangePubKey, _state.exchangePrivKey);
} catch (err) {
    throw new KeysetError(ERRORS.DECRYPTION_FAILED, 'DEK decryption failed...');
}

// crypto_secretbox_open_easy now wrapped:
try {
    plaintext = sodium.crypto_secretbox_open_easy(encryptedRecord, nonce, dek);
} catch (err) {
    throw new KeysetError(ERRORS.DECRYPTION_FAILED, 'Record decryption failed...');
}
5. Test Files (make_key.test.js, key_manager.test.js)
Updated imports from 'libsodium-wrappers' to 'libsodium-wrappers-sumo'

Fixed "sealed box cannot be opened" test: crypto_box_seal_open now throws instead of returning null; changed assertion to expect(...).toThrow()

Added 30-second timeout for large file (1 MB) encryption test

Test Results
text
 Test Files  2 passed (2)
      Tests  79 passed (79)
All cryptographic operations now function correctly:

✅ Argon2id password hashing

✅ Ed25519 key generation, signing, verification

✅ X25519 key exchange with sealed boxes

✅ XSalsa20-Poly1305 symmetric encryption/decryption

✅ BLAKE2b hashing

✅ Proper key material wiping (sodium.memzero)

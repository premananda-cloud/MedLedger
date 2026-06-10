/**
 * key_manager.js — MedLedger Keyset Manager v1.1
 * ─────────────────────────────────────────────────
 * The single client-side module that owns all cryptographic state and
 * operations. Exposes a clean API to the React layer. The only place
 * private keys ever exist in this application.
 *
 * Rules:
 *   - No network I/O. No DOM access. No framework dependencies.
 *   - Private keys never leave this module (public API returns base64 strings only).
 *   - sodium.memzero() on every private key — including on failure paths.
 *   - logoutUser() is always synchronous. No await. No promises.
 *   - assertUnlocked() on every method that uses private keys.
 *   - Sealed boxes for all share encryption. No manual ECDH exposed.
 *
 * Requires: libsodium-wrappers, ./make_key.js
 */

import sodium from 'libsodium-wrappers';
import { deriveKeys } from './make_key.js';

// ─────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────

export class KeysetError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'KeysetError';
        this.code = code;
    }
}

export const ERRORS = {
    NOT_INITIALIZED:   'KEYSET_NOT_INITIALIZED',
    SESSION_LOCKED:    'KEYSET_SESSION_LOCKED',
    DERIVATION_FAILED: 'KEYSET_DERIVATION_FAILED',
    DECRYPTION_FAILED: 'KEYSET_DECRYPTION_FAILED',
    SIGNATURE_INVALID: 'KEYSET_SIGNATURE_INVALID',
    BAD_KEY_FORMAT:    'KEYSET_BAD_KEY_FORMAT',
};

// ─────────────────────────────────────────────────────────────────
// Private State  (module closure — never accessible from outside)
// ─────────────────────────────────────────────────────────────────

let _state = {
    initialized:     false,   // survives logout — no need to re-init
    locked:          true,
    username:        null,

    // Private keys — Uint8Array, wiped on every logout
    signingPrivKey:  null,    // Ed25519, 64 bytes
    exchangePrivKey: null,    // X25519,  32 bytes

    // Public keys — safe to cache; cleared on logout for cleanliness
    signingPubKey:   null,    // Ed25519, 32 bytes
    exchangePubKey:  null,    // X25519,  32 bytes

    // Derived identity
    userIdHex:       null,    // BLAKE2b(signingPubKey, 16) as hex
};

// ─────────────────────────────────────────────────────────────────
// Guards
// ─────────────────────────────────────────────────────────────────

function assertInitialized() {
    if (!_state.initialized) {
        throw new KeysetError(ERRORS.NOT_INITIALIZED, 'Call init() before any other method');
    }
}

function assertUnlocked() {
    assertInitialized();
    if (_state.locked) {
        throw new KeysetError(ERRORS.SESSION_LOCKED, 'Session is locked — call loginUser() first');
    }
}

// ─────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────

/**
 * Canonical JSON serialization for signing.
 *
 * IMPROVEMENT: JSON.stringify() does not guarantee key order, so two objects
 * with the same data but different construction order produce different strings
 * → different signatures. We sort keys recursively to produce a stable,
 * canonical representation that is safe to re-verify on the server.
 *
 * @param {unknown} value
 * @returns {string}
 */
function canonicalJSON(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return JSON.stringify(value);
    }
    const sorted = Object.keys(value)
        .sort()
        .reduce((acc, k) => {
            acc[k] = value[k];
            return acc;
        }, {});
    return JSON.stringify(sorted, (_, v) =>
        v !== null && typeof v === 'object' && !Array.isArray(v)
            ? Object.keys(v).sort().reduce((a, k) => { a[k] = v[k]; return a; }, {})
            : v
    );
}

/**
 * Build the public-keys result object from current state.
 * Shared by createUser and loginUser.
 */
function _publicKeysResult(sigPub, encPub, userIdHex, username) {
    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    return {
        signingPublicKey:  sodium.to_base64(sigPub, enc),
        exchangePublicKey: sodium.to_base64(encPub, enc),
        userIdHex,
        username,
    };
}

// ─────────────────────────────────────────────────────────────────
// Public API — implementations
// ─────────────────────────────────────────────────────────────────

/**
 * Initialize libsodium. Must be called (and awaited) before any other method.
 * Safe to call multiple times — no-ops if already initialized.
 *
 * @returns {Promise<void>}
 */
async function init() {
    if (_state.initialized) return;
    await sodium.ready;
    _state.initialized = true;
}

// ─────────────────────────────────────────────────────────────────

/**
 * Derive keys for a new user. Returns public keys only — does NOT unlock
 * the session. Call loginUser() after successful server registration.
 *
 * @param {string}      username
 * @param {string}      password
 * @param {Uint8Array}  [serverSalt] - Optional 32-byte salt from server
 *
 * @returns {Promise<{
 *   signingPublicKey:  string,   // Base64url, 32 bytes
 *   exchangePublicKey: string,   // Base64url, 32 bytes
 *   userIdHex:         string,   // BLAKE2b hex, 16 bytes → 32 hex chars
 *   username:          string,
 * }>}
 */
async function createUser(username, password, serverSalt = null) {
    assertInitialized();

    let keys;
    try {
        keys = deriveKeys(username, password, serverSalt);
    } catch (err) {
        throw new KeysetError(ERRORS.DERIVATION_FAILED, `Key derivation failed: ${err.message}`);
    }

    const userIdHex = sodium.to_hex(sodium.crypto_generichash(16, keys.signing.publicKey));
    const result    = _publicKeysResult(keys.signing.publicKey, keys.exchange.publicKey, userIdHex, username);

    // Wipe private material immediately — caller will loginUser() separately
    sodium.memzero(keys.signing.privateKey);
    sodium.memzero(keys.exchange.privateKey);

    return result;
}

// ─────────────────────────────────────────────────────────────────

/**
 * Derive keys and unlock the session. Call after successful server
 * authentication (JWT cookie is already set by the server).
 *
 * @param {string}      username
 * @param {string}      password
 * @param {Uint8Array}  [serverSalt] - Same salt used during createUser()
 *
 * @returns {Promise<{
 *   signingPublicKey:  string,
 *   exchangePublicKey: string,
 *   userIdHex:         string,
 *   username:          string,
 * }>}
 */
async function loginUser(username, password, serverSalt = null) {
    assertInitialized();

    let keys;
    try {
        keys = deriveKeys(username, password, serverSalt);
    } catch (err) {
        throw new KeysetError(ERRORS.DERIVATION_FAILED, `Key derivation failed: ${err.message}`);
    }

    _state.locked          = false;
    _state.username        = username;
    _state.signingPrivKey  = keys.signing.privateKey;    // held in memory
    _state.exchangePrivKey = keys.exchange.privateKey;   // held in memory
    _state.signingPubKey   = keys.signing.publicKey;
    _state.exchangePubKey  = keys.exchange.publicKey;
    _state.userIdHex       = sodium.to_hex(
        sodium.crypto_generichash(16, keys.signing.publicKey)
    );

    return _publicKeysResult(
        _state.signingPubKey,
        _state.exchangePubKey,
        _state.userIdHex,
        _state.username
    );
}

// ─────────────────────────────────────────────────────────────────

/**
 * Wipe all private key material and reset session state. SYNCHRONOUS.
 * Must not be made async — key wipe cannot be deferred.
 *
 * Note: _state.initialized is preserved so init() need not be called again.
 * Public keys are also cleared — they are not secret but clearing prevents
 * stale identity from lingering after logout.
 *
 * @returns {void}
 */
function logoutUser() {
    if (_state.signingPrivKey)  sodium.memzero(_state.signingPrivKey);
    if (_state.exchangePrivKey) sodium.memzero(_state.exchangePrivKey);

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
}

// ─────────────────────────────────────────────────────────────────

/**
 * Encrypt a medical record for sharing.
 *
 * Generates a random 256-bit DEK, encrypts the file with XSalsa20-Poly1305,
 * then seals the DEK for the recipient using a sealed box (anonymous sender —
 * the recipient cannot tell who encrypted it from the ciphertext alone).
 *
 * IMPROVEMENT: encryptFor() (from the original spec) has been removed from
 * the public API and its logic is now an internal step inside this function.
 * Having both was redundant and created ambiguity about which to call.
 * All share encryption goes through encryptRecord().
 *
 * Does NOT require an unlocked session — sealed box is public-key-only.
 * The signed share payload (requiring unlock) is produced separately via
 * signPayload().
 *
 * @param {Uint8Array} fileBytes                      - Raw file content
 * @param {string}     recipientExchangePublicKeyB64  - Recipient's X25519 pub key (Base64url)
 *
 * @returns {{
 *   encryptedRecord: string,   // Base64url — XSalsa20-Poly1305 ciphertext
 *   nonce:           string,   // Base64url — 24-byte nonce
 *   dekBundle:       string,   // Base64url — sealed DEK (recipient opens with their priv key)
 *   fileHash:        string,   // Hex       — BLAKE2b-256(plaintext) for integrity check
 * }}
 */
function encryptRecord(fileBytes, recipientExchangePublicKeyB64) {
    assertInitialized();

    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;

    const recipientPubKey = sodium.from_base64(recipientExchangePublicKeyB64, enc);

    // 1. Random DEK (256-bit)
    const dek   = sodium.randombytes_buf(32);
    // 2. Random nonce (192-bit / 24 bytes — XSalsa20 requirement)
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

    // 3. Encrypt file
    const encrypted = sodium.crypto_secretbox_easy(fileBytes, nonce, dek);

    // 4. Integrity hash of plaintext
    const fileHash = sodium.to_hex(sodium.crypto_generichash(32, fileBytes));

    // 5. Seal DEK for recipient (anonymous sender / sealed box)
    const dekBundle = sodium.crypto_box_seal(dek, recipientPubKey);

    // 6. Wipe DEK — must happen before return
    sodium.memzero(dek);

    return {
        encryptedRecord: sodium.to_base64(encrypted, enc),
        nonce:           sodium.to_base64(nonce,     enc),
        dekBundle:       sodium.to_base64(dekBundle, enc),
        fileHash,
    };
}

// ─────────────────────────────────────────────────────────────────

/**
 * Decrypt a received share. Session must be unlocked.
 *
 * IMPROVEMENT: The original spec's implementation could leak the DEK if
 * the second crypto call threw — memzero would never run. We now use
 * try/finally to guarantee the DEK is wiped regardless of outcome.
 *
 * @param {string} encryptedRecordB64  - Base64url ciphertext
 * @param {string} nonceB64            - Base64url 24-byte nonce
 * @param {string} dekBundleB64        - Base64url sealed DEK bundle
 *
 * @returns {Uint8Array} Decrypted plaintext bytes
 *
 * @throws {KeysetError} if session is locked, DEK decryption fails, or
 *                        record authentication fails (tampered ciphertext)
 */
function decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) {
    assertUnlocked();

    const enc           = sodium.base64_variants.URLSAFE_NO_PADDING;
    const encryptedRecord = sodium.from_base64(encryptedRecordB64, enc);
    const nonce           = sodium.from_base64(nonceB64,           enc);
    const dekBundle       = sodium.from_base64(dekBundleB64,       enc);

    // 1. Open sealed DEK — requires our exchange keypair
    const dek = sodium.crypto_box_seal_open(
        dekBundle,
        _state.exchangePubKey,
        _state.exchangePrivKey
    );

    if (!dek) {
        throw new KeysetError(
            ERRORS.DECRYPTION_FAILED,
            'DEK decryption failed — wrong recipient key or tampered DEK bundle'
        );
    }

    // 2. Decrypt record — wipe DEK in finally regardless of success or failure
    let plaintext;
    try {
        plaintext = sodium.crypto_secretbox_open_easy(encryptedRecord, nonce, dek);
        if (!plaintext) {
            throw new KeysetError(
                ERRORS.DECRYPTION_FAILED,
                'Record decryption failed — ciphertext may be tampered'
            );
        }
    } finally {
        // IMPROVEMENT: DEK is always wiped, even if decryption throws.
        // In the original spec this memzero was at the end and would be
        // skipped on any thrown error, leaving the DEK in memory.
        sodium.memzero(dek);
    }

    return plaintext;
}

// ─────────────────────────────────────────────────────────────────

/**
 * Sign a JSON-serializable payload with the session's Ed25519 private key.
 * Session must be unlocked.
 *
 * IMPROVEMENT: Payload is serialized with canonicalJSON() (recursive key sort)
 * before signing. The original spec used JSON.stringify() directly, which does
 * not guarantee key order — the same object built differently in two places
 * would produce a different byte string and therefore a different signature,
 * causing server-side verification failures.
 *
 * @param {object} payloadObject - JSON-serializable object
 *
 * @returns {{
 *   payload:        object,   // Original payload (unchanged)
 *   payloadCanon:   string,   // The canonical JSON string that was signed
 *   signature:      string,   // Base64url Ed25519 signature (64 bytes)
 * }}
 */
function signPayload(payloadObject) {
    assertUnlocked();

    const payloadCanon = canonicalJSON(payloadObject);
    const payloadBytes = sodium.from_string(payloadCanon);
    const signature    = sodium.crypto_sign_detached(payloadBytes, _state.signingPrivKey);

    return {
        payload:      payloadObject,
        payloadCanon,
        signature: sodium.to_base64(signature, sodium.base64_variants.URLSAFE_NO_PADDING),
    };
}

// ─────────────────────────────────────────────────────────────────

/**
 * Verify an Ed25519 signature. Does NOT require an unlocked session.
 *
 * IMPORTANT: The server must use canonicalJSON() (sorted keys) when
 * reconstructing the signed payload for verification, matching signPayload().
 * If payloadCanon is provided (returned from signPayload), use that directly
 * instead of re-serializing.
 *
 * @param {object|string} payloadOrCanon  - Original object or pre-canonicalized string
 * @param {string}        signatureB64    - Base64url signature
 * @param {string}        signerPubKeyB64 - Base64url Ed25519 public key
 *
 * @returns {boolean}
 */
function verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64) {
    assertInitialized();

    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;

    const payloadStr   = typeof payloadOrCanon === 'string'
        ? payloadOrCanon
        : canonicalJSON(payloadOrCanon);
    const payloadBytes = sodium.from_string(payloadStr);
    const signature    = sodium.from_base64(signatureB64,   enc);
    const pubKey       = sodium.from_base64(signerPubKeyB64, enc);

    return sodium.crypto_sign_verify_detached(signature, payloadBytes, pubKey);
}

// ─────────────────────────────────────────────────────────────────

/**
 * Get the current session's public keys. Session must be unlocked.
 *
 * @returns {{
 *   signingPublicKey:  string,  // Base64url
 *   exchangePublicKey: string,  // Base64url
 *   userIdHex:         string,  // BLAKE2b hex
 *   username:          string,
 * }}
 */
function getPublicKeys() {
    assertUnlocked();
    return _publicKeysResult(
        _state.signingPubKey,
        _state.exchangePubKey,
        _state.userIdHex,
        _state.username
    );
}

// ─────────────────────────────────────────────────────────────────
// Public API — exported object
// ─────────────────────────────────────────────────────────────────

export const KeysetManager = {
    init,
    createUser,
    loginUser,
    logoutUser,
    encryptRecord,
    decryptShare,
    signPayload,
    verifySignature,
    getPublicKeys,
    isLocked: () => _state.locked,
};

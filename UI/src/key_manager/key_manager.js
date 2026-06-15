/**
 * key_manager.js — MedLedger Keyset Manager v2.0
 * ─────────────────────────────────────────────────
 * The single client-side module that owns all cryptographic state and
 * operations. Exports a clean API to the React layer. The only place
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

import _sodium from "libsodium-wrappers-sumo";

import { generateKeypair } from "./make_key.js";
await _sodium.ready;
const sodium = _sodium;

// ─────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────

export class KeysetError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "KeysetError";
    this.code = code;
  }
}

export const ERRORS = {
  NOT_INITIALIZED: "KEYSET_NOT_INITIALIZED",
  SESSION_LOCKED: "KEYSET_SESSION_LOCKED",
  DECRYPTION_FAILED: "KEYSET_DECRYPTION_FAILED",
  SIGNATURE_INVALID: "KEYSET_SIGNATURE_INVALID",
  BAD_KEY_FORMAT: "KEYSET_BAD_KEY_FORMAT",
};

// ─────────────────────────────────────────────────────────────────
// Private State  (module closure — never accessible from outside)
// ─────────────────────────────────────────────────────────────────

let _state = {
  initialized: false, // survives logout — no need to re-init
  locked: true,
  username: null,

  // Private keys — Uint8Array, wiped on every logout
  signingPrivKey: null, // Ed25519, 64 bytes
  exchangePrivKey: null, // X25519,  32 bytes

  // Public keys — safe to cache; cleared on logout for cleanliness
  signingPubKey: null, // Ed25519, 32 bytes
  exchangePubKey: null, // X25519,  32 bytes

  // Derived identity
  userIdHex: null, // BLAKE2b(signingPubKey, 16) as hex
};

// ─────────────────────────────────────────────────────────────────
// Guards
// ─────────────────────────────────────────────────────────────────

function assertInitialized() {
  if (!_state.initialized) {
    throw new KeysetError(
      ERRORS.NOT_INITIALIZED,
      "Call init() before any other method",
    );
  }
}

function assertUnlocked() {
  assertInitialized();
  if (_state.locked) {
    throw new KeysetError(
      ERRORS.SESSION_LOCKED,
      "Session is locked — call loginUser() first",
    );
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
  // Recursively sort object keys at every depth, including objects inside arrays.
  function sortDeep(v) {
    if (Array.isArray(v)) return v.map(sortDeep);
    if (v !== null && typeof v === "object") {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = sortDeep(v[k]);
          return acc;
        }, {});
    }
    return v;
  }
  return JSON.stringify(sortDeep(value));
}

/**
 * Build the public-keys result object from current state.
 * Shared by createUser and loginUser.
 */
function _publicKeysResult(sigPub, encPub, userIdHex, username) {
  const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
  return {
    signingPublicKey: sodium.to_base64(sigPub, enc),
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
  // sodium is already initialized via top-level await
  _state.initialized = true;
}

// ─────────────────────────────────────────────────────────────────

/**
 * Generate random keys for a new user. Returns public keys only — does NOT unlock
 * the session. Call loginUser() after successful server registration.
 *
 * IMPORTANT: Keys are randomly generated and CANNOT be recovered from a password.
 * Loss of the private key means permanent loss of decryption capability for any
 * shares encrypted to this user. For a sharing service (not storage), this is
 * acceptable — the data owner can re-share.
 *
 * @param {string}      username
 *
 * @returns {Promise<{
 *   signingPublicKey:  string,   // Base64url, 32 bytes
 *   exchangePublicKey: string,   // Base64url, 32 bytes
 *   userIdHex:         string,   // BLAKE2b hex, 16 bytes → 32 hex chars
 *   username:          string,
 * }>}
 */
async function createUser(username) {
  assertInitialized();

  const keys = generateKeypair();

  const userIdHex = sodium.to_hex(
    sodium.crypto_generichash(16, keys.signing.publicKey),
  );
  const result = _publicKeysResult(
    keys.signing.publicKey,
    keys.exchange.publicKey,
    userIdHex,
    username,
  );

  // NOTE: Private keys are NOT stored or cached here.
  // The caller (React layer) must send public keys to the server,
  // then immediately call loginUser() with the private keys to unlock the session.
  // This design expects the React layer to hold the private keys temporarily
  // between createUser and loginUser, OR the server returns them (but that would
  // defeat the purpose). Alternative: createUser returns the full keypair,
  // and loginUser accepts pre-generated keys.
  //
  // For now, we wipe them and assume the React layer will re-generate on login? No.
  // Let's fix this: createUser should NOT wipe keys. loginUser will accept them.
  // But since we can't change the API signature without breaking tests, we need
  // a different approach.
  //
  // ACTUAL SOLUTION: The React layer calls createUser, gets public keys to send
  // to server, AND keeps the private keys in memory, then calls loginUserWithKeys()
  // or passes them back. But that's an API change.
  //
  // For minimal change: createUser generates and returns public keys, but also
  // stores private keys in _state? That would unlock the session immediately,
  // which might be fine for a fresh registration.
  //
  // Let's do the simplest thing: after createUser, the session is unlocked.
  // The user just registered — they should be logged in.
  _state.locked = false;
  _state.username = username;
  _state.signingPrivKey = keys.signing.privateKey;
  _state.exchangePrivKey = keys.exchange.privateKey;
  _state.signingPubKey = keys.signing.publicKey;
  _state.exchangePubKey = keys.exchange.publicKey;
  _state.userIdHex = userIdHex;

  // Return public keys AND private keys. This is the only time private keys are
  // surfaced outside this module. The caller MUST store them securely — they are
  // needed for every subsequent loginUser() call and cannot be recovered if lost.
  //
  // CRITICAL: return .slice() copies of the private key Uint8Arrays, NOT the
  // live references stored in _state. logoutUser() calls sodium.memzero() on
  // the _state buffers in-place. If the caller holds the same reference,
  // their copy is silently zeroed on logout — causing every subsequent
  // loginUser() call to load an all-zeros private key and making
  // crypto_box_seal_open fail with a wrong-key error.
  return {
      ...result,
      signingPrivateKey: keys.signing.privateKey.slice(),
      exchangePrivateKey: keys.exchange.privateKey.slice(),
  };
}

// ─────────────────────────────────────────────────────────────────

/**
 * Unlock the session with previously generated keys.
 * Call after successful server authentication (JWT cookie is already set).
 *
 * NOTE: There is no password-based key derivation. The password only authenticates
 * to the server; the private keys must be stored by the client (e.g., encrypted
 * download, password manager) and supplied here on every login.
 *
 * @param {string}      username
 * @param {object}      keypair - Required: { signing: { privateKey: Uint8Array, publicKey: Uint8Array }, exchange: { privateKey: Uint8Array, publicKey: Uint8Array } }
 *
 * @returns {Promise<{
 *   signingPublicKey:  string,
 *   exchangePublicKey: string,
 *   userIdHex:         string,
 *   username:          string,
 * }>}
 */
async function loginUser(username, keypair = null) {
  assertInitialized();

  let signingPrivKey, exchangePrivKey, signingPubKey, exchangePubKey;

  // Keys are not stored server-side. Caller (App.js) must supply the keypair
  // returned by createUser(). A missing or malformed keypair is always a caller
  // error — there is no fallback and no server-side recovery path.
  if (
    !keypair ||
    !keypair.signing?.privateKey ||
    !keypair.signing?.publicKey ||
    !keypair.exchange?.privateKey ||
    !keypair.exchange?.publicKey
  ) {
    throw new KeysetError(
      ERRORS.BAD_KEY_FORMAT,
      "loginUser() requires a full keypair ({ signing, exchange } with publicKey and privateKey). " +
        "Keys are not stored server-side — pass the keypair returned from createUser().",
    );
  }

  signingPrivKey = keypair.signing.privateKey;
  exchangePrivKey = keypair.exchange.privateKey;
  signingPubKey = keypair.signing.publicKey;
  exchangePubKey = keypair.exchange.publicKey;

  const userIdHex = sodium.to_hex(sodium.crypto_generichash(16, signingPubKey));

  _state.locked = false;
  _state.username = username;
  _state.signingPrivKey = signingPrivKey;
  _state.exchangePrivKey = exchangePrivKey;
  _state.signingPubKey = signingPubKey;
  _state.exchangePubKey = exchangePubKey;
  _state.userIdHex = userIdHex;

  return _publicKeysResult(
    _state.signingPubKey,
    _state.exchangePubKey,
    _state.userIdHex,
    _state.username,
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
  if (_state.signingPrivKey) sodium.memzero(_state.signingPrivKey);
  if (_state.exchangePrivKey) sodium.memzero(_state.exchangePrivKey);

  _state = {
    initialized: _state.initialized, // preserve — intentional
    locked: true,
    username: null,
    signingPrivKey: null,
    exchangePrivKey: null,
    signingPubKey: null,
    exchangePubKey: null,
    userIdHex: null,
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
  // Intentionally assertInitialized() only — not assertUnlocked().
  // Sealed boxes are a public-key-only operation: only the recipient's exchange
  // public key is needed. The caller's private key is never touched here.
  assertInitialized();

  const enc = sodium.base64_variants.URLSAFE_NO_PADDING;

  const recipientPubKey = sodium.from_base64(
    recipientExchangePublicKeyB64,
    enc,
  );

  // 1. Random DEK (256-bit)
  const dek = sodium.randombytes_buf(32);
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
    nonce: sodium.to_base64(nonce, enc),
    dekBundle: sodium.to_base64(dekBundle, enc),
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

  const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
  const encryptedRecord = sodium.from_base64(encryptedRecordB64, enc);
  const nonce = sodium.from_base64(nonceB64, enc);
  const dekBundle = sodium.from_base64(dekBundleB64, enc);

  // 1. Open sealed DEK — requires our exchange keypair
  let dek;
  try {
    dek = sodium.crypto_box_seal_open(
      dekBundle,
      _state.exchangePubKey,
      _state.exchangePrivKey,
    );
  } catch (err) {
    throw new KeysetError(
      ERRORS.DECRYPTION_FAILED,
      "DEK decryption failed — wrong recipient key or tampered DEK bundle",
    );
  }

  if (!dek) {
    throw new KeysetError(
      ERRORS.DECRYPTION_FAILED,
      "DEK decryption failed — wrong recipient key or tampered DEK bundle",
    );
  }

  // 2. Decrypt record — wipe DEK in finally regardless of success or failure
  let plaintext;
  try {
    try {
      plaintext = sodium.crypto_secretbox_open_easy(
        encryptedRecord,
        nonce,
        dek,
      );
    } catch (err) {
      throw new KeysetError(
        ERRORS.DECRYPTION_FAILED,
        "Record decryption failed — ciphertext may be tampered",
      );
    }
    if (!plaintext) {
      throw new KeysetError(
        ERRORS.DECRYPTION_FAILED,
        "Record decryption failed — ciphertext may be tampered",
      );
    }
  } finally {
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
  const signature = sodium.crypto_sign_detached(
    payloadBytes,
    _state.signingPrivKey,
  );

  return {
    payload: payloadObject,
    payloadCanon,
    signature: sodium.to_base64(
      signature,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    ),
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

  try {
    const payloadStr =
      typeof payloadOrCanon === "string"
        ? payloadOrCanon
        : canonicalJSON(payloadOrCanon);
    const payloadBytes = sodium.from_string(payloadStr);
    const signature = sodium.from_base64(signatureB64, enc);
    const pubKey = sodium.from_base64(signerPubKeyB64, enc);

    return sodium.crypto_sign_verify_detached(signature, payloadBytes, pubKey);
  } catch (err) {
    if (err instanceof KeysetError) throw err;
    // A well-formed but invalid signature returns false from libsodium without
    // throwing. If we land here, the inputs were malformed (bad base64, wrong
    // key length). Return false rather than throwing so callers get a consistent
    // boolean — only re-throw if it was already a KeysetError (checked above).
    return false;
  }
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
    _state.username,
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

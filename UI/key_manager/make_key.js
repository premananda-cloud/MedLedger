/**
 * make_key.js — MedLedger Key Derivation
 * ────────────────────────────────────────
 * Single responsibility: derive Ed25519 + X25519 keypairs from credentials.
 *
 * Rules:
 *   - No state. No side effects. No network I/O. No DOM access.
 *   - Every private key intermediate is wiped with sodium.memzero() before return.
 *   - Caller is responsible for wiping the returned private key Uint8Arrays when done.
 *   - Only key_manager.js should call this module.
 *
 * Requires: libsodium-wrappers (npm install libsodium-wrappers)
 */

import sodium from 'libsodium-wrappers';

// ─────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────

/**
 * Argon2id parameters.
 *
 * IMPROVEMENT NOTE (vs original spec):
 * The original spec derived the salt entirely from the username via BLAKE2b,
 * making it fully predictable. We now accept an optional serverSalt (32 bytes,
 * fetched from the server at registration/login time and stored publicly in the
 * users table). When provided, it is mixed with the username hash, giving a
 * per-user salt with real entropy and defeating precomputed rainbow tables.
 *
 * If no serverSalt is provided (e.g. offline/test use), we fall back to the
 * deterministic username-derived salt — behaviour is identical to the original
 * spec and the system still works, just with slightly reduced preimage resistance
 * for weak passwords.
 */
const ARGON2_PARAMS = {
    OPSLIMIT:  3,
    MEMLIMIT:  67_108_864,   // 64 MB
    SEED_BYTES: 64,          // split: [0..31] → Ed25519 seed, [32..63] → X25519 seed
};

// ─────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────

/**
 * Derive an Ed25519 signing keypair and X25519 exchange keypair from
 * username + password (+ optional server-provided salt).
 *
 * Deterministic: same inputs → same outputs (no randomness in derivation path).
 * All intermediate seeds are wiped with sodium.memzero() before return.
 *
 * @param {string}     username   - Canonical username (trimmed, lowercased internally)
 * @param {string}     password   - User's password (UTF-8)
 * @param {Uint8Array} [serverSalt] - Optional 32-byte random salt from server.
 *                                    If omitted, falls back to deterministic username hash.
 *
 * @returns {{
 *   signing:  { publicKey: Uint8Array, privateKey: Uint8Array },  // Ed25519
 *   exchange: { publicKey: Uint8Array, privateKey: Uint8Array },  // X25519
 * }}
 *
 * @throws {Error} if sodium is not yet ready (call `await sodium.ready` first)
 */
export function deriveKeys(username, password, serverSalt = null) {
    // sodium.ready must already be resolved — this is a sync function by design.
    // The caller (key_manager.js init()) is responsible for awaiting sodium.ready.

    const canonicalUsername = username.toLowerCase().trim();

    // Build salt: BLAKE2b(username) XOR'd with serverSalt if available.
    // This keeps determinism (same username → same base) while adding
    // real entropy from the server when present.
    const usernameSalt = sodium.crypto_generichash(
        16,
        sodium.from_string(canonicalUsername)
    );

    let salt;
    if (serverSalt instanceof Uint8Array && serverSalt.length >= 16) {
        // Mix server salt into the first 16 bytes by XOR.
        // Use the first 16 bytes of serverSalt so Argon2id gets its required
        // crypto_pwhash_SALTBYTES (16) while the server can store 32 bytes.
        salt = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            salt[i] = usernameSalt[i] ^ serverSalt[i];
        }
    } else {
        salt = usernameSalt;
    }

    // Argon2id: stretch password into 64-byte master seed
    const seed = sodium.crypto_pwhash(
        ARGON2_PARAMS.SEED_BYTES,
        sodium.from_string(password),
        salt,
        ARGON2_PARAMS.OPSLIMIT,
        ARGON2_PARAMS.MEMLIMIT,
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // Split seed into two 32-byte sub-seeds
    const sigSeed = seed.slice(0, 32);
    const encSeed = seed.slice(32, 64);

    // Derive keypairs from seeds
    const signingKeypair  = sodium.crypto_sign_seed_keypair(sigSeed);
    const exchangeKeypair = sodium.crypto_box_seed_keypair(encSeed);

    // Wipe all intermediate material immediately
    sodium.memzero(seed);
    sodium.memzero(sigSeed);
    sodium.memzero(encSeed);

    // Caller owns the returned private keys and must memzero them when done.
    return {
        signing:  signingKeypair,
        exchange: exchangeKeypair,
    };
}

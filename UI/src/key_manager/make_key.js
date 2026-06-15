/**
 * make_key.js — MedLedger Key Generation
 * ────────────────────────────────────────
 * Single responsibility: generate random Ed25519 + X25519 keypairs.
 *
 * Rules:
 *   - No state. No side effects. No network I/O. No DOM access.
 *   - Every private key is generated randomly (non-derivable).
 *   - Caller is responsible for wiping the returned private key Uint8Arrays when done.
 *   - Only key_manager.js should call this module.
 *
 * Requires: libsodium-wrappers (npm install libsodium-wrappers)
 */

import _sodium from "libsodium-wrappers-sumo";

await _sodium.ready;
const sodium = _sodium;

// ─────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────

/**
 * Generate a random Ed25519 signing keypair and X25519 exchange keypair.
 *
 * Non-deterministic: each call produces a fresh, cryptographically random
 * keypair. Cannot be recovered from a password — user is responsible for
 * key backup or accepts that lost keys mean lost access.
 *
 * @returns {{
 *   signing:  { publicKey: Uint8Array, privateKey: Uint8Array },  // Ed25519
 *   exchange: { publicKey: Uint8Array, privateKey: Uint8Array },  // X25519
 * }}
 */
export function generateKeypair() {
  // Generate fresh random Ed25519 signing keypair
  const signingKeypair = sodium.crypto_sign_keypair();

  // Generate fresh random X25519 exchange keypair
  const exchangeKeypair = sodium.crypto_box_keypair();

  // Caller owns the returned private keys and must memzero them when done.
  return {
    signing: {
      publicKey: signingKeypair.publicKey,
      privateKey: signingKeypair.privateKey,
    },
    exchange: {
      publicKey: exchangeKeypair.publicKey,
      privateKey: exchangeKeypair.privateKey,
    },
  };
}

/**
 * key_backup.js — MedLedger key bundle encrypt/decrypt.
 *
 * Produces and consumes the .mledger file format:
 *
 * ┌──────────────────────────────────────────────────────┐
 * │ Offset │ Len │ Field                                 │
 * ├──────────────────────────────────────────────────────┤
 * │   0    │  4  │ Magic: 'MLED' (0x4d 0x4c 0x45 0x44) │
 * │   4    │  1  │ Version: 0x01                         │
 * │   5    │ 16  │ Argon2id salt (random)                │
 * │  21    │ 24  │ XSalsa20-Poly1305 nonce (random)      │
 * │  45    │144  │ Ciphertext (128 plaintext + 16 MAC)   │
 * └──────────────────────────────────────────────────────┘
 * Total: 189 bytes
 *
 * Plaintext layout (128 bytes):
 *   [0..63]   signing.privateKey  (Ed25519, 64 bytes)
 *   [64..95]  signing.publicKey   (Ed25519, 32 bytes)
 *   [96..127] exchange.privateKey (X25519,  32 bytes)
 *
 * Key derivation: Argon2id (INTERACTIVE params) with passphrase + salt
 *   → 32-byte symmetric key for crypto_secretbox_easy.
 *
 * The public key is embedded so decryptBundleToKeypair can return it
 * without re-derivation (avoids a libsodium call on the hot unlock path).
 *
 * Rules:
 *   - No network I/O. No DOM access. No state.
 *   - All derived key material is wiped with sodium.memzero() before return.
 *   - Throws named errors for all failure cases — callers must not swallow.
 */

import _sodium from 'libsodium-wrappers-sumo';

await _sodium.ready;
const sodium = _sodium;

// ─── Constants ────────────────────────────────────────────────────────────────

const MAGIC = new Uint8Array([0x4d, 0x4c, 0x45, 0x44]); // 'MLED'
const VERSION = 0x01;

const OFFSET_MAGIC   = 0;
const OFFSET_VERSION = 4;
const OFFSET_SALT    = 5;
const OFFSET_NONCE   = 21;  // 5 + 16
const OFFSET_CIPHER  = 45;  // 5 + 16 + 24

const LEN_MAGIC   = 4;
const LEN_VERSION = 1;
const LEN_SALT    = 16;  // crypto_pwhash_SALTBYTES
const LEN_NONCE   = 24;  // crypto_secretbox_NONCEBYTES
const LEN_HEADER  = LEN_MAGIC + LEN_VERSION + LEN_SALT + LEN_NONCE; // 45

const LEN_SIG_PRIV  = 64;
const LEN_SIG_PUB   = 32;
const LEN_EXCH_PRIV = 32;
const LEN_PLAINTEXT = LEN_SIG_PRIV + LEN_SIG_PUB + LEN_EXCH_PRIV; // 128

const LEN_MAC       = 16;  // crypto_secretbox_MACBYTES
const LEN_CIPHER    = LEN_PLAINTEXT + LEN_MAC; // 144
const LEN_BUNDLE    = LEN_HEADER + LEN_CIPHER; // 189

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * encryptKeypairToBundle(keypair, passphrase)
 *
 * Encrypts a keypair to a 189-byte .mledger bundle.
 *
 * @param {{ signing: { privateKey: Uint8Array, publicKey: Uint8Array },
 *            exchange: { privateKey: Uint8Array } }} keypair
 * @param {string} passphrase
 * @returns {Uint8Array} 189-byte bundle
 * @throws if key lengths are wrong
 */
export function encryptKeypairToBundle(keypair, passphrase) {
  // ── Validate ────────────────────────────────────────────────────────────────
  if (keypair.signing.privateKey.length !== LEN_SIG_PRIV) {
    throw new Error(
      `signing.privateKey must be 64 bytes, got ${keypair.signing.privateKey.length}`
    );
  }
  if (keypair.exchange.privateKey.length !== LEN_EXCH_PRIV) {
    throw new Error(
      `exchange.privateKey must be 32 bytes, got ${keypair.exchange.privateKey.length}`
    );
  }

  // ── Random salt + nonce ─────────────────────────────────────────────────────
  const salt  = sodium.randombytes_buf(LEN_SALT);
  const nonce = sodium.randombytes_buf(LEN_NONCE);

  // ── Derive symmetric key via Argon2id ────────────────────────────────────────
  let symKey;
  try {
    symKey = sodium.crypto_pwhash(
      32,
      passphrase,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } catch (err) {
    throw new Error(`Key derivation failed: ${err.message}`);
  }

  // ── Build plaintext: sigPriv || sigPub || exchPriv ───────────────────────────
  const plaintext = new Uint8Array(LEN_PLAINTEXT);
  plaintext.set(keypair.signing.privateKey,  0);
  plaintext.set(keypair.signing.publicKey,   LEN_SIG_PRIV);
  plaintext.set(keypair.exchange.privateKey, LEN_SIG_PRIV + LEN_SIG_PUB);

  // ── Encrypt ──────────────────────────────────────────────────────────────────
  let ciphertext;
  try {
    ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, symKey);
  } finally {
    sodium.memzero(symKey);
    sodium.memzero(plaintext);
  }

  // ── Assemble bundle ──────────────────────────────────────────────────────────
  const bundle = new Uint8Array(LEN_BUNDLE);
  bundle.set(MAGIC,      OFFSET_MAGIC);
  bundle[OFFSET_VERSION] = VERSION;
  bundle.set(salt,       OFFSET_SALT);
  bundle.set(nonce,      OFFSET_NONCE);
  bundle.set(ciphertext, OFFSET_CIPHER);

  return bundle;
}

/**
 * decryptBundleToKeypair(bundle, passphrase)
 *
 * Decrypts a 189-byte .mledger bundle and returns the keypair.
 * Returns only private keys — caller re-derives public keys if needed,
 * or uses the embedded signing public key directly.
 *
 * @param {Uint8Array} bundle
 * @param {string}     passphrase
 * @returns {{ signing:  { privateKey: Uint8Array, publicKey: Uint8Array },
 *             exchange: { privateKey: Uint8Array } }}
 * @throws INVALID_BUNDLE — bad magic, wrong version, wrong length
 * @throws WRONG_PASSPHRASE — decryption failed (wrong passphrase or tampered)
 */
export function decryptBundleToKeypair(bundle, passphrase) {
  // ── Structural checks ────────────────────────────────────────────────────────
  if (!(bundle instanceof Uint8Array) || bundle.length !== LEN_BUNDLE) {
    throw new Error(`INVALID_BUNDLE: expected ${LEN_BUNDLE} bytes, got ${bundle?.length}`);
  }

  // Magic
  for (let i = 0; i < LEN_MAGIC; i++) {
    if (bundle[OFFSET_MAGIC + i] !== MAGIC[i]) {
      throw new Error('INVALID_BUNDLE: wrong magic bytes');
    }
  }

  // Version
  if (bundle[OFFSET_VERSION] !== VERSION) {
    throw new Error(`INVALID_BUNDLE: unsupported version 0x${bundle[OFFSET_VERSION].toString(16).padStart(2,'0')}`);
  }

  // ── Extract fields ───────────────────────────────────────────────────────────
  const salt       = bundle.slice(OFFSET_SALT,   OFFSET_SALT   + LEN_SALT);
  const nonce      = bundle.slice(OFFSET_NONCE,  OFFSET_NONCE  + LEN_NONCE);
  const ciphertext = bundle.slice(OFFSET_CIPHER, OFFSET_CIPHER + LEN_CIPHER);

  // ── Derive key ───────────────────────────────────────────────────────────────
  let symKey;
  try {
    symKey = sodium.crypto_pwhash(
      32,
      passphrase,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } catch (err) {
    throw new Error(`INVALID_BUNDLE: key derivation failed: ${err.message}`);
  }

  // ── Decrypt ──────────────────────────────────────────────────────────────────
  let plaintext;
  try {
    plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, symKey);
  } catch (_) {
    // libsodium throws on MAC failure
    throw new Error('WRONG_PASSPHRASE: decryption failed');
  } finally {
    sodium.memzero(symKey);
  }

  if (!plaintext || plaintext.length !== LEN_PLAINTEXT) {
    throw new Error('WRONG_PASSPHRASE: decryption produced wrong output');
  }

  // ── Slice out key material ───────────────────────────────────────────────────
  const signingPrivKey  = plaintext.slice(0,                          LEN_SIG_PRIV);
  const signingPubKey   = plaintext.slice(LEN_SIG_PRIV,               LEN_SIG_PRIV + LEN_SIG_PUB);
  const exchangePrivKey = plaintext.slice(LEN_SIG_PRIV + LEN_SIG_PUB, LEN_PLAINTEXT);

  // Wipe intermediate plaintext buffer — slices above are independent copies
  sodium.memzero(plaintext);

  return {
    signing: {
      privateKey: signingPrivKey,
      publicKey:  signingPubKey,
    },
    exchange: {
      privateKey: exchangePrivKey,
    },
  };
}

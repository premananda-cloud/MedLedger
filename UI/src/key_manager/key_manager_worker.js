/**
 * key_manager_worker.js — MedLedger SharedWorker
 * ─────────────────────────────────────────────────
 * Runs as a SharedWorker. Private keys NEVER leave this context.
 * The main thread communicates only via postMessage, receiving back
 * base64 strings and booleans — never raw key material.
 *
 * SharedWorker: one instance is shared across all tabs of the same origin.
 * Locking in one tab locks all tabs. Loading keys in one tab unlocks all.
 *
 * Message protocol (main → worker):
 *   { id: string, cmd: string, args: object }
 *
 * Response (worker → main, success):
 *   { id: string, result: any }
 *
 * Response (worker → main, error):
 *   { id: string, error: { code: string, message: string } }
 *
 * Push event (worker → all ports, no id):
 *   { event: "locked", reason: string }
 *
 * Supported commands:
 *   init()
 *   createUser(username)                        → { publicKeys, bundleB64 } *
 *   loadAndUnlock(username, bundleB64, passphrase) → publicKeys
 *   logout()                                    → void
 *   isLocked()                                  → boolean
 *   getPublicKeys()                             → publicKeys
 *   encryptRecord(fileBytesB64, recipientExchangePubKeyB64) → encryptedPackage
 *   decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) → fileBytesB64
 *   signPayload(payloadObject)                  → { payload, payloadCanon, signature }
 *   verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64) → boolean
 *   setAutoLockMs(ms)                           → void
 *
 * * createUser returns bundleB64 — the Argon2id-encrypted keypair file — so the
 *   main thread can offer it for download. Private keys never cross the boundary.
 */

import _sodium from "libsodium-wrappers-sumo";
import { KeysetManager, KeysetError } from "./key_manager.js";
import { encryptKeypairToBundle } from "./key_backup.js";

// ─────────────────────────────────────────────────────────────────
// Port registry — SharedWorker can have many connected tabs
// ─────────────────────────────────────────────────────────────────

const ports = new Set();

function broadcast(message) {
  for (const port of ports) {
    port.postMessage(message);
  }
}

// ─────────────────────────────────────────────────────────────────
// Auto-lock timer — lives in the Worker, not in React
// ─────────────────────────────────────────────────────────────────

let _autoLockMs = 15 * 60 * 1000; // default 15 minutes
let _lockTimer = null;

function resetLockTimer() {
  if (_lockTimer !== null) clearTimeout(_lockTimer);
  if (KeysetManager.isLocked()) return;
  _lockTimer = setTimeout(() => {
    KeysetManager.logoutUser();
    broadcast({ event: "locked", reason: "inactivity" });
  }, _autoLockMs);
}

function cancelLockTimer() {
  if (_lockTimer !== null) {
    clearTimeout(_lockTimer);
    _lockTimer = null;
  }
}

// ─────────────────────────────────────────────────────────────────
// Command handlers
// ─────────────────────────────────────────────────────────────────

const handlers = {
  async init() {
    await KeysetManager.init();
    return null;
  },

  /**
   * Create a new user. Returns public keys AND the encrypted keypair bundle
   * as a base64 string for download — private keys stay in the Worker.
   *
   * The caller must pass a passphrase used to encrypt the bundle file.
   * The same passphrase is required on every subsequent loadAndUnlock().
   */
  async createUser({ username, passphrase }) {
    const result = await KeysetManager.createUser(username);

    // Build keypair object for key_backup (private keys from createUser result)
    const keypair = {
      signing: { privateKey: result.signingPrivateKey },
      exchange: { privateKey: result.exchangePrivateKey },
    };

    let bundleBytes;
    try {
      bundleBytes = encryptKeypairToBundle(keypair, passphrase);
    } finally {
      // Wipe the private key copies returned by createUser
      _sodium.memzero(result.signingPrivateKey);
      _sodium.memzero(result.exchangePrivateKey);
    }

    const bundleB64 = _sodium.to_base64(
      bundleBytes,
      _sodium.base64_variants.URLSAFE_NO_PADDING,
    );

    resetLockTimer();

    // Return public identity + encrypted bundle for download
    // Private keys are NOT in this result
    return {
      signingPublicKey: result.signingPublicKey,
      exchangePublicKey: result.exchangePublicKey,
      userIdHex: result.userIdHex,
      username: result.username,
      bundleB64,
    };
  },

  /**
   * Decrypt the keypair bundle and unlock the session.
   * bundleB64 comes from the file the user uploads — it was downloaded at
   * createUser time. Private keys are decrypted inside the Worker.
   */
  async loadAndUnlock({ username, bundleB64, passphrase }) {
    const { decryptBundleToKeypair } = await import("./key_backup.js");

    const bundleBytes = _sodium.from_base64(
      bundleB64,
      _sodium.base64_variants.URLSAFE_NO_PADDING,
    );

    // Decrypt inside Worker — private keys never go to main thread
    const partialKeypair = decryptBundleToKeypair(bundleBytes, passphrase);

    // Re-derive public keys from private keys
    const signingPubKey = _sodium.crypto_sign_ed25519_sk_to_pk(
      partialKeypair.signing.privateKey,
    );
    const exchangePubKey = _sodium.crypto_scalarmult_base(
      partialKeypair.exchange.privateKey,
    );

    const fullKeypair = {
      signing: {
        privateKey: partialKeypair.signing.privateKey,
        publicKey: signingPubKey,
      },
      exchange: {
        privateKey: partialKeypair.exchange.privateKey,
        publicKey: exchangePubKey,
      },
    };

    let publicKeys;
    try {
      publicKeys = await KeysetManager.loginUser(username, fullKeypair);
    } finally {
      _sodium.memzero(partialKeypair.signing.privateKey);
      _sodium.memzero(partialKeypair.exchange.privateKey);
    }

    resetLockTimer();
    return publicKeys;
  },

  logout() {
    KeysetManager.logoutUser();
    cancelLockTimer();
    return null;
  },

  isLocked() {
    return KeysetManager.isLocked();
  },

  getPublicKeys() {
    return KeysetManager.getPublicKeys();
  },

  encryptRecord({ fileBytesB64, recipientExchangePubKeyB64 }) {
    const fileBytes = _sodium.from_base64(
      fileBytesB64,
      _sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    const result = KeysetManager.encryptRecord(fileBytes, recipientExchangePubKeyB64);
    resetLockTimer();
    return result;
  },

  decryptShare({ encryptedRecordB64, nonceB64, dekBundleB64 }) {
    const plaintext = KeysetManager.decryptShare(
      encryptedRecordB64,
      nonceB64,
      dekBundleB64,
    );
    const fileBytesB64 = _sodium.to_base64(
      plaintext,
      _sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    resetLockTimer();
    return { fileBytesB64 };
  },

  signPayload({ payloadObject }) {
    const result = KeysetManager.signPayload(payloadObject);
    resetLockTimer();
    return result;
  },

  verifySignature({ payloadOrCanon, signatureB64, signerPubKeyB64 }) {
    return KeysetManager.verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64);
  },

  setAutoLockMs({ ms }) {
    if (typeof ms !== "number" || ms < 60_000) {
      throw new Error("autoLockMs must be a number >= 60000 (1 minute)");
    }
    _autoLockMs = ms;
    resetLockTimer();
    return null;
  },
};

// ─────────────────────────────────────────────────────────────────
// Message dispatch
// ─────────────────────────────────────────────────────────────────

async function handleMessage(port, { id, cmd, args }) {
  if (!id || !cmd) return; // malformed, ignore

  try {
    const handler = handlers[cmd];
    if (!handler) {
      port.postMessage({
        id,
        error: { code: "UNKNOWN_COMMAND", message: `Unknown command: ${cmd}` },
      });
      return;
    }

    const result = await handler(args ?? {});
    port.postMessage({ id, result: result ?? null });
  } catch (err) {
    // Serialize KeysetError or generic Error — classes don't survive structured clone
    const code = err instanceof KeysetError ? err.code : "WORKER_ERROR";
    port.postMessage({
      id,
      error: { code, message: err.message ?? String(err) },
    });
  }
}

// ─────────────────────────────────────────────────────────────────
// SharedWorker entry point
// ─────────────────────────────────────────────────────────────────

self.onconnect = (connectEvent) => {
  const port = connectEvent.ports[0];
  ports.add(port);

  port.onmessage = (event) => handleMessage(port, event.data);

  port.onmessageerror = (err) => {
    console.error("[KeyWorker] message error", err);
  };

  // Remove port when tab closes
  port.addEventListener("close", () => {
    ports.delete(port);
  });

  port.start();
};

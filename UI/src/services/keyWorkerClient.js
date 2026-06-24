/**
 * keyWorkerClient.js — Main-thread client for the KeyManager SharedWorker
 * ──────────────────────────────────────────────────────────────────────────
 * This is the ONLY file the rest of the application imports for key operations.
 * Components, hooks, and services never talk to the Worker directly.
 *
 * Provides a promise-based API that mirrors the Worker command surface.
 * Each call:
 *   1. Generates a unique message id
 *   2. Sends { id, cmd, args } to the Worker
 *   3. Returns a Promise that resolves/rejects when the Worker replies with that id
 *
 * Also listens for push events from the Worker (e.g. auto-lock fired) and
 * dispatches them as CustomEvents on window so useKeySession can react.
 *
 * Push events dispatched on window:
 *   "keysession:locked"  — { detail: { reason: string } }
 *
 * Usage:
 *   import { keyWorker } from "@/services/keyWorkerClient";
 *   await keyWorker.init();
 *   const keys = await keyWorker.loadAndUnlock(username, bundleB64, passphrase);
 */

// ─────────────────────────────────────────────────────────────────
// Worker singleton
// ─────────────────────────────────────────────────────────────────

let _worker = null;
let _port = null;

// id → { resolve, reject }
const _pending = new Map();

let _idCounter = 0;
function nextId() {
  return `km_${++_idCounter}_${Date.now()}`;
}

function getPort() {
  if (_port) return _port;

  _worker = new SharedWorker(
    new URL("../key_manager/key_manager_worker.js", import.meta.url),
    { type: "module", name: "key-manager" },
  );

  _port = _worker.port;

  _port.onmessage = (event) => {
    const msg = event.data;

    // Push event (no id) — Worker broadcasting to all tabs
    if (!msg.id && msg.event) {
      handlePushEvent(msg);
      return;
    }

    const pending = _pending.get(msg.id);
    if (!pending) return; // stale or unknown id

    _pending.delete(msg.id);

    if (msg.error) {
      const err = new WorkerKeyError(msg.error.code, msg.error.message);
      pending.reject(err);
    } else {
      pending.resolve(msg.result);
    }
  };

  _port.onmessageerror = (err) => {
    console.error("[keyWorkerClient] message error", err);
  };

  _port.start();
  return _port;
}

function handlePushEvent(msg) {
  if (msg.event === "locked") {
    window.dispatchEvent(
      new CustomEvent("keysession:locked", {
        detail: { reason: msg.reason ?? "unknown" },
      }),
    );
  }
}

// ─────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────

export class WorkerKeyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "WorkerKeyError";
    this.code = code;
  }
}

// ─────────────────────────────────────────────────────────────────
// Core send helper
// ─────────────────────────────────────────────────────────────────

function send(cmd, args = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId();
    _pending.set(id, { resolve, reject });
    getPort().postMessage({ id, cmd, args });
  });
}

// ─────────────────────────────────────────────────────────────────
// Public API — mirrors Worker command surface
// ─────────────────────────────────────────────────────────────────

export const keyWorker = {
  /** Initialize libsodium inside the Worker. Call once on app start. */
  init() {
    return send("init");
  },

  /**
   * Generate a new keypair, encrypt it with passphrase, unlock the session.
   * Returns public keys + bundleB64 (encrypted file for download).
   * Private keys never leave the Worker.
   *
   * @param {string} username
   * @param {string} passphrase
   * @returns {Promise<{
   *   signingPublicKey: string,
   *   exchangePublicKey: string,
   *   userIdHex: string,
   *   username: string,
   *   bundleB64: string,   // base64url — pass to keyFileService.download()
   * }>}
   */
  createUser(username, passphrase) {
    return send("createUser", { username, passphrase });
  },

  /**
   * Decrypt the .medledger bundle and unlock the session.
   * bundleB64 comes from keyFileService.readAsBase64().
   *
   * @param {string} username
   * @param {string} bundleB64   — base64url bytes of the .medledger file
   * @param {string} passphrase
   * @returns {Promise<{
   *   signingPublicKey: string,
   *   exchangePublicKey: string,
   *   userIdHex: string,
   *   username: string,
   * }>}
   */
  loadAndUnlock(username, bundleB64, passphrase) {
    return send("loadAndUnlock", { username, bundleB64, passphrase });
  },

  /**
   * Wipe private keys and lock the session. Synchronous inside the Worker;
   * async here only because postMessage is always async.
   */
  logout() {
    return send("logout");
  },

  /** @returns {Promise<boolean>} */
  isLocked() {
    return send("isLocked");
  },

  /**
   * @returns {Promise<{
   *   signingPublicKey: string,
   *   exchangePublicKey: string,
   *   userIdHex: string,
   *   username: string,
   * }>}
   */
  getPublicKeys() {
    return send("getPublicKeys");
  },

  /**
   * Encrypt a file for a recipient. Does not require an unlocked session.
   *
   * @param {Uint8Array} fileBytes
   * @param {string}     recipientExchangePubKeyB64  — base64url X25519 public key
   * @returns {Promise<{
   *   encryptedRecord: string,
   *   nonce: string,
   *   dekBundle: string,
   *   fileHash: string,
   * }>}
   */
  encryptRecord(fileBytes, recipientExchangePubKeyB64) {
    // Convert Uint8Array to base64 for structured-clone-safe transfer
    // (Uint8Array survives structured clone but this keeps the Worker API uniform)
    const fileBytesB64 = uint8ToBase64(fileBytes);
    return send("encryptRecord", { fileBytesB64, recipientExchangePubKeyB64 });
  },

  /**
   * Decrypt a received share. Session must be unlocked.
   *
   * @param {string} encryptedRecordB64
   * @param {string} nonceB64
   * @param {string} dekBundleB64
   * @returns {Promise<Uint8Array>}  plaintext file bytes
   */
  async decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) {
    const { fileBytesB64 } = await send("decryptShare", {
      encryptedRecordB64,
      nonceB64,
      dekBundleB64,
    });
    return base64ToUint8(fileBytesB64);
  },

  /**
   * Sign a JSON-serializable payload. Session must be unlocked.
   *
   * @param {object} payloadObject
   * @returns {Promise<{ payload: object, payloadCanon: string, signature: string }>}
   */
  signPayload(payloadObject) {
    return send("signPayload", { payloadObject });
  },

  /**
   * Verify an Ed25519 signature. Does not require an unlocked session.
   *
   * @param {object|string} payloadOrCanon
   * @param {string}        signatureB64
   * @param {string}        signerPubKeyB64
   * @returns {Promise<boolean>}
   */
  verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64) {
    return send("verifySignature", {
      payloadOrCanon,
      signatureB64,
      signerPubKeyB64,
    });
  },

  /**
   * Override the auto-lock inactivity timeout.
   * Minimum 60 000 ms (1 minute). Default 900 000 ms (15 minutes).
   *
   * @param {number} ms
   */
  setAutoLockMs(ms) {
    return send("setAutoLockMs", { ms });
  },
};

// ─────────────────────────────────────────────────────────────────
// Base64 helpers (main thread only — no libsodium dependency here)
// ─────────────────────────────────────────────────────────────────

function uint8ToBase64(bytes) {
  // base64url, no padding
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64ToUint8(b64) {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

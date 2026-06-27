/**
 * crypto.js — Bridge to the key_manager SharedWorker.
 *
 * Single point of contact with key_manager_worker.js. Every worker command
 * is wrapped as an async function. Writes to cryptoStore as a side effect.
 * No other file knows the worker exists.
 *
 * Worker message protocol:
 *   Main → Worker:  { id: string, cmd: string, args: object }
 *   Worker → Main:  { id: string, result: any }   (success)
 *                   { id: string, error: { code, message } }  (failure)
 *   Worker push:    { event: 'locked', reason: string }  (no id)
 */

import cryptoStore from '../state/cryptoStore.js';

// ─── Worker lifecycle ────────────────────────────────────────────────────────

let _worker = null;
const _pending = new Map(); // id → { resolve, reject }
let _msgIdCounter = 0;

/**
 * initWorker() — Start the SharedWorker. Call once at app boot.
 * Safe to call multiple times (no-op if already started).
 */
export function initWorker() {
  if (_worker) return;

  _worker = new SharedWorker(
    new URL('../key_manager/key_manager_worker.js', import.meta.url),
    { type: 'module', name: 'medledger-key-worker' }
  );

  _worker.port.onmessage = _handleMessage;

  _worker.port.onmessageerror = (err) => {
    console.error('[crypto] Worker message error', err);
  };

  _worker.port.start();
}

function _handleMessage(event) {
  const msg = event.data;

  // Push event (no id) — e.g. inactivity lock broadcast
  if (!msg.id && msg.event) {
    _handlePushEvent(msg);
    return;
  }

  const pending = _pending.get(msg.id);
  if (!pending) return;
  _pending.delete(msg.id);

  if (msg.error) {
    const err = new Error(msg.error.message);
    err.code = msg.error.code;
    pending.reject(err);
  } else {
    pending.resolve(msg.result);
  }
}

function _handlePushEvent(msg) {
  if (msg.event === 'locked') {
    cryptoStore.setState({
      status: 'locked',
      publicKeys: null,
      lockReason: msg.reason ?? 'inactivity',
    });
    // Route to /unlock — the server session is still alive
    window.location.href = '/unlock';
  }
}

/**
 * Send a command to the worker and return a Promise for the result.
 */
function _send(cmd, args = {}) {
  if (!_worker) throw new Error('Worker not initialised — call initWorker() first');

  const id = String(++_msgIdCounter);
  return new Promise((resolve, reject) => {
    _pending.set(id, { resolve, reject });
    _worker.port.postMessage({ id, cmd, args });
  });
}

// ─── Lock event registration ─────────────────────────────────────────────────

let _lockCallbackRegistered = false;

/**
 * onLockEvent(callback) — Register a listener for the worker's locked broadcast.
 * Must be called once at app boot, NOT per-component.
 *
 * The default handler in _handlePushEvent already updates cryptoStore and
 * redirects. Use this if you need additional app-level side effects.
 *
 * @param {function} callback — receives { event, reason }
 */
export function onLockEvent(callback) {
  if (_lockCallbackRegistered) {
    console.warn('[crypto] onLockEvent already registered — ignoring duplicate');
    return;
  }
  _lockCallbackRegistered = true;

  // Wrap the existing handler — we patch _handlePushEvent rather than adding
  // a separate listener, so there is still only one code path.
  const original = _handlePushEvent;
  // eslint-disable-next-line no-global-assign
  Object.defineProperty(window, '__cryptoLockCallback', {
    value: callback,
    writable: true,
  });

  // Re-assign module-level handler reference via closure
  _worker.port.onmessage = (event) => {
    const msg = event.data;
    if (!msg.id && msg.event) {
      original(msg);
      window.__cryptoLockCallback?.(msg);
      return;
    }
    _handleMessage(event);
  };
}

// ─── Worker commands ─────────────────────────────────────────────────────────

/**
 * createUser(username, passphrase)
 * Generate keys for a new user. Returns publicKeys + bundleB64 for download.
 * Private keys stay in the worker. Writes cryptoStore to 'unlocked'.
 *
 * @returns {{ signingPublicKey, exchangePublicKey, userIdHex, username, bundleB64 }}
 */
export async function createUser(username, passphrase) {
  const result = await _send('createUser', { username, passphrase });

  const publicKeys = {
    signingPublicKey: result.signingPublicKey,
    exchangePublicKey: result.exchangePublicKey,
    userIdHex: result.userIdHex,
    username: result.username,
  };

  cryptoStore.setState({
    status: 'unlocked',
    publicKeys,
    lockReason: null,
  });

  return { ...publicKeys, bundleB64: result.bundleB64 };
}

/**
 * loadAndUnlock(username, bundleB64, passphrase)
 * Decrypt the bundle file and unlock the crypto session.
 * Writes cryptoStore to 'unlocked'.
 *
 * @throws if passphrase is wrong or bundle is invalid
 */
export async function loadAndUnlock(username, bundleB64, passphrase) {
  const publicKeys = await _send('loadAndUnlock', { username, bundleB64, passphrase });

  cryptoStore.setState({
    status: 'unlocked',
    publicKeys,
    lockReason: null,
  });

  return publicKeys;
}

/**
 * lock() — Manual lock. Wipes keys in the worker, updates cryptoStore.
 */
export async function lock() {
  await _send('logout');
  cryptoStore.setState({
    status: 'locked',
    publicKeys: null,
    lockReason: 'manual',
  });
}

/**
 * getPublicKeys() — Returns from cryptoStore (no worker call needed).
 * @returns {{ signingPublicKey, exchangePublicKey, userIdHex, username } | null}
 */
export function getPublicKeys() {
  return cryptoStore.getState().publicKeys;
}

/**
 * isLocked() — Synchronous check.
 */
export function isLocked() {
  return cryptoStore.getState().status === 'locked';
}

/**
 * encryptRecord(fileBytes, recipientExchangePubKeyB64)
 * fileBytes is a Uint8Array from the main thread; converted to base64 before
 * crossing the worker boundary (structured clone handles Uint8Array fine, but
 * base64 is explicit and consistent with the worker's protocol).
 *
 * @returns {{ encryptedRecord, nonce, dekBundle, fileHash }}
 */
export async function encryptRecord(fileBytes, recipientExchangePubKeyB64) {
  // The worker expects fileBytesB64 (base64url no-padding)
  // We use a simple btoa path for ArrayBuffer — works in all modern browsers
  const b64 = _uint8ToBase64Url(fileBytes);
  return _send('encryptRecord', {
    fileBytesB64: b64,
    recipientExchangePubKeyB64,
  });
}

/**
 * decryptShare(encryptedRecordB64, nonceB64, dekBundleB64)
 * @returns {Uint8Array} plaintext bytes
 */
export async function decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) {
  const result = await _send('decryptShare', {
    encryptedRecordB64,
    nonceB64,
    dekBundleB64,
  });
  return _base64UrlToUint8(result.fileBytesB64);
}

/**
 * signPayload(payloadObject)
 * @returns {{ payload, payloadCanon, signature }}
 */
export async function signPayload(payloadObject) {
  return _send('signPayload', { payloadObject });
}

/**
 * verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64)
 * @returns {boolean}
 */
export async function verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64) {
  return _send('verifySignature', { payloadOrCanon, signatureB64, signerPubKeyB64 });
}

// ─── Base64url helpers ───────────────────────────────────────────────────────

function _uint8ToBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _base64UrlToUint8(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const binary = atob(padded + '='.repeat(padLen));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

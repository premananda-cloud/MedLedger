/**
 * crypto.js — Bridge to the key_manager SharedWorker.
 *
 * FIX: _handlePushEvent was calling window.location.href = '/unlock'
 * which triggers a full page reload and loses all in-memory state
 * (access token, crypto session, everything). The router is hash-based —
 * use window.location.hash instead, which triggers hashchange without reload.
 *
 * All other logic is unchanged from the original.
 */

import cryptoStore from '../state/cryptoStore.js';

// ─── Worker lifecycle ────────────────────────────────────────────────────────

let _worker = null;
const _pending = new Map(); // id → { resolve, reject }
let _msgIdCounter = 0;

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
    // FIX: set lockReason in store BEFORE navigating so the unlock screen
    // reads the correct reason on mount (was: navigate first, state second)
    cryptoStore.setState({
      status: 'locked',
      publicKeys: null,
      lockReason: msg.reason ?? 'inactivity',
    });

    // FIX: hash navigation — no page reload, no loss of server session state
    // (was: window.location.href = '/unlock' which wipes all in-memory tokens)
    window.location.hash = '/unlock';
  }
}

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

export function onLockEvent(callback) {
  if (_lockCallbackRegistered) {
    console.warn('[crypto] onLockEvent already registered — ignoring duplicate');
    return;
  }
  _lockCallbackRegistered = true;

  Object.defineProperty(window, '__cryptoLockCallback', {
    value: callback,
    writable: true,
  });

  _worker.port.onmessage = (event) => {
    const msg = event.data;
    if (!msg.id && msg.event) {
      _handlePushEvent(msg);
      window.__cryptoLockCallback?.(msg);
      return;
    }
    _handleMessage(event);
  };
}

// ─── Worker commands ─────────────────────────────────────────────────────────

export async function createUser(username, passphrase) {
  const result = await _send('createUser', { username, passphrase });

  const publicKeys = {
    signingPublicKey:  result.signingPublicKey,
    exchangePublicKey: result.exchangePublicKey,
    userIdHex:         result.userIdHex,
    username:          result.username,
  };

  cryptoStore.setState({ status: 'unlocked', publicKeys, lockReason: null });

  return { ...publicKeys, bundleB64: result.bundleB64 };
}

export async function loadAndUnlock(username, bundleB64, passphrase) {
  const publicKeys = await _send('loadAndUnlock', { username, bundleB64, passphrase });

  cryptoStore.setState({ status: 'unlocked', publicKeys, lockReason: null });

  return publicKeys;
}

export async function lock() {
  await _send('logout');
  cryptoStore.setState({ status: 'locked', publicKeys: null, lockReason: 'manual' });
}

export function getPublicKeys() {
  return cryptoStore.getState().publicKeys;
}

export function isLocked() {
  return cryptoStore.getState().status === 'locked';
}

export async function encryptRecord(fileBytes, recipientExchangePubKeyB64) {
  const b64 = _uint8ToBase64Url(fileBytes);
  return _send('encryptRecord', { fileBytesB64: b64, recipientExchangePubKeyB64 });
}

export async function decryptShare(encryptedRecordB64, nonceB64, dekBundleB64) {
  const result = await _send('decryptShare', {
    encryptedRecordB64,
    nonceB64,
    dekBundleB64,
  });
  return _base64UrlToUint8(result.fileBytesB64);
}

export async function signPayload(payloadObject) {
  return _send('signPayload', { payloadObject });
}

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
  const padLen  = (4 - (padded.length % 4)) % 4;
  const binary  = atob(padded + '='.repeat(padLen));
  const bytes   = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

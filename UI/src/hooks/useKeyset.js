/**
 * useKeyset.js
 *
 * React hook that owns the KeysetManager session lifecycle.
 *
 * Provides:
 *  - locked / publicKeys state kept in sync with KeysetManager
 *  - login(username, keypair)  — calls KeysetManager.loginUser(), updates state
 *  - logout()                  — wipes keys, clears JWT, updates state
 *  - init() on mount           — idempotent; safe to call multiple times
 *  - beforeunload listener     — wipes keys synchronously on tab close
 *  - 30-minute inactivity lock — resets on any user interaction
 *  - encryptRecord / decryptShare / signPayload pass-throughs — so components
 *    never import KeysetManager directly
 *
 * Usage:
 *   const { locked, publicKeys, login, logout, signPayload } = useKeyset();
 *
 * Wire to VaultStatus and VaultUnlock via the shared context (see below).
 * One instance per app — place at the root and pass values down via context
 * or props; do not call useKeyset() in multiple unrelated subtrees.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { KeysetManager, KeysetError, ERRORS } from "../key_manager/key_manager.js";
import { clearToken } from "../shared/apiClient.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

const ACTIVITY_EVENTS = ["mousemove", "keydown", "click", "touchstart", "scroll"];

// ─── Hook ─────────────────────────────────────────────────────────────────────

/**
 * @param {object}   [options]
 * @param {number}   [options.inactivityTimeoutMs]  Override the 30-minute default
 * @param {Function} [options.onInactivityLock]     Called when the inactivity timer fires
 * @param {Function} [options.onError]              Called with a KeysetError if a crypto op fails
 *
 * @returns {{
 *   locked:         boolean,
 *   publicKeys:     { signingPublicKey, exchangePublicKey, userIdHex, username } | null,
 *   ready:          boolean,
 *   login:          (username: string, keypair: object) => Promise<object>,
 *   logout:         () => void,
 *   encryptRecord:  (fileBytes: Uint8Array, recipientPubKeyB64: string) => object,
 *   decryptShare:   (encB64: string, nonceB64: string, dekB64: string) => Uint8Array,
 *   signPayload:    (payloadObject: object) => { payloadCanon: string, signature: string },
 *   verifySignature:(payloadOrCanon: any, sig: string, pubKey: string) => boolean,
 *   getPublicKeys:  () => object | null,
 * }}
 */
export function useKeyset({
  inactivityTimeoutMs = INACTIVITY_TIMEOUT_MS,
  onInactivityLock = null,
  onError = null,
} = {}) {
  // true  = no private keys in memory
  // false = session is active
  const [locked, setLocked] = useState(true);
  const [publicKeys, setPublicKeys] = useState(null);
  // false until KeysetManager.init() resolves (libsodium wasm loaded)
  const [ready, setReady] = useState(false);

  const inactivityTimer = useRef(null);

  // ── Inactivity timer management ────────────────────────────────────────────

  const clearInactivityTimer = useCallback(() => {
    if (inactivityTimer.current !== null) {
      clearTimeout(inactivityTimer.current);
      inactivityTimer.current = null;
    }
  }, []);

  const resetInactivityTimer = useCallback(() => {
    clearInactivityTimer();
    inactivityTimer.current = setTimeout(() => {
      // Only lock if still unlocked when the timer fires
      if (!KeysetManager.isLocked()) {
        KeysetManager.logoutUser();
        clearToken();
        setLocked(true);
        setPublicKeys(null);
        onInactivityLock?.();
      }
    }, inactivityTimeoutMs);
  }, [clearInactivityTimer, inactivityTimeoutMs, onInactivityLock]);

  // ── Mount / unmount effects ────────────────────────────────────────────────

  useEffect(() => {
    // Initialize libsodium once
    KeysetManager.init().then(() => setReady(true));

    // Wipe keys synchronously on tab close — last line of defense
    const onUnload = () => {
      KeysetManager.logoutUser();
      clearToken();
    };
    window.addEventListener("beforeunload", onUnload);

    return () => {
      window.removeEventListener("beforeunload", onUnload);
      clearInactivityTimer();
    };
  }, [clearInactivityTimer]);

  // ── Inactivity listeners (only active when session is unlocked) ────────────

  useEffect(() => {
    if (locked) {
      // Session is locked — no point tracking activity
      clearInactivityTimer();
      return;
    }

    // Start the timer immediately on unlock
    resetInactivityTimer();

    // Reset it on any interaction
    const handleActivity = () => resetInactivityTimer();
    ACTIVITY_EVENTS.forEach((e) =>
      window.addEventListener(e, handleActivity, { passive: true })
    );

    return () => {
      ACTIVITY_EVENTS.forEach((e) =>
        window.removeEventListener(e, handleActivity)
      );
      clearInactivityTimer();
    };
  }, [locked, resetInactivityTimer, clearInactivityTimer]);

  // ── Session operations ─────────────────────────────────────────────────────

  /**
   * Load a keypair into KeysetManager and unlock the session.
   * Returns the public keys so callers can update their own state.
   *
   * @param {string} username
   * @param {{ signing: { publicKey: Uint8Array, privateKey: Uint8Array },
   *            exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }} keypair
   * @returns {Promise<object>} publicKeys
   * @throws {KeysetError} BAD_KEY_FORMAT if the keypair is malformed
   */
  const login = useCallback(
    async (username, keypair) => {
      const keys = await KeysetManager.loginUser(username, keypair);
      setLocked(false);
      setPublicKeys(keys);
      return keys;
    },
    []
  );

  /**
   * Wipe private keys and clear the JWT.
   * This is the canonical logout path — always call this, not KeysetManager directly.
   */
  const logout = useCallback(() => {
    KeysetManager.logoutUser();
    clearToken();
    clearInactivityTimer();
    setLocked(true);
    setPublicKeys(null);
  }, [clearInactivityTimer]);

  // ── Crypto pass-throughs ──────────────────────────────────────────────────
  //
  // These wrap KeysetManager methods so the rest of the app never has to
  // import key_manager.js directly. Errors are surfaced via onError if
  // provided, and re-thrown so callers can still handle them.

  const encryptRecord = useCallback(
    (fileBytes, recipientExchangePublicKeyB64) => {
      try {
        return KeysetManager.encryptRecord(fileBytes, recipientExchangePublicKeyB64);
      } catch (err) {
        onError?.(err);
        throw err;
      }
    },
    [onError]
  );

  const decryptShare = useCallback(
    (encryptedRecordB64, nonceB64, dekBundleB64) => {
      try {
        return KeysetManager.decryptShare(encryptedRecordB64, nonceB64, dekBundleB64);
      } catch (err) {
        onError?.(err);
        throw err;
      }
    },
    [onError]
  );

  const signPayload = useCallback(
    (payloadObject) => {
      try {
        return KeysetManager.signPayload(payloadObject);
      } catch (err) {
        onError?.(err);
        throw err;
      }
    },
    [onError]
  );

  /**
   * Verify an Ed25519 signature.
   * Does not require an unlocked session.
   * Returns false (never throws) for any verification failure.
   */
  const verifySignature = useCallback(
    (payloadOrCanon, signatureB64, signerPubKeyB64) =>
      KeysetManager.verifySignature(payloadOrCanon, signatureB64, signerPubKeyB64),
    []
  );

  /**
   * Returns public keys from the current session, or null if locked.
   * Thin wrapper so callers don't need to handle KeysetError.
   */
  const getPublicKeys = useCallback(() => {
    if (KeysetManager.isLocked()) return null;
    try {
      return KeysetManager.getPublicKeys();
    } catch {
      return null;
    }
  }, []);

  return {
    /** True when no private keys are in memory */
    locked,
    /** Current session's public keys, or null when locked */
    publicKeys,
    /** True once libsodium has finished initializing */
    ready,
    login,
    logout,
    encryptRecord,
    decryptShare,
    signPayload,
    verifySignature,
    getPublicKeys,
  };
}

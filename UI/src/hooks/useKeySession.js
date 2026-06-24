/**
 * useKeySession.js — React hook for key session state
 * ──────────────────────────────────────────────────────
 * The single React integration point for the key system.
 * Components call this hook; they never import keyWorker or services directly.
 *
 * State exposed:
 *   isLocked       boolean         — true until loadAndUnlock or createAndSave succeeds
 *   isInitialized  boolean         — true after Worker init() completes
 *   user           object | null   — { signingPublicKey, exchangePublicKey, userIdHex, username }
 *   error          string | null   — last error message, cleared on next action
 *   isBusy         boolean         — true during any async Worker operation
 *
 * Actions exposed:
 *   createAndSave(username, passphrase)  — generate keys, download file, unlock session
 *   loadAndUnlock(passphrase)            — pick file, decrypt, unlock session
 *   logout()                             — wipe keys, lock session
 *
 * Auto-lock:
 *   The Worker fires the lock timer on inactivity. This hook listens for
 *   the "keysession:locked" window event and updates React state accordingly.
 *   No timer logic lives here — it's entirely in the Worker.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { keyWorker, WorkerKeyError } from "../services/keyWorkerClient.js";
import { downloadKeyFile, pickAndReadKeyFile } from "../services/keyFileService.js";

// ─────────────────────────────────────────────────────────────────
// Hook
// ─────────────────────────────────────────────────────────────────

export function useKeySession() {
  const [state, setState] = useState({
    isLocked: true,
    isInitialized: false,
    user: null,
    error: null,
    isBusy: false,
  });

  // Track mount status to avoid state updates after unmount
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  function safeSetState(updater) {
    if (mountedRef.current) setState(updater);
  }

  // ── Init ──────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function initWorker() {
      try {
        await keyWorker.init();
        if (!cancelled) {
          safeSetState((s) => ({ ...s, isInitialized: true }));
        }
      } catch (err) {
        if (!cancelled) {
          safeSetState((s) => ({
            ...s,
            error: `Worker initialization failed: ${err.message}`,
          }));
        }
      }
    }

    initWorker();
    return () => { cancelled = true; };
  }, []);

  // ── Auto-lock listener ────────────────────────────────────────

  useEffect(() => {
    function onAutoLocked() {
      safeSetState({
        isLocked: true,
        isInitialized: true,
        user: null,
        error: null,
        isBusy: false,
      });
    }

    window.addEventListener("keysession:locked", onAutoLocked);
    return () => window.removeEventListener("keysession:locked", onAutoLocked);
  }, []);

  // ── Actions ───────────────────────────────────────────────────

  /**
   * Generate a new keypair, offer the encrypted file for download,
   * and unlock the session. All in one step — user must save the file.
   *
   * @param {string} username
   * @param {string} passphrase   — used to encrypt the key file
   */
  const createAndSave = useCallback(async (username, passphrase) => {
    safeSetState((s) => ({ ...s, isBusy: true, error: null }));
    try {
      const result = await keyWorker.createUser(username, passphrase);

      // Trigger the .medledger file download — must happen before we navigate away
      downloadKeyFile(result.bundleB64, username);

      const { bundleB64: _omit, ...publicKeys } = result;
      safeSetState({
        isLocked: false,
        isInitialized: true,
        user: publicKeys,
        error: null,
        isBusy: false,
      });

      return publicKeys;
    } catch (err) {
      safeSetState((s) => ({
        ...s,
        isBusy: false,
        error: formatError(err),
      }));
      throw err;
    }
  }, []);

  /**
   * Open file picker, read the .medledger file, decrypt with passphrase,
   * and unlock the session.
   *
   * @param {string} passphrase
   */
  const loadAndUnlock = useCallback(async (passphrase) => {
    safeSetState((s) => ({ ...s, isBusy: true, error: null }));
    try {
      const { bundleB64, filename } = await pickAndReadKeyFile();

      // Infer username from filename — strip extension and sanitize
      const inferredUsername = filename
        .replace(/\.medledger$/i, "")
        .replace(/[^a-zA-Z0-9_-]/g, "_")
        || "user";

      const publicKeys = await keyWorker.loadAndUnlock(
        inferredUsername,
        bundleB64,
        passphrase,
      );

      safeSetState({
        isLocked: false,
        isInitialized: true,
        user: publicKeys,
        error: null,
        isBusy: false,
      });

      return publicKeys;
    } catch (err) {
      safeSetState((s) => ({
        ...s,
        isBusy: false,
        error: formatError(err),
      }));
      throw err;
    }
  }, []);

  /**
   * Lock the session and wipe keys from the Worker.
   */
  const logout = useCallback(async () => {
    safeSetState((s) => ({ ...s, isBusy: true, error: null }));
    try {
      await keyWorker.logout();
      safeSetState({
        isLocked: true,
        isInitialized: true,
        user: null,
        error: null,
        isBusy: false,
      });
    } catch (err) {
      // Logout errors are non-fatal — treat session as locked regardless
      safeSetState({
        isLocked: true,
        isInitialized: true,
        user: null,
        error: formatError(err),
        isBusy: false,
      });
    }
  }, []);

  return {
    // State
    isLocked: state.isLocked,
    isInitialized: state.isInitialized,
    user: state.user,
    error: state.error,
    isBusy: state.isBusy,
    // Actions
    createAndSave,
    loadAndUnlock,
    logout,
  };
}

// ─────────────────────────────────────────────────────────────────
// Error formatting
// ─────────────────────────────────────────────────────────────────

function formatError(err) {
  if (err instanceof WorkerKeyError) {
    // Map Worker error codes to user-friendly messages
    switch (err.code) {
      case "KEYSET_SESSION_LOCKED":
        return "Session is locked. Please load your key file.";
      case "KEYSET_DECRYPTION_FAILED":
        return "Decryption failed. The file may be corrupted or intended for another user.";
      case "KEYSET_SIGNATURE_INVALID":
        return "Signature verification failed.";
      case "KEYSET_BAD_KEY_FORMAT":
        return "Invalid key format.";
      default:
        return err.message || "An unexpected key error occurred.";
    }
  }

  if (err.message?.includes("WRONG_PASSPHRASE")) {
    return "Wrong passphrase. Please check your passphrase and try again.";
  }
  if (err.message?.includes("INVALID_BUNDLE")) {
    return "This file is not a valid MedLedger key file.";
  }
  if (err.message === "File picker cancelled") {
    return null; // not an error, user cancelled
  }

  return err.message || "An unexpected error occurred.";
}

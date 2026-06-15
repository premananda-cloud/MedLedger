/**
 * useAuth.js
 *
 * Wraps loginBridge.js for keypair-based authentication.
 * Manages isAuthenticated state, public keys, and login/logout lifecycle.
 *
 * The JWT lives in apiClient module memory (never localStorage).
 * This hook does not persist sessions across page reloads by default —
 * the user must log in again after a reload (by design, per the security spec).
 *
 * Usage:
 *   const {
 *     isAuthenticated, publicKeys,
 *     loading, error,
 *     login, logout,
 *     clearError,
 *   } = useAuth();
 */

import { useState, useCallback, useEffect } from "react";
import {
  login as bridgeLogin,
  logout as bridgeLogout,
  isSessionActive,
  getSessionPublicKeys,
} from "../services/loginBridge.js";

export function useAuth() {
  // Sync initial state from the bridge in case the module is already
  // authenticated (e.g. same-page navigation without unmount)
  const [isAuthenticated, setIsAuthenticated] = useState(() => isSessionActive());
  const [publicKeys, setPublicKeys] = useState(() => getSessionPublicKeys());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Keep state consistent if the bridge session is already active on mount
  useEffect(() => {
    const active = isSessionActive();
    setIsAuthenticated(active);
    setPublicKeys(active ? getSessionPublicKeys() : null);
  }, []);

  // ─── Actions ──────────────────────────────────────────────────────────────

  /**
   * Authenticates the user with their username and saved keypair.
   * On success: sets isAuthenticated=true and surfaces publicKeys.
   * The JWT is stored in apiClient memory automatically by loginBridge.
   *
   * @param {string} username
   * @param {{ signing: { publicKey: Uint8Array, privateKey: Uint8Array },
   *            exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }} keypair
   * @returns {boolean} true on success, false on failure
   */
  const login = useCallback(async (username, keypair) => {
    setError(null);
    setLoading(true);
    try {
      const result = await bridgeLogin(username, keypair);
      setPublicKeys(result.publicKeys);
      setIsAuthenticated(true);
      return true;
    } catch (err) {
      setError(formatError(err));
      setIsAuthenticated(false);
      setPublicKeys(null);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Logs out the user.
   * Clears JWT first (resilient — loginBridge guarantees this order),
   * then wipes private keys from KeysetManager.
   * Network errors on the server-side logout call are silently ignored.
   */
  const logout = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      await bridgeLogout();
    } catch (err) {
      // loginBridge.logout() swallows network errors by design,
      // but catch anything unexpected so the local state still clears.
    } finally {
      setIsAuthenticated(false);
      setPublicKeys(null);
      setLoading(false);
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return {
    // State
    isAuthenticated,
    publicKeys,   // { signingPublicKey, exchangePublicKey, userIdHex, username } | null
    loading,
    error,

    // Actions
    login,
    logout,
    clearError,
  };
}

// ─── Error formatter ──────────────────────────────────────────────────────────

function formatError(err) {
  if (!err) return "An unknown error occurred.";

  if (err.name === "ApiError") {
    if (err.status === 0) return "Network error — check your connection.";
    // Surface server-side error codes the UI might want to handle specifically
    const serverMessages = {
      INVALID_SIGNATURE: "Login failed — keypair does not match this account.",
      USER_NOT_FOUND: "Account not found.",
      TOKEN_EXPIRED: "Session expired — please log in again.",
    };
    if (err.code && serverMessages[err.code]) return serverMessages[err.code];
    return err.message || `Server error (${err.status}).`;
  }

  if (err.name === "KeysetError") {
    const messages = {
      BAD_KEY_FORMAT: "Invalid keypair file — check the file and try again.",
      SESSION_LOCKED: "Crypto session is locked.",
    };
    return messages[err.code] || err.message || "Crypto error.";
  }

  // Plain errors: invalid username, bad keypair shape
  return err.message || "Login failed.";
}

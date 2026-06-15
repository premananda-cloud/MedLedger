/**
 * useKeyset.js
 *
 * Wraps the authKeyBridge crypto session.
 * Mirrors the KeysetManager UNLOCKED / LOCKED / UNINITIALIZED state machine.
 * React never receives raw private key material — only public keys are exposed.
 *
 * Usage:
 *   const {
 *     vaultStatus,        // "uninitialized" | "locked" | "unlocked"
 *     isLocked,           // shorthand boolean
 *     publicKeys,         // available when unlocked
 *     loading, error,
 *     unlockSession,
 *     lockSession,
 *     encryptRecord,
 *     decryptShare,
 *     signPayload,
 *     verifySignature,
 *     clearError,
 *   } = useKeyset();
 */

import { useState, useCallback, useEffect } from "react";
import { getAuthKeyBridge } from "../services/authKeyBridge.js";

const VAULT_STATUS = {
  UNINITIALIZED: "uninitialized",
  LOCKED: "locked",
  UNLOCKED: "unlocked",
};

function deriveStatus(bridge) {
  try {
    if (bridge.isCryptoLocked()) return VAULT_STATUS.LOCKED;
    return VAULT_STATUS.UNLOCKED;
  } catch {
    // isCryptoLocked throws if the bridge hasn't been init'd yet
    return VAULT_STATUS.UNINITIALIZED;
  }
}

export function useKeyset() {
  const bridge = getAuthKeyBridge(); // singleton — safe to call repeatedly

  const [initialized, setInitialized] = useState(false);
  const [vaultStatus, setVaultStatus] = useState(VAULT_STATUS.UNINITIALIZED);
  const [publicKeys, setPublicKeys] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // ─── Init libsodium once on mount ─────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        await bridge.init();
        if (cancelled) return;
        const status = deriveStatus(bridge);
        setVaultStatus(status);
        if (status === VAULT_STATUS.UNLOCKED) {
          setPublicKeys(safeGetPublicKeys(bridge));
        }
        setInitialized(true);
      } catch (err) {
        if (!cancelled) {
          setError("Failed to initialize crypto layer.");
        }
      }
    }

    init();
    return () => { cancelled = true; };
  }, []);

  // ─── Sync helper ─────────────────────────────────────────────────────────

  function syncStatus() {
    const status = deriveStatus(bridge);
    setVaultStatus(status);
    if (status === VAULT_STATUS.UNLOCKED) {
      setPublicKeys(safeGetPublicKeys(bridge));
    } else {
      setPublicKeys(null);
    }
  }

  // ─── Actions ──────────────────────────────────────────────────────────────

  /**
   * Unlocks the crypto session with the user's saved keypair.
   * Sets vaultStatus → "unlocked" and surfaces publicKeys on success.
   *
   * @param {string} username
   * @param {{ signing: { publicKey: Uint8Array, privateKey: Uint8Array },
   *            exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }} savedKeypair
   * @returns {boolean} true on success, false on failure
   */
  const unlockSession = useCallback(async (username, savedKeypair) => {
    setError(null);
    setLoading(true);
    try {
      await bridge.unlockCryptoSession(username, savedKeypair);
      syncStatus();
      return true;
    } catch (err) {
      setError(formatError(err));
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Locks the crypto session (wipes private keys from KeysetManager).
   * Sets vaultStatus → "locked".
   */
  const lockSession = useCallback(() => {
    try {
      bridge.logout();
    } catch {
      // Best-effort — always update local state
    }
    setVaultStatus(VAULT_STATUS.LOCKED);
    setPublicKeys(null);
    setError(null);
  }, []);

  // ─── Crypto operations (require unlocked session) ─────────────────────────

  /**
   * Encrypts a file for a recipient using a sealed box.
   * Throws (and sets error) if the session is locked.
   *
   * @param {Uint8Array} fileBytes
   * @param {string} recipientPublicKey  Base64-encoded X25519 public key
   * @returns {object | null}  Encrypted record object
   */
  const encryptRecord = useCallback(async (fileBytes, recipientPublicKey) => {
    setError(null);
    try {
      return bridge.encryptRecord(fileBytes, recipientPublicKey);
    } catch (err) {
      setError(formatError(err));
      return null;
    }
  }, []);

  /**
   * Decrypts a received record share.
   * Throws (and sets error) if the session is locked.
   *
   * @param {Uint8Array} encryptedRecord
   * @param {Uint8Array} nonce
   * @param {object}     dekBundle
   * @returns {Uint8Array | null}  Decrypted plaintext bytes
   */
  const decryptShare = useCallback(async (encryptedRecord, nonce, dekBundle) => {
    setError(null);
    try {
      return bridge.decryptShare(encryptedRecord, nonce, dekBundle);
    } catch (err) {
      setError(formatError(err));
      return null;
    }
  }, []);

  /**
   * Signs a payload with the user's Ed25519 private key.
   * Requires an unlocked session.
   *
   * @param {object} payload
   * @returns {{ payloadCanon: string, signature: string } | null}
   */
  const signPayload = useCallback(async (payload) => {
    setError(null);
    try {
      return bridge.signPayload(payload);
    } catch (err) {
      setError(formatError(err));
      return null;
    }
  }, []);

  /**
   * Verifies a signature against a known public key.
   * Does NOT require an unlocked session.
   *
   * @param {object} payload
   * @param {string} signature
   * @param {string} signerPublicKey  Base64-encoded Ed25519 public key
   * @returns {boolean}
   */
  const verifySignature = useCallback((payload, signature, signerPublicKey) => {
    try {
      return bridge.verifySignature(payload, signature, signerPublicKey);
    } catch (err) {
      setError(formatError(err));
      return false;
    }
  }, []);

  const clearError = useCallback(() => setError(null), []);

  return {
    // State
    vaultStatus,                                    // "uninitialized" | "locked" | "unlocked"
    isLocked: vaultStatus !== VAULT_STATUS.UNLOCKED, // shorthand for common checks
    isUnlocked: vaultStatus === VAULT_STATUS.UNLOCKED,
    initialized,                                    // true once bridge.init() resolves
    publicKeys,  // { signingPublicKey, exchangePublicKey, userIdHex } | null
    loading,
    error,

    // Session management
    unlockSession,
    lockSession,

    // Crypto operations
    encryptRecord,
    decryptShare,
    signPayload,
    verifySignature,

    // Utilities
    clearError,

    // Status constants for switch/comparison in components
    VAULT_STATUS,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function safeGetPublicKeys(bridge) {
  try {
    return bridge.getPublicKeys();
  } catch {
    return null;
  }
}

function formatError(err) {
  if (!err) return "An unknown error occurred.";

  if (err.name === "ApiError") {
    if (err.status === 0) return "Network error — check your connection.";
    return err.message || `Server error (${err.status}).`;
  }

  if (err.name === "KeysetError") {
    const messages = {
      BAD_KEY_FORMAT: "Invalid keypair — check your saved keys and try again.",
      SESSION_LOCKED: "The vault is locked. Upload your keypair to unlock.",
      UNINITIALIZED: "Crypto layer not ready. Refresh the page.",
    };
    return messages[err.code] || err.message || "Crypto error.";
  }

  return err.message || "An unexpected error occurred.";
}

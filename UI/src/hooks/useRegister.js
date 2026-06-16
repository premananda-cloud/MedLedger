/**
 * useRegister.js
 *
 * Drives the RegisterBridge six-step registration flow.
 * Exposes a step state machine, per-step loading/error state,
 * TOTP info, and the final keypair for download.
 *
 * Steps (in order):
 *   "idle" → "pow" → "emailVerify" → "totp" → "createAccount" → "keypairReady"
 *
 * Usage:
 *   const {
 *     step, loading, error,
 *     startPoW,
 *     submitEmail, verifyEmailCode,
 *     totpInfo, verifyTOTP,
 *     createAccount,
 *     keypair, publicKeys,
 *     clearKeypair, reset,
 *   } = useRegister();
 */

import { useState, useCallback, useRef } from "react";
import { RegisterBridge } from "../services/registerBridge.js";

const STEPS = {
  IDLE: "idle",
  POW: "pow",                     // PoW solving in progress / done
  EMAIL_VERIFY: "emailVerify",    // Waiting for 6-digit email code
  TOTP: "totp",                   // Waiting for TOTP verification
  CREATE_ACCOUNT: "createAccount",// Account creation in progress
  KEYPAIR_READY: "keypairReady",  // Keys generated, awaiting user save
};

export function useRegister() {
  const bridgeRef = useRef(null);

  // Lazily create the bridge so each hook instance gets its own
  function getBridge() {
    if (!bridgeRef.current) {
      bridgeRef.current = new RegisterBridge();
    }
    return bridgeRef.current;
  }

  const [step, setStep] = useState(STEPS.IDLE);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Data surfaced to the UI
  const [totpInfo, setTotpInfo] = useState(null);   // { qrCodeUri, manualKey }
  const [keypair, setKeypair] = useState(null);     // { signing, exchange } — Uint8Arrays
  const [publicKeys, setPublicKeys] = useState(null); // { signingPublicKey, exchangePublicKey, userIdHex, username }

  // AbortController ref for PoW cancellation
  const powAbortRef = useRef(null);

  // ─── Internal helpers ────────────────────────────────────────────────────

  function clearError() {
    setError(null);
  }

  async function run(targetStep, fn) {
    clearError();
    setLoading(true);
    try {
      const result = await fn();
      setStep(targetStep);
      return result;
    } catch (err) {
      setError(formatError(err));
      return null;
    } finally {
      setLoading(false);
    }
  }

  // ─── Step 1+2: PoW ───────────────────────────────────────────────────────

  /**
   * Fetches a PoW challenge, solves it, and verifies with the server.
   * Sets step → "pow" on success.
   * Stores the sessionToken internally in the bridge.
   *
   * @returns {{ sessionToken: string } | null}
   */
  const startPoW = useCallback(async () => {
    // Cancel any in-progress PoW
    if (powAbortRef.current) {
      powAbortRef.current.abort();
    }
    const controller = new AbortController();
    powAbortRef.current = controller;

    try {
      return await run(STEPS.POW, async () => {
        const bridge = getBridge();
        const result = await bridge.startPoW({ signal: controller.signal });
        return result;
      });
    } finally {
      powAbortRef.current = null;
    }
  }, []);

  /**
   * Cancels an in-flight PoW solve.
   */
  const cancelPoW = useCallback(() => {
    if (powAbortRef.current) {
      powAbortRef.current.abort();
      powAbortRef.current = null;
    }
    setLoading(false);
    setStep(STEPS.IDLE);
  }, []);

  // ─── Step 3: Submit email ─────────────────────────────────────────────────

  /**
   * Submits the user's email address for verification.
   * Sets step → "emailVerify" on success.
   *
   * @param {string} email
   * @returns {{ message: string, expiresIn: number, email: string } | null}
   */
  const submitEmail = useCallback(async (email) => {
    return run(STEPS.EMAIL_VERIFY, async () => {
      const bridge = getBridge();
      // bridge.startPoW() stored the sessionToken internally
      return bridge.submitEmail(email);
    });
  }, []);

  // ─── Step 4: Verify email code ────────────────────────────────────────────

  /**
   * Submits the 6-digit email verification code.
   * Caches TOTP enrollment info from the server.
   * Sets step → "totp" on success.
   *
   * @param {string} code  6-digit string
   * @returns {{ totp: { qrCodeUri, manualKey } } | null}
   */
  const verifyEmailCode = useCallback(async (code) => {
    return run(STEPS.TOTP, async () => {
      const bridge = getBridge();
      const result = await bridge.verifyEmailCode(code);
      const info = bridge.getTotpInfo();
      setTotpInfo(info);
      return result;
    });
  }, []);

  // ─── Step 5: Verify TOTP ──────────────────────────────────────────────────

  /**
   * Submits the 6-digit TOTP token from the user's authenticator app.
   * Sets step → "createAccount" on success (ready for final step).
   *
   * @param {string} totpToken  6-digit string
   * @returns {object | null}
   */
  const verifyTOTP = useCallback(async (totpToken) => {
    return run(STEPS.CREATE_ACCOUNT, async () => {
      const bridge = getBridge();
      return bridge.verifyTOTP(totpToken);
    });
  }, []);

  // ─── Step 6: Create account ───────────────────────────────────────────────

  /**
   * Creates the account and generates the Ed25519 + X25519 keypair.
   * Sets step → "keypairReady" on success.
   * ⚠️ The keypair contains raw private keys — surface the download prompt immediately.
   *
   * @param {string} username  ≥ 2 characters
   * @param {string} password  ≥ 8 characters
   * @returns {{ keypair, publicKeys, userId } | null}
   */
  const createAccount = useCallback(async (username, password) => {
    return run(STEPS.KEYPAIR_READY, async () => {
      const bridge = getBridge();
      const result = await bridge.createAccount(username, password);
      setKeypair(result.keypair);
      setPublicKeys(result.publicKeys);
      return result;
    });
  }, []);

  // ─── Post-keypair actions ─────────────────────────────────────────────────

  /**
   * Releases the hook's reference to the raw keypair.
   * Call after the user confirms they have saved their keys.
   * Also calls bridge.clearKeypair() to drop the bridge's reference.
   */
  const clearKeypair = useCallback(() => {
    const bridge = getBridge();
    bridge.clearKeypair();
    setKeypair(null);
  }, []);

  /**
   * Resets the entire registration flow back to "idle".
   * Creates a fresh RegisterBridge instance.
   */
  const reset = useCallback(() => {
    if (powAbortRef.current) {
      powAbortRef.current.abort();
      powAbortRef.current = null;
    }
    bridgeRef.current = null; // drop old bridge, lazy-create fresh on next use
    setStep(STEPS.IDLE);
    setLoading(false);
    setError(null);
    setTotpInfo(null);
    setKeypair(null);
    setPublicKeys(null);
  }, []);

  return {
    // State
    step,
    loading,
    error,

    // Step actions (call in order)
    startPoW,
    cancelPoW,
    submitEmail,
    verifyEmailCode,
    totpInfo,         // available after verifyEmailCode succeeds
    verifyTOTP,
    createAccount,

    // Post-registration
    keypair,          // ⚠️ contains raw private keys — show download prompt immediately
    publicKeys,
    clearKeypair,

    // Utilities
    reset,

    // Step constants for switch/comparison in components
    STEPS,
  };
}

// ─── Error formatter ──────────────────────────────────────────────────────────

function formatError(err) {
  if (!err) return "An unknown error occurred.";

  // ApiError: network or server rejection
  if (err.name === "ApiError") {
    if (err.status === 0) return "Network error — check your connection.";
    return err.message || `Server error (${err.status}).`;
  }

  // KeysetError: crypto layer
  if (err.name === "KeysetError") {
    const messages = {
      BAD_KEY_FORMAT: "Invalid key format — re-upload your keypair.",
      SESSION_LOCKED: "Crypto session is locked.",
    };
    return messages[err.code] || err.message || "Crypto error.";
  }

  // Validation errors thrown by the bridge (plain Error)
  return err.message || "An unexpected error occurred.";
}

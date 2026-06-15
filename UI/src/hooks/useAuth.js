/**
 * useAuth.js
 *
 * React hook managing the multi-step registration and login flows.
 *
 * Registration steps (mirrors authFlow.js + RegisterBridge):
 *   pow        → email_sent  → email_verified  → totp_pending  → credentials  → done
 *
 * Login:
 *   idle → loading → done (or error)
 *
 * This hook owns:
 *  - Flow step state
 *  - Per-step error messages
 *  - Loading flags
 *  - The RegisterBridge instance (one per registration attempt)
 *  - Exposing the raw keypair exactly once (at registration completion) so
 *    the parent can pass it to <KeypairDownload>
 *  - Calling useKeyset().login() after registration so the session is
 *    immediately unlocked without a second file-upload
 *
 * This hook does NOT:
 *  - Render anything
 *  - Import KeysetManager directly (all crypto goes through useKeyset)
 *  - Handle routing/navigation (caller decides what to mount)
 *
 * Usage:
 *   const keyset = useKeyset();
 *   const auth = useAuth({ keyset });
 *
 *   // Registration
 *   await auth.startPoW();
 *   await auth.submitEmail("alice@example.com");
 *   await auth.verifyEmailCode("483920");
 *   // auth.totpInfo is now { qrCodeUri, manualKey }
 *   await auth.verifyTOTP("123456");
 *   await auth.createAccount("alice", "SecureP@ss!");
 *   // auth.keypair is now set — render <KeypairDownload>
 *   auth.confirmKeypairSaved();
 *
 *   // Login
 *   await auth.login(username, keypair);
 */

import { useState, useCallback, useRef } from "react";
import { RegisterBridge } from "../shared/registerBridge.js";
import { login as bridgeLogin, logout as bridgeLogout } from "../shared/loginBridge.js";

// ─── Step definitions ─────────────────────────────────────────────────────────

export const REGISTER_STEPS = {
  IDLE:             "idle",            // Not started
  POW:              "pow",             // Solving PoW (transparent to user)
  EMAIL_SENT:       "email_sent",      // Waiting for user to enter email code
  EMAIL_VERIFIED:   "email_verified",  // Code accepted; TOTP QR ready
  TOTP_PENDING:     "totp_pending",    // Waiting for TOTP token
  CREDENTIALS:      "credentials",     // Waiting for username + password
  CREATING:         "creating",        // createAccount() in flight
  KEYPAIR_DOWNLOAD: "keypair_download",// Keys generated — user must download
  DONE:             "done",            // Registration complete, session unlocked
  ERROR:            "error",           // Fatal error — must restart
};

export const LOGIN_STEPS = {
  IDLE:    "idle",
  LOADING: "loading",
  DONE:    "done",
  ERROR:   "error",
};

// ─── Hook ─────────────────────────────────────────────────────────────────────

/**
 * @param {object} options
 * @param {ReturnType<import('./useKeyset').useKeyset>} options.keyset
 *   The useKeyset() return value — used to unlock the session after auth.
 *
 * @returns {{
 *   // ── Shared ──
 *   error:                string | null,
 *   loading:              boolean,
 *
 *   // ── Registration ──
 *   registerStep:         string,
 *   totpInfo:             { qrCodeUri: string, manualKey: string } | null,
 *   keypair:              object | null,
 *   startPoW:             () => Promise<void>,
 *   submitEmail:          (email: string) => Promise<void>,
 *   verifyEmailCode:      (code: string) => Promise<void>,
 *   verifyTOTP:           (token: string) => Promise<void>,
 *   advanceToCredentials: () => void,
 *   createAccount:        (username: string, password: string) => Promise<void>,
 *   confirmKeypairSaved:  () => void,
 *   resetRegistration:    () => void,
 *
 *   // ── Login ──
 *   loginStep:            string,
 *   login:                (username: string, keypair: object) => Promise<void>,
 *   logout:               () => Promise<void>,
 * }}
 */
export function useAuth({ keyset }) {
  // ── Registration state ────────────────────────────────────────────────────
  const [registerStep, setRegisterStep] = useState(REGISTER_STEPS.IDLE);
  const [totpInfo, setTotpInfo] = useState(null);
  // Keypair is held here from createAccount() until confirmKeypairSaved()
  const [keypair, setKeypair] = useState(null);

  // ── Login state ───────────────────────────────────────────────────────────
  const [loginStep, setLoginStep] = useState(LOGIN_STEPS.IDLE);

  // ── Shared ────────────────────────────────────────────────────────────────
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // Bridge is recreated on each registration attempt
  const bridgeRef = useRef(null);

  // ── Helpers ───────────────────────────────────────────────────────────────

  const clearError = () => setError(null);

  /**
   * Wrap an async operation: clear error, set loading, catch and surface errors.
   * @param {() => Promise<void>} fn
   */
  const run = useCallback(async (fn) => {
    clearError();
    setLoading(true);
    try {
      await fn();
    } catch (err) {
      const msg = friendlyError(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  // ── Registration steps ─────────────────────────────────────────────────────

  /**
   * Step 1+2: Begin registration — solve PoW transparently.
   * Creates a new RegisterBridge and starts the flow.
   */
  const startPoW = useCallback(async () => {
    await run(async () => {
      bridgeRef.current = new RegisterBridge();
      setRegisterStep(REGISTER_STEPS.POW);
      await bridgeRef.current.startPoW();
      setRegisterStep(REGISTER_STEPS.EMAIL_SENT);
    });
  }, [run]);

  /**
   * Step 3: Submit email address. Server sends a 6-digit code.
   * @param {string} email
   */
  const submitEmail = useCallback(
    async (email) => {
      await run(async () => {
        assertBridge(bridgeRef.current);
        await bridgeRef.current.submitEmail(email);
        // Step stays EMAIL_SENT — component shows the code input
      });
    },
    [run]
  );

  /**
   * Step 4: Verify the 6-digit email code.
   * On success, TOTP enrollment info becomes available via totpInfo.
   * @param {string} code
   */
  const verifyEmailCode = useCallback(
    async (code) => {
      await run(async () => {
        assertBridge(bridgeRef.current);
        const result = await bridgeRef.current.verifyEmailCode(code);
        // Bridge caches TOTP info; mirror it into state for the QR component
        const info = bridgeRef.current.getTotpInfo();
        if (info) setTotpInfo(info);
        setRegisterStep(REGISTER_STEPS.EMAIL_VERIFIED);
      });
    },
    [run]
  );

  /**
   * Advance from EMAIL_VERIFIED → TOTP_PENDING.
   * Call this after the UI has displayed the QR code and the user is ready
   * to type their authenticator token.
   */
  const advanceToCredentials = useCallback(() => {
    setRegisterStep(REGISTER_STEPS.TOTP_PENDING);
  }, []);

  /**
   * Step 5: Verify the TOTP token from the user's authenticator app.
   * @param {string} token  6-digit string
   */
  const verifyTOTP = useCallback(
    async (token) => {
      await run(async () => {
        assertBridge(bridgeRef.current);
        await bridgeRef.current.verifyTOTP(token);
        setRegisterStep(REGISTER_STEPS.CREDENTIALS);
      });
    },
    [run]
  );

  /**
   * Step 6: Generate keypair and create the account.
   * Sets keypair in state — caller must render <KeypairDownload> now.
   *
   * After createAccount() returns, the KeysetManager session is already
   * unlocked (createUser() was called internally). We also update useKeyset
   * state by calling keyset.login() with the returned keypair so the rest
   * of the app sees an unlocked vault immediately.
   *
   * @param {string} username
   * @param {string} password
   */
  const createAccount = useCallback(
    async (username, password) => {
      await run(async () => {
        assertBridge(bridgeRef.current);
        setRegisterStep(REGISTER_STEPS.CREATING);

        const { keypair: kp, publicKeys } =
          await bridgeRef.current.createAccount(username, password);

        // Sync the keyset hook so the rest of the app knows the vault is open.
        // loginUser() is idempotent here — it just loads what createUser() already set.
        await keyset.login(username, kp);

        // Surface the keypair for <KeypairDownload>
        setKeypair(kp);
        setRegisterStep(REGISTER_STEPS.KEYPAIR_DOWNLOAD);
      });
    },
    [run, keyset]
  );

  /**
   * Called by the parent once the user has confirmed their keypair is saved.
   * Clears the keypair reference and advances to DONE.
   */
  const confirmKeypairSaved = useCallback(() => {
    bridgeRef.current?.clearKeypair();
    setKeypair(null);
    setRegisterStep(REGISTER_STEPS.DONE);
  }, []);

  /**
   * Reset the entire registration flow so the user can start over.
   */
  const resetRegistration = useCallback(() => {
    bridgeRef.current?.reset();
    bridgeRef.current = null;
    setRegisterStep(REGISTER_STEPS.IDLE);
    setTotpInfo(null);
    setKeypair(null);
    setError(null);
    setLoading(false);
  }, []);

  // ── Login ─────────────────────────────────────────────────────────────────

  /**
   * Log in with a stored keypair.
   * On success, the vault is unlocked and the JWT is stored in apiClient.
   *
   * @param {string} username
   * @param {{ signing: { publicKey: Uint8Array, privateKey: Uint8Array },
   *            exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }} kp
   */
  const login = useCallback(
    async (username, kp) => {
      await run(async () => {
        setLoginStep(LOGIN_STEPS.LOADING);
        // loginBridge handles signing + server exchange; also calls
        // KeysetManager.loginUser() which we mirror into useKeyset via keyset.login()
        const { publicKeys } = await bridgeLogin(username, kp);
        // Sync keyset state — bridgeLogin already called KeysetManager.loginUser(),
        // so this just updates React's locked/publicKeys state
        await keyset.login(username, kp);
        setLoginStep(LOGIN_STEPS.DONE);
      });
    },
    [run, keyset]
  );

  /**
   * Log out: wipe keys from memory, clear JWT, invalidate server session.
   */
  const logout = useCallback(async () => {
    await run(async () => {
      await bridgeLogout();
      // useKeyset.logout() wipes its own state
      keyset.logout();
      setLoginStep(LOGIN_STEPS.IDLE);
    });
  }, [run, keyset]);

  // ─────────────────────────────────────────────────────────────────────────

  return {
    // Shared
    error,
    loading,

    // Registration
    registerStep,
    totpInfo,
    keypair,
    startPoW,
    submitEmail,
    verifyEmailCode,
    advanceToCredentials,
    verifyTOTP,
    createAccount,
    confirmKeypairSaved,
    resetRegistration,

    // Login
    loginStep,
    login,
    logout,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function assertBridge(bridge) {
  if (!bridge) {
    throw new Error(
      "useAuth: no active registration session — call startPoW() first"
    );
  }
}

/**
 * Convert a raw error into a user-readable string.
 * Maps known server error codes and KeysetError codes to helpful messages.
 *
 * @param {unknown} err
 * @returns {string}
 */
function friendlyError(err) {
  if (!err) return "An unexpected error occurred.";

  // ApiError from apiClient
  if (err?.code) {
    switch (err.code) {
      case "NETWORK_ERROR":
        return "Could not reach the server. Check your connection and try again.";
      case "INVALID_SESSION":
      case "SESSION_EXPIRED":
        return "Your session expired. Please start over.";
      case "EMAIL_CODE_INVALID":
        return "That code isn't right. Check your email and try again.";
      case "EMAIL_CODE_EXPIRED":
        return "The code expired. Start over to request a new one.";
      case "EMAIL_MAX_ATTEMPTS":
        return "Too many attempts. Please start the registration over.";
      case "TOTP_INVALID":
        return "That authenticator code isn't valid. Check the time on your device and try again.";
      case "USERNAME_TAKEN":
        return "That username is already taken. Please choose another.";
      case "WEAK_PASSWORD":
        return "Password isn't strong enough. Use uppercase, lowercase, numbers, and symbols.";
      // KeysetError codes
      case "KEYSET_BAD_KEY_FORMAT":
        return "The keypair file is malformed or missing required key data.";
      case "KEYSET_SESSION_LOCKED":
        return "The vault is locked. Please upload your keypair to continue.";
      default:
        break;
    }
  }

  // HTTP status fallback
  if (err?.status) {
    if (err.status === 401) return "Authentication failed. Please check your credentials.";
    if (err.status === 429) return "Too many requests. Please wait a moment and try again.";
    if (err.status >= 500) return "Server error. Please try again in a moment.";
  }

  return err?.message ?? "An unexpected error occurred.";
}

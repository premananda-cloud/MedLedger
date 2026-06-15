/**
 * registerBridge.js
 *
 * Coordinates the six-step registration flow, bridging the auth server
 * (authFlow.js steps) with the crypto layer (KeysetManager).
 *
 * Step order:
 *   1.  initPoW()          — fetch a PoW challenge from the server
 *   2.  solveAndVerifyPoW()— client solves the SHA-256 puzzle, server verifies
 *   3.  submitEmail()      — send the user's email; server sends a 6-digit code
 *   4.  verifyEmailCode()  — confirm the code the user received
 *   5.  verifyTOTP()       — confirm the TOTP token from the user's authenticator
 *   6.  createAccount()    — generate keypair, set username/password, register
 *                            public keys with the server
 *
 * The bridge owns:
 *  - All PoW solving (Web Crypto SHA-256)
 *  - Calling KeysetManager.createUser() at the right moment
 *  - Handing the caller the raw keypair for safe storage (only surfaced once)
 *  - Storing the server-issued JWT via apiClient.setToken()
 *
 * The bridge does NOT:
 *  - Render anything
 *  - Store the keypair itself (the UI must prompt the user to download it)
 *  - Store the JWT in localStorage
 */

import { authApi, setToken } from "./apiClient.js";
import { KeysetManager } from "../key_manager/key_manager.js";

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_POW_DIFFICULTY = 6; // Prevent main-thread DoS
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_REGEX = /^\d{6}$/;
const TOTP_REGEX = /^\d{6}$/;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function assert(condition, message) {
  if (!condition) throw new Error(`registerBridge: ${message}`);
}

/**
 * Safely decode a base64 string to Uint8Array.
 * Handles both raw base64 and base64url.
 */
function base64ToUint8Array(base64) {
  if (base64 instanceof Uint8Array) return base64;
  if (typeof base64 !== "string") {
    throw new Error("base64ToUint8Array: expected string or Uint8Array");
  }
  // Normalize base64url → base64
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  let binary;
  try {
    binary = atob(normalized);
  } catch (err) {
    throw new Error(
      `base64ToUint8Array: invalid base64 string (${err.message})`,
    );
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─── PoW solver ──────────────────────────────────────────────────────────────

/**
 * Finds a nonce such that SHA-256(challenge + nonce) starts with
 * `difficulty` leading zero hex chars.
 *
 * @param {string} challenge   Base64-encoded challenge string from the server
 * @param {number} difficulty  Number of required leading zero hex characters (default 4)
 * @param {AbortSignal} [signal]  Optional abort signal
 * @returns {Promise<string>}  The winning nonce (decimal string)
 */
async function solvePoW(challenge, difficulty = 4, signal) {
  const effectiveDifficulty = Math.max(
    1,
    Math.min(difficulty ?? 4, MAX_POW_DIFFICULTY),
  );

  // Reject server-sent difficulty that exceeds our safety limit
  if ((difficulty ?? 4) > MAX_POW_DIFFICULTY) {
    throw new Error(
      `PoW difficulty ${difficulty} exceeds max ${MAX_POW_DIFFICULTY}. Offload to a Worker.`,
    );
  }

  assert(
    effectiveDifficulty <= MAX_POW_DIFFICULTY,
    `PoW difficulty ${effectiveDifficulty} exceeds max ${MAX_POW_DIFFICULTY}. Offload to a Worker.`,
  );

  const prefix = "0".repeat(effectiveDifficulty);
  const encoder = new TextEncoder();
  let nonce = 0;

  while (true) {
    if (signal?.aborted) {
      throw new Error("PoW solving aborted");
    }

    const input = encoder.encode(challenge + nonce);
    const hashBuffer = await crypto.subtle.digest("SHA-256", input);
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (hashHex.startsWith(prefix)) {
      return String(nonce);
    }
    nonce++;
  }
}

// ─── Registration state machine ──────────────────────────────────────────────
//
// Callers advance the flow step-by-step; each method returns a plain object
// describing what happened. On error it throws (ApiError or KeysetError).
//
// Typical usage from a React component / hook:
//
//   const bridge = new RegisterBridge();
//
//   // Step 1+2 (PoW is transparent to the user)
//   await bridge.startPoW();
//
//   // Step 3
//   await bridge.submitEmail("user@example.com");
//
//   // Step 4 — after user types the code they received
//   await bridge.verifyEmailCode("483920");
//
//   // Step 5 — after user enters TOTP from their authenticator app
//   const { qrCodeUri, manualKey } = bridge.getTotpInfo();  // already set by step 4
//   await bridge.verifyTOTP("123456");
//
//   // Step 6 — set credentials and finalize
//   const { keypair, publicKeys } = await bridge.createAccount("alice", "SecureP@ss!");
//   // ← caller MUST show KeypairDownload now; keypair is the ONLY time private keys surface

export class RegisterBridge {
  constructor() {
    this._sessionToken = null;
    this._totpInfo = null; // { qrCodeUri, manualKey } from step 4
    this._keypair = null; // held temporarily until createAccount resolves
  }

  /**
   * Steps 1 + 2: fetch a PoW challenge, solve it, verify with the server.
   * Returns the sessionToken that must accompany all subsequent steps.
   *
   * @param {object} [opts]  Optional { signal: AbortSignal }
   * @returns {Promise<{ sessionToken: string }>}
   */
  async startPoW(opts = {}) {
    const { challenge_id, challenge, difficulty } = await authApi.initPoW();

    const nonce = await solvePoW(challenge, difficulty, opts.signal);

    const { sessionToken } = await authApi.verifyPoW(challenge_id, nonce);
    this._sessionToken = sessionToken;

    return { sessionToken };
  }

  /**
   * Step 3: submit the user's email address.
   * The server sends a 6-digit verification code to that address.
   *
   * @param {string} email
   * @returns {Promise<{ message: string, expiresIn: number, email: string }>}
   */
  async submitEmail(email) {
    this._assertSession();
    assert(
      typeof email === "string" && email.length > 0,
      "email must be a non-empty string",
    );
    assert(EMAIL_REGEX.test(email), "email format is invalid");

    return authApi.submitEmail(this._sessionToken, email);
  }

  /**
   * Step 4: verify the 6-digit code the user received by email.
   * On success, the server returns TOTP enrollment info (QR URI + manual key).
   *
   * @param {string} code  6-digit string (leading zeros preserved)
   * @returns {Promise<{ message: string, totp: { qrCodeUri: string, manualKey: string } }>}
   */
  async verifyEmailCode(code) {
    this._assertSession();
    assert(typeof code === "string", "code must be a string");
    assert(CODE_REGEX.test(code), "code must be exactly 6 digits");

    const result = await authApi.verifyEmailCode(this._sessionToken, code);
    // Cache TOTP info so the UI can display the QR before the user types the token
    if (result?.totp) {
      this._totpInfo = result.totp;
    }
    return result;
  }

  /**
   * Returns the TOTP enrollment data (QR code URI + manual key) set during
   * step 4. Call this after verifyEmailCode() to render the QR code.
   *
   * @returns {{ qrCodeUri: string, manualKey: string } | null}
   */
  getTotpInfo() {
    return this._totpInfo;
  }

  /**
   * Step 5: verify the TOTP token from the user's authenticator app.
   *
   * @param {string} totpToken  6-digit token
   * @returns {Promise<{ message: string }>}
   */
  async verifyTOTP(totpToken) {
    this._assertSession();
    assert(typeof totpToken === "string", "totpToken must be a string");
    assert(TOTP_REGEX.test(totpToken), "totpToken must be exactly 6 digits");

    return authApi.verifyTOTP(this._sessionToken, totpToken);
  }

  /**
   * Step 6: generate a keypair, set credentials, and create the account.
   *
   * This is the ONLY moment private keys are surfaced. The caller must
   * immediately hand the returned `keypair` to a <KeypairDownload> component
   * or equivalent safe storage prompt. After the user confirms they've saved
   * the keypair, call bridge.clearKeypair() to release the reference.
   *
   * @param {string} username
   * @param {string} password
   * @returns {Promise<{
   *   keypair: { signing: { publicKey, privateKey }, exchange: { publicKey, privateKey } },
   *   publicKeys: { signingPublicKey, exchangePublicKey, userIdHex, username },
   *   userId: string,
   * }>}
   */
  async createAccount(username, password) {
    this._assertSession();
    assert(
      typeof username === "string" && username.length >= 2,
      "username must be a string with at least 2 characters",
    );
    assert(
      typeof password === "string" && password.length >= 8,
      "password must be at least 8 characters",
    );

    // Ensure libsodium is ready
    await KeysetManager.init();

    // Generate the keypair and unlock the session
    const result = await KeysetManager.createUser(username);

    const {
      signingPublicKey,
      exchangePublicKey,
      userIdHex,
      signingPrivateKey,
      exchangePrivateKey,
    } = result;

    // ─── FIX: Normalize all key material to Uint8Array ──────────────────────
    // KeysetManager may return mixed types (base64 strings vs Uint8Arrays).
    // We normalize everything here so the caller gets a consistent interface.

    const signingPubBytes = base64ToUint8Array(signingPublicKey);
    const signingPrivBytes = base64ToUint8Array(signingPrivateKey);
    const exchangePubBytes = base64ToUint8Array(exchangePublicKey);
    const exchangePrivBytes = base64ToUint8Array(exchangePrivateKey);

    const keypair = {
      signing: {
        publicKey: signingPubBytes,
        privateKey: signingPrivBytes,
      },
      exchange: {
        publicKey: exchangePubBytes,
        privateKey: exchangePrivBytes,
      },
    };

    // Hold the keypair temporarily — caller clears it via clearKeypair()
    this._keypair = keypair;

    const publicKeys = {
      signingPublicKey: signingPubBytes,
      exchangePublicKey: exchangePubBytes,
      userIdHex,
      username,
    };

    // Register with server — public keys + credentials in one request
    // The server expects base64 strings for the public keys.
    const serverPublicKeys = {
      signingPublicKey: signingPublicKey, // keep original format for server
      exchangePublicKey: exchangePublicKey,
      userIdHex,
    };

    const { userId, token } = await authApi.createAccount(
      this._sessionToken,
      username,
      password,
      serverPublicKeys,
    );

    // ─── FIX: Store JWT if the server returns one at registration ────────────
    if (token) {
      setToken(token);
    }

    // ─── FIX: Clear session token after successful registration ──────────────
    // The session token is no longer needed; keeping it is a security risk.
    this._sessionToken = null;

    return { keypair, publicKeys, userId };
  }

  /**
   * Call this after the user has confirmed their keypair is saved.
   * Releases the bridge's reference so GC can reclaim the memory.
   * (Private keys in KeysetManager's module scope remain until logoutUser().)
   */
  clearKeypair() {
    this._keypair = null;
  }

  /**
   * Full reset — use if the user wants to start registration over.
   */
  reset() {
    this._sessionToken = null;
    this._totpInfo = null;
    this._keypair = null;
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  _assertSession() {
    if (!this._sessionToken) {
      throw new Error(
        "RegisterBridge: no active session — call startPoW() first",
      );
    }
  }
}

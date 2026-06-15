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
import { KeysetManager, KeysetError, ERRORS } from "../key_manager/key_manager.js";

// ─── PoW solver ──────────────────────────────────────────────────────────────

/**
 * Finds a nonce such that SHA-256(challenge + nonce) starts with
 * `difficulty` leading zero hex chars. Runs on the calling thread —
 * keep difficulty ≤ 6 or offload to a Worker for large values.
 *
 * @param {string} challenge   Base64-encoded challenge string from the server
 * @param {number} difficulty  Number of required leading zero hex characters (default 4)
 * @returns {Promise<string>}  The winning nonce (decimal string)
 */
async function solvePoW(challenge, difficulty = 4) {
  const prefix = "0".repeat(difficulty);
  const encoder = new TextEncoder();
  let nonce = 0;

  while (true) {
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
//   const { qrCodeUri, manualKey } = await bridge.getQRInfo();  // already set by step 4
//   await bridge.verifyTOTP("123456");
//
//   // Step 6 — set credentials and finalize
//   const { keypair, publicKeys } = await bridge.createAccount("alice", "SecureP@ss!");
//   // ← caller MUST show KeypairDownload now; keypair is the ONLY time private keys surface

export class RegisterBridge {
  constructor() {
    this._sessionToken = null;
    this._totpInfo = null; // { qrCodeUri, manualKey } from step 4
    this._keypair = null;  // held temporarily until createAccount resolves
  }

  /**
   * Steps 1 + 2: fetch a PoW challenge, solve it, verify with the server.
   * Returns the sessionToken that must accompany all subsequent steps.
   *
   * @returns {Promise<{ sessionToken: string }>}
   */
  async startPoW() {
    const { challenge_id, challenge, difficulty } = await authApi.initPoW();

    const nonce = await solvePoW(challenge, difficulty ?? 4);

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

    // Build the keypair object the caller needs to persist
    const keypair = {
      signing: {
        publicKey: signingPrivateKey.slice(32),  // Ed25519: last 32 bytes are pub
        privateKey: signingPrivateKey,
      },
      exchange: {
        publicKey: new Uint8Array(
          atob(exchangePublicKey)
            .split("")
            .map((c) => c.charCodeAt(0))
        ),
        privateKey: exchangePrivateKey,
      },
    };

    // Hold the keypair temporarily — caller clears it via clearKeypair()
    this._keypair = keypair;

    const publicKeys = { signingPublicKey, exchangePublicKey, userIdHex, username };

    // Register with server — public keys + credentials in one request
    const { userId } = await authApi.createAccount(
      this._sessionToken,
      username,
      password,
      publicKeys
    );

    // If the server issues a JWT on registration, store it
    // (server may also choose to require an explicit login after registration)

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
        "RegisterBridge: no active session — call startPoW() first"
      );
    }
  }
}

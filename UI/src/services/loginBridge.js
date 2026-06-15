/**
 * loginBridge.js
 *
 * Handles the login flow for returning users.
 *
 * Login is signature-based — no password travels to the server:
 *   1. Build a timestamped login payload (username + ISO timestamp)
 *   2. Sign it with KeysetManager.signPayload() (requires the user's private key)
 *   3. POST { payloadCanon, signature, username } to /auth/login
 *   4. Server re-canonicalizes the payload, looks up the stored public key,
 *      and verifies the Ed25519 signature
 *   5. On success, the server returns a JWT — stored in apiClient via setToken()
 *
 * The caller supplies the keypair (loaded from wherever the user stored it —
 * file upload, paste, hardware wallet bridge, etc.). This module does not
 * touch storage.
 *
 * Usage:
 *   import { login, logout } from './loginBridge.js';
 *
 *   // On login form submit:
 *   const { publicKeys } = await login(username, keypair);
 *
 *   // On logout button / inactivity timer:
 *   await logout();
 */

import { authApi, setToken, clearToken } from "./apiClient.js";
import { KeysetManager, KeysetError, ERRORS } from "../key_manager/key_manager.js";

// ─── Login ────────────────────────────────────────────────────────────────────

/**
 * Loads the keypair into KeysetManager, signs a login challenge, and
 * exchanges the signature for a JWT.
 *
 * @param {string} username
 * @param {{ signing: { publicKey: Uint8Array, privateKey: Uint8Array },
 *            exchange: { publicKey: Uint8Array, privateKey: Uint8Array } }} keypair
 *   The keypair the user saved at registration.
 *
 * @returns {Promise<{
 *   publicKeys: { signingPublicKey: string, exchangePublicKey: string,
 *                 userIdHex: string, username: string }
 * }>}
 *
 * @throws {KeysetError} ERRORS.BAD_KEY_FORMAT — keypair is null/malformed
 * @throws {ApiError}    On server rejection (wrong key, expired timestamp, etc.)
 */
export async function login(username, keypair) {
  // Ensure libsodium is ready
  await KeysetManager.init();

  // Load the keypair into module memory — throws BAD_KEY_FORMAT if malformed
  const publicKeys = await KeysetManager.loginUser(username, keypair);

  // Build a signed login payload.
  // The timestamp lets the server reject replays older than a short window
  // (recommend ≤ 2 minutes server-side).
  const loginPayload = {
    action: "login",
    username,
    issuedAt: new Date().toISOString(),
  };

  let payloadCanon, signature;
  try {
    ({ payloadCanon, signature } = KeysetManager.signPayload(loginPayload));
  } catch (err) {
    // If signing fails, wipe the session and re-throw so the UI can recover
    KeysetManager.logoutUser();
    clearToken();
    throw err;
  }

  // Optional: self-verify before sending (catches key mismatch early)
  const selfCheckOk = KeysetManager.verifySignature(
    payloadCanon,
    signature,
    publicKeys.signingPublicKey
  );
  if (!selfCheckOk) {
    KeysetManager.logoutUser();
    clearToken();
    throw new Error(
      "loginBridge: self-verification of login signature failed — keypair may be corrupt"
    );
  }

  // Exchange the signature for a JWT
  const { token } = await authApi.login(payloadCanon, signature, username);
  setToken(token);

  return { publicKeys };
}

// ─── Logout ───────────────────────────────────────────────────────────────────

/**
 * Wipes private keys from KeysetManager and invalidates the server-side JWT.
 * Safe to call even if the session is already locked (no-op in that case).
 *
 * @returns {Promise<void>}
 */
export async function logout() {
  // Wipe private keys synchronously — this must happen even if the API call fails
  KeysetManager.logoutUser();
  clearToken();

  // Best-effort server-side invalidation — don't let a network failure
  // block the client from completing logout
  try {
    await authApi.logout();
  } catch {
    // Silently ignore — the local session is already destroyed
  }
}

// ─── Session helpers ──────────────────────────────────────────────────────────

/**
 * Returns true if the KeysetManager session is currently unlocked.
 * Thin wrapper so callers don't need to import KeysetManager directly.
 */
export function isSessionActive() {
  return !KeysetManager.isLocked();
}

/**
 * Returns the current session's public keys, or null if locked.
 */
export function getSessionPublicKeys() {
  if (KeysetManager.isLocked()) return null;
  try {
    return KeysetManager.getPublicKeys();
  } catch {
    return null;
  }
}

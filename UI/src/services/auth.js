/**
 * auth.js — Server authentication service.
 *
 * Wraps all /api/auth/* endpoints. Writes to authStore as a side effect.
 * Never touches cryptoStore — that belongs to crypto.js.
 *
 * Token strategy:
 *   - access_token  → in memory only (authStore.accessToken)
 *   - refresh_token → in memory only (authStore._refreshToken)
 *   Page refresh loses both. User must re-login. No localStorage.
 *
 * The _refreshToken field is prefixed with _ to signal "internal" — only
 * http.js reads it for the silent refresh path.
 */

import { httpPublic, http } from './http.js';
import authStore from '../state/authStore.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _setTokens(tokens, user = null) {
  authStore.setState({
    status: 'authenticated',
    accessToken: tokens.access_token,
    _refreshToken: tokens.refresh_token,
    user: user ?? authStore.getState().user,
  });
}

function _clearAuth() {
  authStore.setState({
    status: 'unauthenticated',
    user: null,
    accessToken: null,
    _refreshToken: null,
  });
}

// ─── Login ────────────────────────────────────────────────────────────────────

/**
 * login(email, password)
 *
 * Returns:
 *   { done: true }                    — logged in, tokens set
 *   { done: false, requiresTotp: true, userIdHex } — TOTP step required
 *
 * @throws HttpError on invalid credentials
 */
export async function login(email, password) {
  const data = await httpPublic('/api/auth/login', {
    method: 'POST',
    body: { email, password },
  });

  if (data.requires_totp) {
    // Partial auth — no tokens yet. Store userIdHex for the TOTP step.
    authStore.setState({ _pendingUserIdHex: data.user_id_hex });
    return { done: false, requiresTotp: true, userIdHex: data.user_id_hex };
  }

  _setTokens(data.tokens, data.user);
  return { done: true };
}

/**
 * verifyTotpLogin(userIdHex, totpCode)
 * Completes the TOTP step after login().
 * @throws HttpError on wrong code
 */
export async function verifyTotpLogin(userIdHex, totpCode) {
  const data = await httpPublic('/api/auth/verify-totp-login', {
    method: 'POST',
    body: { user_id_hex: userIdHex, totp_code: totpCode },
  });
  _setTokens(data.tokens, data.user);
  authStore.setState({ _pendingUserIdHex: null });
}

// ─── Register ─────────────────────────────────────────────────────────────────

/**
 * register({ email, username, password, fullName, signingPublicKey, exchangePublicKey })
 *
 * Caller is responsible for:
 *   1. Solving PoW via pow.js before calling this
 *   2. Generating keys via crypto.createUser() before calling this
 *
 * Returns UserResponse. Does NOT set tokens — user must verify email first.
 */
export async function register({
  email,
  username,
  password,
  fullName,
  signingPublicKey,
  exchangePublicKey,
}) {
  const data = await httpPublic('/api/auth/register', {
    method: 'POST',
    body: {
      email,
      username,
      password,
      full_name: fullName,
      signing_public_key: signingPublicKey,
      exchange_public_key: exchangePublicKey,
    },
  });
  // Store username temporarily so the verify-email screen can use it
  authStore.setState({ _pendingUser: data.user });
  return data.user;
}

/**
 * verifyEmail(userIdHex, code)
 * @throws HttpError on wrong code
 */
export async function verifyEmail(userIdHex, code) {
  return httpPublic('/api/auth/verify-email', {
    method: 'POST',
    body: { user_id_hex: userIdHex, code },
  });
}

/**
 * resendVerification(email)
 */
export async function resendVerification(email) {
  return httpPublic('/api/auth/resend-verification', {
    method: 'POST',
    body: { email },
  });
}

// ─── PoW challenge ────────────────────────────────────────────────────────────

/**
 * requestPoWChallenge()
 * @returns {{ challenge_id, challenge, difficulty }}
 */
export async function requestPoWChallenge() {
  return httpPublic('/api/auth/pow/challenge', { method: 'POST' });
}

/**
 * verifyPoWSolution(challengeId, solution)
 * Called by pow.js — not directly by components.
 */
export async function verifyPoWSolution(challengeId, solution) {
  return httpPublic('/api/auth/pow/verify', {
    method: 'POST',
    body: { challenge_id: challengeId, solution },
  });
}

// ─── Logout ───────────────────────────────────────────────────────────────────

/**
 * logout()
 * Best-effort server call, always clears local state.
 */
export async function logout() {
  const { _refreshToken } = authStore.getState();
  try {
    if (_refreshToken) {
      await http('/api/auth/logout', {
        method: 'POST',
        body: { refresh_token: _refreshToken },
      });
    }
  } catch (_) {
    // Ignore — local state is cleared regardless
  } finally {
    _clearAuth();
  }
}

/**
 * logoutAll()
 * Revoke all sessions.
 */
export async function logoutAll() {
  try {
    await http('/api/auth/logout-all', { method: 'POST' });
  } finally {
    _clearAuth();
  }
}

// ─── Password ─────────────────────────────────────────────────────────────────

/**
 * changePassword(currentPassword, newPassword)
 */
export async function changePassword(currentPassword, newPassword) {
  return http('/api/auth/change-password', {
    method: 'POST',
    body: { old_password: currentPassword, new_password: newPassword },
  });
}

/**
 * requestPasswordReset(email)
 */
export async function requestPasswordReset(email) {
  return httpPublic('/api/auth/request-password-reset', {
    method: 'POST',
    body: { email },
  });
}

/**
 * confirmPasswordReset(email, code, newPassword)
 */
export async function confirmPasswordReset(email, code, newPassword) {
  return httpPublic('/api/auth/confirm-password-reset', {
    method: 'POST',
    body: { email, code, new_password: newPassword },
  });
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

/**
 * setupTotp()
 * @returns {{ uri, backup_codes, message }}
 */
export async function setupTotp() {
  return http('/api/auth/totp/setup', { method: 'POST' });
}

/**
 * confirmTotp(totpCode)
 * Activates TOTP after setup.
 */
export async function confirmTotp(totpCode) {
  return http('/api/auth/totp/confirm', {
    method: 'POST',
    body: { totp_code: totpCode },
  });
}

/**
 * disableTotp(password, totpCode)
 */
export async function disableTotp(password, totpCode) {
  return http('/api/auth/totp/disable', {
    method: 'POST',
    body: { password, totp_code: totpCode },
  });
}

// ─── Current user ─────────────────────────────────────────────────────────────

/**
 * getMe()
 * Fetch current user profile from /api/auth/me (auth endpoint, not /api/users/me).
 * Updates authStore.user.
 */
export async function getMe() {
  const data = await http('/api/auth/me');
  authStore.setState({ user: data });
  return data;
}

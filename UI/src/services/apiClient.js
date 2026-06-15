/**
 * apiClient.js
 *
 * Base HTTP client for MedLedger.
 *
 * Responsibilities:
 *  - Attach Authorization: Bearer <jwt> on every request (when a token is held)
 *  - Parse the server's JSON envelope: { ok, data, error }
 *  - Throw ApiError (with .status and .code) on any non-2xx response OR
 *    when the envelope indicates failure (ok === false)
 *  - Expose setToken() / clearToken() so the login/register bridges can
 *    store the JWT after the server returns it, without touching localStorage
 *    themselves
 *
 * What this module does NOT do:
 *  - Crypto (that's KeysetManager)
 *  - Routing / navigation
 *  - Anything that touches the DOM directly
 */

// ─── Configuration ──────────────────────────────────────────────────────────

const BASE_URL = (import.meta.env?.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

// ─── Token store (in-memory only — never written to localStorage) ────────────

let _jwt = null;

/**
 * Store the JWT returned after login / registration.
 * Called by loginBridge and registerBridge once the server issues a token.
 *
 * @param {string} token
 */
export function setToken(token) {
  if (typeof token !== "string" || !token) {
    throw new Error("apiClient.setToken: token must be a non-empty string");
  }
  _jwt = token;
}

/**
 * Wipe the in-memory token.
 * Wire this to KeysetManager.logoutUser() — both should be called together.
 */
export function clearToken() {
  _jwt = null;
}

/**
 * Returns true if a JWT is currently held.
 */
export function hasToken() {
  return _jwt !== null;
}

// ─── Error type ──────────────────────────────────────────────────────────────

export class ApiError extends Error {
  /**
   * @param {string}      message   Human-readable reason
   * @param {number}      status    HTTP status code
   * @param {string|null} code      Server-side error code, e.g. "INVALID_SIGNATURE"
   */
  constructor(message, status, code = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

// ─── Core request helper ─────────────────────────────────────────────────────

/**
 * @param {string} method   "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
 * @param {string} path     e.g. "/auth/login" — leading slash required
 * @param {object} [body]   JSON-serializable request body (omit for GET)
 * @param {object} [opts]   Extra fetch options (e.g. signal for AbortController)
 * @returns {Promise<any>}  Parsed `data` field from the server envelope
 * @throws  {ApiError}      On any non-2xx response, envelope failure, or network failure
 */
async function request(method, path, body = null, opts = {}) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  if (_jwt) {
    headers["Authorization"] = `Bearer ${_jwt}`;
  }

  const fetchOpts = {
    method,
    headers,
    ...opts,
  };

  if (body !== null) {
    fetchOpts.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(`${BASE_URL}${path}`, fetchOpts);
  } catch (networkErr) {
    // Network-level failure (offline, DNS, CORS preflight blocked)
    throw new ApiError(
      `Network error: ${networkErr.message}`,
      0,
      "NETWORK_ERROR"
    );
  }

  let envelope;
  try {
    envelope = await response.json();
  } catch {
    throw new ApiError(
      `Server returned non-JSON response (HTTP ${response.status})`,
      response.status,
      "PARSE_ERROR"
    );
  }

  // ─── FIX: Check both HTTP status AND envelope ok field ────────────────────
  // The server may return HTTP 200 with { ok: false, error: {...} }
  if (!response.ok || envelope?.ok === false) {
    const message =
      envelope?.error?.message ?? envelope?.detail ?? `HTTP ${response.status}`;
    const code = envelope?.error?.code ?? null;
    throw new ApiError(message, response.status, code);
  }

  // Successful response — return the data payload (or the whole envelope if
  // the server doesn't wrap it)
  return envelope?.data ?? envelope;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const api = {
  get: (path, opts) => request("GET", path, null, opts),
  post: (path, body, opts) => request("POST", path, body, opts),
  put: (path, body, opts) => request("PUT", path, body, opts),
  patch: (path, body, opts) => request("PATCH", path, body, opts),
  delete: (path, opts) => request("DELETE", path, null, opts),
};

// ─── Auth-specific endpoints ──────────────────────────────────────────────────
//
// These are thin wrappers — business logic lives in the bridge modules.
// Naming follows the authFlow orchestrator's step vocabulary.

export const authApi = {
  /** Step 1 — get a PoW challenge */
  initPoW: () => api.get("/auth/pow/init"),

  /** Step 2 — submit solved nonce, receive sessionToken */
  verifyPoW: (challengeId, nonce) =>
    api.post("/auth/pow/verify", { challenge_id: challengeId, nonce }),

  /** Step 3 — submit email address for verification */
  submitEmail: (sessionToken, email) =>
    api.post("/auth/email/submit", { session_token: sessionToken, email }),

  /** Step 4 — submit 6-digit email code */
  verifyEmailCode: (sessionToken, code) =>
    api.post("/auth/email/verify", { session_token: sessionToken, code }),

  /** Step 5 — submit TOTP token */
  verifyTOTP: (sessionToken, totpToken) =>
    api.post("/auth/totp/verify", {
      session_token: sessionToken,
      totp_token: totpToken,
    }),

  /**
   * Step 6 — create account.
   * Sends credentials + public crypto keys together so the server can store
   * the public keys alongside the account.
   */
  createAccount: (sessionToken, username, password, publicKeys) =>
    api.post("/auth/account/create", {
      session_token: sessionToken,
      username,
      password,
      signing_public_key: publicKeys.signingPublicKey,
      exchange_public_key: publicKeys.exchangePublicKey,
      user_id_hex: publicKeys.userIdHex,
    }),

  /**
   * Login — returns a JWT (stored via setToken()).
   * Expects the server to verify the Ed25519 signature so no password is
   * transmitted; the payload is signed client-side in loginBridge.
   */
  login: (payloadCanon, signature, username) =>
    api.post("/auth/login", { payload_canon: payloadCanon, signature, username }),

  /** Explicit server-side logout (invalidates JWT) */
  logout: () => api.post("/auth/logout", {}),

  /** Fetch another user's public keys (for encryption) */
  getUserKeys: (username) => api.get(`/users/${username}/keys`),
};

/**
 * http.js — Authenticated fetch wrapper.
 *
 * All API calls go through here. Never call fetch() directly in a service.
 *
 * Behaviour:
 *  - Attaches Authorization: Bearer <token> from authStore automatically.
 *  - On 401: attempts one silent token refresh, retries the original request.
 *  - If retry also 401s: calls authStore logout path and redirects to /login.
 *  - All other errors are thrown as HttpError for the caller to handle.
 *  - Accepts a plain path ('/api/auth/login') or a full URL string.
 *
 * Usage:
 *   import { http } from './http.js';
 *   const data = await http('/api/vault/records');          // GET
 *   const data = await http('/api/auth/login', {           // POST
 *     method: 'POST',
 *     body: { email, password }                            // objects auto-serialised
 *   });
 */

import authStore from '../state/authStore.js';

// ─── Error type ──────────────────────────────────────────────────────────────

export class HttpError extends Error {
  constructor(status, body) {
    super(`HTTP ${status}`);
    this.name = 'HttpError';
    this.status = status;
    this.body = body; // parsed JSON or null
  }
}

// ─── Internals ───────────────────────────────────────────────────────────────

const BASE = ''; // same origin; set to 'http://localhost:8000' in dev if needed

let _isRefreshing = false;
let _refreshWaiters = []; // queued callers waiting for token refresh

/**
 * Low-level fetch — no retry logic, no auth attachment.
 * @returns {Promise<any>} parsed JSON body
 * @throws  {HttpError}
 */
async function _rawFetch(path, options = {}) {
  const { body, headers: extraHeaders = {}, ...rest } = options;

  const headers = {
    'Content-Type': 'application/json',
    ...extraHeaders,
  };

  const init = {
    ...rest,
    headers,
    credentials: 'include', // send httpOnly refresh token cookie automatically
  };

  if (body !== undefined) {
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  const res = await fetch(`${BASE}${path}`, init);

  // Parse body regardless — errors from the server come as JSON too
  let parsed = null;
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    parsed = await res.json();
  }

  if (!res.ok) throw new HttpError(res.status, parsed);
  return parsed;
}

/**
 * Attempt to refresh the access token using the refresh token.
 * The refresh token is in authStore memory (not a cookie — see build plan notes).
 * Returns the new access token string, or throws.
 */
async function _refresh() {
  const { accessToken } = authStore.getState(); // we hold the refresh token alongside
  // The API takes { refresh_token } in the body per the openapi.json schema.
  // We need the refresh token — it's stored in authStore alongside the access token.
  const state = authStore.getState();
  const refreshToken = state._refreshToken; // internal field, set by auth.js

  if (!refreshToken) throw new Error('No refresh token available');

  const data = await _rawFetch('/api/auth/refresh', {
    method: 'POST',
    body: { refresh_token: refreshToken },
  });

  // data is TokenResponse: { access_token, refresh_token, expires_in }
  authStore.setState({
    status: 'authenticated',
    accessToken: data.access_token,
    _refreshToken: data.refresh_token,
  });

  return data.access_token;
}

/**
 * Force logout — wipe auth state and redirect to /login.
 * Imported lazily to avoid circular dependency with auth.js.
 */
async function _forceLogout() {
  authStore.setState({
    status: 'unauthenticated',
    user: null,
    accessToken: null,
    _refreshToken: null,
  });
  window.location.href = '/login';
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Make an authenticated API request.
 *
 * @param {string} path     - e.g. '/api/vault/records'
 * @param {object} [options]
 *   @param {string} [options.method='GET']
 *   @param {object|string} [options.body]  - auto-serialised if object
 *   @param {object} [options.headers]
 * @returns {Promise<any>} parsed JSON
 * @throws {HttpError}
 */
export async function http(path, options = {}) {
  const { accessToken } = authStore.getState();

  const authHeader = accessToken
    ? { Authorization: `Bearer ${accessToken}` }
    : {};

  try {
    return await _rawFetch(path, {
      method: 'GET',
      ...options,
      headers: { ...authHeader, ...(options.headers ?? {}) },
    });
  } catch (err) {
    if (!(err instanceof HttpError) || err.status !== 401) throw err;

    // ── 401 path: attempt one token refresh ──────────────────────────────────
    if (_isRefreshing) {
      // Another request is already refreshing — queue and wait
      return new Promise((resolve, reject) => {
        _refreshWaiters.push({ resolve, reject, path, options });
      });
    }

    _isRefreshing = true;

    let newToken;
    try {
      newToken = await _refresh();
    } catch (_refreshErr) {
      // Refresh failed — log out and reject all queued callers
      _isRefreshing = false;
      const waiters = _refreshWaiters.splice(0);
      for (const w of waiters) w.reject(new HttpError(401, null));
      await _forceLogout();
      throw new HttpError(401, null);
    }

    _isRefreshing = false;

    // Drain the queue with the new token
    const waiters = _refreshWaiters.splice(0);
    for (const w of waiters) {
      http(w.path, w.options).then(w.resolve).catch(w.reject);
    }

    // Retry the original request
    return _rawFetch(path, {
      method: 'GET',
      ...options,
      headers: {
        Authorization: `Bearer ${newToken}`,
        ...(options.headers ?? {}),
      },
    });
  }
}

/**
 * Raw unauthenticated fetch — for auth endpoints that don't need a token.
 * Same signature as http() but no auth header and no 401 retry.
 */
export async function httpPublic(path, options = {}) {
  return _rawFetch(path, { method: 'GET', ...options });
}

/**
 * router.js — Minimal hash-based router.
 *
 * Routes are matched in order. The first match wins.
 * Guards are called before the component is rendered — returning false
 * redirects instead of rendering.
 *
 * Usage:
 *   import { router } from './router.js';
 *   router.on('/login', () => renderLogin());
 *   router.on('/vault', () => renderVault(), { guard: requireAuth });
 *   router.start();
 *
 * In components:
 *   import { navigate } from './router.js';
 *   navigate('/vault');
 */

import authStore from './state/authStore.js';
import cryptoStore from './state/cryptoStore.js';

// ─── Built-in guards ──────────────────────────────────────────────────────────

/**
 * requireAuth — redirect to /login if not authenticated.
 */
export function requireAuth() {
  if (authStore.getState().status !== 'authenticated') {
    navigate('/login');
    return false;
  }
  return true;
}

/**
 * requireUnlocked — redirect to /unlock if crypto session is locked.
 * Implies requireAuth.
 */
export function requireUnlocked() {
  if (!requireAuth()) return false;
  if (cryptoStore.getState().status === 'locked') {
    navigate('/unlock');
    return false;
  }
  return true;
}

/**
 * requireGuest — redirect to /vault if already authenticated + unlocked.
 * Use on /login, /register.
 */
export function requireGuest() {
  const auth = authStore.getState();
  const crypto = cryptoStore.getState();
  if (auth.status === 'authenticated' && crypto.status === 'unlocked') {
    navigate('/vault');
    return false;
  }
  return true;
}

// ─── Router ───────────────────────────────────────────────────────────────────

const _routes = [];

function _getHash() {
  // Normalise: strip leading '#', ensure leading '/'
  const hash = window.location.hash.replace(/^#/, '') || '/';
  return hash.startsWith('/') ? hash : `/${hash}`;
}

function _match(path) {
  for (const route of _routes) {
    const match = _execPattern(route.pattern, path);
    if (match !== null) return { route, params: match };
  }
  return null;
}

/**
 * Very simple pattern matching — supports :param segments.
 * Returns params object on match, null on no match.
 */
function _execPattern(pattern, path) {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = path.split('/').filter(Boolean);

  if (patternParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patternParts.length; i++) {
    const p = patternParts[i];
    if (p.startsWith(':')) {
      params[p.slice(1)] = decodeURIComponent(pathParts[i]);
    } else if (p !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

async function _resolve() {
  const path = _getHash();
  const result = _match(path);

  if (!result) {
    // 404 — redirect to login by default
    navigate('/login');
    return;
  }

  const { route, params } = result;

  // Run guard if provided
  if (route.guard) {
    const allowed = await route.guard(params);
    if (allowed === false) return; // guard already redirected
  }

  // Render
  await route.handler(params);
}

export const router = {
  /**
   * Register a route.
   * @param {string}   pattern  — e.g. '/vault', '/shares/:shareId'
   * @param {function} handler  — called with params object
   * @param {object}   [opts]
   *   @param {function} [opts.guard]  — called before handler, return false to block
   */
  on(pattern, handler, opts = {}) {
    _routes.push({ pattern, handler, guard: opts.guard ?? null });
    return this; // chainable
  },

  start() {
    window.addEventListener('hashchange', _resolve);
    _resolve(); // resolve on load
  },

  stop() {
    window.removeEventListener('hashchange', _resolve);
  },
};

/**
 * navigate(path)
 * Push a new hash route without full page reload.
 * @param {string} path — e.g. '/vault'
 */
export function navigate(path) {
  window.location.hash = path;
}

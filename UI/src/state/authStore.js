/**
 * authStore.js — Server session state.
 *
 * Shape:
 *   status:         'unauthenticated' | 'authenticated'
 *   user:           null | { user_id_hex, username, email, full_name, role,
 *                             is_verified, totp_enabled }
 *   accessToken:    null | string   ← in memory ONLY, never localStorage
 *   _refreshToken:  null | string   ← internal, read only by http.js refresh path
 *   _pendingUserIdHex: null | string  ← TOTP flow interim state
 *   _pendingUser:   null | object   ← registration email-verify flow
 *
 * Fix: _refreshToken was missing from initial state (undefined vs null).
 * http.js reads authStore.getState()._refreshToken — undefined fails the
 * truthiness check differently from null and causes silent refresh failures.
 *
 * Only services/auth.js writes to this store.
 * Components read via subscribe() or getState().
 */

import { Store } from './store.js';

const authStore = new Store({
  status:            'unauthenticated',
  user:              null,
  accessToken:       null,
  _refreshToken:     null,   // FIX: was missing — http.js depends on this being null not undefined
  _pendingUserIdHex: null,   // set during TOTP login flow
  _pendingUser:      null,   // set during registration before email verify
});

export default authStore;

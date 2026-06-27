/**
 * authStore.js — Server session state.
 *
 * Shape:
 *   status:      'unauthenticated' | 'authenticated'
 *   user:        null | { user_id_hex, username, email, full_name, role,
 *                          is_verified, totp_enabled }
 *   accessToken: null | string   ← in memory ONLY, never localStorage
 *
 * Only services/auth.js writes to this store.
 * Components read via subscribe().
 */

import { Store } from './store.js';

const authStore = new Store({
  status: 'unauthenticated',
  user: null,
  accessToken: null,
});

export default authStore;

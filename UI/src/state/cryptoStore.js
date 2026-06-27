/**
 * cryptoStore.js — Crypto session state.
 *
 * Shape:
 *   status:     'locked' | 'unlocked'
 *   publicKeys: null | { signingPublicKey, exchangePublicKey, userIdHex, username }
 *   lockReason: null | 'inactivity' | 'manual'
 *
 * Only services/crypto.js writes to this store.
 * Components read via subscribe().
 */

import { Store } from './store.js';

const cryptoStore = new Store({
  status: 'locked',
  publicKeys: null,
  lockReason: null,
});

export default cryptoStore;

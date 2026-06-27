/**
 * keys.js — Public key lookup service.
 *
 * Used when:
 *   - Creating a share (need recipient's exchange key to re-encrypt DEK)
 *   - Creating a grant (same)
 *   - Verifying a signature (need signer's signing key)
 *   - Updating own keys after key rotation (rare)
 */

import { http } from './http.js';

/**
 * getMyKeys()
 * @returns {PublicKeysResponse}
 */
export async function getMyKeys() {
  return http('/api/keys/my');
}

/**
 * getUserKeys(userIdHex)
 * @returns {PublicKeysResponse}
 */
export async function getUserKeys(userIdHex) {
  return http(`/api/keys/${encodeURIComponent(userIdHex)}`);
}

/**
 * getExchangeKey(userIdHex)
 * @returns {ExchangeKeyResponse}
 */
export async function getExchangeKey(userIdHex) {
  return http(`/api/keys/${encodeURIComponent(userIdHex)}/exchange`);
}

/**
 * getSigningKey(userIdHex)
 * @returns {SigningKeyResponse}
 */
export async function getSigningKey(userIdHex) {
  return http(`/api/keys/${encodeURIComponent(userIdHex)}/signing`);
}

/**
 * updateKeys({ signingPublicKey, exchangePublicKey })
 * Update own public keys (after key rotation).
 * Caller must re-encrypt all existing records for the new key.
 */
export async function updateKeys({ signingPublicKey, exchangePublicKey }) {
  return http('/api/keys/update', {
    method: 'PUT',
    body: {
      signing_public_key: signingPublicKey,
      exchange_public_key: exchangePublicKey,
    },
  });
}

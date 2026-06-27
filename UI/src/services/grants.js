/**
 * grants.js — Grant management service.
 *
 * Grants give a named user (grantee) access to a specific vault record
 * for a defined time window. The DEK is re-encrypted for the grantee's
 * exchange public key before calling createGrant().
 *
 * Caller responsibilities:
 *   - Fetch grantee's exchange key via keys.js
 *   - Re-encrypt DEK for grantee via crypto.encryptRecord() or a dedicated worker cmd
 *   - Sign the grant payload via crypto.signPayload()
 *   - Pass the results into createGrant()
 */

import { http } from './http.js';

/**
 * createGrant({
 *   granteeIdHex, recordId, permissionLevel,
 *   timeStart, timeEnd,            ← ISO strings
 *   dekBundleGrantee,              ← re-encrypted DEK object
 *   signatureHex                   ← from crypto.signPayload()
 * })
 * @returns {GrantResponse}
 */
export async function createGrant({
  granteeIdHex,
  recordId,
  permissionLevel,
  timeStart,
  timeEnd,
  dekBundleGrantee,
  signatureHex,
}) {
  return http('/api/grants', {
    method: 'POST',
    body: {
      grantee_id_hex: granteeIdHex,
      record_id: recordId,
      permission_level: permissionLevel,
      time_start: timeStart,
      time_end: timeEnd,
      dek_bundle_grantee: dekBundleGrantee,
      signature_hex: signatureHex,
    },
  });
}

/**
 * revokeGrant(grantId)
 */
export async function revokeGrant(grantId) {
  return http(`/api/grants/${grantId}`, { method: 'DELETE' });
}

/**
 * getGrant(grantId)
 * @returns {GrantDetailsResponse}
 */
export async function getGrant(grantId) {
  return http(`/api/grants/${grantId}`);
}

/**
 * listMyGrants(asGrantor)
 * @param {boolean} asGrantor — true = grants I gave; false = grants I received
 * @returns {GrantListResponse}
 */
export async function listMyGrants(asGrantor = true) {
  const data = await http(`/api/grants/my?as_grantor=${asGrantor}`);
  return data.grants ?? data;
}

/**
 * checkAccess(recordId)
 * Check whether the current user has an active grant for a record.
 * @returns {AccessCheckResponse}
 */
export async function checkAccess(recordId) {
  return http(`/api/grants/check/${encodeURIComponent(recordId)}`);
}

/**
 * listGrantsForRecord(recordId)
 * List all grants on a specific record (owner-only).
 * @returns {Array<GrantResponse>}
 */
export async function listGrantsForRecord(recordId) {
  const data = await http(`/api/grants/record/${encodeURIComponent(recordId)}`);
  return data.grants ?? data;
}

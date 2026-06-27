/**
 * shares.js — Share management service + notification polling.
 *
 * Share creation requires:
 *   1. crypto.encryptRecord() to re-encrypt the DEK for the recipient
 *   2. crypto.signPayload() to sign the share request
 * Those are the caller's responsibility — this service only handles HTTP.
 *
 * Notification polling uses recursive setTimeout (not setInterval) so
 * requests never overlap on slow networks.
 */

import { http } from './http.js';

// ─── Share CRUD ───────────────────────────────────────────────────────────────

/**
 * createShare({
 *   recordId, recipientUsername,
 *   recipientEncryptedDek, nonce,       ← re-encrypted for recipient
 *   signature, payloadCanon,            ← from crypto.signPayload()
 *   expiresAt                           ← ISO string, optional
 * })
 * @returns {Share}
 */
export async function createShare({
  recordId,
  recipientUsername,
  recipientEncryptedDek,
  nonce,
  signature,
  payloadCanon,
  expiresAt,
}) {
  return http('/api/shares', {
    method: 'POST',
    body: {
      record_id: recordId,
      recipient_username: recipientUsername,
      recipient_encrypted_dek: recipientEncryptedDek,
      nonce,
      signature,
      payload_canon: payloadCanon,
      expires_at: expiresAt,
    },
  });
}

/**
 * listSentShares()
 * @returns {Array<Share>}
 */
export async function listSentShares() {
  const data = await http('/api/shares/sent');
  return data.shares ?? data;
}

/**
 * listReceivedShares()
 * @returns {Array<Share>}
 */
export async function listReceivedShares() {
  const data = await http('/api/shares/received');
  return data.shares ?? data;
}

/**
 * getShare(shareId)
 * @returns {Share}
 */
export async function getShare(shareId) {
  return http(`/api/shares/${shareId}`);
}

/**
 * revokeShare(shareId)
 */
export async function revokeShare(shareId) {
  return http(`/api/shares/${shareId}`, { method: 'DELETE' });
}

/**
 * lookupRecipient(username)
 * Returns the recipient's public exchange key for encrypting the DEK.
 * @returns {{ username, exchangePublicKey, userIdHex }}
 */
export async function lookupRecipient(username) {
  return http(`/api/shares/recipient/${encodeURIComponent(username)}`);
}

// ─── Notification polling ─────────────────────────────────────────────────────

let _stopPolling = null;

/**
 * startNotificationPolling(onNotifications, intervalMs)
 *
 * Polls /api/shares/notifications on a recursive setTimeout schedule.
 * Failures are silenced — polling interruptions shouldn't bother the user.
 * 401s are handled by http.js (force logout).
 *
 * @param {function} onNotifications — called with Array<Notification> when new ones arrive
 * @param {number}   intervalMs      — default 30 000
 */
export function startNotificationPolling(onNotifications, intervalMs = 30_000) {
  if (_stopPolling) {
    console.warn('[shares] Polling already active — call stopNotificationPolling() first');
    return;
  }

  let stopped = false;
  let timeoutId = null;

  async function poll() {
    if (stopped) return;

    try {
      const data = await http('/api/shares/notifications');
      const notifications = data.notifications ?? [];
      if (notifications.length > 0) {
        onNotifications(notifications);
      }
    } catch (_) {
      // Silent — don't surface polling failures to the user
    }

    if (!stopped) {
      timeoutId = setTimeout(poll, intervalMs);
    }
  }

  // First poll immediately, then on the interval
  poll();

  _stopPolling = () => {
    stopped = true;
    if (timeoutId !== null) clearTimeout(timeoutId);
    _stopPolling = null;
  };
}

/**
 * stopNotificationPolling()
 * Call on logout or when the app shell unmounts.
 */
export function stopNotificationPolling() {
  if (_stopPolling) _stopPolling();
}

/**
 * vault.js — Medical records (vault) service.
 *
 * All encryption/decryption is done via services/crypto.js before calling
 * these functions. This service only handles the network I/O.
 *
 * The caller is responsible for:
 *   - Encrypting the file bytes via crypto.encryptRecord() before upload
 *   - Decrypting the returned bytes via crypto.decryptShare() after download
 */

import { http } from './http.js';

/**
 * listRecords()
 * @returns {Array<VaultRecordSummary>}
 */
export async function listRecords() {
  const data = await http('/api/vault/records');
  return data.records ?? data;
}

/**
 * getRecord(recordId)
 * @returns {VaultRecord}
 */
export async function getRecord(recordId) {
  return http(`/api/vault/records/${recordId}`);
}

/**
 * uploadRecord({ title, description, encryptedRecord, nonce, dekBundle,
 *                fileHash, mimeType, fileName })
 *
 * All encrypted fields come from crypto.encryptRecord().
 * @returns {VaultRecord}
 */
export async function uploadRecord({
  title,
  description,
  encryptedRecord,
  nonce,
  dekBundle,
  fileHash,
  mimeType,
  fileName,
}) {
  return http('/api/vault/records', {
    method: 'POST',
    body: {
      title,
      description,
      encrypted_record: encryptedRecord,
      nonce,
      dek_bundle: dekBundle,
      file_hash: fileHash,
      mime_type: mimeType,
      file_name: fileName,
    },
  });
}

/**
 * updateRecord(recordId, { title, description })
 * Only metadata fields can be updated — ciphertext is immutable.
 * @returns {VaultRecord}
 */
export async function updateRecord(recordId, { title, description }) {
  return http(`/api/vault/records/${recordId}`, {
    method: 'PUT',
    body: { title, description },
  });
}

/**
 * deleteRecord(recordId)
 */
export async function deleteRecord(recordId) {
  return http(`/api/vault/records/${recordId}`, { method: 'DELETE' });
}

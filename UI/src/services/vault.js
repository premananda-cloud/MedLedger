/**
 * vault.js — Medical records (vault) service.
 *
 * FIX: CreateVaultRecordRequest field names corrected to match OpenAPI schema.
 * Previous field names (encrypted_record, nonce, file_name) were wrong.
 * Correct names per schema: ciphertext, iv_hex, filename, record_id,
 * owner_key_hash, owner_public_key_hex, size_bytes, mime_type, dek_bundle.
 *
 * The caller (med-vault.js) is responsible for:
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
  return http(`/api/vault/records/${encodeURIComponent(recordId)}`);
}

/**
 * uploadRecord({
 *   recordId,           ← unique ID generated client-side (uuid or crypto random)
 *   ownerKeyHash,       ← hash of owner's signing public key
 *   ownerPublicKeyHex,  ← owner's signing public key hex
 *   filename,           ← original file name
 *   mimeType,
 *   sizeBytes,          ← plaintext file size in bytes
 *   ivHex,              ← nonce/IV as hex string (from encryptRecord)
 *   ciphertext,         ← base64url encrypted content (from encryptRecord)
 *   dekBundle,          ← object: sealed DEK (from encryptRecord)
 *   tags,               ← optional string[]
 * })
 *
 * All encrypted fields come from crypto.encryptRecord().
 * @returns {VaultRecord}
 */
export async function uploadRecord({
  recordId,
  ownerKeyHash,
  ownerPublicKeyHex,
  filename,
  mimeType,
  sizeBytes,
  ivHex,
  ciphertext,
  dekBundle,
  tags,
}) {
  return http('/api/vault/records', {
    method: 'POST',
    body: {
      record_id:            recordId,
      owner_key_hash:       ownerKeyHash,
      owner_public_key_hex: ownerPublicKeyHex,
      filename,
      mime_type:            mimeType,
      size_bytes:           sizeBytes,
      iv_hex:               ivHex,
      ciphertext,
      dek_bundle:           dekBundle,
      ...(tags ? { tags } : {}),
    },
  });
}

/**
 * deleteRecord(recordId)
 */
export async function deleteRecord(recordId) {
  return http(`/api/vault/records/${encodeURIComponent(recordId)}`, {
    method: 'DELETE',
  });
}

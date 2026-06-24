/**
 * shareService.js — MedLedger Record Share Orchestration
 * ────────────────────────────────────────────────────────
 * Assembles and parses the share envelope. Calls keyWorker for all crypto.
 * Has no knowledge of UI, routing, or HTTP — that belongs to the layer above.
 *
 * Share envelope schema (JSON, sent over the wire):
 * {
 *   version:              1,
 *   senderPublicKeys: {
 *     signingPublicKey:   string,   // base64url Ed25519 pub
 *     exchangePublicKey:  string,   // base64url X25519 pub
 *     userIdHex:          string,
 *     username:           string,
 *   },
 *   encryptedPackage: {
 *     encryptedRecord:    string,   // base64url ciphertext
 *     nonce:              string,   // base64url 24-byte nonce
 *     dekBundle:          string,   // base64url sealed DEK
 *     fileHash:           string,   // hex BLAKE2b-256 of plaintext
 *   },
 *   signature:            string,   // base64url Ed25519 sig over canonical envelope
 *   payloadCanon:         string,   // the exact string that was signed
 * }
 *
 * Request envelope schema (JSON, requester → owner):
 * {
 *   version:              1,
 *   requesterPublicKeys: {
 *     signingPublicKey:   string,
 *     exchangePublicKey:  string,
 *     userIdHex:          string,
 *     username:           string,
 *   },
 *   requestedRecordId:    string,
 *   timestamp:            string,   // ISO 8601
 *   signature:            string,
 *   payloadCanon:         string,
 * }
 */

import { keyWorker } from "./keyWorkerClient.js";

const ENVELOPE_VERSION = 1;

// ─────────────────────────────────────────────────────────────────
// Sending a record
// ─────────────────────────────────────────────────────────────────

/**
 * Encrypt a file for a recipient and produce a signed share envelope.
 * Session must be unlocked (signPayload requires it).
 *
 * @param {Uint8Array} fileBytes
 * @param {{
 *   signingPublicKey:  string,
 *   exchangePublicKey: string,
 *   userIdHex:         string,
 *   username:          string,
 * }} recipientPublicKeys   — from the recipient's request envelope
 *
 * @returns {Promise<object>}  Share envelope (ready to JSON.stringify and send)
 */
export async function sendRecord(fileBytes, recipientPublicKeys) {
  // 1. Get sender's public identity (session must be unlocked)
  const senderPublicKeys = await keyWorker.getPublicKeys();

  // 2. Encrypt the file — does not require unlocked session, but session
  //    is already unlocked because step 1 would have thrown otherwise
  const encryptedPackage = await keyWorker.encryptRecord(
    fileBytes,
    recipientPublicKeys.exchangePublicKey,
  );

  // 3. Build the signable payload — everything the recipient needs to verify
  //    and decrypt, minus the signature itself
  const signable = {
    version: ENVELOPE_VERSION,
    senderPublicKeys,
    encryptedPackage,
    recipientUserIdHex: recipientPublicKeys.userIdHex,
  };

  // 4. Sign — canonicalJSON is applied inside the Worker
  const { signature, payloadCanon } = await keyWorker.signPayload(signable);

  return {
    version: ENVELOPE_VERSION,
    senderPublicKeys,
    encryptedPackage,
    recipientUserIdHex: recipientPublicKeys.userIdHex,
    signature,
    payloadCanon,
  };
}

// ─────────────────────────────────────────────────────────────────
// Receiving a record
// ─────────────────────────────────────────────────────────────────

/**
 * Verify and decrypt a received share envelope. Session must be unlocked.
 *
 * @param {object} envelope   — parsed share envelope from the wire
 *
 * @returns {Promise<{
 *   plaintext:   Uint8Array,
 *   fileHash:    string,     // hex — verify against expected hash if known
 *   sender:      object,     // senderPublicKeys from envelope
 * }>}
 *
 * @throws {Error} if signature is invalid or decryption fails
 */
export async function receiveRecord(envelope) {
  validateEnvelopeShape(envelope);

  // 1. Verify signature — does not require unlocked session
  const isValid = await keyWorker.verifySignature(
    envelope.payloadCanon,
    envelope.signature,
    envelope.senderPublicKeys.signingPublicKey,
  );

  if (!isValid) {
    throw new Error("INVALID_SIGNATURE: share envelope signature verification failed");
  }

  // 2. Verify the payloadCanon matches the envelope fields
  //    (prevents signature substitution attacks)
  verifyCanonMatchesEnvelope(envelope);

  // 3. Decrypt — requires unlocked session
  const { encryptedRecord, nonce, dekBundle, fileHash } = envelope.encryptedPackage;
  const plaintext = await keyWorker.decryptShare(encryptedRecord, nonce, dekBundle);

  return {
    plaintext,
    fileHash,
    sender: envelope.senderPublicKeys,
  };
}

// ─────────────────────────────────────────────────────────────────
// Building a request (requester sends to record owner)
// ─────────────────────────────────────────────────────────────────

/**
 * Build a signed access request envelope. Session must be unlocked.
 * The requester's public keys are included so the owner can encrypt for them.
 *
 * @param {string} requestedRecordId   — record/document identifier
 *
 * @returns {Promise<object>}  Request envelope
 */
export async function buildAccessRequest(requestedRecordId) {
  const requesterPublicKeys = await keyWorker.getPublicKeys();

  const signable = {
    version: ENVELOPE_VERSION,
    requesterPublicKeys,
    requestedRecordId,
    timestamp: new Date().toISOString(),
  };

  const { signature, payloadCanon } = await keyWorker.signPayload(signable);

  return {
    ...signable,
    signature,
    payloadCanon,
  };
}

/**
 * Verify an incoming access request from a requester.
 * Returns the verified requester public keys so the owner can call sendRecord().
 *
 * @param {object} requestEnvelope
 *
 * @returns {Promise<{
 *   requesterPublicKeys: object,
 *   requestedRecordId:   string,
 *   timestamp:           string,
 * }>}
 *
 * @throws {Error} if signature is invalid
 */
export async function verifyAccessRequest(requestEnvelope) {
  if (!requestEnvelope?.requesterPublicKeys?.signingPublicKey) {
    throw new Error("INVALID_REQUEST: missing requesterPublicKeys");
  }

  const isValid = await keyWorker.verifySignature(
    requestEnvelope.payloadCanon,
    requestEnvelope.signature,
    requestEnvelope.requesterPublicKeys.signingPublicKey,
  );

  if (!isValid) {
    throw new Error("INVALID_SIGNATURE: access request signature verification failed");
  }

  return {
    requesterPublicKeys: requestEnvelope.requesterPublicKeys,
    requestedRecordId: requestEnvelope.requestedRecordId,
    timestamp: requestEnvelope.timestamp,
  };
}

// ─────────────────────────────────────────────────────────────────
// Internal validation helpers
// ─────────────────────────────────────────────────────────────────

function validateEnvelopeShape(env) {
  if (!env || typeof env !== "object") throw new Error("INVALID_ENVELOPE: not an object");
  if (env.version !== ENVELOPE_VERSION) throw new Error(`INVALID_ENVELOPE: unsupported version ${env.version}`);
  if (!env.senderPublicKeys?.signingPublicKey) throw new Error("INVALID_ENVELOPE: missing senderPublicKeys");
  if (!env.encryptedPackage?.encryptedRecord) throw new Error("INVALID_ENVELOPE: missing encryptedPackage");
  if (!env.signature) throw new Error("INVALID_ENVELOPE: missing signature");
  if (!env.payloadCanon) throw new Error("INVALID_ENVELOPE: missing payloadCanon");
}

function verifyCanonMatchesEnvelope(env) {
  // Parse the payloadCanon and verify the key fields match the envelope
  // This prevents an attacker from swapping the encryptedPackage while
  // keeping a valid signature from a different message
  let canon;
  try {
    canon = JSON.parse(env.payloadCanon);
  } catch {
    throw new Error("INVALID_ENVELOPE: payloadCanon is not valid JSON");
  }

  if (canon.encryptedPackage?.encryptedRecord !== env.encryptedPackage.encryptedRecord) {
    throw new Error("INVALID_ENVELOPE: payloadCanon does not match envelope encryptedPackage");
  }
  if (canon.senderPublicKeys?.signingPublicKey !== env.senderPublicKeys.signingPublicKey) {
    throw new Error("INVALID_ENVELOPE: payloadCanon does not match senderPublicKeys");
  }
}

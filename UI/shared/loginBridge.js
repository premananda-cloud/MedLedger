// shared/loginBridge.js
import { KeysetManager, KeysetError, ERRORS } from "../key_manager/key_manager.js";
import { apiClient } from "./apiClient.js";

/**
 * Unlock the crypto vault by loading a user's keypair.
 * 
 * Flow:
 *   1. Validate keypair file format
 *   2. Decode base64 private keys back to Uint8Array
 *   3. Call KeysetManager.loginUser() to load into memory
 *   4. Fetch server public keys and verify they match
 *   5. Return session public keys
 * 
 * @param {string} username - The username to unlock
 * @param {object} keypairFile - The parsed .medledger-key.json file
 * @param {object} serverPublicKeys - Optional: {signingPublicKey, exchangePublicKey} from server
 * @returns {Promise<{publicKeys: object, username: string, userIdHex: string}>}
 */
export async function unlockVault(username, keypairFile, serverPublicKeys = null) {
  // Validate keypair file structure
  if (!keypairFile || typeof keypairFile !== "object") {
    throw new KeysetError("Invalid keypair file: expected object", ERRORS.BAD_KEY_FORMAT);
  }

  const required = [
    "version", "username", "userIdHex",
    "signingPublicKey", "exchangePublicKey",
    "signingPrivateKey", "exchangePrivateKey"
  ];
  for (const field of required) {
    if (!(field in keypairFile)) {
      throw new KeysetError(
        `Missing field in keypair file: ${field}`,
        ERRORS.BAD_KEY_FORMAT
      );
    }
  }

  if (keypairFile.version !== "medledger-keypair-v1") {
    throw new KeysetError(
      `Unsupported keypair version: ${keypairFile.version}`,
      ERRORS.BAD_KEY_FORMAT
    );
  }

  // Ensure libsodium is ready
  const sodium = await import("libsodium-wrappers-sumo").then((m) => m.default);
  await sodium.ready;

  // Decode base64 private keys back to Uint8Array
  let signingPrivateKey, exchangePrivateKey;
  try {
    signingPrivateKey = sodium.from_base64(
      keypairFile.signingPrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    exchangePrivateKey = sodium.from_base64(
      keypairFile.exchangePrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  } catch (e) {
    throw new KeysetError(
      "Failed to decode private keys from base64",
      ERRORS.BAD_KEY_FORMAT
    );
  }

  // Decode public keys too (loginUser expects Uint8Array)
  let signingPublicKey, exchangePublicKey;
  try {
    signingPublicKey = sodium.from_base64(
      keypairFile.signingPublicKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    exchangePublicKey = sodium.from_base64(
      keypairFile.exchangePublicKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  } catch (e) {
    throw new KeysetError(
      "Failed to decode public keys from base64",
      ERRORS.BAD_KEY_FORMAT
    );
  }

  // Validate key lengths
  if (signingPrivateKey.length !== 64 || signingPublicKey.length !== 32) {
    throw new KeysetError(
      `Invalid Ed25519 key lengths: private=${signingPrivateKey.length}, public=${signingPublicKey.length}`,
      ERRORS.BAD_KEY_FORMAT
    );
  }
  if (exchangePrivateKey.length !== 32 || exchangePublicKey.length !== 32) {
    throw new KeysetError(
      `Invalid X25519 key lengths: private=${exchangePrivateKey.length}, public=${exchangePublicKey.length}`,
      ERRORS.BAD_KEY_FORMAT
    );
  }

  // Build keypair object for KeysetManager
  const keypair = {
    signing: { publicKey: signingPublicKey, privateKey: signingPrivateKey },
    exchange: { publicKey: exchangePublicKey, privateKey: exchangePrivateKey },
  };

  // Initialize if needed
  await KeysetManager.init();

  // Load into KeysetManager (this unlocks the session)
  const session = await KeysetManager.loginUser(username, keypair);

  // If server keys provided, verify they match (anti-tamper)
  if (serverPublicKeys) {
    if (serverPublicKeys.signingPublicKey !== session.signingPublicKey) {
      // Mismatch — lock immediately and throw
      KeysetManager.logoutUser();
      throw new KeysetError(
        "Server signing public key does not match keypair file. Possible tampering.",
        ERRORS.BAD_KEY_FORMAT
      );
    }
    if (serverPublicKeys.exchangePublicKey !== session.exchangePublicKey) {
      KeysetManager.logoutUser();
      throw new KeysetError(
        "Server exchange public key does not match keypair file. Possible tampering.",
        ERRORS.BAD_KEY_FORMAT
      );
    }
  }

  // Wipe the decoded private keys from this function's scope
  // (KeysetManager now holds them; these are copies)
  sodium.memzero(signingPrivateKey);
  sodium.memzero(exchangePrivateKey);

  return {
    publicKeys: {
      signing: session.signingPublicKey,
      exchange: session.exchangePublicKey,
    },
    username: session.username,
    userIdHex: session.userIdHex,
  };
}

/**
 * Lock the vault — wipe all private keys from memory.
 * Synchronous; safe to call even if already locked.
 */
export function lockVault() {
  KeysetManager.logoutUser();
}

/**
 * Check if the vault is currently unlocked.
 * @returns {boolean}
 */
export function isVaultUnlocked() {
  return !KeysetManager.isLocked();
}

/**
 * Re-lock vault after inactivity timeout.
 * Call this from a setTimeout/idle detector in your UI layer.
 */
export function autoLockVault() {
  if (!KeysetManager.isLocked()) {
    KeysetManager.logoutUser();
  }
}

/**
 * Verify a keypair file without unlocking the vault.
 * Useful for "preview" before full unlock.
 * @param {object} keypairFile - Parsed .medledger-key.json
 * @returns {Promise<{valid: boolean, username: string, userIdHex: string, error?: string}>}
 */
export async function previewKeypair(keypairFile) {
  try {
    if (!keypairFile || keypairFile.version !== "medledger-keypair-v1") {
      return { valid: false, username: null, userIdHex: null, error: "Invalid version" };
    }
    const required = ["username", "userIdHex", "signingPublicKey", "exchangePublicKey"];
    for (const f of required) {
      if (!(f in keypairFile)) {
        return { valid: false, username: null, userIdHex: null, error: `Missing ${f}` };
      }
    }
    return {
      valid: true,
      username: keypairFile.username,
      userIdHex: keypairFile.userIdHex,
    };
  } catch (e) {
    return { valid: false, username: null, userIdHex: null, error: e.message };
  }
}

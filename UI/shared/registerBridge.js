// shared/registerBridge.js
import { KeysetManager } from "../key_manager/key_manager.js";
import { authFlow } from "../auth/orchestrator/authFlow.js";
import { apiClient } from "./apiClient.js";

/**
 * Full registration: auth + crypto key generation
 * @param {string} email - For rate-limiting (not verification)
 * @param {string} username - Becomes crypto identity
 * @param {string} password - Used for Argon2id (not PBKDF2)
 * @param {string} powChallengeId - From authFlow.initPOW()
 * @param {string} powNonce - Client-computed solution
 * @returns {Promise<{authResult, keypairResult, keypairSaved}>}
 */
export async function registerUser(
  email,
  username,
  password,
  powChallengeId,
  powNonce,
) {
  // Step 1: Verify PoW (anti-spam gate)
  const powResult = authFlow.verifyPOW(powChallengeId, powNonce);
  if (!powResult.data.sessionToken) {
    throw new Error("PoW verification failed");
  }
  const sessionToken = powResult.data.sessionToken;

  // Step 2: Submit email (rate-limiting)
  const emailResult = authFlow.submitEmail(sessionToken, email);
  if (emailResult.step !== "email_submitted") {
    throw new Error(`Email submission failed: ${emailResult.data.message}`);
  }

  // Step 3: Create auth account
  const authResult = await authFlow.createAccount(
    sessionToken,
    username,
    password,
  );
  if (authResult.step !== "account_created") {
    throw new Error(`Account creation failed: ${authResult.data.message}`);
  }

  // Step 4: Initialize crypto layer
  await KeysetManager.init();

  // Step 5: Generate keypair
  const keypairResult = await KeysetManager.createUser(username);

  // Step 6: Get sodium for base64 encoding
  const sodium = await import("libsodium-wrappers-sumo").then((m) => m.default);
  await sodium.ready;

  // Step 7: Create keypair file for user download
  const keypairFile = {
    version: "medledger-keypair-v1",
    username: keypairResult.username,
    userIdHex: keypairResult.userIdHex,
    signingPublicKey: keypairResult.signingPublicKey,
    exchangePublicKey: keypairResult.exchangePublicKey,
    signingPrivateKey: sodium.to_base64(
      keypairResult.signingPrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    ),
    exchangePrivateKey: sodium.to_base64(
      keypairResult.exchangePrivateKey,
      sodium.base64_variants.URLSAFE_NO_PADDING,
    ),
    createdAt: new Date().toISOString(),
  };

  // Step 8: Trigger browser download
  const blob = new Blob([JSON.stringify(keypairFile, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${username}.medledger-key.json`;
  a.click();
  URL.revokeObjectURL(url);

  // Step 9: Send public keys to server
  await apiClient.post("/api/register/keys", {
    username: keypairResult.username,
    userIdHex: keypairResult.userIdHex,
    signingPublicKey: keypairResult.signingPublicKey,
    exchangePublicKey: keypairResult.exchangePublicKey,
  });

  // Step 10: Wipe private keys from memory (user has file copy)
  keypairFile.signingPrivateKey = null;
  keypairFile.exchangePrivateKey = null;

  return {
    authResult: authResult.data,
    keypairResult: {
      username: keypairResult.username,
      userIdHex: keypairResult.userIdHex,
      signingPublicKey: keypairResult.signingPublicKey,
      exchangePublicKey: keypairResult.exchangePublicKey,
    },
    keypairSaved: true,
  };
}

/**
 * Helper to download keypair (if needed separately)
 */
export function downloadKeypair(keypairResult) {
  const keypairFile = {
    version: "medledger-keypair-v1",
    username: keypairResult.username,
    userIdHex: keypairResult.userIdHex,
    signingPublicKey: keypairResult.signingPublicKey,
    exchangePublicKey: keypairResult.exchangePublicKey,
    signingPrivateKey: keypairResult.signingPrivateKey,
    exchangePrivateKey: keypairResult.exchangePrivateKey,
    createdAt: new Date().toISOString(),
  };

  const blob = new Blob([JSON.stringify(keypairFile, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${keypairResult.username}.medledger-key.json`;
  a.click();
  URL.revokeObjectURL(url);
}

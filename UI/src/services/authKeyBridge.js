// shared/authKeyBridge.js
/**
 * Bridges the authentication system with the crypto key management system.
 * Handles the complete user lifecycle: registration, login, key generation,
 * and session management.
 */

import { getAuthFlow, resetAuthFlow } from "../auth/orchestrator/authFlow.js";
import {
  KeysetManager,
  KeysetError,
  ERRORS,
} from "../key_manager/key_manager.js";
import { generateKeypair } from "../key_manager/make_key.js";

/**
 * AuthKeyBridge - Coordinates auth flow with key generation
 *
 * Registration Flow:
 * 1. Complete auth flow (PoW, email, TOTP, username/password)
 * 2. Generate Ed25519 + X25519 keypair for the user
 * 3. Return keypair for user to store securely
 * 4. User must save keys before proceeding
 *
 * Login Flow:
 * 1. Authenticate with username/password
 * 2. Verify TOTP (if enabled)
 * 3. Load user's keypair from storage (provided by user)
 * 4. Unlock crypto session with the keypair
 */
export class AuthKeyBridge {
  constructor() {
    this.authFlow = getAuthFlow();
    this.pendingRegistration = new Map(); // sessionToken -> { email, username, password }
    this.initialized = false;
  }

  /**
   * Initialize libsodium and auth system
   * Call once at application startup
   */
  async init() {
    if (!this.initialized) {
      await KeysetManager.init();
      this.initialized = true;
    }
    return this;
  }

  /**
   * ====================
   * REGISTRATION FLOW
   * ====================
   */

  /**
   * Step 1: Initialize PoW challenge
   */
  initRegistration() {
    return this.authFlow.initPOW();
  }

  /**
   * Step 2: Verify PoW and create session
   */
  verifyPoW(challengeId, nonce) {
    const result = this.authFlow.verifyPOW(challengeId, nonce);
    if (result.step === "error") {
      throw new Error(result.data.message);
    }
    return result.data.sessionToken;
  }

  /**
   * Step 3: Submit email for verification
   */
  submitEmail(sessionToken, email) {
    const result = this.authFlow.submitEmail(sessionToken, email);
    if (result.step === "error") {
      throw new Error(result.data.message);
    }
    return result.data;
  }

  /**
   * Step 4: Verify email code and get TOTP setup
   */
  verifyEmailCode(sessionToken, code) {
    const result = this.authFlow.verifyEmailCode(sessionToken, code);
    if (result.step === "error") {
      throw new Error(result.data.message);
    }
    return result.data.totp;
  }

  /**
   * Step 5: Verify TOTP and complete auth
   */
  verifyTOTP(sessionToken, totpToken) {
    return this.authFlow.verifyTOTP(sessionToken, totpToken);
  }

  /**
   * Step 6: Create account and generate crypto keys
   * This is the final registration step
   */
  async createAccountWithKeys(sessionToken, username, password) {
    // First, create the auth account
    const authResult = await this.authFlow.createAccount(
      sessionToken,
      username,
      password,
    );

    if (authResult.step === "error") {
      throw new Error(authResult.data.message);
    }

    // Now generate crypto keys for the user
    const keypair = await KeysetManager.createUser(username);

    // Store mapping between auth user and crypto keys
    // In production, this would be saved to your database
    await this.storeKeyMapping(username, {
      userIdHex: keypair.userIdHex,
      signingPublicKey: keypair.signingPublicKey,
      exchangePublicKey: keypair.exchangePublicKey,
      createdAt: Date.now(),
    });

    // Return both auth account info and crypto keys
    return {
      account: {
        userId: authResult.data.userId,
        username: authResult.data.username,
        message: authResult.data.message,
      },
      cryptoKeys: {
        signingPublicKey: keypair.signingPublicKey,
        exchangePublicKey: keypair.exchangePublicKey,
        userIdHex: keypair.userIdHex,
        // PRIVATE KEYS - MUST BE SAVED BY USER
        signingPrivateKey: keypair.signingPrivateKey,
        exchangePrivateKey: keypair.exchangePrivateKey,
      },
      warning:
        "SAVE THESE PRIVATE KEYS IMMEDIATELY - THEY CANNOT BE RECOVERED!",
    };
  }

  /**
   * ====================
   * LOGIN FLOW
   * ====================
   */

  /**
   * Login with username/password and TOTP
   * Returns session info and public keys, but crypto session remains locked
   * until user provides their keypair
   */
  async login(username, password, totpToken) {
    // Step 1: Verify credentials against auth system
    const authValid = await this.verifyAuthCredentials(
      username,
      password,
      totpToken,
    );

    if (!authValid) {
      throw new Error("Invalid credentials");
    }

    // Step 2: Get user's crypto public keys from storage
    const keyMapping = await this.getKeyMapping(username);

    if (!keyMapping) {
      throw new Error(
        "No crypto keys found for this user. Did you save them during registration?",
      );
    }

    // Return auth success with public key info
    // Crypto session is NOT unlocked yet - user must provide private keys
    return {
      authenticated: true,
      username,
      publicKeys: {
        signingPublicKey: keyMapping.signingPublicKey,
        exchangePublicKey: keyMapping.exchangePublicKey,
        userIdHex: keyMapping.userIdHex,
      },
      requiresKeyUnlock: true,
      message:
        "Authentication successful. Please provide your crypto keypair to unlock encryption features.",
    };
  }

  /**
   * Unlock crypto session with user's saved keypair
   * Call this after successful login when user provides their saved keys
   */
  async unlockCryptoSession(username, savedKeypair) {
    try {
      const publicKeys = await KeysetManager.loginUser(username, savedKeypair);
      return {
        unlocked: true,
        publicKeys,
        message: "Crypto session unlocked. You can now encrypt/decrypt files.",
      };
    } catch (error) {
      if (error instanceof KeysetError) {
        switch (error.code) {
          case ERRORS.BAD_KEY_FORMAT:
            throw new Error(
              "Invalid keypair format. Please check your saved keys.",
            );
          case ERRORS.SESSION_LOCKED:
            throw new Error("No session to unlock. Please log in first.");
          default:
            throw error;
        }
      }
      throw error;
    }
  }

  /**
   * ====================
   * HELPER METHODS
   * ====================
   */

  /**
   * Verify auth credentials against the auth system
   * This would integrate with your actual auth database
   */
  async verifyAuthCredentials(username, password, totpToken) {
    // TODO: Implement actual credential verification
    // This should check against your auth database and verify TOTP
    // For now, this is a placeholder
    console.log(
      `Verifying credentials for ${username} with TOTP: ${totpToken}`,
    );

    // In production, this would:
    // 1. Look up user in auth database
    // 2. Verify password hash
    // 3. Verify TOTP token
    // 4. Return true/false

    return true; // Placeholder - replace with actual verification
  }

  /**
   * Store mapping between username and crypto public keys
   * In production, this would save to your database
   */
  async storeKeyMapping(username, keyData) {
    // TODO: Implement database storage
    // This should save to your users table/collection
    console.log(`Storing key mapping for ${username}:`, keyData);

    // Example structure for database:
    // {
    //   username: username,
    //   userIdHex: keyData.userIdHex,
    //   signingPublicKey: keyData.signingPublicKey,
    //   exchangePublicKey: keyData.exchangePublicKey,
    //   createdAt: keyData.createdAt
    // }

    // For demo purposes, store in localStorage (DON'T DO THIS IN PRODUCTION)
    if (typeof window !== "undefined") {
      const keyMap = JSON.parse(
        localStorage.getItem("crypto_key_mapping") || "{}",
      );
      keyMap[username] = keyData;
      localStorage.setItem("crypto_key_mapping", JSON.stringify(keyMap));
    }

    return true;
  }

  /**
   * Retrieve crypto public keys for a user
   * In production, this would query your database
   */
  async getKeyMapping(username) {
    // TODO: Implement database lookup
    console.log(`Retrieving key mapping for ${username}`);

    // For demo purposes, retrieve from localStorage
    if (typeof window !== "undefined") {
      const keyMap = JSON.parse(
        localStorage.getItem("crypto_key_mapping") || "{}",
      );
      return keyMap[username] || null;
    }

    return null;
  }

  /**
   * Logout - clear auth session and crypto session
   */
  logout() {
    KeysetManager.logoutUser();
    // TODO: Clear auth session/cookies
    console.log("Logged out - crypto session cleared");
  }

  /**
   * Check if crypto session is locked
   */
  isCryptoLocked() {
    return KeysetManager.isLocked();
  }

  /**
   * Get current public keys (requires unlocked session)
   */
  getPublicKeys() {
    if (KeysetManager.isLocked()) {
      throw new Error(
        "Crypto session is locked. Please unlock with your keypair.",
      );
    }
    return KeysetManager.getPublicKeys();
  }

  /**
   * Encrypt a record for a recipient
   */
  encryptRecord(fileBytes, recipientPublicKey) {
    return KeysetManager.encryptRecord(fileBytes, recipientPublicKey);
  }

  /**
   * Decrypt a received share (requires unlocked session)
   */
  decryptShare(encryptedRecord, nonce, dekBundle) {
    if (KeysetManager.isLocked()) {
      throw new Error(
        "Cannot decrypt: Crypto session is locked. Please unlock with your keypair.",
      );
    }
    return KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle);
  }

  /**
   * Sign a payload (requires unlocked session)
   */
  signPayload(payload) {
    if (KeysetManager.isLocked()) {
      throw new Error(
        "Cannot sign: Crypto session is locked. Please unlock with your keypair.",
      );
    }
    return KeysetManager.signPayload(payload);
  }

  /**
   * Verify a signature (does not require unlocked session)
   */
  verifySignature(payload, signature, signerPublicKey) {
    return KeysetManager.verifySignature(payload, signature, signerPublicKey);
  }

  /**
   * Reset everything (for testing)
   */
  reset() {
    resetAuthFlow();
    KeysetManager.logoutUser();
    this.pendingRegistration.clear();
    console.log("AuthKeyBridge reset");
  }
}

// Singleton instance
let bridgeInstance = null;

export function getAuthKeyBridge() {
  if (!bridgeInstance) {
    bridgeInstance = new AuthKeyBridge();
  }
  return bridgeInstance;
}

export function resetAuthKeyBridge() {
  if (bridgeInstance) {
    bridgeInstance.reset();
    bridgeInstance = null;
  }
}

/**
 * key_manager.test.js - Unit tests for KeysetManager
 */

import { describe, it, expect, beforeAll, afterEach, beforeEach } from "vitest";
import { KeysetManager, KeysetError, ERRORS } from "./key_manager.js";
import _sodium from "libsodium-wrappers-sumo";

// Helper: given what createUser() returns, build a proper keypair object for
// loginUser(). createUser() surfaces the raw Uint8Array private keys; we
// re-derive the matching public key bytes from them rather than trusting the
// base64 string (which loginUser never receives directly).

function keypairFromCreateResult(result) {
  const sodium = _sodium;

  const sigPriv = result.signingPrivateKey;
  // crypto_sign_ed25519_sk_to_pk extracts the 32-byte public key
  const sigPub = sodium.crypto_sign_ed25519_sk_to_pk(sigPriv);

  const exchPriv = result.exchangePrivateKey;
  const exchPub = sodium.crypto_scalarmult_base(exchPriv);

  return {
    signing: {
      publicKey: sigPub,
      privateKey: sigPriv,
    },
    exchange: {
      publicKey: exchPub,
      privateKey: exchPriv,
    },
  };
}

describe("key_manager.js - KeysetManager", () => {
  let testKeypair;

  beforeAll(async () => {
    await _sodium.ready;
    await KeysetManager.init();
  });

  afterEach(() => {
    // Clean up after each test
    if (!KeysetManager.isLocked()) {
      KeysetManager.logoutUser();
    }
  });

  describe("Initialization", () => {
    it("should initialize successfully", async () => {
      await expect(KeysetManager.init()).resolves.not.toThrow();
      expect(KeysetManager.isLocked()).toBe(true);
    });
  });

  describe("createUser()", () => {
    it("should create a new user with valid keys", async () => {
      const result = await KeysetManager.createUser("alice_test");

      expect(result).toHaveProperty("signingPublicKey");
      expect(result).toHaveProperty("exchangePublicKey");
      expect(result).toHaveProperty("userIdHex");
      expect(result).toHaveProperty("username", "alice_test");
      expect(result).toHaveProperty("signingPrivateKey");
      expect(result).toHaveProperty("exchangePrivateKey");

      expect(KeysetManager.isLocked()).toBe(false);

      // Verify base64url format
      const base64Regex = /^[A-Za-z0-9_-]+$/;
      expect(base64Regex.test(result.signingPublicKey)).toBe(true);
      expect(base64Regex.test(result.exchangePublicKey)).toBe(true);

      // userIdHex should be 32 hex chars (16 bytes)
      expect(result.userIdHex).toMatch(/^[a-f0-9]{32}$/);

      // FIX: derive correct public key bytes instead of re-using the private key
      testKeypair = keypairFromCreateResult(result);
    });

    it("should generate unique userIdHex for different users", async () => {
      const alice = await KeysetManager.createUser("alice_unique");
      const bob = await KeysetManager.createUser("bob_unique");

      expect(alice.userIdHex).not.toBe(bob.userIdHex);

      KeysetManager.logoutUser();
    });
  });

  describe("loginUser()", () => {
    beforeEach(async () => {
      const result = await KeysetManager.createUser("login_test_user");
      // FIX: derive correct public key bytes instead of re-using the private key
      testKeypair = keypairFromCreateResult(result);
      KeysetManager.logoutUser();
    });

    it("should login successfully with valid keypair", async () => {
      expect(KeysetManager.isLocked()).toBe(true);

      const result = await KeysetManager.loginUser(
        "login_test_user",
        testKeypair,
      );

      expect(KeysetManager.isLocked()).toBe(false);
      expect(result).toHaveProperty("signingPublicKey");
      expect(result).toHaveProperty("exchangePublicKey");
      expect(result).toHaveProperty("userIdHex");
      expect(result.username).toBe("login_test_user");
    });

    it("should throw BAD_KEY_FORMAT for missing keypair", async () => {
      await expect(KeysetManager.loginUser("test", null)).rejects.toThrow(
        KeysetError,
      );
      await expect(KeysetManager.loginUser("test", null)).rejects.toMatchObject(
        { code: ERRORS.BAD_KEY_FORMAT },
      );
    });

    it("should throw BAD_KEY_FORMAT for incomplete keypair", async () => {
      const incompleteKeypair = {
        signing: {
          privateKey: new Uint8Array(64),
          publicKey: new Uint8Array(32),
        },
        // missing exchange keys
      };

      await expect(
        KeysetManager.loginUser("test", incompleteKeypair),
      ).rejects.toMatchObject({ code: ERRORS.BAD_KEY_FORMAT });
    });
  });

  describe("logoutUser()", () => {
    it("should wipe private keys and lock session", async () => {
      await KeysetManager.createUser("logout_test");
      expect(KeysetManager.isLocked()).toBe(false);

      KeysetManager.logoutUser();
      expect(KeysetManager.isLocked()).toBe(true);
    });

    it("should be callable multiple times without error", () => {
      KeysetManager.logoutUser();
      KeysetManager.logoutUser();
      expect(KeysetManager.isLocked()).toBe(true);
    });
  });

  describe("encryptRecord()", () => {
    let recipientPubKey;

    beforeAll(async () => {
      const result = await KeysetManager.createUser("recipient");
      recipientPubKey = result.exchangePublicKey;
      KeysetManager.logoutUser();
    });

    beforeEach(async () => {
      await KeysetManager.createUser("sender");
    });

    it("should encrypt a file without requiring unlocked session", async () => {
      KeysetManager.logoutUser();

      const fileBytes = new TextEncoder().encode(
        "Hello, this is a medical record",
      );
      const result = KeysetManager.encryptRecord(fileBytes, recipientPubKey);

      expect(result).toHaveProperty("encryptedRecord");
      expect(result).toHaveProperty("nonce");
      expect(result).toHaveProperty("dekBundle");
      expect(result).toHaveProperty("fileHash");
      expect(result.fileHash).toMatch(/^[a-f0-9]{64}$/);

      // Base64url should not have padding
      expect(result.encryptedRecord).not.toContain("=");
      expect(result.nonce).not.toContain("=");
      expect(result.dekBundle).not.toContain("=");
    });

    it("should produce different ciphertext for same file", () => {
      const fileBytes = new TextEncoder().encode("Same content");

      const result1 = KeysetManager.encryptRecord(fileBytes, recipientPubKey);
      const result2 = KeysetManager.encryptRecord(fileBytes, recipientPubKey);

      expect(result1.nonce).not.toBe(result2.nonce);
      expect(result1.encryptedRecord).not.toBe(result2.encryptedRecord);
      expect(result1.fileHash).toBe(result2.fileHash);
    });
  });

  // FIX: restructured the entire describe block — the original had its closing
  // brace too early, leaving the success test body and a stray closing brace
  // floating outside any it() / describe() context, causing a parse error.
  describe("decryptShare()", () => {
    let recipientKeypair;
    let encryptedData;

    beforeAll(async () => {
      const recipient = await KeysetManager.createUser("recipient_decrypt");
      // FIX: derive correct public key bytes from private keys
      recipientKeypair = keypairFromCreateResult(recipient);
      KeysetManager.logoutUser();

      const fileBytes = new TextEncoder().encode("Top secret medical data");
      encryptedData = KeysetManager.encryptRecord(
        fileBytes,
        recipient.exchangePublicKey,
      );
    });

    it("should decrypt successfully with correct recipient session", async () => {
      await KeysetManager.loginUser("recipient_decrypt", recipientKeypair);

      const plaintext = KeysetManager.decryptShare(
        encryptedData.encryptedRecord,
        encryptedData.nonce,
        encryptedData.dekBundle,
      );

      const decryptedString = new TextDecoder().decode(plaintext);
      expect(decryptedString).toBe("Top secret medical data");
    });

    it("should throw DECRYPTION_FAILED for wrong recipient", async () => {
      const wrongUser = await KeysetManager.createUser("wrong_user");
      // FIX: use properly derived public key, not zeroed Uint8Array
      const wrongKeypair = keypairFromCreateResult(wrongUser);
      await KeysetManager.loginUser("wrong_user", wrongKeypair);

      // FIX: use toThrowError(expect.objectContaining(...)) — toMatchObject()
      // asserts on a return value, not a thrown error
      expect(() => {
        KeysetManager.decryptShare(
          encryptedData.encryptedRecord,
          encryptedData.nonce,
          encryptedData.dekBundle,
        );
      }).toThrowError(
        expect.objectContaining({ code: ERRORS.DECRYPTION_FAILED }),
      );
    });

    it("should throw SESSION_LOCKED when session is locked", () => {
      KeysetManager.logoutUser();

      // FIX: use toThrowError(expect.objectContaining(...))
      expect(() => {
        KeysetManager.decryptShare("test", "test", "test");
      }).toThrowError(expect.objectContaining({ code: ERRORS.SESSION_LOCKED }));
    });
  });

  describe("signPayload() and verifySignature()", () => {
    beforeEach(async () => {
      await KeysetManager.createUser("sign_test_user");
    });

    it("should sign a payload and verify successfully", () => {
      const payload = {
        action: "create_share",
        ownerUsername: "alice",
        recipientUsername: "bob",
        fileHash: "abc123",
        expiresAt: "2026-07-10T00:00:00Z",
      };

      const { payloadCanon, signature } = KeysetManager.signPayload(payload);

      expect(payloadCanon).toBeDefined();
      expect(signature).toBeDefined();
      expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);

      const publicKeys = KeysetManager.getPublicKeys();
      const isValid = KeysetManager.verifySignature(
        payloadCanon,
        signature,
        publicKeys.signingPublicKey,
      );

      expect(isValid).toBe(true);
    });

    it("should produce canonical JSON with sorted keys", () => {
      const payload1 = { b: 2, a: 1, c: { z: 26, y: 25 } };
      const payload2 = { a: 1, c: { y: 25, z: 26 }, b: 2 };

      const result1 = KeysetManager.signPayload(payload1);
      const result2 = KeysetManager.signPayload(payload2);

      expect(result1.payloadCanon).toBe(result2.payloadCanon);
      expect(result1.signature).toBe(result2.signature);
    });

    it("should throw SESSION_LOCKED when locked", () => {
      KeysetManager.logoutUser();

      // FIX: use toThrowError(expect.objectContaining(...))
      expect(() => {
        KeysetManager.signPayload({ test: "data" });
      }).toThrowError(expect.objectContaining({ code: ERRORS.SESSION_LOCKED }));
    });

    it("should verify signature from object (not pre-canonicalized)", () => {
      const payload = { foo: "bar", num: 42 };
      const { signature } = KeysetManager.signPayload(payload);
      const publicKeys = KeysetManager.getPublicKeys();

      const isValid = KeysetManager.verifySignature(
        payload,
        signature,
        publicKeys.signingPublicKey,
      );

      expect(isValid).toBe(true);
    });

    it("should return false for invalid signature", () => {
      const payload = { test: "data" };
      const { signature } = KeysetManager.signPayload(payload);
      const publicKeys = KeysetManager.getPublicKeys();

      const tamperedSig = signature.slice(0, -5) + "xxxxx";

      const isValid = KeysetManager.verifySignature(
        payload,
        tamperedSig,
        publicKeys.signingPublicKey,
      );

      expect(isValid).toBe(false);
    });
  });

  describe("getPublicKeys()", () => {
    it("should return public keys when session unlocked", async () => {
      const created = await KeysetManager.createUser("public_test");

      const publicKeys = KeysetManager.getPublicKeys();

      expect(publicKeys).toHaveProperty("signingPublicKey");
      expect(publicKeys).toHaveProperty("exchangePublicKey");
      expect(publicKeys).toHaveProperty("userIdHex");
      expect(publicKeys).toHaveProperty("username", "public_test");

      expect(publicKeys.signingPublicKey).toBe(created.signingPublicKey);
      expect(publicKeys.exchangePublicKey).toBe(created.exchangePublicKey);
      expect(publicKeys.userIdHex).toBe(created.userIdHex);
    });

    it("should throw SESSION_LOCKED when locked", () => {
      KeysetManager.logoutUser();

      // FIX: use toThrowError(expect.objectContaining(...))
      expect(() => {
        KeysetManager.getPublicKeys();
      }).toThrowError(expect.objectContaining({ code: ERRORS.SESSION_LOCKED }));
    });
  });

  describe("Full roundtrip encryption/decryption", () => {
    it("should handle complete encryption/decryption flow", async () => {
      const alice = await KeysetManager.createUser("alice_roundtrip");
      const bob = await KeysetManager.createUser("bob_roundtrip");

      // FIX: derive correct public key bytes from private keys instead of
      // using zeroed Uint8Array(32), which would cause crypto_box_seal_open
      // to fail (wrong public key → can't unseal the DEK).
      const bobKeypair = keypairFromCreateResult(bob);

      KeysetManager.logoutUser();
      await KeysetManager.loginUser("bob_roundtrip", bobKeypair);

      const fileBytes = new TextEncoder().encode(
        "Secret message from Alice to Bob",
      );
      const encrypted = KeysetManager.encryptRecord(
        fileBytes,
        bob.exchangePublicKey,
      );

      const decrypted = KeysetManager.decryptShare(
        encrypted.encryptedRecord,
        encrypted.nonce,
        encrypted.dekBundle,
      );

      expect(new TextDecoder().decode(decrypted)).toBe(
        "Secret message from Alice to Bob",
      );

      const sodium = _sodium;
      const expectedHash = sodium.to_hex(
        sodium.crypto_generichash(32, new Uint8Array(fileBytes)),
      );
      expect(encrypted.fileHash).toBe(expectedHash);
    });
  });
});

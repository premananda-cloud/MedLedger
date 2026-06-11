/**
 * make_key.test.js - Unit tests for key generation module
 */

import { describe, it, expect, beforeAll } from "vitest";
import { generateKeypair } from "./make_key.js";
import _sodium from "libsodium-wrappers-sumo";

describe("make_key.js - Key Generation", () => {
  beforeAll(async () => {
    await _sodium.ready;
  });

  describe("generateKeypair()", () => {
    it("should generate both signing and exchange keypairs", () => {
      const keypair = generateKeypair();

      expect(keypair).toHaveProperty("signing");
      expect(keypair).toHaveProperty("exchange");
      expect(keypair.signing).toHaveProperty("publicKey");
      expect(keypair.signing).toHaveProperty("privateKey");
      expect(keypair.exchange).toHaveProperty("publicKey");
      expect(keypair.exchange).toHaveProperty("privateKey");
    });

    it("should generate Ed25519 signing keys of correct length", () => {
      const keypair = generateKeypair();

      expect(keypair.signing.publicKey).toBeInstanceOf(Uint8Array);
      expect(keypair.signing.publicKey.length).toBe(32);
      expect(keypair.signing.privateKey).toBeInstanceOf(Uint8Array);
      expect(keypair.signing.privateKey.length).toBe(64);
    });

    it("should generate X25519 exchange keys of correct length", () => {
      const keypair = generateKeypair();

      expect(keypair.exchange.publicKey).toBeInstanceOf(Uint8Array);
      expect(keypair.exchange.publicKey.length).toBe(32);
      expect(keypair.exchange.privateKey).toBeInstanceOf(Uint8Array);
      expect(keypair.exchange.privateKey.length).toBe(32);
    });

    it("should generate different keys each time", () => {
      const keypair1 = generateKeypair();
      const keypair2 = generateKeypair();

      expect(keypair1.signing.publicKey).not.toEqual(
        keypair2.signing.publicKey,
      );
      expect(keypair1.signing.privateKey).not.toEqual(
        keypair2.signing.privateKey,
      );
      expect(keypair1.exchange.publicKey).not.toEqual(
        keypair2.exchange.publicKey,
      );
      expect(keypair1.exchange.privateKey).not.toEqual(
        keypair2.exchange.privateKey,
      );
    });

    it("should generate valid Ed25519 keypair (can sign and verify)", async () => {
      const sodium = _sodium;
      const keypair = generateKeypair();
      const message = new TextEncoder().encode("test message");

      const signature = sodium.crypto_sign_detached(
        message,
        keypair.signing.privateKey,
      );

      const isValid = sodium.crypto_sign_verify_detached(
        signature,
        message,
        keypair.signing.publicKey,
      );

      expect(isValid).toBe(true);
    });

    it("should generate valid X25519 keypair (can encrypt and decrypt)", async () => {
      const sodium = _sodium;
      const alice = generateKeypair();
      const bob = generateKeypair();
      const message = new TextEncoder().encode("secret message");

      const ciphertext = sodium.crypto_box_seal(
        message,
        bob.exchange.publicKey,
      );

      const decrypted = sodium.crypto_box_seal_open(
        ciphertext,
        bob.exchange.publicKey,
        bob.exchange.privateKey,
      );

      expect(decrypted).toEqual(message);
    });
  });
});

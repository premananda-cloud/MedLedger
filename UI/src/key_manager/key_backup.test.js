/**
 * key_backup.test.js — Unit tests for key_backup.js
 *
 * These tests run in the Vitest/Node environment where libsodium-wrappers-sumo
 * works normally. The roundtrip test is the most important: it proves that a
 * bundle produced by encryptKeypairToBundle can be recovered by
 * decryptBundleToKeypair with the correct passphrase, and cannot be recovered
 * with a wrong passphrase.
 */

import { describe, it, expect, beforeAll } from "vitest";
import _sodium from "libsodium-wrappers-sumo";
import {
  encryptKeypairToBundle,
  decryptBundleToKeypair,
} from "./key_backup.js";

// ─────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────

const PASSPHRASE = "correct-horse-battery-staple";
const WRONG_PASSPHRASE = "wrong-passphrase";

function makeTestKeypair() {
  const signing = _sodium.crypto_sign_keypair();
  const exchange = _sodium.crypto_box_keypair();
  return {
    signing: {
      privateKey: signing.privateKey, // 64 bytes
      publicKey: signing.publicKey,   // 32 bytes
    },
    exchange: {
      privateKey: exchange.privateKey, // 32 bytes
      publicKey: exchange.publicKey,   // 32 bytes
    },
  };
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

describe("key_backup.js", () => {
  beforeAll(async () => {
    await _sodium.ready;
  });

  describe("encryptKeypairToBundle()", () => {
    it("should return a Uint8Array of the correct length (189 bytes)", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      expect(bundle).toBeInstanceOf(Uint8Array);
      expect(bundle.length).toBe(189);
    });

    it("should start with MLED magic bytes", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      expect(bundle[0]).toBe(0x4d); // M
      expect(bundle[1]).toBe(0x4c); // L
      expect(bundle[2]).toBe(0x45); // E
      expect(bundle[3]).toBe(0x44); // D
    });

    it("should embed version byte 0x01 at offset 4", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      expect(bundle[4]).toBe(0x01);
    });

    it("should produce different bundles on every call (random salt + nonce)", () => {
      const keypair = makeTestKeypair();
      const bundle1 = encryptKeypairToBundle(keypair, PASSPHRASE);
      const bundle2 = encryptKeypairToBundle(keypair, PASSPHRASE);
      // Bundles differ because salt and nonce are random
      expect(Buffer.from(bundle1).toString("hex")).not.toBe(
        Buffer.from(bundle2).toString("hex"),
      );
    });

    it("should throw if signing private key is wrong length", () => {
      const keypair = makeTestKeypair();
      keypair.signing.privateKey = new Uint8Array(32); // wrong — should be 64
      expect(() => encryptKeypairToBundle(keypair, PASSPHRASE)).toThrow(
        /signing.privateKey must be 64 bytes/,
      );
    });

    it("should throw if exchange private key is wrong length", () => {
      const keypair = makeTestKeypair();
      keypair.exchange.privateKey = new Uint8Array(16); // wrong — should be 32
      expect(() => encryptKeypairToBundle(keypair, PASSPHRASE)).toThrow(
        /exchange.privateKey must be 32 bytes/,
      );
    });
  });

  describe("decryptBundleToKeypair()", () => {
    it("should recover signing and exchange private keys with correct passphrase", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const recovered = decryptBundleToKeypair(bundle, PASSPHRASE);

      expect(recovered.signing.privateKey).toBeInstanceOf(Uint8Array);
      expect(recovered.exchange.privateKey).toBeInstanceOf(Uint8Array);
      expect(recovered.signing.privateKey.length).toBe(64);
      expect(recovered.exchange.privateKey.length).toBe(32);

      // Recovered private keys must match originals byte-for-byte
      expect(Buffer.from(recovered.signing.privateKey).toString("hex")).toBe(
        Buffer.from(keypair.signing.privateKey).toString("hex"),
      );
      expect(Buffer.from(recovered.exchange.privateKey).toString("hex")).toBe(
        Buffer.from(keypair.exchange.privateKey).toString("hex"),
      );
    });

    it("should throw WRONG_PASSPHRASE with incorrect passphrase", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      expect(() => decryptBundleToKeypair(bundle, WRONG_PASSPHRASE)).toThrow(
        /WRONG_PASSPHRASE/,
      );
    });

    it("should throw INVALID_BUNDLE for a truncated bundle", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const truncated = bundle.slice(0, 100);
      expect(() => decryptBundleToKeypair(truncated, PASSPHRASE)).toThrow(
        /INVALID_BUNDLE/,
      );
    });

    it("should throw INVALID_BUNDLE for wrong magic bytes", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const corrupted = new Uint8Array(bundle);
      corrupted[0] = 0xff; // corrupt first magic byte
      expect(() => decryptBundleToKeypair(corrupted, PASSPHRASE)).toThrow(
        /INVALID_BUNDLE.*magic/,
      );
    });

    it("should throw WRONG_PASSPHRASE for tampered ciphertext", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const tampered = new Uint8Array(bundle);
      // Flip a byte in the ciphertext region (after 45-byte header)
      tampered[50] ^= 0xff;
      expect(() => decryptBundleToKeypair(tampered, PASSPHRASE)).toThrow(
        /WRONG_PASSPHRASE/,
      );
    });

    it("should throw INVALID_BUNDLE for unsupported version", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const badVersion = new Uint8Array(bundle);
      badVersion[4] = 0x02; // unsupported version
      expect(() => decryptBundleToKeypair(badVersion, PASSPHRASE)).toThrow(
        /INVALID_BUNDLE.*version/,
      );
    });
  });

  describe("Full roundtrip", () => {
    it("should produce keys that still sign and verify after roundtrip", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const recovered = decryptBundleToKeypair(bundle, PASSPHRASE);

      // Re-derive public key from recovered private key
      const recoveredPub = _sodium.crypto_sign_ed25519_sk_to_pk(
        recovered.signing.privateKey,
      );

      const message = new TextEncoder().encode("test medical record");
      const sig = _sodium.crypto_sign_detached(
        message,
        recovered.signing.privateKey,
      );
      const valid = _sodium.crypto_sign_verify_detached(
        sig,
        message,
        recoveredPub,
      );
      expect(valid).toBe(true);
    });

    it("should produce exchange keys that still encrypt/decrypt after roundtrip", () => {
      const keypair = makeTestKeypair();
      const bundle = encryptKeypairToBundle(keypair, PASSPHRASE);
      const recovered = decryptBundleToKeypair(bundle, PASSPHRASE);

      const recoveredExchPub = _sodium.crypto_scalarmult_base(
        recovered.exchange.privateKey,
      );

      const message = new TextEncoder().encode("secret data");
      const sealed = _sodium.crypto_box_seal(message, recoveredExchPub);
      const opened = _sodium.crypto_box_seal_open(
        sealed,
        recoveredExchPub,
        recovered.exchange.privateKey,
      );
      expect(new Uint8Array(opened)).toEqual(new Uint8Array(message));
    });
  });
});

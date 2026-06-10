/**
 * make_key.test.js — Unit tests for make_key.js
 *
 * Runner: Vitest  (or Jest with --experimental-vm-modules)
 * Install: npm install -D vitest libsodium-wrappers
 * Run:     npx vitest run make_key.test.js
 *
 * These tests run the real libsodium — no mocks on the crypto layer.
 * Argon2id is slow by design; expect ~2–4 s per deriveKeys() call.
 */

import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { deriveKeys } from "./make_key.js";

// ─────────────────────────────────────────────────────────────────
// Setup
// ─────────────────────────────────────────────────────────────────

beforeAll(async () => {
  await sodium.ready;
});

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

/** Returns true if a Uint8Array is all zeros (wiped). */
function isZeroed(buf) {
  return buf.every((b) => b === 0);
}

/** Make a fixed 32-byte server salt for deterministic tests. */
function mockServerSalt(fill = 0xab) {
  return new Uint8Array(32).fill(fill);
}

// ─────────────────────────────────────────────────────────────────
// Suite 1 — Return shape
// ─────────────────────────────────────────────────────────────────

describe("deriveKeys — return shape", () => {
  it("returns signing and exchange keypairs", async () => {
    const result = deriveKeys("alice", "hunter2");

    expect(result).toHaveProperty("signing");
    expect(result).toHaveProperty("exchange");
  });

  it("signing keypair has correct byte lengths (Ed25519)", async () => {
    const { signing } = deriveKeys("alice", "hunter2");

    // Ed25519 public key: 32 bytes
    expect(signing.publicKey).toBeInstanceOf(Uint8Array);
    expect(signing.publicKey.byteLength).toBe(32);

    // Ed25519 private key: 64 bytes (seed + public key, libsodium convention)
    expect(signing.privateKey).toBeInstanceOf(Uint8Array);
    expect(signing.privateKey.byteLength).toBe(64);
  });

  it("exchange keypair has correct byte lengths (X25519)", async () => {
    const { exchange } = deriveKeys("alice", "hunter2");

    // X25519 public key: 32 bytes
    expect(exchange.publicKey).toBeInstanceOf(Uint8Array);
    expect(exchange.publicKey.byteLength).toBe(32);

    // X25519 private key: 32 bytes
    expect(exchange.privateKey).toBeInstanceOf(Uint8Array);
    expect(exchange.privateKey.byteLength).toBe(32);
  });

  it("signing and exchange public keys are different", async () => {
    const { signing, exchange } = deriveKeys("alice", "hunter2");
    expect(signing.publicKey).not.toEqual(exchange.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 2 — Determinism
// ─────────────────────────────────────────────────────────────────

describe("deriveKeys — determinism", () => {
  it("same credentials produce identical keys (no serverSalt)", async () => {
    const a = deriveKeys("alice", "hunter2");
    const b = deriveKeys("alice", "hunter2");

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
    expect(a.exchange.publicKey).toEqual(b.exchange.publicKey);
    // Private keys should also match
    expect(a.signing.privateKey).toEqual(b.signing.privateKey);
    expect(a.exchange.privateKey).toEqual(b.exchange.privateKey);
  });

  it("same credentials + same serverSalt produce identical keys", async () => {
    const salt = mockServerSalt(0x42);
    const a = deriveKeys("alice", "hunter2", salt);
    const b = deriveKeys("alice", "hunter2", salt);

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
    expect(a.exchange.publicKey).toEqual(b.exchange.publicKey);
  });

  it("different passwords produce different keys", async () => {
    const a = deriveKeys("alice", "hunter2");
    const b = deriveKeys("alice", "correcthorsebatterystaple");

    expect(a.signing.publicKey).not.toEqual(b.signing.publicKey);
    expect(a.exchange.publicKey).not.toEqual(b.exchange.publicKey);
  });

  it("different usernames produce different keys", async () => {
    const a = deriveKeys("alice", "hunter2");
    const b = deriveKeys("bob", "hunter2");

    expect(a.signing.publicKey).not.toEqual(b.signing.publicKey);
    expect(a.exchange.publicKey).not.toEqual(b.exchange.publicKey);
  });

  it("different serverSalts produce different keys", async () => {
    const a = deriveKeys("alice", "hunter2", mockServerSalt(0x01));
    const b = deriveKeys("alice", "hunter2", mockServerSalt(0x02));

    expect(a.signing.publicKey).not.toEqual(b.signing.publicKey);
    expect(a.exchange.publicKey).not.toEqual(b.exchange.publicKey);
  });

  it("with serverSalt produces different keys than without", async () => {
    const a = deriveKeys("alice", "hunter2");
    const b = deriveKeys("alice", "hunter2", mockServerSalt());

    expect(a.signing.publicKey).not.toEqual(b.signing.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 3 — Username canonicalisation
// ─────────────────────────────────────────────────────────────────

describe("deriveKeys — username canonicalisation", () => {
  it("trims leading/trailing whitespace", async () => {
    const a = deriveKeys("alice", "pw");
    const b = deriveKeys("  alice  ", "pw");

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
  });

  it("lowercases username", async () => {
    const a = deriveKeys("alice", "pw");
    const b = deriveKeys("ALICE", "pw");

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
  });

  it("mixed case + whitespace normalises correctly", async () => {
    const a = deriveKeys("alice", "pw");
    const b = deriveKeys(" Alice  ", "pw");

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 4 — Server salt handling
// ─────────────────────────────────────────────────────────────────

describe("deriveKeys — serverSalt handling", () => {
  it("accepts null serverSalt (falls back to deterministic salt)", async () => {
    expect(() => deriveKeys("alice", "pw", null)).not.toThrow();
  });

  it("accepts undefined serverSalt (default param)", async () => {
    expect(() => deriveKeys("alice", "pw", undefined)).not.toThrow();
  });

  it("ignores serverSalt if it is not a Uint8Array", async () => {
    // Should not throw — falls back to deterministic salt
    const withString = deriveKeys("alice", "pw", "not-a-uint8array");
    const withNull = deriveKeys("alice", "pw", null);

    expect(withString.signing.publicKey).toEqual(withNull.signing.publicKey);
  });

  it("ignores serverSalt if it is shorter than 16 bytes", async () => {
    const shortSalt = new Uint8Array(8).fill(0xff); // too short
    const withShort = deriveKeys("alice", "pw", shortSalt);
    const withNull = deriveKeys("alice", "pw", null);

    expect(withShort.signing.publicKey).toEqual(withNull.signing.publicKey);
  });

  it("accepts exactly 16-byte serverSalt", async () => {
    const salt = new Uint8Array(16).fill(0x77);
    expect(() => deriveKeys("alice", "pw", salt)).not.toThrow();
  });

  it("accepts 32-byte serverSalt (spec recommended size)", async () => {
    const salt = mockServerSalt();
    expect(() => deriveKeys("alice", "pw", salt)).not.toThrow();
  });

  it("only first 16 bytes of a long salt are used", async () => {
    // Build two salts that differ only after byte 16 — should produce same keys
    const saltA = new Uint8Array(32).fill(0x11);
    const saltB = new Uint8Array(32).fill(0x11);
    saltB[16] = 0xff; // differs after the 16-byte boundary

    const a = deriveKeys("alice", "pw", saltA);
    const b = deriveKeys("alice", "pw", saltB);

    expect(a.signing.publicKey).toEqual(b.signing.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 5 — Returned keys are usable (crypto smoke tests)
// ─────────────────────────────────────────────────────────────────

describe("deriveKeys — returned keys are cryptographically valid", () => {
  it("Ed25519 signing key can sign and verify", async () => {
    const { signing } = deriveKeys("alice", "hunter2");
    const message = sodium.from_string("test message");

    const sig = sodium.crypto_sign_detached(message, signing.privateKey);
    const ok = sodium.crypto_sign_verify_detached(
      sig,
      message,
      signing.publicKey,
    );

    expect(ok).toBe(true);
  });

  it("Ed25519 signature fails with wrong public key", async () => {
    const { signing } = deriveKeys("alice", "hunter2");
    const { signing: other } = deriveKeys("bob", "hunter2");
    const message = sodium.from_string("test message");

    const sig = sodium.crypto_sign_detached(message, signing.privateKey);
    const ok = sodium.crypto_sign_verify_detached(
      sig,
      message,
      other.publicKey,
    );

    expect(ok).toBe(false);
  });

  it("X25519 exchange key can seal and open a message", async () => {
    const { exchange } = deriveKeys("alice", "hunter2");
    const plaintext = sodium.from_string("secret data");

    const sealed = sodium.crypto_box_seal(plaintext, exchange.publicKey);
    const opened = sodium.crypto_box_seal_open(
      sealed,
      exchange.publicKey,
      exchange.privateKey,
    );

    expect(opened).toEqual(plaintext);
  });
  it("X25519 sealed box cannot be opened with a different private key", async () => {
    const { exchange: alice } = deriveKeys("alice", "hunter2");
    const { exchange: bob } = deriveKeys("bob", "hunter2");
    const plaintext = sodium.from_string("secret data");

    const sealed = sodium.crypto_box_seal(plaintext, alice.publicKey);

    // bob tries to open alice's sealed box — should throw or return null
    expect(() => {
      sodium.crypto_box_seal_open(sealed, alice.publicKey, bob.privateKey);
    }).toThrow();
  });
});

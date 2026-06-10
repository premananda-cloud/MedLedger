/**
 * key_manager.test.js — Unit tests for key_manager.js
 *
 * Runner: Vitest  (or Jest with --experimental-vm-modules)
 * Install: npm install -D vitest libsodium-wrappers
 * Run:     npx vitest run key_manager.test.js
 *
 * IMPORTANT: key_manager.js uses module-level state (_state).
 * Each describe block that touches session state calls resetManager()
 * in beforeEach to start from a clean, initialized, locked state.
 *
 * Argon2id is slow — full suite runs in ~30–60 s.
 * To run a single suite: npx vitest run -t "logout"
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { KeysetManager, KeysetError, ERRORS } from "./key_manager.js";

// ─────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────

const ALICE = { username: "alice", password: "hunter2" };
const BOB = { username: "bob", password: "correcthorsebatterystaple" };

// ─────────────────────────────────────────────────────────────────
// Setup
// ─────────────────────────────────────────────────────────────────

beforeAll(async () => {
  await sodium.ready;
  await KeysetManager.init();
});
/**
 * Reset manager to a clean initialized+locked state between tests
 * that manipulate session state.
 */
async function resetManager() {
  KeysetManager.logoutUser();
  // Re-initialize (no-op internally if already done, but keeps state clean)
  await KeysetManager.init();
}

// ─────────────────────────────────────────────────────────────────
// Suite 1 — init()
// ─────────────────────────────────────────────────────────────────

describe("init()", () => {
  it("resolves without throwing", async () => {
    await expect(KeysetManager.init()).resolves.toBeUndefined();
  });

  it("is idempotent — calling twice does not throw", async () => {
    await KeysetManager.init();
    await expect(KeysetManager.init()).resolves.toBeUndefined();
  });

  it("starts in locked state after init", async () => {
    expect(KeysetManager.isLocked()).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 2 — Guard: NOT_INITIALIZED
// ─────────────────────────────────────────────────────────────────

// Note: we cannot truly un-initialize in a module that caches _state,
// so we test the guard by confirming the error class and code exist and
// that the guard logic is reachable via the exported ERRORS constant.
describe("guard — ERRORS constant", () => {
  it("exports all expected error codes", () => {
    expect(ERRORS.NOT_INITIALIZED).toBe("KEYSET_NOT_INITIALIZED");
    expect(ERRORS.SESSION_LOCKED).toBe("KEYSET_SESSION_LOCKED");
    expect(ERRORS.DERIVATION_FAILED).toBe("KEYSET_DERIVATION_FAILED");
    expect(ERRORS.DECRYPTION_FAILED).toBe("KEYSET_DECRYPTION_FAILED");
    expect(ERRORS.SIGNATURE_INVALID).toBe("KEYSET_SIGNATURE_INVALID");
    expect(ERRORS.BAD_KEY_FORMAT).toBe("KEYSET_BAD_KEY_FORMAT");
  });

  it("KeysetError carries a code", () => {
    const err = new KeysetError(ERRORS.SESSION_LOCKED, "locked");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("KeysetError");
    expect(err.code).toBe(ERRORS.SESSION_LOCKED);
    expect(err.message).toBe("locked");
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 3 — Guard: SESSION_LOCKED
// ─────────────────────────────────────────────────────────────────

describe("guard — SESSION_LOCKED", () => {
  beforeEach(resetManager);

  it("decryptShare throws SESSION_LOCKED when not logged in", () => {
    expect(() =>
      KeysetManager.decryptShare("fakeRecord", "fakeNonce", "fakeDEK"),
    ).toThrow(expect.objectContaining({ code: ERRORS.SESSION_LOCKED }));
  });

  it("signPayload throws SESSION_LOCKED when not logged in", () => {
    expect(() => KeysetManager.signPayload({ action: "test" })).toThrow(
      expect.objectContaining({ code: ERRORS.SESSION_LOCKED }),
    );
  });

  it("getPublicKeys throws SESSION_LOCKED when not logged in", () => {
    expect(() => KeysetManager.getPublicKeys()).toThrow(
      expect.objectContaining({ code: ERRORS.SESSION_LOCKED }),
    );
  });

  it("isLocked returns true when locked", () => {
    expect(KeysetManager.isLocked()).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 4 — createUser()
// ─────────────────────────────────────────────────────────────────

describe("createUser()", () => {
  beforeEach(resetManager);

  it("returns signingPublicKey, exchangePublicKey, userIdHex, username", async () => {
    const result = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );

    expect(result).toHaveProperty("signingPublicKey");
    expect(result).toHaveProperty("exchangePublicKey");
    expect(result).toHaveProperty("userIdHex");
    expect(result).toHaveProperty("username", ALICE.username);
  });

  it("public keys are non-empty base64url strings", async () => {
    const { signingPublicKey, exchangePublicKey } =
      await KeysetManager.createUser(ALICE.username, ALICE.password);
    const b64urlRegex = /^[A-Za-z0-9_-]+$/;

    expect(signingPublicKey).toMatch(b64urlRegex);
    expect(exchangePublicKey).toMatch(b64urlRegex);
  });

  it("userIdHex is a 32-character hex string (16 bytes)", async () => {
    const { userIdHex } = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );

    expect(userIdHex).toMatch(/^[0-9a-f]{32}$/);
  });

  it("does NOT unlock the session — still locked after createUser", async () => {
    await KeysetManager.createUser(ALICE.username, ALICE.password);
    expect(KeysetManager.isLocked()).toBe(true);
  });

  it("is deterministic — same inputs produce same public keys", async () => {
    const a = await KeysetManager.createUser(ALICE.username, ALICE.password);
    const b = await KeysetManager.createUser(ALICE.username, ALICE.password);

    expect(a.signingPublicKey).toBe(b.signingPublicKey);
    expect(a.exchangePublicKey).toBe(b.exchangePublicKey);
    expect(a.userIdHex).toBe(b.userIdHex);
  });

  it("different users get different public keys", async () => {
    const alice = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );
    const bob = await KeysetManager.createUser(BOB.username, BOB.password);

    expect(alice.signingPublicKey).not.toBe(bob.signingPublicKey);
    expect(alice.exchangePublicKey).not.toBe(bob.exchangePublicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 5 — loginUser()
// ─────────────────────────────────────────────────────────────────

describe("loginUser()", () => {
  beforeEach(resetManager);

  it("unlocks the session", async () => {
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    expect(KeysetManager.isLocked()).toBe(false);
  });

  it("returns same public keys as createUser for the same credentials", async () => {
    const created = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );
    await resetManager();
    const logged = await KeysetManager.loginUser(
      ALICE.username,
      ALICE.password,
    );

    expect(logged.signingPublicKey).toBe(created.signingPublicKey);
    expect(logged.exchangePublicKey).toBe(created.exchangePublicKey);
    expect(logged.userIdHex).toBe(created.userIdHex);
  });

  it("returns username on the result object", async () => {
    const result = await KeysetManager.loginUser(
      ALICE.username,
      ALICE.password,
    );
    expect(result.username).toBe(ALICE.username);
  });

  it("logging in as alice does not expose bob's keys", async () => {
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    const aliceKeys = KeysetManager.getPublicKeys();
    await resetManager();
    await KeysetManager.loginUser(BOB.username, BOB.password);
    const bobKeys = KeysetManager.getPublicKeys();

    expect(aliceKeys.signingPublicKey).not.toBe(bobKeys.signingPublicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 6 — logoutUser()
// ─────────────────────────────────────────────────────────────────

describe("logoutUser()", () => {
  beforeEach(resetManager);

  it("locks the session", async () => {
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    expect(KeysetManager.isLocked()).toBe(false);

    KeysetManager.logoutUser();
    expect(KeysetManager.isLocked()).toBe(true);
  });

  it("getPublicKeys throws after logout", async () => {
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    KeysetManager.logoutUser();

    expect(() => KeysetManager.getPublicKeys()).toThrow(
      expect.objectContaining({ code: ERRORS.SESSION_LOCKED }),
    );
  });

  it("can login again after logout without calling init()", async () => {
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    KeysetManager.logoutUser();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);

    expect(KeysetManager.isLocked()).toBe(false);
  });

  it("logout is idempotent — calling twice does not throw", () => {
    KeysetManager.logoutUser();
    expect(() => KeysetManager.logoutUser()).not.toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 7 — getPublicKeys()
// ─────────────────────────────────────────────────────────────────

describe("getPublicKeys()", () => {
  beforeEach(async () => {
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
  });

  it("returns all four fields", () => {
    const keys = KeysetManager.getPublicKeys();

    expect(keys).toHaveProperty("signingPublicKey");
    expect(keys).toHaveProperty("exchangePublicKey");
    expect(keys).toHaveProperty("userIdHex");
    expect(keys).toHaveProperty("username", ALICE.username);
  });

  it("matches what loginUser returned", async () => {
    await resetManager();
    const loginResult = await KeysetManager.loginUser(
      ALICE.username,
      ALICE.password,
    );
    const pubKeys = KeysetManager.getPublicKeys();

    expect(pubKeys.signingPublicKey).toBe(loginResult.signingPublicKey);
    expect(pubKeys.exchangePublicKey).toBe(loginResult.exchangePublicKey);
    expect(pubKeys.userIdHex).toBe(loginResult.userIdHex);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 8 — encryptRecord()
// ─────────────────────────────────────────────────────────────────

describe("encryptRecord()", () => {
  let aliceExchangePubKeyB64;

  beforeAll(async () => {
    await resetManager();
    const keys = await KeysetManager.createUser(ALICE.username, ALICE.password);
    aliceExchangePubKeyB64 = keys.exchangePublicKey;
  });

  beforeEach(resetManager);

  it("returns encryptedRecord, nonce, dekBundle, fileHash", () => {
    const fileBytes = new TextEncoder().encode("medical record content");
    const result = KeysetManager.encryptRecord(
      fileBytes,
      aliceExchangePubKeyB64,
    );

    expect(result).toHaveProperty("encryptedRecord");
    expect(result).toHaveProperty("nonce");
    expect(result).toHaveProperty("dekBundle");
    expect(result).toHaveProperty("fileHash");
  });

  it("fileHash is a 64-char hex string (BLAKE2b-256)", () => {
    const fileBytes = new TextEncoder().encode("some data");
    const { fileHash } = KeysetManager.encryptRecord(
      fileBytes,
      aliceExchangePubKeyB64,
    );

    expect(fileHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("fileHash is deterministic for same plaintext", () => {
    const fileBytes = new TextEncoder().encode("same data");
    const a = KeysetManager.encryptRecord(fileBytes, aliceExchangePubKeyB64);
    const b = KeysetManager.encryptRecord(fileBytes, aliceExchangePubKeyB64);

    expect(a.fileHash).toBe(b.fileHash);
  });

  it("ciphertext differs each call (random nonce)", () => {
    const fileBytes = new TextEncoder().encode("same data");
    const a = KeysetManager.encryptRecord(fileBytes, aliceExchangePubKeyB64);
    const b = KeysetManager.encryptRecord(fileBytes, aliceExchangePubKeyB64);

    // Nonces must be different
    expect(a.nonce).not.toBe(b.nonce);
    // Ciphertexts will also differ because nonce differs
    expect(a.encryptedRecord).not.toBe(b.encryptedRecord);
  });

  it("does NOT require an unlocked session (public-key-only op)", () => {
    // Logged out — encryptRecord should still work
    expect(KeysetManager.isLocked()).toBe(true);
    const fileBytes = new TextEncoder().encode("test");

    expect(() =>
      KeysetManager.encryptRecord(fileBytes, aliceExchangePubKeyB64),
    ).not.toThrow();
  });

  it("encrypts empty file without throwing", () => {
    expect(() =>
      KeysetManager.encryptRecord(new Uint8Array(0), aliceExchangePubKeyB64),
    ).not.toThrow();
  });
  it("encrypts large file (1 MB)", () => {
    const largeFile = sodium.randombytes_buf(1_048_576); // 1 MB
    expect(() =>
      KeysetManager.encryptRecord(largeFile, aliceExchangePubKeyB64),
    ).not.toThrow();
  }, 30000); // 30 second timeout
}); // <-- ADD THIS MISSING CLOSING BRACE

// ─────────────────────────────────────────────────────────────────
// Suite 9 — decryptShare()
// ─────────────────────────────────────────────────────────────────
describe("decryptShare()", () => {
  let aliceExchangePubKeyB64;
  const originalText = "super secret medical data 🏥";
  const originalBytes = new TextEncoder().encode(originalText);

  beforeAll(async () => {
    await resetManager();
    const keys = await KeysetManager.createUser(ALICE.username, ALICE.password);
    aliceExchangePubKeyB64 = keys.exchangePublicKey;
  });

  beforeEach(async () => {
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
  });

  it("decrypts a record encrypted for the logged-in user", () => {
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      originalBytes,
      aliceExchangePubKeyB64,
    );
    const decrypted = KeysetManager.decryptShare(
      encryptedRecord,
      nonce,
      dekBundle,
    );
    const decryptedText = new TextDecoder().decode(decrypted);

    expect(decryptedText).toBe(originalText);
  });

  it("round-trips arbitrary bytes unchanged", () => {
    const randomBytes = sodium.randombytes_buf(256);
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      randomBytes,
      aliceExchangePubKeyB64,
    );
    const decrypted = KeysetManager.decryptShare(
      encryptedRecord,
      nonce,
      dekBundle,
    );

    expect(decrypted).toEqual(randomBytes);
  });

  it("throws SESSION_LOCKED if called while locked", async () => {
    KeysetManager.logoutUser();
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      originalBytes,
      aliceExchangePubKeyB64,
    );

    expect(() =>
      KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle),
    ).toThrow(expect.objectContaining({ code: ERRORS.SESSION_LOCKED }));
  });

  it("throws DECRYPTION_FAILED when DEK bundle is for a different recipient (bob)", async () => {
    // Encrypt for Bob
    const bobKeys = await KeysetManager.createUser(BOB.username, BOB.password);
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      originalBytes,
      bobKeys.exchangePublicKey, // sealed for Bob
    );

    // Alice tries to open it — should fail on DEK open
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);

    expect(() =>
      KeysetManager.decryptShare(encryptedRecord, nonce, dekBundle),
    ).toThrow(expect.objectContaining({ code: ERRORS.DECRYPTION_FAILED }));
  });

  it("throws DECRYPTION_FAILED when ciphertext is tampered", () => {
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      originalBytes,
      aliceExchangePubKeyB64,
    );

    // Flip a byte in the middle of the ciphertext
    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    const tampered = sodium.from_base64(encryptedRecord, enc);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    const tamperedB64 = sodium.to_base64(tampered, enc);

    expect(() =>
      KeysetManager.decryptShare(tamperedB64, nonce, dekBundle),
    ).toThrow(expect.objectContaining({ code: ERRORS.DECRYPTION_FAILED }));
  });

  it("throws DECRYPTION_FAILED when nonce is wrong", () => {
    const { encryptedRecord, dekBundle } = KeysetManager.encryptRecord(
      originalBytes,
      aliceExchangePubKeyB64,
    );
    const wrongNonce = sodium.to_base64(
      sodium.randombytes_buf(24),
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );

    expect(() =>
      KeysetManager.decryptShare(encryptedRecord, wrongNonce, dekBundle),
    ).toThrow(expect.objectContaining({ code: ERRORS.DECRYPTION_FAILED }));
  });

  it("decrypts empty file correctly", () => {
    const { encryptedRecord, nonce, dekBundle } = KeysetManager.encryptRecord(
      new Uint8Array(0),
      aliceExchangePubKeyB64,
    );
    const decrypted = KeysetManager.decryptShare(
      encryptedRecord,
      nonce,
      dekBundle,
    );

    expect(decrypted.byteLength).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 10 — signPayload()
// ─────────────────────────────────────────────────────────────────

describe("signPayload()", () => {
  beforeEach(async () => {
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
  });

  it("returns payload, payloadCanon, and signature", () => {
    const result = KeysetManager.signPayload({
      action: "share",
      recordId: "123",
    });

    expect(result).toHaveProperty("payload");
    expect(result).toHaveProperty("payloadCanon");
    expect(result).toHaveProperty("signature");
  });

  it("payload on result is the original object reference", () => {
    const obj = { action: "share" };
    const result = KeysetManager.signPayload(obj);

    expect(result.payload).toBe(obj);
  });

  it("payloadCanon is valid JSON", () => {
    const { payloadCanon } = KeysetManager.signPayload({ z: 1, a: 2 });
    expect(() => JSON.parse(payloadCanon)).not.toThrow();
  });

  it("payloadCanon has keys sorted alphabetically (canonical JSON)", () => {
    const { payloadCanon } = KeysetManager.signPayload({ z: 1, m: 2, a: 3 });
    const parsed = JSON.parse(payloadCanon);
    const keys = Object.keys(parsed);

    expect(keys).toEqual([...keys].sort());
  });

  it("objects with same data but different key insertion order produce same payloadCanon", () => {
    const objA = { z: 1, a: 2, m: 3 };
    const objB = { a: 2, m: 3, z: 1 }; // same data, different order

    const { payloadCanon: canonA } = KeysetManager.signPayload(objA);
    const { payloadCanon: canonB } = KeysetManager.signPayload(objB);

    expect(canonA).toBe(canonB);
  });

  it("signature is a non-empty base64url string", () => {
    const { signature } = KeysetManager.signPayload({ x: 1 });
    expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("throws SESSION_LOCKED when not logged in", async () => {
    KeysetManager.logoutUser();

    expect(() => KeysetManager.signPayload({ x: 1 })).toThrow(
      expect.objectContaining({ code: ERRORS.SESSION_LOCKED }),
    );
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 11 — verifySignature()
// ─────────────────────────────────────────────────────────────────

describe("verifySignature()", () => {
  let aliceSigningPubKeyB64;
  let bobSigningPubKeyB64;

  beforeAll(async () => {
    await resetManager();
    const alice = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );
    aliceSigningPubKeyB64 = alice.signingPublicKey;
    const bob = await KeysetManager.createUser(BOB.username, BOB.password);
    bobSigningPubKeyB64 = bob.signingPublicKey;
  });

  beforeEach(async () => {
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
  });

  it("returns true for a valid signature", () => {
    const { payloadCanon, signature } = KeysetManager.signPayload({
      action: "test",
    });
    const valid = KeysetManager.verifySignature(
      payloadCanon,
      signature,
      aliceSigningPubKeyB64,
    );

    expect(valid).toBe(true);
  });

  it("accepts the payload object directly (re-canonicalises internally)", () => {
    const payload = { action: "test", id: "42" };
    const { payloadCanon, signature } = KeysetManager.signPayload(payload);

    // Pass the object instead of the canonical string
    const valid = KeysetManager.verifySignature(
      payload,
      signature,
      aliceSigningPubKeyB64,
    );

    expect(valid).toBe(true);
  });

  it("returns false when verified against wrong public key (bob's)", () => {
    const { payloadCanon, signature } = KeysetManager.signPayload({
      action: "test",
    });
    const valid = KeysetManager.verifySignature(
      payloadCanon,
      signature,
      bobSigningPubKeyB64,
    );

    expect(valid).toBe(false);
  });

  it("returns false when signature is tampered", () => {
    const enc = sodium.base64_variants.URLSAFE_NO_PADDING;
    const { payloadCanon, signature } = KeysetManager.signPayload({
      action: "test",
    });

    const sigBytes = sodium.from_base64(signature, enc);
    sigBytes[0] ^= 0xff; // flip a byte
    const tamperedSig = sodium.to_base64(sigBytes, enc);

    const valid = KeysetManager.verifySignature(
      payloadCanon,
      tamperedSig,
      aliceSigningPubKeyB64,
    );
    expect(valid).toBe(false);
  });

  it("returns false when payload is modified after signing", () => {
    const { signature } = KeysetManager.signPayload({
      action: "share",
      id: "1",
    });
    const modifiedPayload = { action: "share", id: "999" }; // id changed

    const valid = KeysetManager.verifySignature(
      modifiedPayload,
      signature,
      aliceSigningPubKeyB64,
    );
    expect(valid).toBe(false);
  });

  it("does NOT require an unlocked session", async () => {
    // Sign while unlocked
    const { payloadCanon, signature } = KeysetManager.signPayload({ x: 1 });

    // Logout, then verify — should still work
    KeysetManager.logoutUser();
    expect(KeysetManager.isLocked()).toBe(true);

    const valid = KeysetManager.verifySignature(
      payloadCanon,
      signature,
      aliceSigningPubKeyB64,
    );
    expect(valid).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────
// Suite 12 — Full end-to-end flows
// ─────────────────────────────────────────────────────────────────

describe("end-to-end flows", () => {
  beforeEach(resetManager);

  it("full share flow: alice registers, logs in, encrypts for bob, bob decrypts", async () => {
    // Registration
    const aliceReg = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );
    const bobReg = await KeysetManager.createUser(BOB.username, BOB.password);

    // Alice logs in and encrypts a record for Bob
    await resetManager();
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    const fileContent = new TextEncoder().encode(
      "Bob's prescription: 500mg ibuprofen",
    );
    const encrypted = KeysetManager.encryptRecord(
      fileContent,
      bobReg.exchangePublicKey,
    );

    // Alice signs the share metadata
    const { payloadCanon, signature } = KeysetManager.signPayload({
      action: "share",
      recordId: "rec_001",
      to: bobReg.userIdHex,
    });

    // Bob logs in and decrypts
    await resetManager();
    await KeysetManager.loginUser(BOB.username, BOB.password);
    const decrypted = KeysetManager.decryptShare(
      encrypted.encryptedRecord,
      encrypted.nonce,
      encrypted.dekBundle,
    );
    const decryptedText = new TextDecoder().decode(decrypted);

    expect(decryptedText).toBe("Bob's prescription: 500mg ibuprofen");

    // Bob verifies Alice's signature
    const valid = KeysetManager.verifySignature(
      payloadCanon,
      signature,
      aliceReg.signingPublicKey,
    );
    expect(valid).toBe(true);
  });

  it("logout between createUser and loginUser gives same keys", async () => {
    const created = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );

    // Session is locked after createUser — now login
    const logged = await KeysetManager.loginUser(
      ALICE.username,
      ALICE.password,
    );

    expect(created.signingPublicKey).toBe(logged.signingPublicKey);
    expect(created.exchangePublicKey).toBe(logged.exchangePublicKey);
  });

  it("verify with createUser public key matches signPayload from loginUser session", async () => {
    // Get Alice's public key via createUser
    const created = await KeysetManager.createUser(
      ALICE.username,
      ALICE.password,
    );

    // Login and sign something
    await KeysetManager.loginUser(ALICE.username, ALICE.password);
    const { payloadCanon, signature } = KeysetManager.signPayload({
      msg: "hello",
    });

    // Verify using the public key from createUser
    const valid = KeysetManager.verifySignature(
      payloadCanon,
      signature,
      created.signingPublicKey,
    );
    expect(valid).toBe(true);
  });
});

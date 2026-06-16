// tests/auth.test.js
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getAuthFlow, resetAuthFlow } from "../orchestrator/authFlow.js";
import { getEmailVerifier } from "../modules/email.js";
import { getTOTPManager } from "../modules/totp.js";
import { resetStorage } from "../modules/storage.js";

describe("Auth Flow", () => {
  let authFlow;
  let testEmail;
  let testUsername;

  beforeEach(async () => {
    // Set test environment
    process.env.NODE_ENV = "test";

    // Reset all singletons
    await resetAuthFlow();
    await resetStorage();

    // Get fresh instances
    authFlow = getAuthFlow();
    testEmail = `test-${Date.now()}@example.com`;
    testUsername = `testuser_${Date.now()}`;
  });

  afterEach(async () => {
    await resetAuthFlow();
    await resetStorage();
  });

  it("should complete full registration flow", async () => {
    // Step 1: Get PoW challenge
    const step1 = authFlow.initPOW();
    expect(step1.step).toBe("pow_challenge");
    expect(step1.data.challenge).toBeDefined();
    expect(step1.data.difficulty).toBe(4);

    // Step 2: Solve PoW (simulated)
    const { challenge_id, challenge, difficulty } = step1.data;
    let nonce = 0;
    const prefix = "0".repeat(difficulty);

    while (true) {
      const input = challenge + nonce;
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (hashHex.startsWith(prefix)) break;
      nonce++;
      if (nonce > 1000000) throw new Error("PoW solving timeout");
    }

    const step2 = authFlow.verifyPOW(challenge_id, nonce.toString());
    expect(step2.step).toBe("pow_verified");
    const sessionToken = step2.data.sessionToken;
    expect(sessionToken).toBeDefined();

    // Step 3: Submit email
    const step3 = authFlow.submitEmail(sessionToken, testEmail);
    expect(step3.step).toBe("email_code_sent");

    // Step 4: Verify email code
    const emailVerifier = getEmailVerifier();
    const code = emailVerifier.getCodeForTesting(testEmail);
    expect(code).toBeDefined();

    const step4 = authFlow.verifyEmailCode(sessionToken, code);
    expect(step4.step).toBe("email_verified");
    expect(step4.data.totp).toBeDefined();

    // Step 5: Verify TOTP
    const totpManager = getTOTPManager();
    const totpToken = totpManager.getCurrentToken(testEmail);
    expect(totpToken).toBeDefined();

    const step5 = await authFlow.verifyTOTP(sessionToken, totpToken);
    expect(step5.step).toBe("totp_verified");

    // Step 6: Create account
    const step6 = await authFlow.createAccount(
      sessionToken,
      testUsername,
      "TestP@ssw0rd123",
    );
    // ADD THIS DEBUGGING:
    if (step6.step === "error") {
      console.log("Account creation error:", step6.data);
    }
    expect(step6.step).toBe("account_created");
    expect(step6.data.username).toBe(testUsername.toLowerCase());
  });

  it("should reject invalid PoW", () => {
    const step1 = authFlow.initPOW();
    const step2 = authFlow.verifyPOW(step1.data.challenge_id, "invalid_nonce");
    expect(step2.step).toBe("error");
  });

  it("should reject invalid email code", async () => {
    const step1 = authFlow.initPOW();
    const { challenge_id, challenge, difficulty } = step1.data;

    let nonce = 0;
    const prefix = "0".repeat(difficulty);
    while (true) {
      const input = challenge + nonce;
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (hashHex.startsWith(prefix)) break;
      nonce++;
      if (nonce > 1000000) throw new Error("PoW solving timeout");
    }

    const step2 = authFlow.verifyPOW(challenge_id, nonce.toString());
    const sessionToken = step2.data.sessionToken;

    authFlow.submitEmail(sessionToken, testEmail);
    const step4 = authFlow.verifyEmailCode(sessionToken, "000000");
    expect(step4.step).toBe("error");
  });
});

describe("User Validation", () => {
  let userManager;

  beforeEach(async () => {
    process.env.NODE_ENV = "test";
    await resetAuthFlow();
    await resetStorage();
    const { getUserManager } = await import("../modules/user.js");
    userManager = getUserManager();
  });

  it("should validate usernames correctly", () => {
    expect(userManager.validateUsername("valid_user_123").valid).toBe(true);
    expect(userManager.validateUsername("ab").valid).toBe(false);
    expect(userManager.validateUsername("user@name").valid).toBe(false);
  });

  it("should validate passwords correctly", () => {
    expect(userManager.validatePassword("TestP@ss123").valid).toBe(true);
    expect(userManager.validatePassword("weak").valid).toBe(false);
    expect(userManager.validatePassword("").valid).toBe(false);
  });
});

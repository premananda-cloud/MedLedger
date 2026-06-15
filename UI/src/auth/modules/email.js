// modules/email.js (add to existing file)
import crypto from "node:crypto";

export class EmailVerifier {
  constructor(codeLength = 6, expiryMs = 10 * 60 * 1000, maxAttempts = 3) {
    this.codeLength = codeLength;
    this.expiryMs = expiryMs;
    this.maxAttempts = maxAttempts;
    this.codes = new Map();
    this.isTest = process.env.NODE_ENV === "test";
  }

  generateCode(email) {
    const normalizedEmail = email.toLowerCase();

    let code = "";
    for (let i = 0; i < this.codeLength; i++) {
      code += crypto.randomInt(0, 10).toString();
    }

    this.codes.set(normalizedEmail, {
      code,
      expiresAt: Date.now() + this.expiryMs,
      attempts: 0,
      verified: false,
    });

    if (!this.isTest) {
      console.log(`[EMAIL] Verification code for ${email}: ${code}`);
    }

    return {
      code,
      expiresIn: this.expiryMs,
      timestamp: Date.now(),
    };
  }

  verifyCode(email, code) {
    const normalizedEmail = email.toLowerCase();
    const record = this.codes.get(normalizedEmail);

    if (!record) {
      return {
        verified: false,
        message: "No code found for this email",
        attemptsLeft: 0,
      };
    }

    if (record.verified) {
      return {
        verified: false,
        message: "Code already verified",
        attemptsLeft: 0,
      };
    }

    if (Date.now() > record.expiresAt) {
      this.codes.delete(normalizedEmail);
      return { verified: false, message: "Code expired", attemptsLeft: 0 };
    }

    if (record.attempts >= this.maxAttempts) {
      this.codes.delete(normalizedEmail);
      return { verified: false, message: "Too many attempts", attemptsLeft: 0 };
    }

    record.attempts++;

    const isMatch = record.code === code;

    if (!isMatch) {
      const remaining = this.maxAttempts - record.attempts;
      return {
        verified: false,
        message: `Invalid code. ${remaining} attempts remaining`,
        attemptsLeft: remaining,
      };
    }

    record.verified = true;
    return {
      verified: true,
      message: "Email verified successfully",
      attemptsLeft: this.maxAttempts - record.attempts,
    };
  }

  isVerified(email) {
    const record = this.codes.get(email?.toLowerCase());
    return record?.verified === true;
  }

  getCodeForTesting(email) {
    if (process.env.NODE_ENV !== "test") {
      throw new Error("getCodeForTesting only available in test environment");
    }
    const record = this.codes.get(email?.toLowerCase());
    return record?.code || null;
  }

  getStatus() {
    return {
      activeCodes: this.codes.size,
      expiryTime: this.expiryMs,
    };
  }

  // Add reset method
  reset() {
    this.codes.clear();
  }
}

let instance = null;

export function getEmailVerifier() {
  if (!instance) {
    instance = new EmailVerifier();
  }
  return instance;
}

export function resetEmailVerifier() {
  instance = null;
}

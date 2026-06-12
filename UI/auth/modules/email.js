/**
 * Email Module - Email Verification Code Generation & Validation
 *
 * INPUT:
 *   - email: string (user's email address)
 *   - code: string (verification code to validate)
 *
 * OUTPUT:
 *   - code: string (generated verification code)
 *   - verified: boolean
 *   - expiresIn: number (seconds until expiry)
 *
 * SECURITY:
 *   - Codes generated with CSPRNG (crypto.randomInt)
 *   - Constant-time comparison prevents timing attacks
 *   - Attempt limiting prevents brute force
 *   - Codes expire after 10 minutes
 */

const crypto = require("crypto");

class EmailVerifier {
  constructor() {
    this.codes = new Map(); // Store verification codes
    this.codeExpiry = 10 * 60 * 1000; // 10 minutes
    this.codeLength = 6;
  }

  /**
   * Generate verification code for email
   * Uses crypto.randomInt for cryptographically secure random numbers
   * @param {string} email - User's email
   * @returns {Object} { code, expiresIn, timestamp }
   */
  generateCode(email) {
    const code = crypto.randomInt(100000, 1000000).toString();

    const codeData = {
      code,
      email,
      timestamp: Date.now(),
      attempts: 0,
      maxAttempts: 3,
      verified: false,
    };

    this.codes.set(email, codeData);

    // Clean old codes
    this.cleanupExpiredCodes();

    return {
      code,
      expiresIn: this.codeExpiry / 1000,
      timestamp: codeData.timestamp,
    };
  }

  /**
   * Verify the code for given email
   * Uses constant-time comparison to prevent timing attacks
   * @param {string} email - User's email
   * @param {string} code - Verification code
   * @returns {Object} { verified, message, attemptsLeft }
   */
  verifyCode(email, code) {
    // Helper function for dummy timing-safe comparison
    const dummyCompare = (input) => {
      const dummyBuffer = Buffer.alloc(this.codeLength, "0");
      const inputStr = String(input)
        .padEnd(this.codeLength, "0")
        .slice(0, this.codeLength);
      const inputBuffer = Buffer.from(inputStr);
      if (dummyBuffer.length === inputBuffer.length) {
        crypto.timingSafeEqual(dummyBuffer, inputBuffer);
      }
    };

    const codeData = this.codes.get(email);

    // No code found - do dummy comparison for timing consistency
    if (!codeData) {
      dummyCompare(code);
      return {
        verified: false,
        message: "No verification code found for this email",
        attemptsLeft: 0,
      };
    }

    // Check expiry - do dummy comparison for timing consistency
    if (Date.now() - codeData.timestamp > this.codeExpiry) {
      this.codes.delete(email);
      dummyCompare(code);
      return {
        verified: false,
        message: "Verification code expired",
        attemptsLeft: 0,
      };
    }

    // Check max attempts - do dummy comparison for timing consistency
    if (codeData.attempts >= codeData.maxAttempts) {
      this.codes.delete(email);
      dummyCompare(code);
      return {
        verified: false,
        message: "Maximum attempts exceeded",
        attemptsLeft: 0,
      };
    }

    // Increment attempts BEFORE comparison to prevent race conditions
    codeData.attempts++;

    // Prepare buffers for constant-time comparison
    // Ensure both buffers are exactly codeLength bytes
    const normalizeCode = (str) => {
      return String(str).padEnd(this.codeLength, "0").slice(0, this.codeLength);
    };

    const codeBuffer = Buffer.from(normalizeCode(codeData.code));
    const inputBuffer = Buffer.from(normalizeCode(code));

    // Constant-time comparison (prevents timing attacks)
    let isValid = false;
    if (codeBuffer.length === inputBuffer.length) {
      isValid = crypto.timingSafeEqual(codeBuffer, inputBuffer);
    }

    if (isValid) {
      codeData.verified = true;
      return {
        verified: true,
        message: "Email verified successfully",
        attemptsLeft: codeData.maxAttempts - codeData.attempts,
      };
    }

    return {
      verified: false,
      message: "Invalid verification code",
      attemptsLeft: codeData.maxAttempts - codeData.attempts,
    };
  }

  /**
   * Get verification code for testing purposes only
   * Only available when NODE_ENV is set to 'test'
   */
  getCodeForTesting(email) {
    if (process.env.NODE_ENV !== "test") {
      throw new Error(
        "getCodeForTesting is only available in test environment",
      );
    }
    const codeData = this.codes.get(email);
    return codeData ? codeData.code : null;
  }

  /**
   * Check if email is already verified
   */
  isVerified(email) {
    const codeData = this.codes.get(email);
    return codeData ? codeData.verified : false;
  }

  /**
   * Clean expired verification codes
   */
  cleanupExpiredCodes() {
    const now = Date.now();
    for (const [email, data] of this.codes) {
      if (now - data.timestamp > this.codeExpiry) {
        this.codes.delete(email);
      }
    }
  }

  /**
   * Get status for debugging
   */
  getStatus() {
    return {
      activeCodes: this.codes.size,
      expiryTime: this.codeExpiry / 1000,
      codeLength: this.codeLength,
    };
  }
}

module.exports = new EmailVerifier();

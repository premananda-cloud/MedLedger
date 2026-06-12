/**
 * Auth Flow Orchestrator
 *
 * Coordinates all modules to perform the complete authentication flow
 *
 * FLOW:
 * 1. POW Verification (CAP.js)
 * 2. Email Input & Verification Code
 * 3. TOTP 2FA Generation
 * 4. Username/Password Creation
 * 5. Account Creation Confirmation
 */

const powVerifier = require("../modules/pow");
const totpManager = require("../modules/totp");
const emailVerifier = require("../modules/email");
const userManager = require("../modules/user");

class AuthFlow {
  constructor() {
    this.sessions = new Map(); // Store session state
  }

  /**
   * Step 1: Initialize POW challenge
   */
  initPOW() {
    const challenge = powVerifier.generateChallenge();
    return {
      step: "pow_challenge",
      data: challenge,
      next: "verify_pow",
    };
  }

  /**
   * Step 2: Verify POW solution
   */
  verifyPOW(challengeId, nonce) {
    const result = powVerifier.verify(challengeId, nonce);

    if (!result.success) {
      return {
        step: "pow_failed",
        data: { message: result.message },
        next: "retry_pow",
      };
    }

    const sessionId = result.sessionToken;
    this.sessions.set(sessionId, {
      powVerified: true,
      timestamp: Date.now(),
    });

    return {
      step: "pow_verified",
      data: {
        sessionToken: sessionId,
        message: "POW verified. Please enter your email.",
      },
      next: "submit_email",
    };
  }

  /**
   * Step 3: Submit email and get verification code
   */
  submitEmail(sessionToken, email) {
    const session = this.sessions.get(sessionToken);

    if (!session || !session.powVerified) {
      return {
        step: "error",
        data: { message: "Invalid or expired session" },
        next: null,
      };
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        step: "error",
        data: { message: "Invalid email format" },
        next: "retry_email",
      };
    }

    // Generate verification code
    const codeData = emailVerifier.generateCode(email);

    session.email = email;
    this.sessions.set(sessionToken, session);

    // FIXED Bug 5: No longer log plaintext verification code
    // In test environment, use emailVerifier.getCodeForTesting()

    return {
      step: "email_code_sent",
      data: {
        message: "Verification code sent to your email",
        expiresIn: codeData.expiresIn,
        email: email.replace(/(.{3}).*(@.*)/, "$1***$2"), // Mask email
      },
      next: "verify_email_code",
    };
  }

  /**
   * Step 4: Verify email code
   */
  verifyEmailCode(sessionToken, code) {
    const session = this.sessions.get(sessionToken);

    if (!session || !session.email) {
      return {
        step: "error",
        data: { message: "Invalid session" },
        next: null,
      };
    }

    const result = emailVerifier.verifyCode(session.email, code);

    if (!result.verified) {
      return {
        step: "email_verification_failed",
        data: {
          message: result.message,
          attemptsLeft: result.attemptsLeft,
        },
        next: result.attemptsLeft > 0 ? "retry_code" : "restart",
      };
    }

    session.emailVerified = true;

    // FIXED Bug 1: Store both secret and QR URI in session
    const totpData = totpManager.generateSecret(session.email);
    session.totpSecret = totpData.secret;
    session.totpQrUri = totpData.qrCodeUri; // Store URI to avoid regeneration

    this.sessions.set(sessionToken, session);

    return {
      step: "email_verified",
      data: {
        message: "Email verified. Please set up 2FA.",
        totp: {
          qrCodeUri: totpData.qrCodeUri,
          manualKey: totpData.manualKey,
        },
      },
      next: "verify_totp",
    };
  }

  /**
   * Step 5: Verify TOTP token
   * FIXED Bug 1: Uses stored secret/URI instead of generating new one
   */
  async verifyTOTP(sessionToken, token) {
    const session = this.sessions.get(sessionToken);

    if (!session || !session.emailVerified) {
      return {
        step: "error",
        data: { message: "Invalid session" },
        next: null,
      };
    }

    const result = totpManager.verifyToken(session.email, token);

    if (!result.verified) {
      return {
        step: "totp_failed",
        data: {
          message: result.message,
          remaining: result.remaining,
        },
        next: "retry_totp",
      };
    }

    session.totpVerified = true;
    this.sessions.set(sessionToken, session);

    // FIXED Bug 1: Generate QR from stored URI, not new secret
    const qrDataUrl = await totpManager.generateQRCode(session.totpQrUri);

    return {
      step: "totp_verified",
      data: {
        message:
          "2FA set up successfully. Please create your username and password.",
        qrCode: qrDataUrl,
      },
      next: "create_account",
    };
  }

  /**
   * Step 6: Create user account
   * FIXED Bug 3: Now async to support PBKDF2 with proper iterations
   */
  async createAccount(sessionToken, username, password) {
    const session = this.sessions.get(sessionToken);

    if (!session || !session.totpVerified) {
      return {
        step: "error",
        data: { message: "Invalid session" },
        next: null,
      };
    }

    const result = await userManager.createUser(
      username,
      password,
      session.email,
    );

    if (!result.created) {
      return {
        step: "account_creation_failed",
        data: { message: result.message },
        next: "retry_credentials",
      };
    }

    // Clear session
    this.sessions.delete(sessionToken);

    return {
      step: "account_created",
      data: {
        message: "Account created successfully!",
        userId: result.userId,
        username: username,
      },
      next: null,
    };
  }

  /**
   * Get session status (for debugging)
   */
  getSessionStatus(sessionToken) {
    const session = this.sessions.get(sessionToken);
    if (!session) return { exists: false };

    return {
      exists: true,
      powVerified: session.powVerified || false,
      emailVerified: session.emailVerified || false,
      totpVerified: session.totpVerified || false,
      email: session.email
        ? session.email.replace(/(.{3}).*(@.*)/, "$1***$2")
        : null,
    };
  }
}

module.exports = new AuthFlow();

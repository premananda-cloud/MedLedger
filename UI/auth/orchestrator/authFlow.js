// orchestrator/authFlow.js (add reset to existing file)
import { getPoW, resetPoW } from "../modules/pow.js";
import { getEmailVerifier, resetEmailVerifier } from "../modules/email.js";
import { getTOTPManager, resetTOTPManager } from "../modules/totp.js";
import { getUserManager, resetUserManager } from "../modules/user.js";

export class AuthFlow {
  constructor() {
    this.pow = getPoW();
    this.emailVerifier = getEmailVerifier();
    this.totpManager = getTOTPManager();
    this.userManager = getUserManager();
    this.sessions = new Map();
  }

  initPOW() {
    return {
      step: "pow_challenge",
      data: this.pow.generateChallenge(),
    };
  }

  verifyPOW(challengeId, nonce) {
    const result = this.pow.verify(challengeId, nonce);

    if (!result.success) {
      return {
        step: "error",
        data: { message: result.message },
        next: "restart",
      };
    }

    const sessionToken = result.sessionToken;
    this.sessions.set(sessionToken, {
      step: "pow_verified",
      powVerified: true,
      emailVerified: false,
      totpVerified: false,
      email: null,
    });

    return {
      step: "pow_verified",
      data: {
        sessionToken,
        message: result.message,
      },
    };
  }

  submitEmail(sessionToken, email) {
    const session = this.sessions.get(sessionToken);
    if (!session || !session.powVerified) {
      return {
        step: "error",
        data: { message: "Invalid or expired session" },
        next: "restart",
      };
    }

    if (!email || !email.includes("@")) {
      return {
        step: "error",
        data: { message: "Valid email required" },
        next: "retry",
      };
    }

    const result = this.emailVerifier.generateCode(email);
    session.email = email.toLowerCase();
    session.step = "email_sent";

    const [local, domain] = email.split("@");
    const maskedLocal =
      local.length > 3 ? local.slice(0, 3) + "***" : local[0] + "***";
    const maskedEmail = `${maskedLocal}@${domain}`;

    return {
      step: "email_code_sent",
      data: {
        message: "Verification code sent",
        expiresIn: result.expiresIn,
        email: maskedEmail,
      },
    };
  }

  verifyEmailCode(sessionToken, code) {
    const session = this.sessions.get(sessionToken);
    if (!session || !session.powVerified) {
      return {
        step: "error",
        data: { message: "Invalid or expired session" },
        next: "restart",
      };
    }

    if (!session.email) {
      return {
        step: "error",
        data: { message: "No email submitted" },
        next: "restart",
      };
    }

    const result = this.emailVerifier.verifyCode(session.email, code);

    if (!result.verified) {
      return {
        step: "error",
        data: { message: result.message },
        next: "retry_code",
      };
    }

    session.emailVerified = true;
    session.step = "email_verified";

    const totpSecret = this.totpManager.generateSecret(session.email);

    return {
      step: "email_verified",
      data: {
        message: "Email verified",
        totp: {
          qrCodeUri: totpSecret.qrCodeUri,
          manualKey: totpSecret.manualKey,
        },
      },
    };
  }

  async verifyTOTP(sessionToken, totpToken) {
    const session = this.sessions.get(sessionToken);
    if (!session || !session.emailVerified) {
      return {
        step: "error",
        data: { message: "Complete email verification first" },
        next: "restart",
      };
    }

    const result = this.totpManager.verifyToken(session.email, totpToken);

    if (!result.verified) {
      return {
        step: "error",
        data: { message: result.message },
        next: "retry_totp",
      };
    }

    session.totpVerified = true;
    session.step = "totp_verified";

    const secret = this.totpManager.generateSecret(session.email);
    const qrCode = await this.totpManager.generateQRCode(secret.qrCodeUri);

    return {
      step: "totp_verified",
      data: {
        message: "TOTP verified",
        qrCode,
      },
    };
  }

  async createAccount(sessionToken, username, password) {
    const session = this.sessions.get(sessionToken);
    if (!session || !session.totpVerified) {
      return {
        step: "error",
        data: { message: "Complete TOTP verification first" },
        next: "restart",
      };
    }

    const result = await this.userManager.createUser(
      username,
      password,
      session.email,
    );

    if (!result.created) {
      return {
        step: "error",
        data: { message: result.message },
        next: "restart",
      };
    }

    this.sessions.delete(sessionToken);

    return {
      step: "account_created",
      data: {
        message: result.message,
        userId: result.userId,
        username: username.toLowerCase(),
      },
    };
  }

  getSessionStatus(sessionToken) {
    const session = this.sessions.get(sessionToken);
    if (!session) {
      return { exists: false };
    }

    let maskedEmail = null;
    if (session.email) {
      const [local, domain] = session.email.split("@");
      const maskedLocal =
        local.length > 3 ? local.slice(0, 3) + "***" : local[0] + "***";
      maskedEmail = `${maskedLocal}@${domain}`;
    }

    return {
      exists: true,
      powVerified: session.powVerified,
      emailVerified: session.emailVerified,
      totpVerified: session.totpVerified,
      email: maskedEmail,
    };
  }

  // Add reset method
  reset() {
    this.sessions.clear();
    this.pow.reset();
    this.emailVerifier.reset();
    this.totpManager.reset();
  }
}

let instance = null;

export function getAuthFlow() {
  if (!instance) {
    instance = new AuthFlow();
  }
  return instance;
}

export async function resetAuthFlow() {
  if (instance) {
    instance.reset();
    await resetUserManager();
  }
  instance = null;
}

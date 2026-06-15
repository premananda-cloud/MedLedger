// modules/totp.js (add to existing file)
import speakeasy from "speakeasy";
import QRCode from "qrcode";

export class TOTPManager {
  constructor(issuer = "AuthSystem", window = 1) {
    this.issuer = issuer;
    this.window = window;
    this.secrets = new Map();
  }

  generateSecret(email) {
    const secret = speakeasy.generateSecret({ length: 20 });
    const normalizedEmail = email.toLowerCase();

    this.secrets.set(normalizedEmail, secret.base32);

    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret.base32,
      label: encodeURIComponent(email),
      issuer: this.issuer,
      encoding: "base32",
    });

    return {
      secret: secret.base32,
      qrCodeUri: otpauthUrl,
      manualKey: secret.base32,
    };
  }

  async generateQRCode(otpauthUrl) {
    try {
      const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
      return qrDataUrl;
    } catch (err) {
      throw new Error(`Failed to generate QR code: ${err.message}`);
    }
  }

  verifyToken(email, token) {
    const normalizedEmail = email.toLowerCase();
    const secret = this.secrets.get(normalizedEmail);

    if (!secret) {
      return {
        verified: false,
        remaining: 0,
        message: "TOTP not set up for this email",
      };
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: this.window,
    });

    if (verified) {
      return {
        verified: true,
        remaining: this.window,
        message: "TOTP verified successfully",
      };
    }

    return { verified: false, remaining: 0, message: "Invalid TOTP token" };
  }

  getCurrentToken(email) {
    const normalizedEmail = email.toLowerCase();
    const secret = this.secrets.get(normalizedEmail);

    if (!secret) return null;

    return speakeasy.totp({
      secret,
      encoding: "base32",
    });
  }

  hasSecret(email) {
    return this.secrets.has(email?.toLowerCase());
  }

  // Add reset method
  reset() {
    this.secrets.clear();
  }
}

let instance = null;

export function getTOTPManager() {
  if (!instance) {
    instance = new TOTPManager();
  }
  return instance;
}

export function resetTOTPManager() {
  instance = null;
}

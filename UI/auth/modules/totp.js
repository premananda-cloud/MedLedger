/**
 * TOTP Module - Time-based One-Time Password Generation & Verification
 *
 * INPUT:
 *   - secret: string (base32 encoded secret)
 *   - token: string (6-digit code for verification)
 *   - email: string (for generating QR code URI)
 *
 * OUTPUT:
 *   - qrCode: string (otpauth:// URI for QR generation)
 *   - verified: boolean
 *   - remaining: number (seconds until code expires)
 */

const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

class TOTPManager {
  constructor() {
    this.secrets = new Map(); // Store secrets per user session
    this.issuer = "AuthSystem";
  }

  /**
   * Generate new TOTP secret for user
   * @param {string} email - User's email
   * @returns {Object} { secret, qrCodeUri, manualKey }
   */
  generateSecret(email) {
    const secret = speakeasy.generateSecret({
      name: `${this.issuer}:${email}`,
      length: 20,
    });

    this.secrets.set(email, {
      base32: secret.base32,
      created: Date.now(),
    });

    return {
      secret: secret.base32,
      qrCodeUri: secret.otpauth_url,
      manualKey: secret.base32,
    };
  }

  /**
   * Generate QR code as data URL
   * @param {string} otpauthUrl - otpauth:// URI
   * @returns {Promise<string>} Data URL of QR code
   */
  async generateQRCode(otpauthUrl) {
    try {
      const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
      return qrDataUrl;
    } catch (error) {
      throw new Error("Failed to generate QR code");
    }
  }

  /**
   * Verify TOTP token
   * @param {string} email - User's email
   * @param {string} token - 6-digit code
   * @returns {Object} { verified, remaining, message }
   */
  verifyToken(email, token) {
    const secretData = this.secrets.get(email);

    if (!secretData) {
      return {
        verified: false,
        remaining: 0,
        message: "No secret found for this email",
      };
    }

    const verified = speakeasy.totp.verify({
      secret: secretData.base32,
      encoding: "base32",
      token: token,
      window: 1, // Allow 30 seconds before/after
    });

    // Calculate remaining time
    const step = 30; // 30-second window
    const now = Math.floor(Date.now() / 1000);
    const remaining = step - (now % step);

    return {
      verified,
      remaining,
      message: verified ? "Token verified" : "Invalid token",
    };
  }

  /**
   * Generate current valid token (for testing)
   * @param {string} email - User's email
   * @returns {string|null} Current valid token
   */
  getCurrentToken(email) {
    const secretData = this.secrets.get(email);
    if (!secretData) return null;

    return speakeasy.totp({
      secret: secretData.base32,
      encoding: "base32",
    });
  }

  /**
   * Check if secret exists for email
   */
  hasSecret(email) {
    return this.secrets.has(email);
  }
}

module.exports = new TOTPManager();

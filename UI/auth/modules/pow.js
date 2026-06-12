/**
 * POW Module - CAP.js Proof of Work Verification
 *
 * INPUT:
 *   - challenge: string (base64 encoded challenge)
 *   - nonce: number (client's solution)
 *   - difficulty: number (leading zeros required)
 *
 * OUTPUT:
 *   - success: boolean
 *   - message: string
 *   - sessionToken: string (if verified)
 */

const crypto = require("crypto");

class POWVerifier {
  constructor() {
    this.activeChallenges = new Map(); // Store active challenges
    this.difficulty = 4; // Default difficulty (leading zeros)
  }

  /**
   * Generate a new challenge for client
   * @returns {Object} { challenge, difficulty, timestamp }
   */
  generateChallenge() {
    const challenge = crypto.randomBytes(32).toString("base64");
    const timestamp = Date.now();
    const challengeId = crypto.randomBytes(16).toString("hex");

    this.activeChallenges.set(challengeId, {
      challenge,
      timestamp,
      difficulty: this.difficulty,
      verified: false,
    });

    // Cleanup old challenges (older than 5 minutes)
    this.cleanupOldChallenges();

    return {
      challengeId,
      challenge,
      difficulty: this.difficulty,
      timestamp,
    };
  }

  /**
   * Verify the proof of work solution
   * @param {string} challengeId - Challenge identifier
   * @param {number} nonce - Client's solution
   * @returns {Object} { success, message, sessionToken }
   */
  verify(challengeId, nonce) {
    const challengeData = this.activeChallenges.get(challengeId);

    if (!challengeData) {
      return {
        success: false,
        message: "Challenge expired or invalid",
        sessionToken: null,
      };
    }

    if (challengeData.verified) {
      return {
        success: false,
        message: "Challenge already used",
        sessionToken: null,
      };
    }

    // Verify the proof of work
    const hash = crypto
      .createHash("sha256")
      .update(challengeData.challenge + nonce)
      .digest("hex");

    const isValid = hash.startsWith("0".repeat(this.difficulty));

    if (isValid) {
      challengeData.verified = true;
      const sessionToken = crypto.randomBytes(32).toString("hex");

      return {
        success: true,
        message: "POW verified successfully",
        sessionToken,
      };
    }

    return {
      success: false,
      message: "Invalid proof of work",
      sessionToken: null,
    };
  }

  /**
   * Cleanup challenges older than 5 minutes
   */
  cleanupOldChallenges() {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    for (const [id, data] of this.activeChallenges) {
      if (data.timestamp < fiveMinutesAgo) {
        this.activeChallenges.delete(id);
      }
    }
  }

  /**
   * Get status of verification
   * @returns {Object} Statistics
   */
  getStatus() {
    return {
      activeChallenges: this.activeChallenges.size,
      difficulty: this.difficulty,
    };
  }
}

module.exports = new POWVerifier();

// modules/pow.js (add to existing file)
import crypto from "node:crypto";

export class PoW {
  constructor(difficulty = 4, expiryMs = 5 * 60 * 1000) {
    this.difficulty = difficulty;
    this.expiryMs = expiryMs;
    this.challenges = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 1000);
  }

  generateChallenge() {
    const challengeId = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(32).toString("base64");
    const timestamp = Date.now();

    this.challenges.set(challengeId, {
      challenge,
      timestamp,
      used: false,
    });

    return {
      challenge_id: challengeId,
      challenge,
      difficulty: this.difficulty,
      timestamp,
    };
  }

  verify(challengeId, nonce) {
    const record = this.challenges.get(challengeId);
    if (!record) {
      return { success: false, message: "Invalid or expired challenge" };
    }

    if (record.used) {
      return { success: false, message: "Challenge already used" };
    }

    if (Date.now() - record.timestamp > this.expiryMs) {
      this.challenges.delete(challengeId);
      return { success: false, message: "Challenge expired" };
    }

    const input = record.challenge + nonce;
    const hash = crypto.createHash("sha256").update(input).digest("hex");
    const prefix = "0".repeat(this.difficulty);

    if (!hash.startsWith(prefix)) {
      return { success: false, message: "Invalid proof of work" };
    }

    record.used = true;
    const sessionToken = crypto.randomBytes(32).toString("hex");

    return {
      success: true,
      message: "PoW verified",
      sessionToken,
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [id, record] of this.challenges) {
      if (now - record.timestamp > this.expiryMs) {
        this.challenges.delete(id);
      }
    }
  }

  getStatus() {
    return {
      activeChallenges: this.challenges.size,
      difficulty: this.difficulty,
    };
  }

  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }

  // Add reset method
  reset() {
    this.challenges.clear();
  }
}

let instance = null;

export function getPoW() {
  if (!instance) {
    instance = new PoW();
  }
  return instance;
}

export function resetPoW() {
  if (instance) {
    instance.destroy();
  }
  instance = null;
}

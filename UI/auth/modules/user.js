/**
 * User Module - Username & Password Management
 *
 * INPUT:
 *   - username: string (3-30 chars, alphanumeric)
 *   - password: string (min 8 chars, must have upper, lower, number)
 *   - email: string (associated email)
 *
 * OUTPUT:
 *   - created: boolean
 *   - message: string
 *   - userId: string (unique identifier)
 */

const crypto = require("crypto");
const storage = require("./storage");

class UserManager {
  constructor() {
    this.usernameMinLength = 3;
    this.usernameMaxLength = 30;
    this.passwordMinLength = 8;
  }

  /**
   * Validate username
   * @param {string} username
   * @returns {Object} { valid, message }
   */
  validateUsername(username) {
    if (!username || typeof username !== "string") {
      return { valid: false, message: "Username is required" };
    }

    if (username.length < this.usernameMinLength) {
      return {
        valid: false,
        message: `Username must be at least ${this.usernameMinLength} characters`,
      };
    }

    if (username.length > this.usernameMaxLength) {
      return {
        valid: false,
        message: `Username must be less than ${this.usernameMaxLength} characters`,
      };
    }

    // Alphanumeric and underscore only
    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    if (!usernameRegex.test(username)) {
      return {
        valid: false,
        message: "Username can only contain letters, numbers, and underscores",
      };
    }

    // FIXED Bug 6: Case-insensitive username check
    const normalizedUsername = username.toLowerCase();
    if (storage.usernameExists(normalizedUsername)) {
      return { valid: false, message: "Username already taken" };
    }

    return { valid: true, message: "Username is valid" };
  }

  /**
   * Validate password strength
   * @param {string} password
   * @returns {Object} { valid, message, strength }
   */
  validatePassword(password) {
    if (!password || typeof password !== "string") {
      return { valid: false, message: "Password is required", strength: 0 };
    }

    if (password.length < this.passwordMinLength) {
      return {
        valid: false,
        message: `Password must be at least ${this.passwordMinLength} characters`,
        strength: 0,
      };
    }

    let strength = 0;
    const checks = {
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumbers: /\d/.test(password),
      hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      isLongEnough: password.length >= 12,
    };

    // Calculate strength score
    Object.values(checks).forEach((check) => {
      if (check) strength++;
    });

    // At least 3 of 5 criteria must be met
    const passedChecks = Object.values(checks).filter((v) => v).length;
    if (passedChecks < 3) {
      return {
        valid: false,
        message:
          "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters, 12+ characters",
        strength,
      };
    }

    const strengthLabels = [
      "Very Weak",
      "Weak",
      "Fair",
      "Strong",
      "Very Strong",
    ];

    return {
      valid: true,
      message: "Password is valid",
      strength,
      strengthLabel: strengthLabels[strength - 1] || "Weak",
    };
  }

  /**
   * FIXED Bug 3: Hash password using async PBKDF2 with proper iteration count
   * @param {string} password
   * @param {string} salt
   * @returns {Promise<string>} Hashed password
   */
  hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
      // FIXED Bug 3: 600,000 iterations per OWASP 2023 recommendations
      crypto.pbkdf2(password, salt, 600000, 64, "sha512", (err, key) => {
        if (err) reject(err);
        else resolve(key.toString("hex"));
      });
    });
  }

  /**
   * Create user account
   * FIXED Bug 3: Async to support PBKDF2
   * FIXED Bug 6: Normalize username to lowercase
   * @param {string} username
   * @param {string} password
   * @param {string} email
   * @returns {Promise<Object>} { created, message, userId }
   */
  async createUser(username, password, email) {
    // FIXED Bug 6: Normalize username to lowercase
    const normalizedUsername = username.toLowerCase();

    // Validate username (with normalization)
    const usernameCheck = this.validateUsername(normalizedUsername);
    if (!usernameCheck.valid) {
      return { created: false, message: usernameCheck.message, userId: null };
    }

    // Validate password
    const passwordCheck = this.validatePassword(password);
    if (!passwordCheck.valid) {
      return { created: false, message: passwordCheck.message, userId: null };
    }

    // Generate salt and hash password
    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = await this.hashPassword(password, salt);

    // Create user with normalized username
    const user = {
      userId: crypto.randomBytes(16).toString("hex"),
      username: normalizedUsername, // FIXED Bug 6: Store lowercase
      email,
      passwordHash: hashedPassword,
      salt,
      createdAt: Date.now(),
      totpEnabled: true,
      verified: true,
    };

    const saved = storage.saveUser(user);

    if (saved) {
      return {
        created: true,
        message: "Account created successfully",
        userId: user.userId,
      };
    }

    return {
      created: false,
      message: "Failed to create account",
      userId: null,
    };
  }

  /**
   * Verify password
   * FIXED Bug 3: Now async
   */
  async verifyPassword(username, password) {
    const user = storage.getUserByUsername(username);
    if (!user) return false;

    const hash = await this.hashPassword(password, user.salt);
    return hash === user.passwordHash;
  }

  /**
   * Get user info (safe, no sensitive data)
   */
  getUserInfo(username) {
    const user = storage.getUserByUsername(username);
    if (!user) return null;

    return {
      userId: user.userId,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
      totpEnabled: user.totpEnabled,
    };
  }
}

module.exports = new UserManager();

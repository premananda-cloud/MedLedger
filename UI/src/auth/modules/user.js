// modules/user.js (add to existing file)
import crypto from "node:crypto";
import { getStorage, resetStorage } from "./storage.js";

export class UserManager {
  constructor(
    minUsername = 3,
    maxUsername = 30,
    minPassword = 8,
    pbkdf2Iterations = process.env.NODE_ENV === "test" ? 1000 : 600000,
    pbkdf2KeyLength = 64,
  ) {
    this.minUsername = minUsername;
    this.maxUsername = maxUsername;
    this.minPassword = minPassword;
    this.pbkdf2Iterations = pbkdf2Iterations;
    this.pbkdf2KeyLength = pbkdf2KeyLength;
    this.storage = getStorage();
  }

  validateUsername(username) {
    if (!username || typeof username !== "string") {
      return { valid: false, message: "Username is required" };
    }

    if (username.length < this.minUsername) {
      return {
        valid: false,
        message: `Username must be at least ${this.minUsername} characters`,
      };
    }

    if (username.length > this.maxUsername) {
      return {
        valid: false,
        message: `Username must be at most ${this.maxUsername} characters`,
      };
    }

    const validPattern = /^[a-zA-Z0-9_]+$/;
    if (!validPattern.test(username)) {
      return {
        valid: false,
        message: "Username can only contain letters, numbers, and underscores",
      };
    }

    if (this.storage.usernameExists(username)) {
      return { valid: false, message: "Username already taken" };
    }

    return { valid: true, message: "Username is valid" };
  }

  validatePassword(password) {
    if (!password || typeof password !== "string") {
      return {
        valid: false,
        message: "Password is required",
        strength: 0,
        strengthLabel: "invalid",
      };
    }

    let criteria = 0;
    if (/[A-Z]/.test(password)) criteria++;
    if (/[a-z]/.test(password)) criteria++;
    if (/[0-9]/.test(password)) criteria++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) criteria++;
    if (password.length >= 12) criteria++;

    const meetsMinimum = criteria >= 3 && password.length >= this.minPassword;

    let strengthLabel = "weak";
    if (criteria >= 4 && password.length >= 12) strengthLabel = "strong";
    else if (criteria >= 3 && password.length >= 10) strengthLabel = "good";

    return {
      valid: meetsMinimum,
      message: meetsMinimum
        ? "Password is valid"
        : "Password must meet at least 3 of 5 complexity criteria",
      strength: criteria,
      strengthLabel,
    };
  }

  async hashPassword(password, salt = null) {
    const actualSalt = salt || crypto.randomBytes(16);
    const saltHex = actualSalt.toString("hex");

    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        password,
        actualSalt,
        this.pbkdf2Iterations,
        this.pbkdf2KeyLength,
        "sha512",
        (err, derivedKey) => {
          if (err) reject(err);
          else
            resolve({
              hash: derivedKey.toString("hex"),
              salt: saltHex,
            });
        },
      );
    });
  }

  async createUser(username, password, email) {
    const usernameValid = this.validateUsername(username);
    if (!usernameValid.valid) {
      return { created: false, message: usernameValid.message, userId: null };
    }

    const passwordValid = this.validatePassword(password);
    if (!passwordValid.valid) {
      return { created: false, message: passwordValid.message, userId: null };
    }

    if (this.storage.emailExists(email)) {
      return {
        created: false,
        message: "Email already registered",
        userId: null,
      };
    }

    const { hash, salt } = await this.hashPassword(password);
    const userId = crypto.randomBytes(16).toString("hex");
    const lowerUsername = username.toLowerCase();

    const user = {
      userId,
      username: lowerUsername,
      email: email.toLowerCase(),
      passwordHash: hash,
      salt,
      createdAt: Date.now(),
      totpEnabled: true,
      verified: true,
    };

    const saved = await this.storage.saveUser(user);
    if (!saved) {
      return {
        created: false,
        message: "Username or email already exists",
        userId: null,
      };
    }

    return {
      created: true,
      message: "User created successfully",
      userId,
    };
  }

  async verifyPassword(username, password) {
    const user = this.storage.getUserByUsername(username);
    if (!user) return false;

    const saltBuffer = Buffer.from(user.salt, "hex");
    const { hash } = await this.hashPassword(password, saltBuffer);

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(user.passwordHash, "hex"),
    );
  }

  getUserInfo(username) {
    const user = this.storage.getUserByUsername(username);
    if (!user) return null;

    return {
      username: user.username,
      email: user.email,
      userId: user.userId,
      createdAt: user.createdAt,
      totpEnabled: user.totpEnabled,
      verified: user.verified,
    };
  }

  // Add reset method
  async reset() {
    await this.storage.reset();
  }
}

let instance = null;

export function getUserManager() {
  if (!instance) {
    instance = new UserManager();
  }
  return instance;
}

export async function resetUserManager() {
  if (instance) {
    await instance.reset();
  }
  instance = null;
}

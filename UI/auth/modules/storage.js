// modules/storage.js (add to existing file)
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_DATA_DIR = path.join(__dirname, "..", "data");
const DEFAULT_USERS_FILE = "users.json";

export class Storage {
  constructor(dataDir = DEFAULT_DATA_DIR, fileName = DEFAULT_USERS_FILE) {
    this.dataDir = dataDir;
    this.filePath = path.join(dataDir, fileName);
    this.users = new Map();
    this.emailMap = new Map();
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;

    try {
      await fs.mkdir(this.dataDir, { recursive: true });
      const data = await fs.readFile(this.filePath, "utf-8").catch(() => "[]");
      const users = JSON.parse(data);

      for (const user of users) {
        this.users.set(user.username.toLowerCase(), user);
        if (user.email)
          this.emailMap.set(
            user.email.toLowerCase(),
            user.username.toLowerCase(),
          );
      }
    } catch (err) {
      console.error("Storage init error:", err);
    }
    this.initialized = true;
  }

  async save() {
    const usersArray = Array.from(this.users.values());
    await fs.writeFile(this.filePath, JSON.stringify(usersArray, null, 2));
  }

  async saveUser(user) {
    await this.init();

    const lowerUsername = user.username.toLowerCase();
    if (this.users.has(lowerUsername)) return false;
    if (user.email && this.emailMap.has(user.email.toLowerCase())) return false;

    this.users.set(lowerUsername, user);
    if (user.email) this.emailMap.set(user.email.toLowerCase(), lowerUsername);
    await this.save();
    return true;
  }

  getUserByUsername(username) {
    return this.users.get(username?.toLowerCase()) || null;
  }

  getUserByEmail(email) {
    const username = this.emailMap.get(email?.toLowerCase());
    return username ? this.users.get(username) : null;
  }

  usernameExists(username) {
    return this.users.has(username?.toLowerCase());
  }

  emailExists(email) {
    return this.emailMap.has(email?.toLowerCase());
  }

  getUserCount() {
    return this.users.size;
  }

  getAllUsers() {
    return Array.from(this.users.values()).map((u) => ({
      username: u.username,
      email: u.email,
      createdAt: u.createdAt,
    }));
  }

  // Add reset method for testing
  async reset() {
    this.users.clear();
    this.emailMap.clear();
    this.initialized = false;
    await fs.writeFile(this.filePath, "[]").catch(() => {});
  }
}

let instance = null;

export function getStorage() {
  if (!instance) {
    instance = new Storage();
  }
  return instance;
}

// Add reset function for testing
export async function resetStorage() {
  if (instance) {
    await instance.reset();
  }
  instance = null;
}

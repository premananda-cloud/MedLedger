/**
 * Storage Module - Local File-based User Storage
 *
 * INPUT:
 *   - user: object (user data to save)
 *   - username: string (to lookup)
 *
 * OUTPUT:
 *   - saved: boolean
 *   - user: object (retrieved user data)
 */

const fs = require("fs");
const path = require("path");

class LocalStorage {
  constructor() {
    this.dataDir = path.join(__dirname, "..", "data");
    this.usersFile = path.join(this.dataDir, "users.json");
    this.ensureDataDirectory();
    this.loadUsers();
  }

  ensureDataDirectory() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.usersFile)) {
      fs.writeFileSync(this.usersFile, JSON.stringify({ users: [] }, null, 2));
    }
  }

  loadUsers() {
    try {
      const data = fs.readFileSync(this.usersFile, "utf8");
      this.data = JSON.parse(data);
    } catch (error) {
      this.data = { users: [] };
    }
  }

  saveToDisk() {
    fs.writeFileSync(this.usersFile, JSON.stringify(this.data, null, 2));
  }

  /**
   * Save user to storage
   */
  saveUser(user) {
    // Check for duplicate username or email
    if (this.usernameExists(user.username)) {
      return false;
    }
    if (this.emailExists(user.email)) {
      return false;
    }

    this.data.users.push(user);
    this.saveToDisk();
    return true;
  }

  /**
   * Get user by username
   * FIXED Bug 6: Case-insensitive comparison
   */
  getUserByUsername(username) {
    const lower = username.toLowerCase();
    return this.data.users.find((u) => u.username === lower) || null;
  }

  /**
   * Get user by email
   */
  getUserByEmail(email) {
    return this.data.users.find((u) => u.email === email) || null;
  }

  /**
   * Check if username exists
   * FIXED Bug 6: Case-insensitive comparison
   */
  usernameExists(username) {
    const lower = username.toLowerCase();
    return this.data.users.some((u) => u.username === lower);
  }

  /**
   * Check if email exists
   */
  emailExists(email) {
    return this.data.users.some((u) => u.email === email);
  }

  /**
   * Get total user count
   */
  getUserCount() {
    return this.data.users.length;
  }

  /**
   * Get all users (without sensitive data)
   */
  getAllUsers() {
    return this.data.users.map((u) => ({
      username: u.username,
      email: u.email,
      createdAt: u.createdAt,
    }));
  }
}

module.exports = new LocalStorage();

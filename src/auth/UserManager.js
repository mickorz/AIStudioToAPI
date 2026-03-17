/**
 * File: src/auth/UserManager.js
 * Description: User management module with JSON file storage
 *
 * Author: Ellinav, iBenzene, bbbugg
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/**
 * UserManager
 *
 * Manages user authentication with JSON file storage.
 * Passwords are hashed using PBKDF2 with salt.
 *
 * UserManager 初始化流程:
 *
 * UserManager.constructor()
 *     |
 *     +-> 加载或创建用户数据文件
 *     |
 *     +-> 检查是否存在默认用户，不存在则创建
 */
class UserManager {
    constructor(logger) {
        this.logger = logger;
        this.dataPath = path.join(process.cwd(), "configs", "users.json");
        this.users = [];
        this._loadUsers();
    }

    /**
     * Load users from JSON file
     */
    _loadUsers() {
        try {
            // Ensure configs directory exists
            const configsDir = path.dirname(this.dataPath);
            if (!fs.existsSync(configsDir)) {
                fs.mkdirSync(configsDir, { recursive: true });
            }

            if (fs.existsSync(this.dataPath)) {
                const content = fs.readFileSync(this.dataPath, "utf-8");
                const data = JSON.parse(content);
                this.users = Array.isArray(data.users) ? data.users : [];
                this.logger.info(`[UserManager] Loaded ${this.users.length} users from file.`);
            } else {
                this.users = [];
                this.logger.info("[UserManager] No users file found, starting fresh.");
            }

            // Create default admin user if no users exist
            if (this.users.length === 0) {
                this.logger.info("[UserManager] No users found, creating default admin user...");
                this.createUser("admin", "mickorz", "Administrator");
                this.logger.info("[UserManager] Default admin user created. Username: admin, Password: mickorz");
                this.logger.warn("[UserManager] IMPORTANT: Please change the default password immediately!");
            }
        } catch (error) {
            this.logger.error(`[UserManager] Failed to load users: ${error.message}`);
            this.users = [];
        }
    }

    /**
     * Save users to JSON file
     */
    _saveUsers() {
        try {
            const configsDir = path.dirname(this.dataPath);
            if (!fs.existsSync(configsDir)) {
                fs.mkdirSync(configsDir, { recursive: true });
            }

            const data = {
                users: this.users,
            };
            fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2), "utf-8");
        } catch (error) {
            this.logger.error(`[UserManager] Failed to save users: ${error.message}`);
            throw error;
        }
    }

    /**
     * Hash password with salt using PBKDF2
     * @param {string} password - Plain text password
     * @param {string} salt - Salt for hashing
     * @returns {string} Hashed password
     */
    _hashPassword(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
    }

    /**
     * Generate a random salt
     * @returns {string} Random salt
     */
    _generateSalt() {
        return crypto.randomBytes(32).toString("hex");
    }

    /**
     * Generate a unique ID
     * @returns {string} Unique ID
     */
    _generateId() {
        return Date.now().toString(36) + crypto.randomBytes(4).toString("hex");
    }

    /**
     * Create a new user
     * @param {string} username - Username
     * @param {string} password - Plain text password
     * @param {string} displayName - Display name (optional)
     * @returns {Object} Created user info
     */
    createUser(username, password, displayName = null) {
        if (!username || !password) {
            throw new Error("Username and password are required");
        }

        const normalizedUsername = username.toLowerCase();

        if (normalizedUsername.length < 2 || normalizedUsername.length > 50) {
            throw new Error("Username must be between 2 and 50 characters");
        }

        if (password.length < 4) {
            throw new Error("Password must be at least 4 characters");
        }

        // Check if username already exists
        if (this.users.some(u => u.username === normalizedUsername)) {
            throw new Error("Username already exists");
        }

        const salt = this._generateSalt();
        const passwordHash = this._hashPassword(password, salt);

        const user = {
            createdAt: new Date().toISOString(),
            displayName: displayName || username,
            id: this._generateId(),
            passwordHash,
            salt,
            updatedAt: new Date().toISOString(),
            username: normalizedUsername,
        };

        this.users.push(user);
        this._saveUsers();
        this.logger.info(`[UserManager] User created: ${username}`);

        return {
            displayName: user.displayName,
            id: user.id,
            username: user.username,
        };
    }

    /**
     * Verify user credentials
     * @param {string} username - Username
     * @param {string} password - Plain text password
     * @returns {Object|null} User info if valid, null otherwise
     */
    verifyUser(username, password) {
        if (!username || !password) {
            return null;
        }

        const normalizedUsername = username.toLowerCase();
        const user = this.users.find(u => u.username === normalizedUsername);

        if (!user) {
            return null;
        }

        const passwordHash = this._hashPassword(password, user.salt);
        if (passwordHash !== user.passwordHash) {
            return null;
        }

        return {
            displayName: user.displayName,
            id: user.id,
            username: user.username,
        };
    }

    /**
     * Update user password
     * @param {string} userId - User ID
     * @param {string} newPassword - New plain text password
     * @returns {boolean} Success status
     */
    updatePassword(userId, newPassword) {
        if (!newPassword || newPassword.length < 4) {
            throw new Error("Password must be at least 4 characters");
        }

        const user = this.users.find(u => u.id === userId);
        if (!user) {
            return false;
        }

        const salt = this._generateSalt();
        const passwordHash = this._hashPassword(newPassword, salt);

        user.passwordHash = passwordHash;
        user.salt = salt;
        user.updatedAt = new Date().toISOString();

        this._saveUsers();
        this.logger.info(`[UserManager] Password updated for user: ${user.username}`);
        return true;
    }

    /**
     * Update user display name
     * @param {string} userId - User ID
     * @param {string} displayName - New display name
     * @returns {boolean} Success status
     */
    updateDisplayName(userId, displayName) {
        const user = this.users.find(u => u.id === userId);
        if (!user) {
            return false;
        }

        user.displayName = displayName;
        user.updatedAt = new Date().toISOString();

        this._saveUsers();
        this.logger.info(`[UserManager] Display name updated for user: ${user.username}`);
        return true;
    }

    /**
     * Delete a user
     * @param {string} userId - User ID
     * @returns {boolean} Success status
     */
    deleteUser(userId) {
        // Check if this is the last user
        if (this.users.length <= 1) {
            throw new Error("Cannot delete the last user");
        }

        const index = this.users.findIndex(u => u.id === userId);
        if (index === -1) {
            return false;
        }

        const deletedUser = this.users.splice(index, 1)[0];
        this._saveUsers();
        this.logger.info(`[UserManager] User deleted: ${deletedUser.username}`);
        return true;
    }

    /**
     * Get all users (without password hashes)
     * @returns {Array} List of users
     */
    getAllUsers() {
        return this.users.map(u => ({
            createdAt: u.createdAt,
            displayName: u.displayName,
            id: u.id,
            updatedAt: u.updatedAt,
            username: u.username,
        }));
    }

    /**
     * Get user by ID
     * @param {string} userId - User ID
     * @returns {Object|null} User info
     */
    getUserById(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) {
            return null;
        }

        return {
            createdAt: user.createdAt,
            displayName: user.displayName,
            id: user.id,
            updatedAt: user.updatedAt,
            username: user.username,
        };
    }

    /**
     * Check if any users exist
     * @returns {boolean} True if users exist
     */
    hasUsers() {
        return this.users.length > 0;
    }
}

module.exports = UserManager;

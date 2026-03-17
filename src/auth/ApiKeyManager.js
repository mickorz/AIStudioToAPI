/**
 * File: src/auth/ApiKeyManager.js
 * Description: API Key management module for generating, storing, and validating API keys
 *
 * Author: Ellinav, iBenzene, bbbugg
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/**
 * ApiKeyManager
 *
 * Responsible for managing API keys stored in configs/api_keys.json
 *
 * ApiKeyManager 初始化流程:
 *
 * ApiKeyManager.constructor()
 *     |
 *     +-> loadKeys()              加载已有 API Keys
 *          |
 *          +-> 读取 configs/api_keys.json
 *          |
 *          +-> 返回 keys 数组
 */
class ApiKeyManager {
    constructor(logger) {
        this.logger = logger;
        this.keys = [];
        this.keysFilePath = path.join(process.cwd(), "configs", "api_keys.json");
        this.loadKeys();
    }

    /**
     * Load API keys from file
     * @returns {Array} Array of key objects
     */
    loadKeys() {
        try {
            if (fs.existsSync(this.keysFilePath)) {
                const content = fs.readFileSync(this.keysFilePath, "utf-8");
                const data = JSON.parse(content);
                this.keys = Array.isArray(data.keys) ? data.keys : [];
                this.logger.info(`[ApiKeyManager] Loaded ${this.keys.length} custom API keys from file.`);
            } else {
                this.keys = [];
                this.logger.info("[ApiKeyManager] No custom API keys file found, starting with empty list.");
            }
        } catch (error) {
            this.logger.error(`[ApiKeyManager] Failed to load API keys: ${error.message}`);
            this.keys = [];
        }
        return this.keys;
    }

    /**
     * Save API keys to file
     * @returns {boolean} Success status
     */
    saveKeys() {
        try {
            const dir = path.dirname(this.keysFilePath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }

            const data = {
                keys: this.keys,
            };
            fs.writeFileSync(this.keysFilePath, JSON.stringify(data, null, 2), "utf-8");
            this.logger.info(`[ApiKeyManager] Saved ${this.keys.length} API keys to file.`);
            return true;
        } catch (error) {
            this.logger.error(`[ApiKeyManager] Failed to save API keys: ${error.message}`);
            return false;
        }
    }

    /**
     * Generate a new API key
     * @param {string} name - Name/description for the key
     * @returns {Object} The generated key object
     */
    generateKey(name = "API Key") {
        const id = crypto.randomUUID();
        const keyString = `sk-${crypto.randomBytes(24).toString("hex")}`;
        const keyObj = {
            createdAt: new Date().toISOString(),
            id,
            key: keyString,
            lastUsedAt: null,
            name,
        };

        this.keys.push(keyObj);
        this.saveKeys();
        this.logger.info(`[ApiKeyManager] Generated new API key: ${name} (${id})`);
        return keyObj;
    }

    /**
     * Delete an API key by ID
     * @param {string} id - The key ID to delete
     * @returns {boolean} Success status
     */
    deleteKey(id) {
        const index = this.keys.findIndex(k => k.id === id);
        if (index === -1) {
            this.logger.warn(`[ApiKeyManager] API key not found: ${id}`);
            return false;
        }

        const deletedKey = this.keys.splice(index, 1)[0];
        this.saveKeys();
        this.logger.info(`[ApiKeyManager] Deleted API key: ${deletedKey.name} (${id})`);
        return true;
    }

    /**
     * Validate if a key string is valid
     * @param {string} keyString - The key string to validate
     * @returns {boolean} Whether the key is valid
     */
    validateKey(keyString) {
        const keyObj = this.keys.find(k => k.key === keyString);
        return !!keyObj;
    }

    /**
     * Update last used timestamp for a key
     * @param {string} keyString - The key string to update
     */
    updateLastUsed(keyString) {
        const keyObj = this.keys.find(k => k.key === keyString);
        if (keyObj) {
            keyObj.lastUsedAt = new Date().toISOString();
            // Debounce saves - only save every 5 minutes at most
            if (!this._lastSaveTime || Date.now() - this._lastSaveTime > 300000) {
                this.saveKeys();
                this._lastSaveTime = Date.now();
            }
        }
    }

    /**
     * Get all key objects (without full key string for security)
     * @param {boolean} includeFullKey - Whether to include the full key string
     * @returns {Array} Array of key objects
     */
    getAllKeys(includeFullKey = false) {
        if (includeFullKey) {
            return [...this.keys];
        }
        // Return keys with masked key string for display
        return this.keys.map(k => ({
            ...k,
            key: this.maskKey(k.key),
        }));
    }

    /**
     * Get all raw key strings for validation
     * @returns {Array<string>} Array of key strings
     */
    getAllKeyStrings() {
        return this.keys.map(k => k.key);
    }

    /**
     * Mask a key string for display
     * @param {string} keyString - The key string to mask
     * @returns {string} Masked key string
     */
    maskKey(keyString) {
        if (!keyString || keyString.length < 12) {
            return keyString;
        }
        return `${keyString.substring(0, 7)}...${keyString.substring(keyString.length - 4)}`;
    }

    /**
     * Get key count
     * @returns {number} Number of keys
     */
    getKeyCount() {
        return this.keys.length;
    }
}

module.exports = ApiKeyManager;

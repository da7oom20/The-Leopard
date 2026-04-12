const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const ENCRYPTED_PREFIX = 'enc:';

// Derive a 32-byte key from the environment variable
function getKey() {
  const raw = process.env.ENCRYPTION_KEY || process.env.JWT_SECRET;
  if (!raw) throw new Error('ENCRYPTION_KEY or JWT_SECRET must be set');
  return crypto.createHash('sha256').update(raw).digest();
}

// Which key source is in use
function getKeySource() {
  return process.env.ENCRYPTION_KEY ? 'ENCRYPTION_KEY' : 'JWT_SECRET';
}

/**
 * Encrypt a plaintext string. Returns prefixed ciphertext.
 * Returns null/empty values as-is.
 */
function encrypt(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return plaintext;
  if (plaintext.startsWith(ENCRYPTED_PREFIX)) return plaintext; // already encrypted

  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();

  // Format: enc:<iv_hex>:<tag_hex>:<ciphertext_hex>
  return `${ENCRYPTED_PREFIX}${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt an encrypted string. Returns plaintext.
 * Returns non-encrypted values as-is (backward compatible).
 */
function decrypt(ciphertext) {
  if (!ciphertext || typeof ciphertext !== 'string') return ciphertext;
  if (!ciphertext.startsWith(ENCRYPTED_PREFIX)) return ciphertext; // plaintext, not encrypted

  const parts = ciphertext.slice(ENCRYPTED_PREFIX.length).split(':');
  if (parts.length !== 3) return ciphertext; // malformed, return as-is

  const [ivHex, tagHex, encrypted] = parts;
  const key = getKey();
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Check if a value is already encrypted.
 */
function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(ENCRYPTED_PREFIX);
}

/**
 * Encrypt sensitive fields in a JSON object (e.g., extraConfig).
 * Only encrypts string values matching password/secret/token keys.
 */
function encryptJsonFields(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const result = { ...obj };
  for (const key of Object.keys(result)) {
    if (/password|secret|token/i.test(key) && typeof result[key] === 'string' && result[key]) {
      result[key] = encrypt(result[key]);
    }
  }
  return result;
}

/**
 * Decrypt sensitive fields in a JSON object.
 */
function decryptJsonFields(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const result = { ...obj };
  for (const key of Object.keys(result)) {
    if (typeof result[key] === 'string' && isEncrypted(result[key])) {
      result[key] = decrypt(result[key]);
    }
  }
  return result;
}

module.exports = { encrypt, decrypt, isEncrypted, encryptJsonFields, decryptJsonFields, getKeySource };

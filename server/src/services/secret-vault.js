/**
 * Secret Vault — AES-256-GCM encryption-at-rest for daemon HMAC keys.
 *
 * Daemon secrets must be recoverable (the server recomputes HMACs with them),
 * so hashing is not an option. Encrypting the column protects against leaks
 * of the SQLite file alone (backups, dumps). See adr/001-daemon-secret-storage.md.
 *
 * Key material, in order of preference:
 *   1. SECRET_ENC_KEY env var (base64, 32 bytes) — production-style injection
 *   2. A key file generated on first use at <dataDir>/secret-enc.key (0600)
 *
 * Stored format: "enc:v1:<iv b64>:<authTag b64>:<ciphertext b64>"
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEY_FILE = path.join(__dirname, '..', '..', 'data', 'secret-enc.key');
const PREFIX = 'enc:v1:';

let encryptionKey = null;

function getEncryptionKey() {
  if (encryptionKey) return encryptionKey;

  if (process.env.SECRET_ENC_KEY) {
    const key = Buffer.from(process.env.SECRET_ENC_KEY, 'base64');
    if (key.length !== 32) {
      throw new Error('SECRET_ENC_KEY must be 32 bytes, base64-encoded');
    }
    encryptionKey = key;
    return encryptionKey;
  }

  if (fs.existsSync(KEY_FILE)) {
    encryptionKey = fs.readFileSync(KEY_FILE);
    return encryptionKey;
  }

  if (process.env.NODE_ENV === 'production') {
    console.warn('[vault.warning] SECRET_ENC_KEY is not set in production environment — generating local key file in data directory');
  }

  encryptionKey = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  fs.writeFileSync(KEY_FILE, encryptionKey, { mode: 0o600 });
  return encryptionKey;
}

/** Encrypts a secret for storage. */
export function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
}

/**
 * Decrypts a stored secret. Returns null when the value cannot be decrypted
 * (wrong key, corrupted row) so callers fail the HMAC check instead of crashing.
 * Values without the "enc:v1:" prefix are legacy plaintext rows and returned as-is.
 */
export function decryptSecret(stored) {
  if (stored == null) return null;
  if (!stored.startsWith(PREFIX)) return stored;

  try {
    const [ivB64, tagB64, ctB64] = stored.slice(PREFIX.length).split(':');
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      getEncryptionKey(),
      Buffer.from(ivB64, 'base64')
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(ctB64, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}

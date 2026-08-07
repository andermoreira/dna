/**
 * Database Layer — SQLite via better-sqlite3
 *
 * Uses a singleton pattern (getDb) with lazy initialization. The database file
 * lives at server/data/pocdna.db and is created on first access.
 *
 * Schema (4 tables):
 *   users          — user accounts with bcrypt password hashes
 *   terminals      — registered device fingerprints (3 layers)
 *   daemon_secrets — HMAC secret keys for daemon signature validation
 *   auth_events    — audit log of registration, verification, and revocations
 *
 * WAL journal mode provides better concurrent read performance.
 * Foreign keys are enforced at the SQLite level.
 */

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Singleton database instance — only one connection per process
let db;

/**
 * Returns the database instance, creating tables on first call.
 * Thread-safe: better-sqlite3 is synchronous and serializes access.
 */
export function getDb() {
  if (db) return db;

  // Database file: server/data/pocdna.db
  const dbPath = join(__dirname, '..', 'data', 'pocdna.db');
  db = new Database(dbPath);

  // WAL mode: writers don't block readers, better concurrent performance
  db.pragma('journal_mode = WAL');

  // Enforce foreign key constraints (SQLite disables by default)
  db.pragma('foreign_keys = ON');

  // ---------------------------------------------------------------------------
  // Schema definition — CREATE TABLE IF NOT EXISTS for idempotent startup
  // ---------------------------------------------------------------------------
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,          -- UUID v4
      username TEXT UNIQUE NOT NULL, -- Login name
      password_hash TEXT NOT NULL,   -- bcrypt hash (12 rounds)
      created_at TEXT NOT NULL       -- ISO 8601 timestamp
    );

    CREATE TABLE IF NOT EXISTS terminals (
      id TEXT PRIMARY KEY,                  -- UUID v4
      user_id TEXT NOT NULL REFERENCES users(id), -- Owner
      label TEXT NOT NULL,                  -- User-given name (e.g. "My Laptop")
      browser_fp_hash TEXT NOT NULL,        -- SHA-256 of Layer 1 components
      browser_fp_data TEXT NOT NULL,        -- JSON: full Layer 1 components
      daemon_fp_hash TEXT,                  -- SHA-256 of Layer 2 payload (null if no daemon)
      daemon_fp_data TEXT,                  -- JSON: full Layer 2 payload
      ja4_hash TEXT,                        -- Layer 3 TLS fingerprint (null if unavailable)
      registered_at TEXT NOT NULL,          -- ISO 8601
      last_seen_at TEXT NOT NULL,           -- ISO 8601 — updated on each successful verify
      revoked_at TEXT                       -- ISO 8601 — NULL until revoked
    );

    CREATE TABLE IF NOT EXISTS daemon_secrets (
      terminal_id TEXT PRIMARY KEY REFERENCES terminals(id), -- 1:1 with terminal
      secret_key TEXT NOT NULL,             -- Base64-encoded 256-bit HMAC key
      created_at TEXT NOT NULL              -- ISO 8601
    );

    CREATE TABLE IF NOT EXISTS auth_events (
      id TEXT PRIMARY KEY,          -- UUID v4
      user_id TEXT NOT NULL REFERENCES users(id),
      terminal_id TEXT REFERENCES terminals(id), -- NULLABLE (e.g. VERIFY_FAIL)
      event_type TEXT NOT NULL,     -- REGISTER, VERIFY_OK, VERIFY_FAIL, REVOKE
      confidence REAL,              -- 0.0 to 1.0 (NULLABLE)
      layers_matched TEXT,          -- JSON: {"browser":true,"daemon":null,"tls":false}
      ip_address TEXT NOT NULL,     -- Client IP
      user_agent TEXT NOT NULL,     -- Browser User-Agent header
      ja4_observed TEXT,            -- JA4 hash observed at event time
      created_at TEXT NOT NULL      -- ISO 8601
    );
  `);

  return db;
}

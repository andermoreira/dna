/**
 * Database Seeder — creates the demo user for immediate POC demonstration.
 *
 * Inserts user "demo" with password "demo123" (bcrypt-hashed) if it doesn't
 * already exist. This allows `docker compose up` + login without registration.
 */

import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from './db.js';

export async function seed() {
  const db = getDb();

  // Check if demo user already exists (idempotent — safe to run on every startup)
  const existing = db.prepare(
    'SELECT COUNT(*) as count FROM users WHERE username = ?'
  ).get('demo');

  if (existing.count > 0) {
    console.log('[seed] demo user already exists');
    return;
  }

  // Hash the demo password with bcrypt (12 salt rounds)
  const passwordHash = await bcrypt.hash('demo123', 12);
  const id = uuidv4();
  const createdAt = new Date().toISOString();

  db.prepare(
    'INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)'
  ).run(id, 'demo', passwordHash, createdAt);

  console.log('[seed] demo user created (demo / demo123)');
}

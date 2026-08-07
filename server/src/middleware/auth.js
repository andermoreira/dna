/**
 * Authentication Middleware
 *
 * requireAuth — Express middleware that validates the user's session.
 *
 * Session-based authentication flow:
 *   1. User POSTs credentials to /api/auth/login
 *   2. Server verifies bcrypt hash, sets req.session.userId
 *   3. On subsequent requests, the session cookie is sent automatically
 *   4. requireAuth reads req.session.userId and loads the user from DB
 *
 * If the session is missing or the user no longer exists in the database,
 * returns 401 and clears the session.
 */

import { getDb } from '../db.js';

/**
 * Middleware: ensures the request has a valid authenticated session.
 *
 * Attaches `req.user` with { id, username, created_at } on success.
 * Returns 401 JSON on failure.
 *
 * Usage:
 *   router.get('/protected', requireAuth, handler);
 */
export function requireAuth(req, res, next) {
  // Check session exists and has userId
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Load user from database (verifies the user still exists — not deleted)
  const db = getDb();
  const user = db.prepare(
    'SELECT id, username, created_at FROM users WHERE id = ?'
  ).get(req.session.userId);

  if (!user) {
    // Session references a deleted user — destroy the invalid session
    req.session.destroy();
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Attach user to request for downstream handlers
  req.user = user;
  next();
}

/**
 * Terminal Authorization Guard Middleware
 *
 * requireKnownTerminal — Express middleware that blocks requests if the
 * current terminal has not been verified and registered.
 *
 * This is the enforcement point of the terminal authentication layer.
 * After a user logs in, sensitive actions require that:
 *   1. The terminal has been verified (fingerprint matched)
 *   2. The verification result is cached in the session
 *   3. The terminal has not been revoked
 *
 * Session flow:
 *   POST /api/auth/verify-terminal → known:true
 *     → setTerminalSession(req, terminalId) called in terminals.js
 *     → req.session.terminalId = "uuid"
 *   POST /api/actions/sensitive
 *     → requireKnownTerminal checks req.session.terminalId
 *     → loads terminal from DB, verifies not revoked
 *     → allows or blocks
 */

import { getDb } from '../db.js';

/**
 * Stores the terminal verification result in the user's session.
 *
 * Called after a successful /api/auth/verify-terminal response.
 * Subsequent requests from the same session don't need to re-collect
 * the fingerprint — the terminal binding persists in the session cookie.
 *
 * @param {Request} req - Express request object (with session)
 * @param {string} terminalId - UUID of the matched terminal
 */
export function setTerminalSession(req, terminalId) {
  req.session.terminalId = terminalId;
  req.session.terminalVerifiedAt = Date.now();
}

/**
 * Middleware: blocks requests from unverified or revoked terminals.
 *
 * Three failure modes:
 *   1. No terminal in session → "not authorized" (never verified)
 *   2. Terminal not found in DB → "not authorized" (deleted externally)
 *   3. Terminal revoked → "revoked" (explicitly removed)
 *
 * Usage:
 *   router.post('/sensitive', requireAuth, requireKnownTerminal, handler);
 */
export function requireKnownTerminal(req, res, next) {
  // Check if a terminal was verified during this session
  if (!req.session || !req.session.terminalId) {
    return res.status(403).json({
      error: 'This terminal is not authorized for this action. Use a registered device or register this one through your account settings.',
    });
  }

  const db = getDb();

  // Load terminal and check it still exists in the database
  const terminal = db.prepare(
    'SELECT id, revoked_at FROM terminals WHERE id = ?'
  ).get(req.session.terminalId);

  if (!terminal) {
    // Terminal was deleted externally (bypassing the normal delete flow)
    req.session.terminalId = null;
    req.session.terminalVerifiedAt = null;
    return res.status(403).json({
      error: 'This terminal is not authorized for this action. Use a registered device or register this one through your account settings.',
    });
  }

  if (terminal.revoked_at) {
    // Terminal was explicitly revoked (by user or admin)
    // Clear the session binding so the user sees the unknown-terminal flow
    req.session.terminalId = null;
    req.session.terminalVerifiedAt = null;
    return res.status(403).json({
      error: 'This terminal has been revoked. Please register again.',
    });
  }

  // Terminal exists, is active, and was verified in this session
  next();
}

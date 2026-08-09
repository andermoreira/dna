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
 * The per-layer results are stored so the sensitive-action guard can require
 * that the daemon layer passed in THIS session — recognition via browser+TLS
 * alone (2/3 quorum) must not unlock sensitive actions.
 *
 * @param {Request} req - Express request object (with session)
 * @param {string} terminalId - UUID of the matched terminal
 * @param {{ browser: boolean, daemon: boolean|null, tls: boolean|null }} layers
 */
export function setTerminalSession(req, terminalId, layers) {
  req.session.terminalId = terminalId;
  req.session.terminalLayers = layers;
  req.session.terminalVerifiedAt = Date.now();
}

/**
 * Middleware: blocks requests from unverified, revoked or weak terminals.
 *
 * Failure modes:
 *   1. No terminal in session → "not authorized" (never verified)
 *   2. Terminal not found for this user → "not authorized" (deleted or cross-user)
 *   3. Terminal revoked → "revoked" (explicitly removed)
 *   4. Daemon layer did not pass in this session → "daemon_layer_required"
 *      (AC-03: browser-only terminals are "weak"; and even daemon-registered
 *      terminals recognized via browser+TLS alone must not unlock sensitive
 *      actions — the daemon HMAC is the only non-spoofable layer)
 *
 * Must run after requireAuth (relies on req.user for ownership scoping).
 *
 * Usage:
 *   router.post('/sensitive', requireAuth, requireKnownTerminal, handler);
 */
export function requireKnownTerminal(req, res, next) {
  // Check if a terminal was verified during this session
  if (!req.session || !req.session.terminalId) {
    return res.status(403).json({
      code: 'terminal_not_authorized',
      message: 'This terminal is not authorized for this action. Use a registered device or register this one through your account settings.',
    });
  }

  const db = getDb();

  // Load terminal scoped to the authenticated user (defense in depth against
  // a session carrying another user's terminal id)
  const terminal = db.prepare(
    'SELECT id, revoked_at FROM terminals WHERE id = ? AND user_id = ?'
  ).get(req.session.terminalId, req.user.id);

  if (!terminal) {
    // Terminal was deleted externally (bypassing the normal delete flow)
    req.session.terminalId = null;
    req.session.terminalLayers = null;
    req.session.terminalVerifiedAt = null;
    return res.status(403).json({
      code: 'terminal_not_authorized',
      message: 'This terminal is not authorized for this action. Use a registered device or register this one through your account settings.',
    });
  }

  if (terminal.revoked_at) {
    // Terminal was explicitly revoked (by user or admin)
    // Clear the session binding so the user sees the unknown-terminal flow
    req.session.terminalId = null;
    req.session.terminalLayers = null;
    req.session.terminalVerifiedAt = null;
    return res.status(403).json({
      code: 'terminal_revoked',
      message: 'This terminal has been revoked. Please register again.',
    });
  }

  // AC-03: sensitive actions require the daemon layer to have passed in THIS
  // session. Covers both weak (browser-only) terminals (daemon = null) and
  // daemon-registered terminals recognized without the daemon (daemon = false).
  if (req.session.terminalLayers?.daemon !== true) {
    return res.status(403).json({
      code: 'daemon_layer_required',
      message: 'Sensitive actions require the terminal security module (daemon). Ensure the daemon is running and verify this terminal again.',
    });
  }

  // Terminal exists, is active, and its daemon layer was verified in this session
  next();
}

/**
 * Admin Panel API Routes
 *
 * Endpoints:
 *   GET  /api/admin/terminals         — list all terminals (all users)
 *   POST /api/admin/terminals/:id/revoke — revoke a terminal globally
 *
 * Protected by x-admin-key header authentication.
 * The admin key is set via the ADMIN_KEY environment variable. When it is not
 * set, the middleware fails closed: every request is rejected with 401.
 *
 * Admin operations are cross-user — an admin can revoke any terminal
 * regardless of who owns it. This is used for fraud investigation and
 * incident response scenarios.
 */

import { Router } from 'express';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from '../db.js';
import { logEvent } from '../log.js';
import { rateLimit } from '../middleware/rateLimit.js';

const router = Router();

// Brute-force protection for the static admin key (only failed attempts count)
const adminRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyFn: (req) => `admin:${req.ip}`,
  failuresOnly: true,
});

/**
 * Admin authentication middleware.
 *
 * Checks the x-admin-key header against the configured ADMIN_KEY.
 * Unlike user authentication (session-based), admin auth uses a simple
 * static API key. This is intentional for POC simplicity; production
 * would use JWT or OAuth with proper admin role validation.
 *
 * Security:
 *   - Fails closed if ADMIN_KEY is unset or empty (500 Admin misconfigured)
 *   - Compares SHA-256 digests with crypto.timingSafeEqual (no length/timing leak)
 *   - Rate-limited per IP (20 failed attempts / 15 min)
 */
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  const expected = process.env.ADMIN_KEY;

  // Fail-closed if ADMIN_KEY is not configured in the server environment
  if (!expected || typeof expected !== 'string' || expected.trim().length === 0) {
    console.error('[admin] request blocked: ADMIN_KEY environment variable is not configured');
    return res.status(500).json({ code: 'admin_misconfigured', message: 'Admin authentication is not configured' });
  }

  if (!key || typeof key !== 'string') {
    return res.status(401).json({ code: 'invalid_admin_key', message: 'Invalid admin key' });
  }

  // Compare fixed-length digests so the key length is not leaked by timing
  const digest = (value) => crypto.createHash('sha256').update(value).digest();
  if (!crypto.timingSafeEqual(digest(key), digest(expected))) {
    return res.status(401).json({ code: 'invalid_admin_key', message: 'Invalid admin key' });
  }

  next();
}

/**
 * GET /api/admin/terminals
 *
 * Returns all terminals in the system with aggregate statistics.
 *
 * Includes revoked terminals (for audit trail visibility).
 * Joins with users table to show the owner username.
 *
 * Response:
 *   {
 *     stats: { total, active, revoked, withDaemon },
 *     terminals: [{ id, username, label, hasDaemon, hasTls, registeredAt, lastSeenAt, revokedAt }]
 *   }
 */
router.get('/terminals', adminRateLimit, requireAdmin, (_req, res) => {
  const db = getDb();

  // Load all terminals with owner username
  const terminals = db.prepare(`
    SELECT t.*, u.username
    FROM terminals t
    JOIN users u ON u.id = t.user_id
    ORDER BY t.registered_at DESC
  `).all();

  // Compute aggregate statistics
  const total = terminals.length;
  const active = terminals.filter(t => !t.revoked_at).length;
  const revoked = terminals.filter(t => t.revoked_at).length;
  const withDaemon = terminals.filter(t => t.daemon_fp_hash).length;

  res.json({
    stats: { total, active, revoked, withDaemon },
    terminals: terminals.map(t => ({
      id: t.id,
      username: t.username,
      label: t.label,
      hasDaemon: !!t.daemon_fp_hash,
      hasTls: !!t.ja4_hash,
      registeredAt: t.registered_at,
      lastSeenAt: t.last_seen_at,
      revokedAt: t.revoked_at,
    })),
  });
});

/**
 * POST /api/admin/terminals/:terminalId/revoke
 *
 * Revokes a terminal globally (cross-user operation).
 *
 * Sets revoked_at on the terminal record and logs an audit event.
 * Once revoked, the terminal cannot pass verification even if the
 * fingerprint matches — the guard middleware checks revoked_at.
 *
 * Returns 404 if terminal not found.
 * Returns 409 if terminal is already revoked.
 */
router.post('/terminals/:terminalId/revoke', adminRateLimit, requireAdmin, (req, res) => {
  const db = getDb();
  const now = new Date().toISOString();

  const terminal = db.prepare(
    'SELECT id, user_id, revoked_at FROM terminals WHERE id = ?'
  ).get(req.params.terminalId);

  if (!terminal) {
    return res.status(404).json({ code: 'terminal_not_found', message: 'Terminal not found' });
  }

  if (terminal.revoked_at) {
    return res.status(409).json({ code: 'terminal_already_revoked', message: 'Terminal already revoked' });
  }

  // Soft-delete the terminal
  db.prepare('UPDATE terminals SET revoked_at = ? WHERE id = ?')
    .run(now, terminal.id);

  // Log admin audit event
  db.prepare(`
    INSERT INTO auth_events
      (id, user_id, terminal_id, event_type, ip_address, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuidv4(), terminal.user_id, terminal.id, 'REVOKE',
    req.ip || '127.0.0.1', req.get('user-agent') || '', now
  );

  logEvent('terminal.revoked', {
    user_id: terminal.user_id,
    terminal_id: terminal.id,
    revoked_by: 'admin',
  });

  res.status(204).end();
});

export default router;

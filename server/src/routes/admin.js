/**
 * Admin Panel API Routes
 *
 * Endpoints:
 *   GET  /api/admin/terminals         — list all terminals (all users)
 *   POST /api/admin/terminals/:id/revoke — revoke a terminal globally
 *
 * Protected by x-admin-key header authentication.
 * The admin key is set via ADMIN_KEY environment variable (default: pocdna-admin-secret).
 *
 * Admin operations are cross-user — an admin can revoke any terminal
 * regardless of who owns it. This is used for fraud investigation and
 * incident response scenarios.
 */

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from '../db.js';

const router = Router();

/**
 * Admin authentication middleware.
 *
 * Checks the x-admin-key header against the configured ADMIN_KEY.
 * Unlike user authentication (session-based), admin auth uses a simple
 * static API key. This is intentional for POC simplicity; production
 * would use JWT or OAuth with proper admin role validation.
 */
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Invalid admin key' });
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
router.get('/terminals', requireAdmin, (_req, res) => {
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
router.post('/terminals/:terminalId/revoke', requireAdmin, (req, res) => {
  const db = getDb();
  const now = new Date().toISOString();

  const terminal = db.prepare(
    'SELECT id, user_id, revoked_at FROM terminals WHERE id = ?'
  ).get(req.params.terminalId);

  if (!terminal) {
    return res.status(404).json({ error: 'Terminal not found' });
  }

  if (terminal.revoked_at) {
    return res.status(409).json({ error: 'Terminal already revoked' });
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

  console.log(
    `[terminal.revoked] user=${terminal.user_id} terminal=${terminal.id} revoked_by=admin`
  );

  res.status(204).end();
});

export default router;

/**
 * Terminal Registration & Verification Routes
 *
 * Endpoints:
 *   POST /api/auth/register-terminal — register current terminal (3-layer FP)
 *   POST /api/auth/verify-terminal   — verify current terminal against registered ones
 *   GET  /api/auth/user/terminals    — list user's registered terminals
 *   DELETE /api/auth/user/terminals/:id — remove (revoke) a terminal
 *
 * All endpoints require authentication (requireAuth middleware).
 *
 * Registration flow:
 *   1. Browser collects Layer 1 (Canvas, WebGL, Audio...) and Layer 2 (daemon)
 *   2. POSTs both to /api/auth/register-terminal
 *   3. Server validates Layer 1 (hash and store), Layer 2 (validate HMAC), Layer 3 (JA4)
 *   4. Stores composite fingerprint in SQLite
 *
 * Verification flow:
 *   1. Browser collects current fingerprint
 *   2. POSTs to /api/auth/verify-terminal
 *   3. Server loads all user's terminals, runs fuzzy matching across all 3 layers
 *   4. Layer availability is based on what each terminal registered — omitting a
 *      registered layer (e.g. daemon payload) counts as failure, not as absent
 *   5. Best match with ≥2 of available registered layers passing → known: true
 *   6. Session is updated with the terminal ID for subsequent sensitive actions
 */

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import {
  hashComponents,
  fuzzyMatchBrowserFP,
  validateDaemonHmac,
  computeConfidence,
} from '../services/fingerprint.js';
import { setTerminalSession } from '../middleware/requireTerminal.js';

const router = Router();

/**
 * POST /api/auth/register-terminal
 *
 * Registers the current terminal (browser + optional daemon) for the user.
 *
 * Request body:
 *   { label, browserFP, daemonPayload?, daemonSignature?, daemonSecret? }
 *
 * Layer 1 (browser FP) — always required. Components are hashed and stored.
 * Layer 2 (daemon FP) — optional. If provided, HMAC signature is validated
 *   against the daemonSecret before storing.
 * Layer 3 (TLS JA4)   — extracted by JA4 middleware from the request context.
 *
 * Business rules:
 *   - Max 5 non-revoked terminals per user
 *   - Duplicate browser fingerprint hash → 409 (already registered)
 *   - Invalid daemon HMAC → 400 (check the secret key)
 */
router.post('/register-terminal', requireAuth, (req, res) => {
  const { label, browserFP, daemonPayload, daemonSignature, daemonSecret } = req.body || {};

  // Validate terminal label
  if (!label || typeof label !== 'string' || label.trim().length === 0 || label.length > 64) {
    return res.status(400).json({ error: 'Terminal label is required (max 64 characters)' });
  }

  // Validate browser fingerprint (Layer 1 — always required)
  if (!browserFP || !browserFP.visitorId || !browserFP.components) {
    return res.status(400).json({ error: 'Browser fingerprint is required' });
  }

  const db = getDb();
  const now = new Date().toISOString();

  // Enforce max 5 terminals per user
  const count = db.prepare(
    'SELECT COUNT(*) as count FROM terminals WHERE user_id = ? AND revoked_at IS NULL'
  ).get(req.user.id);
  if (count.count >= 5) {
    return res.status(403).json({
      error: 'Maximum of 5 registered terminals reached. Remove an existing one first.',
    });
  }

  // Check for duplicate terminal (same browser fingerprint)
  const browserFpHash = hashComponents(browserFP.components);
  const existing = db.prepare(
    'SELECT id FROM terminals WHERE user_id = ? AND browser_fp_hash = ? AND revoked_at IS NULL'
  ).get(req.user.id, browserFpHash);
  if (existing) {
    return res.status(409).json({ error: 'This terminal is already registered' });
  }

  // Process daemon data (Layer 2) if provided
  let daemonFpHash = null;
  let daemonFpData = null;
  let daemonSecretKey = null;

  if (daemonPayload && daemonSignature && daemonSecret) {
    // Validate HMAC signature before trusting the daemon data
    const valid = validateDaemonHmac(daemonPayload, daemonSignature, daemonSecret);
    if (!valid) {
      return res.status(400).json({
        error: 'Daemon signature validation failed. Check the secret key.',
      });
    }
    daemonFpHash = hashComponents(daemonPayload);
    daemonFpData = JSON.stringify(daemonPayload);
    daemonSecretKey = daemonSecret;
  }

  const terminalId = uuidv4();
  const ja4Hash = req.ja4?.hash || null;

  // Store terminal record
  db.prepare(`
    INSERT INTO terminals
      (id, user_id, label, browser_fp_hash, browser_fp_data,
       daemon_fp_hash, daemon_fp_data, ja4_hash,
       registered_at, last_seen_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    terminalId, req.user.id, label.trim(), browserFpHash,
    JSON.stringify(browserFP.components), daemonFpHash, daemonFpData,
    ja4Hash, now, now
  );

  // Store daemon secret key (for future HMAC validation) if daemon was used
  if (daemonSecretKey) {
    db.prepare(
      'INSERT INTO daemon_secrets (terminal_id, secret_key, created_at) VALUES (?, ?, ?)'
    ).run(terminalId, daemonSecretKey, now);
  }

  // Log audit event
  db.prepare(`
    INSERT INTO auth_events
      (id, user_id, terminal_id, event_type, confidence, layers_matched,
       ip_address, user_agent, ja4_observed, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuidv4(), req.user.id, terminalId, 'REGISTER', 1,
    JSON.stringify({ browser: true, daemon: !!daemonSecretKey, tls: !!ja4Hash }),
    req.ip || '127.0.0.1', req.get('user-agent') || '', ja4Hash, now
  );

  console.log(
    `[terminal.registered] user=${req.user.id} terminal=${terminalId} ` +
    `daemon=${!!daemonSecretKey} ja4=${!!ja4Hash}`
  );

  res.status(201).json({
    terminalId,
    label: label.trim(),
    layers: {
      browser: true,
      daemon: !!daemonSecretKey,
      tls: !!ja4Hash,
    },
    registeredAt: now,
  });
});

/**
 * POST /api/auth/verify-terminal
 *
 * Checks if the current terminal matches any of the user's registered terminals.
 *
 * For each registered terminal, the server:
 *   1. Fuzzy-matches the browser fingerprint (weighted Jaccard per signal)
 *   2. Validates the daemon HMAC signature (if both have daemon data)
 *   3. Compares the JA4 TLS hash (if both have TLS data)
 *   4. Computes a confidence score (0.0–1.0)
 *   5. Returns the best match
 *
 * A terminal is "known" when ≥2 of the available layers match.
 * On success, the session is updated with the terminal ID.
 */
router.post('/verify-terminal', requireAuth, (req, res) => {
  const { browserFP, daemonPayload, daemonSignature } = req.body || {};

  if (!browserFP || !browserFP.components) {
    return res.status(400).json({ error: 'Browser fingerprint is required' });
  }

  const db = getDb();
  const now = new Date().toISOString();

  // Load all non-revoked terminals for this user, including daemon secret keys
  const terminals = db.prepare(`
    SELECT t.*, ds.secret_key
    FROM terminals t
    LEFT JOIN daemon_secrets ds ON ds.terminal_id = t.id
    WHERE t.user_id = ? AND t.revoked_at IS NULL
  `).all(req.user.id);

  let bestMatch = null;
  let bestConfidence = -1;

  // Iterate through all registered terminals to find the best match
  for (const term of terminals) {
    // Layer 1: fuzzy match browser fingerprint
    const browserScore = fuzzyMatchBrowserFP(
      JSON.parse(term.browser_fp_data),
      browserFP.components
    );

    const daemonRequired = Boolean(term.daemon_fp_hash);
    const tlsRequired = Boolean(term.ja4_hash);

    // Layer 2: required when terminal registered with daemon
    let daemonValid = null;
    if (daemonRequired) {
      daemonValid = (daemonPayload && daemonSignature)
        ? validateDaemonHmac(daemonPayload, daemonSignature, term.secret_key)
        : false;
    }

    // Layer 3: required when terminal registered with JA4
    let tlsMatch = null;
    if (tlsRequired) {
      tlsMatch = req.ja4 ? req.ja4.hash === term.ja4_hash : false;
    }

    const result = computeConfidence(browserScore, {
      daemonRequired,
      tlsRequired,
      daemonValid,
      tlsMatch,
    });

    if (result.confidence > bestConfidence) {
      bestConfidence = result.confidence;
      bestMatch = { terminalId: term.id, ...result };
    }
  }

  // Terminal recognized: update metadata and log
  if (bestMatch && bestMatch.known) {
    db.prepare('UPDATE terminals SET last_seen_at = ? WHERE id = ?')
      .run(now, bestMatch.terminalId);

    db.prepare(`
      INSERT INTO auth_events
        (id, user_id, terminal_id, event_type, confidence, layers_matched,
         ip_address, user_agent, ja4_observed, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(), req.user.id, bestMatch.terminalId, 'VERIFY_OK',
      bestMatch.confidence, JSON.stringify(bestMatch.layers),
      req.ip || '127.0.0.1', req.get('user-agent') || '', req.ja4?.hash || null, now
    );

    console.log(
      `[terminal.verified] user=${req.user.id} terminal=${bestMatch.terminalId} ` +
      `confidence=${bestMatch.confidence.toFixed(2)}`
    );

    // Store verified terminal ID in session for subsequent sensitive actions
    setTerminalSession(req, bestMatch.terminalId);

    return res.json({
      known: true,
      terminalId: bestMatch.terminalId,
      confidence: bestMatch.confidence,
      layers: bestMatch.layers,
    });
  }

  // Terminal NOT recognized — log the failed attempt
  const bestConf = bestMatch ? bestMatch.confidence : 0;
  const bestLayers = bestMatch ? bestMatch.layers : { browser: false, daemon: null, tls: null };

  db.prepare(`
    INSERT INTO auth_events
      (id, user_id, terminal_id, event_type, confidence, layers_matched,
       ip_address, user_agent, ja4_observed, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuidv4(), req.user.id, null, 'VERIFY_FAIL',
    bestConf, JSON.stringify(bestLayers),
    req.ip || '127.0.0.1', req.get('user-agent') || '', req.ja4?.hash || null, now
  );

  console.log(
    `[terminal.mismatch] user=${req.user.id} best_confidence=${bestConf.toFixed(2)}`
  );

  return res.json({
    known: false,
    confidence: bestConf,
    layers: bestLayers,
    reason: bestConf < 0.33
      ? 'No layers matched'
      : 'Only 1 layer matched, need at least 2',
  });
});

/**
 * GET /api/auth/user/terminals
 *
 * Lists all non-revoked terminals registered for the authenticated user.
 * Returns terminal metadata only — never exposes raw fingerprint data or secrets.
 */
router.get('/user/terminals', requireAuth, (req, res) => {
  const db = getDb();
  const terminals = db.prepare(
    `SELECT id, label, daemon_fp_hash, registered_at, last_seen_at
     FROM terminals
     WHERE user_id = ? AND revoked_at IS NULL
     ORDER BY last_seen_at DESC`
  ).all(req.user.id);

  res.json({
    terminals: terminals.map(t => ({
      id: t.id,
      label: t.label,
      hasDaemon: !!t.daemon_fp_hash,
      registeredAt: t.registered_at,
      lastSeenAt: t.last_seen_at,
    })),
  });
});

/**
 * DELETE /api/auth/user/terminals/:terminalId
 *
 * Soft-deletes a terminal by setting revoked_at. The terminal record is
 * retained for audit purposes but can no longer be used for verification.
 *
 * Soft-delete (rather than hard-delete) preserves the audit trail in auth_events.
 */
router.delete('/user/terminals/:terminalId', requireAuth, (req, res) => {
  const db = getDb();
  const now = new Date().toISOString();

  // Find terminal by ID AND user_id (users can only delete their own terminals)
  const terminal = db.prepare(
    'SELECT id FROM terminals WHERE id = ? AND user_id = ? AND revoked_at IS NULL'
  ).get(req.params.terminalId, req.user.id);

  if (!terminal) {
    return res.status(404).json({ error: 'Terminal not found' });
  }

  // Soft-delete: set revoked_at timestamp
  db.prepare('UPDATE terminals SET revoked_at = ? WHERE id = ?')
    .run(now, terminal.id);

  // Log audit event
  db.prepare(`
    INSERT INTO auth_events
      (id, user_id, terminal_id, event_type, ip_address, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuidv4(), req.user.id, terminal.id, 'REVOKE',
    req.ip || '127.0.0.1', req.get('user-agent') || '', now
  );

  console.log(
    `[terminal.revoked] user=${req.user.id} terminal=${terminal.id} revoked_by=user`
  );

  res.status(204).end();
});

export default router;

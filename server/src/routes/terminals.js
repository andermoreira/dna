/**
 * Terminal Registration & Verification Routes
 *
 * Endpoints (default router, mounted at /api/auth):
 *   POST /api/auth/register-terminal — register current terminal (3-layer FP)
 *   GET  /api/auth/verify-nonce      — issue a single-use nonce for verification
 *   POST /api/auth/verify-terminal   — verify current terminal against registered ones
 *
 * Endpoints (userTerminalsRouter, mounted at /api/user/terminals — spec contract):
 *   GET    /api/user/terminals             — list user's registered terminals
 *   DELETE /api/user/terminals/:terminalId — remove (revoke) a terminal
 *
 * All endpoints require authentication (requireAuth middleware).
 *
 * Registration flow:
 *   1. Browser collects Layer 1 (Canvas, WebGL, Audio...) and Layer 2 (daemon)
 *   2. POSTs both to /api/auth/register-terminal
 *   3. Server validates Layer 1 (hash and store), Layer 2 (validate HMAC), Layer 3 (JA4)
 *   4. Stores composite fingerprint in SQLite. Only the 10 fuzzy-match browser
 *      signals are persisted; the raw daemon payload is never stored (privacy)
 *
 * Verification flow:
 *   1. Browser requests a nonce (GET /verify-nonce) — replay protection
 *   2. Browser collects current fingerprint, POSTs to /api/auth/verify-terminal
 *   3. Server loads all user's terminals, runs fuzzy matching across all 3 layers
 *   4. Layer availability is based on what each terminal registered — omitting a
 *      registered layer (e.g. daemon payload) counts as failure, not as absent
 *   5. Best match with ≥2 of available registered layers passing → known: true
 *   6. Session is updated with the terminal ID for subsequent sensitive actions
 */

import crypto from 'crypto';
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { rateLimit } from '../middleware/rateLimit.js';
import {
  hashComponents,
  fuzzyMatchBrowserFP,
  validateDaemonHmac,
  computeConfidence,
  pickBrowserSignals,
  pickStableDaemonFields,
} from '../services/fingerprint.js';
import { encryptSecret, decryptSecret } from '../services/secret-vault.js';
import { setTerminalSession, clearTerminalSession } from '../middleware/requireTerminal.js';
import { logEvent } from '../log.js';

const router = Router();

/** Verification nonces are single-use and expire after this window. */
const NONCE_MAX_AGE_MS = 5 * 60 * 1000;

// Spec: 10 registrations per user per hour
const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyFn: (req) => `register-terminal:${req.user.id}`,
});

/**
 * POST /api/auth/register-terminal
 *
 * Registers the current terminal (browser + optional daemon) for the user.
 *
 * Request body:
 *   { label, browserFP, daemonPayload?, daemonSignature?, daemonSecret?, nonce? }
 *
 * Layer 1 (browser FP) — always required. Only the 10 fuzzy-match signals are
 *   hashed and stored (userAgent, languages etc. are discarded).
 * Layer 2 (daemon FP) — optional. If provided, daemonSecret and a nonce from
 *   GET /verify-nonce are required; the payload must carry that nonce as its
 *   challenge and its HMAC is validated against the daemonSecret before storing. The secret is encrypted at rest;
 *   the payload hash covers only stable fields and the raw payload is dropped.
 * Layer 3 (TLS JA4)   — extracted by JA4 middleware from the request context.
 *
 * Business rules:
 *   - Max 5 non-revoked terminals per user
 *   - Duplicate browser fingerprint hash → 409 (already registered)
 *   - Invalid daemon HMAC → 400 (check the secret key)
 */
router.post('/register-terminal', requireAuth, registerRateLimit, asyncHandler(async (req, res) => {
  const { label, browserFP, daemonPayload, daemonSignature, daemonSecret, nonce } = req.body || {};

  // Validate terminal label
  if (!label || typeof label !== 'string' || label.trim().length === 0 || label.length > 64) {
    return res.status(400).json({
      code: 'invalid_label',
      message: 'Terminal label is required (max 64 characters)',
    });
  }

  // Validate browser fingerprint (Layer 1 — always required)
  if (!browserFP || !browserFP.visitorId || !browserFP.components) {
    return res.status(400).json({
      code: 'browser_fp_required',
      message: 'Browser fingerprint is required',
    });
  }

  const db = getDb();
  const now = new Date().toISOString();

  // Enforce max 5 terminals per user
  const count = db.prepare(
    'SELECT COUNT(*) as count FROM terminals WHERE user_id = ? AND revoked_at IS NULL'
  ).get(req.user.id);
  if (count.count >= 5) {
    return res.status(403).json({
      code: 'terminal_limit_reached',
      message: 'Maximum of 5 registered terminals reached. Remove an existing one first.',
    });
  }

  // Persist only the signals used for fuzzy matching (privacy: no userAgent/languages)
  const browserSignals = pickBrowserSignals(browserFP.components);

  // Check for duplicate terminal (same browser fingerprint)
  const browserFpHash = hashComponents(browserSignals);
  const existing = db.prepare(
    'SELECT id FROM terminals WHERE user_id = ? AND browser_fp_hash = ? AND revoked_at IS NULL'
  ).get(req.user.id, browserFpHash);
  if (existing) {
    return res.status(409).json({
      code: 'terminal_already_registered',
      message: 'This terminal is already registered',
    });
  }

  // Process daemon data (Layer 2) if provided
  let daemonFpHash = null;
  let encryptedDaemonSecret = null;

  if (daemonPayload || daemonSignature) {
    // A daemon payload without its secret would silently register a weak terminal
    if (!daemonSecret) {
      return res.status(400).json({
        code: 'daemon_secret_required',
        message: 'The daemon secret key is required to register the daemon layer.',
      });
    }
    // The payload must echo a fresh session nonce, as in verify-terminal
    if (!consumeVerifyNonce(req, nonce)) {
      return res.status(400).json({
        code: 'nonce_invalid',
        message: 'A valid verification nonce is required. Request one at /api/auth/verify-nonce.',
      });
    }
    // Validate HMAC signature before trusting the daemon data
    const valid = validateDaemonHmac(daemonPayload, daemonSignature, daemonSecret, nonce);
    if (!valid) {
      return res.status(400).json({
        code: 'invalid_daemon_signature',
        message: 'Daemon signature validation failed. Check the secret key.',
      });
    }
    // Hash only stable fields (freemem/uptime/timestamp would make it useless).
    // The raw payload is never persisted — Layer 2 verification is HMAC key
    // possession, not payload comparison.
    daemonFpHash = hashComponents(pickStableDaemonFields(daemonPayload));
    encryptedDaemonSecret = encryptSecret(daemonSecret);
  }

  const terminalId = uuidv4();
  const ja4Hash = req.ja4?.hash || null;

  // Terminal, secret and audit rows are written atomically
  db.transaction(() => {
    // Store terminal record (daemon_fp_data intentionally null — see above)
    db.prepare(`
      INSERT INTO terminals
        (id, user_id, label, browser_fp_hash, browser_fp_data,
         daemon_fp_hash, daemon_fp_data, ja4_hash,
         registered_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      terminalId, req.user.id, label.trim(), browserFpHash,
      JSON.stringify(browserSignals), daemonFpHash, null,
      ja4Hash, now, now
    );

    // Store daemon secret key (encrypted at rest) if daemon was used
    if (encryptedDaemonSecret) {
      db.prepare(
        'INSERT INTO daemon_secrets (terminal_id, secret_key, created_at) VALUES (?, ?, ?)'
      ).run(terminalId, encryptedDaemonSecret, now);
    }

    // Log audit event
    db.prepare(`
      INSERT INTO auth_events
        (id, user_id, terminal_id, event_type, confidence, layers_matched,
         ip_address, user_agent, ja4_observed, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(), req.user.id, terminalId, 'REGISTER', 1,
      JSON.stringify({ browser: true, daemon: !!daemonFpHash, tls: !!ja4Hash }),
      req.ip || '127.0.0.1', req.get('user-agent') || '', ja4Hash, now
    );
  })();

  logEvent('terminal.registered', {
    user_id: req.user.id,
    terminal_id: terminalId,
    layers: { browser: true, daemon: !!daemonFpHash, tls: !!ja4Hash },
  });

  res.status(201).json({
    terminalId,
    label: label.trim(),
    layers: {
      browser: true,
      daemon: !!daemonFpHash,
      tls: !!ja4Hash,
    },
    registeredAt: now,
  });
}));

/**
 * GET /api/auth/verify-nonce
 *
 * Issues a single-use nonce that must accompany the next verify-terminal
 * request from this session (threat model: fingerprint replay protection).
 */
router.get('/verify-nonce', requireAuth, (req, res) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  req.session.verifyNonce = { value: nonce, issuedAt: Date.now() };
  res.json({ nonce });
});

/** Consumes the session nonce; returns true when the provided value is valid. */
function consumeVerifyNonce(req, nonce) {
  const stored = req.session.verifyNonce;
  req.session.verifyNonce = null;

  if (!stored || typeof nonce !== 'string') return false;
  if (Date.now() - stored.issuedAt > NONCE_MAX_AGE_MS) return false;

  const a = Buffer.from(stored.value);
  const b = Buffer.from(nonce);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * POST /api/auth/verify-terminal
 *
 * Checks if the current terminal matches any of the user's registered terminals.
 *
 * Requires a `nonce` previously issued by GET /verify-nonce (single-use) so a
 * captured verification request cannot be replayed indefinitely.
 *
 * For each registered terminal, the server:
 *   1. Fuzzy-matches the browser fingerprint (weighted Jaccard per signal)
 *   2. Validates the daemon HMAC signature with challenge verification
 *   3. Compares the JA4 TLS hash (if both have TLS data)
 *   4. Computes a confidence score (0.0–1.0)
 *   5. Returns the best match
 *
 * A terminal is "known" when ≥2 of the available layers match.
 * On success, the session is updated with the terminal ID.
 */
router.post('/verify-terminal', requireAuth, asyncHandler(async (req, res) => {
  const { browserFP, daemonPayload, daemonSignature, nonce } = req.body || {};

  if (!browserFP || !browserFP.components) {
    return res.status(400).json({
      code: 'browser_fp_required',
      message: 'Browser fingerprint is required',
    });
  }

  if (!consumeVerifyNonce(req, nonce)) {
    return res.status(400).json({
      code: 'nonce_invalid',
      message: 'A valid verification nonce is required. Request one at /api/auth/verify-nonce.',
    });
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

  // Iterate through all registered terminals to find the best match
  for (const term of terminals) {
    let storedBrowserFP;
    try {
      storedBrowserFP = JSON.parse(term.browser_fp_data);
    } catch {
      continue;
    }

    // Layer 1: fuzzy match browser fingerprint
    const browserScore = fuzzyMatchBrowserFP(
      storedBrowserFP,
      browserFP.components
    );

    const daemonRequired = Boolean(term.daemon_fp_hash);
    const tlsRequired = Boolean(term.ja4_hash);

    // Layer 2: required when terminal registered with daemon
    let daemonValid = null;
    if (daemonRequired) {
      const secretKey = decryptSecret(term.secret_key);
      // The payload must echo this request's nonce as its challenge — a
      // challenge-less payload could be replayed within the timestamp window
      daemonValid = (daemonPayload && daemonSignature && secretKey)
        ? validateDaemonHmac(daemonPayload, daemonSignature, secretKey, nonce)
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

    const candidateMatch = {
      terminalId: term.id,
      browserScore,
      ...result,
    };

    // Tie-breaking selection logic:
    // 1. Prioritize known === true
    // 2. Higher confidence
    // 3. Daemon layer valid === true (strongest layer)
    // 4. Higher browser fuzzy score
    const isBetterMatch = (candidate, current) => {
      if (!current) return true;
      if (candidate.known !== current.known) return candidate.known;
      if (candidate.confidence !== current.confidence) return candidate.confidence > current.confidence;
      if (candidate.layers.daemon !== current.layers.daemon) return candidate.layers.daemon === true;
      return candidate.browserScore > current.browserScore;
    };

    if (isBetterMatch(candidateMatch, bestMatch)) {
      bestMatch = candidateMatch;
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

    logEvent('terminal.verified', {
      user_id: req.user.id,
      terminal_id: bestMatch.terminalId,
      confidence: Number(bestMatch.confidence.toFixed(2)),
      layers: bestMatch.layers,
    });

    // Store verified terminal ID + layer results in session for subsequent
    // sensitive actions (the guard requires layers.daemon === true)
    setTerminalSession(req, bestMatch.terminalId, bestMatch.layers);

    return res.json({
      known: true,
      terminalId: bestMatch.terminalId,
      confidence: bestMatch.confidence,
      layers: bestMatch.layers,
    });
  }

  // Terminal NOT recognized — drop any binding from an earlier verification
  // so the last verification result is what guards sensitive actions
  clearTerminalSession(req);

  // Log the failed attempt
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

  logEvent('terminal.mismatch', {
    user_id: req.user.id,
    best_confidence: Number(bestConf.toFixed(2)),
    layers: bestLayers,
  });

  return res.json({
    known: false,
    confidence: bestConf,
    layers: bestLayers,
    reason: bestConf < 0.33
      ? 'No layers matched'
      : 'Only 1 layer matched, need at least 2',
  });
}));

// ---------------------------------------------------------------------------
// User terminal management — mounted at /api/user/terminals (spec contract)
// ---------------------------------------------------------------------------
export const userTerminalsRouter = Router();

/**
 * GET /api/user/terminals
 *
 * Lists all non-revoked terminals registered for the authenticated user.
 * Returns terminal metadata only — never exposes raw fingerprint data or secrets.
 */
userTerminalsRouter.get('/', requireAuth, asyncHandler(async (req, res) => {
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
}));

/**
 * DELETE /api/user/terminals/:terminalId
 *
 * Soft-deletes a terminal by setting revoked_at. The terminal record is
 * retained for audit purposes but can no longer be used for verification.
 *
 * Soft-delete (rather than hard-delete) preserves the audit trail in auth_events.
 */
userTerminalsRouter.delete('/:terminalId', requireAuth, asyncHandler(async (req, res) => {
  const db = getDb();
  const now = new Date().toISOString();

  // Find terminal by ID AND user_id (users can only delete their own terminals)
  const terminal = db.prepare(
    'SELECT id FROM terminals WHERE id = ? AND user_id = ? AND revoked_at IS NULL'
  ).get(req.params.terminalId, req.user.id);

  if (!terminal) {
    return res.status(404).json({ code: 'terminal_not_found', message: 'Terminal not found' });
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

  logEvent('terminal.revoked', {
    user_id: req.user.id,
    terminal_id: terminal.id,
    revoked_by: 'user',
  });

  res.status(204).end();
}));

export default router;

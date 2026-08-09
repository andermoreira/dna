/**
 * POCDNA Server — Express Application Entry Point
 *
 * Architecture: 3-layer terminal authentication
 *   Layer 1: Browser fingerprint (Canvas, WebGL, Audio, fonts, screen...)
 *   Layer 2: Local OS daemon (HMAC-signed payload from node daemon.js)
 *   Layer 3: TLS fingerprint (JA4 hash extracted from ClientHello)
 *
 * Middleware chain:
 *   1. express.json()      — parse JSON bodies
 *   2. cookie-parser        — parse cookies
 *   3. express-session      — cookie-based sessions (SQLite store)
 *   4. extractJa4           — JA4 TLS fingerprint extraction (Layer 3)
 *   5. static files         — serve public/ directory
 *
 * Route mounting:
 *   /api/auth           — auth.js      (user register/login/logout/me)
 *   /api/auth           — terminals.js (terminal register/verify/nonce)
 *   /api/user/terminals — terminals.js (user terminal list/delete — spec contract)
 *   /api/admin          — admin.js     (admin panel API)
 *   /api/actions        — sensitive action (guarded by requireAuth + requireKnownTerminal)
 *
 * TLS: the server terminates TLS directly (self-signed cert generated via
 * openssl, or TLS_CERT_PATH/TLS_KEY_PATH) so the JA4 layer can read the
 * ClientHello. Without openssl it falls back to plain HTTP with JA4 disabled.
 */

import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import ConnectSqlite3 from 'connect-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { trackClientHellos } from 'read-tls-client-hello';
import authRouter from './routes/auth.js';
import terminalsRouter, { userTerminalsRouter } from './routes/terminals.js';
import adminRouter from './routes/admin.js';
import { seed } from './seed.js';
import { extractJa4 } from './middleware/ja4.js';
import { requireAuth } from './middleware/auth.js';
import { requireKnownTerminal } from './middleware/requireTerminal.js';
import { errorHandler } from './middleware/errorHandler.js';
import { loadOrCreateTlsCert } from './tls.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Data directory — required by SQLite (app db + session db) and TLS certs.
// Created here so a fresh clone works outside Docker (`npm start`).
// ---------------------------------------------------------------------------
const dataDir = join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

// ---------------------------------------------------------------------------
// Express application setup
// ---------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3000;

// TLS decided before session config (cookie.secure depends on it)
const tlsPair = loadOrCreateTlsCert(dataDir);

// Parse JSON request bodies (required for fingerprint payloads)
app.use(express.json());

// Parse cookies for session management
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Session configuration
//
// Uses connect-sqlite3 to store sessions in SQLite. This avoids in-memory
// session loss on server restart and works without external Redis/memcached.
//
// SESSION_SECRET comes from the environment (.env — see .env.example). When
// unset, a random per-boot secret is used: sessions reset on restart, which
// is acceptable for the POC and avoids shipping a hardcoded secret.
// ---------------------------------------------------------------------------
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.log('[server] SESSION_SECRET not set — using a random per-boot secret (sessions reset on restart)');
}

const SQLiteStore = ConnectSqlite3(session);
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: dataDir,
  }),
  secret: sessionSecret,
  resave: false,              // Don't save session if unmodified
  saveUninitialized: false,    // Don't create session until something is stored
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,              // JavaScript can't access the cookie
    sameSite: 'lax',             // CSRF protection: only send on same-site requests
    secure: Boolean(tlsPair),    // HTTPS-only cookie when the server terminates TLS
  },
}));

// ---------------------------------------------------------------------------
// JA4 TLS Fingerprint Middleware (Layer 3)
//
// trackClientHellos (applied to the HTTPS server below) parses the ClientHello
// before the TLS handshake and attaches it to each socket; this middleware
// copies the JA4 hash to req.ja4. On plain HTTP, req.ja4 = null.
// ---------------------------------------------------------------------------
app.use(extractJa4);

// ---------------------------------------------------------------------------
// Static files — served from server/public/
// ---------------------------------------------------------------------------
app.use(express.static(join(__dirname, '..', 'public')));

// ---------------------------------------------------------------------------
// Route mounting
// ---------------------------------------------------------------------------

// User authentication routes: register, login, logout, current user
app.use('/api/auth', authRouter);

// Terminal routes: register, verify, verification nonce
app.use('/api/auth', terminalsRouter);

// User terminal management: list, delete (path defined by the spec contract)
app.use('/api/user/terminals', userTerminalsRouter);

// Admin panel routes: list all terminals, revoke (protected by x-admin-key header)
app.use('/api/admin', adminRouter);

// ---------------------------------------------------------------------------
// Health check — unauthenticated, returns server status
// ---------------------------------------------------------------------------
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// ---------------------------------------------------------------------------
// Sensitive action endpoint
//
// This simulates a high-risk operation (transfer, password change, etc.).
// Protected by TWO middleware layers:
//   1. requireAuth         — user must be logged in
//   2. requireKnownTerminal — terminal must be recognized (session.terminalId),
//      not revoked, and its daemon layer must have passed in this session
//      (AC-03: browser-only or daemon-less verification cannot unlock this)
// ---------------------------------------------------------------------------
app.post('/api/actions/sensitive', requireAuth, requireKnownTerminal, (req, res) => {
  res.json({
    message: 'Sensitive action completed successfully',
    terminalId: req.session.terminalId,
  });
});

app.use(errorHandler);

// ---------------------------------------------------------------------------
// Startup: seed database then listen (HTTPS when a cert is available, so the
// JA4 layer works; otherwise plain HTTP with JA4 disabled)
// ---------------------------------------------------------------------------
seed().then(() => {
  let server;
  if (tlsPair) {
    server = https.createServer({ cert: tlsPair.cert, key: tlsPair.key }, app);
    trackClientHellos(server);
  } else {
    server = http.createServer(app);
  }

  server.listen(PORT, () => {
    const protocol = tlsPair ? 'https' : 'http';
    const ja4Note = tlsPair ? '' : ' (no TLS — JA4 layer disabled)';
    console.log(`[server] listening on ${protocol}://localhost:${PORT}${ja4Note}`);
  });
});

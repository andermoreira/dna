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
 *   /api/auth    — auth.js     (user register/login/logout/me)
 *   /api/auth    — terminals.js (terminal register/verify/list/delete)
 *   /api/admin   — admin.js    (admin panel API)
 *   /api/actions — sensitive action (guarded by requireAuth + requireKnownTerminal)
 */

import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import ConnectSqlite3 from 'connect-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import authRouter from './routes/auth.js';
import terminalsRouter from './routes/terminals.js';
import adminRouter from './routes/admin.js';
import { seed } from './seed.js';
import { extractJa4 } from './middleware/ja4.js';
import { requireAuth } from './middleware/auth.js';
import { requireKnownTerminal } from './middleware/requireTerminal.js';
import { errorHandler } from './middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Express application setup
// ---------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON request bodies (required for fingerprint payloads)
app.use(express.json());

// Parse cookies for session management
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Session configuration
//
// Uses connect-sqlite3 to store sessions in SQLite. This avoids in-memory
// session loss on server restart and works without external Redis/memcached.
// ---------------------------------------------------------------------------
const SQLiteStore = ConnectSqlite3(session);
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: join(__dirname, '..', 'data'),
  }),
  secret: 'pocdna-session-secret-change-in-production',
  resave: false,              // Don't save session if unmodified
  saveUninitialized: false,    // Don't create session until something is stored
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,              // JavaScript can't access the cookie
    sameSite: 'lax',             // CSRF protection: only send on same-site requests
  },
}));

// ---------------------------------------------------------------------------
// JA4 TLS Fingerprint Middleware (Layer 3)
//
// Extracts the JA4 hash from the TLS ClientHello packet. This identifies the
// browser family + OS at the TLS stack level — the client cannot control this.
// Applied globally so every request has req.ja4 available.
//
// In development (plain HTTP), JA4 extraction fails gracefully (req.ja4 = null).
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

// Terminal routes: register, verify, list, delete
// Mounted under /api/auth because endpoints use /api/auth/register-terminal etc.
app.use('/api/auth', terminalsRouter);

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
//   2. requireKnownTerminal — terminal must be recognized (session.terminalId)
//
// If the terminal was revoked or never registered, the guard returns 403.
// ---------------------------------------------------------------------------
app.post('/api/actions/sensitive', requireAuth, requireKnownTerminal, (req, res) => {
  res.json({
    message: 'Sensitive action completed successfully',
    terminalId: req.session.terminalId,
  });
});

app.use(errorHandler);

// ---------------------------------------------------------------------------
// Startup: seed database then listen
// ---------------------------------------------------------------------------
seed().then(() => {
  app.listen(PORT, () => {
    console.log(`[server] listening on http://localhost:${PORT}`);
  });
});

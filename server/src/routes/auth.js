/**
 * User Authentication Routes
 *
 * Endpoints:
 *   POST /api/auth/register  — create new user account
 *   POST /api/auth/login     — authenticate and create session
 *   POST /api/auth/logout    — destroy session
 *   GET  /api/auth/me        — get current user (requires auth)
 *
 * All passwords are hashed with bcrypt (12 salt rounds).
 * Sessions are cookie-based (express-session with SQLite store).
 * On successful login/register, the session cookie is set automatically.
 */

import { Router } from 'express';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from '../db.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { rateLimit } from '../middleware/rateLimit.js';

const router = Router();

// Brute-force protection: per-IP window on credential endpoints
const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyFn: (req) => `login:${req.ip}`,
});

// Precomputed bcrypt hash used to equalize login timing when username is not found.
const DUMMY_PASSWORD_HASH = '$2b$12$XOV8xqpbI93p5h9tUIM3LOglH5ZNz2bjWdrLQT9ZGkpT6b8bvomOu';

/**
 * Regenerates the session ID after authentication to prevent session fixation.
 */
function establishUserSession(req, res, user, statusCode) {
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({ code: 'session_error', message: 'Session error' });
    }
    req.session.userId = user.id;
    return res.status(statusCode).json({
      user: { id: user.id, username: user.username },
    });
  });
}

/**
 * POST /api/auth/register
 *
 * Creates a new user account and logs them in immediately.
 *
 * Validation:
 *   - username: 2-32 characters, unique
 *   - password: minimum 4 characters
 *
 * Returns 201 with user object on success.
 * Returns 409 if username is already taken.
 */
router.post('/register', loginRateLimit, asyncHandler(async (req, res) => {
  const { username, password } = req.body || {};

  // Input validation — reject empty or non-string values
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ code: 'validation_error', message: 'Username and password are required' });
  }

  // Length constraints
  if (username.length < 2 || username.length > 32) {
    return res.status(400).json({ code: 'validation_error', message: 'Username must be between 2 and 32 characters' });
  }

  if (password.length < 4) {
    return res.status(400).json({ code: 'validation_error', message: 'Password must be at least 4 characters' });
  }

  const db = getDb();

  // Check for duplicate username
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ code: 'username_taken', message: 'Username already taken' });
  }

  // Hash password with bcrypt (12 rounds — good balance of security and speed for POC)
  const passwordHash = await bcrypt.hash(password, 12);
  const id = uuidv4();
  const createdAt = new Date().toISOString();

  // Insert user record. The duplicate check above is not atomic with this
  // insert (bcrypt.hash yields the event loop), so concurrent registrations
  // with the same username can still hit the UNIQUE constraint → 409, not 500.
  try {
    db.prepare(
      'INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)'
    ).run(id, username, passwordHash, createdAt);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ code: 'username_taken', message: 'Username already taken' });
    }
    throw err;
  }

  // Log the user in immediately after registration (new session ID)
  establishUserSession(req, res, { id, username }, 201);
}));

/**
 * POST /api/auth/login
 *
 * Authenticates a user with username and password.
 *
 * Uses constant-time comparison via bcrypt.compare() to prevent
 * timing attacks on password validation.
 *
 * Returns 200 with user object on success.
 * Returns 401 with generic "Invalid credentials" on failure (does NOT
 * reveal whether the username exists — prevents user enumeration).
 */
router.post('/login', loginRateLimit, asyncHandler(async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ code: 'validation_error', message: 'Username and password are required' });
  }

  const db = getDb();

  const user = db.prepare(
    'SELECT id, username, password_hash FROM users WHERE username = ?'
  ).get(username);

  const passwordHash = user?.password_hash || DUMMY_PASSWORD_HASH;
  const valid = await bcrypt.compare(password, passwordHash);
  if (!user || !valid) {
    return res.status(401).json({ code: 'invalid_credentials', message: 'Invalid credentials' });
  }

  establishUserSession(req, res, user, 200);
}));

/**
 * POST /api/auth/logout
 *
 * Destroys the current session and clears the session cookie.
 * After logout, all protected routes return 401 until re-login.
 */
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ code: 'logout_failed', message: 'Logout failed' });
    }
    // Clear the cookie on the client side
    res.clearCookie('connect.sid');
    res.status(204).end();
  });
});

/**
 * GET /api/auth/me
 *
 * Returns the currently authenticated user's information.
 * Protected by requireAuth middleware.
 *
 * Used by the frontend to:
 *   1. Check if the user is still logged in
 *   2. Display the username in the navbar
 *   3. Redirect to login if the session expired
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username } });
});

export default router;

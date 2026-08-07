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

const router = Router();

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
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Input validation — reject empty or non-string values
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Length constraints
  if (username.length < 2 || username.length > 32) {
    return res.status(400).json({ error: 'Username must be between 2 and 32 characters' });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  const db = getDb();

  // Check for duplicate username
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  // Hash password with bcrypt (12 rounds — good balance of security and speed for POC)
  const passwordHash = await bcrypt.hash(password, 12);
  const id = uuidv4();
  const createdAt = new Date().toISOString();

  // Insert user record
  db.prepare(
    'INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)'
  ).run(id, username, passwordHash, createdAt);

  // Log the user in immediately after registration
  req.session.userId = id;

  res.status(201).json({ user: { id, username } });
});

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
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const db = getDb();

  // Load user by username — returns undefined if not found
  const user = db.prepare(
    'SELECT id, username, password_hash FROM users WHERE username = ?'
  ).get(username);

  // Generic error message to prevent username enumeration
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Constant-time password comparison via bcrypt
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Set session userId — subsequent requests are authenticated
  req.session.userId = user.id;

  res.json({ user: { id: user.id, username: user.username } });
});

/**
 * POST /api/auth/logout
 *
 * Destroys the current session and clears the session cookie.
 * After logout, all protected routes return 401 until re-login.
 */
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
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

# Step 2: User authentication baseline

## Goal

Register, login, logout with bcrypt password hashing and cookie-based sessions. Seed demo user for immediate POC demonstration.

## Tasks

1. **Create `server/src/middleware/auth.js`** — exports `requireAuth` middleware:
   - Checks `req.session.userId` exists
   - If absent → 401 `{ "error": "Authentication required" }`
   - If present → loads user from DB, attaches `req.user`, calls `next()`

2. **Create `server/src/routes/auth.js`** — Express Router with:
   - `POST /api/auth/register` — body `{ username, password }`. Validates non-empty. Hashes password with bcrypt (12 rounds). Inserts user. Creates session (`req.session.userId = user.id`). Returns 201 `{ "user": { "id", "username" } }`. Returns 409 if username taken.
   - `POST /api/auth/login` — body `{ username, password }`. Finds user by username, compares bcrypt hash. On match → creates session. Returns 200 `{ "user": { "id", "username" } }`. On mismatch → 401 `{ "error": "Invalid credentials" }`.
   - `POST /api/auth/logout` — destroys session. Returns 204.
   - `GET /api/auth/me` — requires `requireAuth`. Returns 200 `{ "user": { "id", "username" } }`.

3. **Create `server/src/seed.js`** — exports `seed()`:
   - Checks if demo user exists (`SELECT COUNT(*) FROM users WHERE username = 'demo'`)
   - If not, inserts: username `demo`, password `demo123` (bcrypt hashed), id via `uuid.v4()`
   - Logs `[seed] demo user created` or `[seed] demo user already exists`

4. **Update `server/src/index.js`**:
   - Import and mount `authRouter` at `/api/auth`
   - Call `seed()` on startup after DB is ready

5. **Create `public/login.html`** — minimal login page:
   - Form with username + password fields
   - On submit: POST /api/auth/login, on success redirect to `/`
   - Link to register (POST /api/auth/register, then redirect to `/`)
   - Error display div
   - Basic styling (dark theme, centered card)

## Out of scope

- Fingerprint collection on login (step 3)
- Dashboard page (step 7)
- Terminal registration/verification APIs (step 6)
- Token-based auth (JWT) — cookie session only
- Password reset, email verification

## Done criteria

- `POST /api/auth/register` with `{ "username": "test", "password": "secret" }` → 201 + session cookie
- `POST /api/auth/login` with demo:demo123 → 200 + session cookie
- `POST /api/auth/login` with wrong password → 401
- `GET /api/auth/me` with valid session → 200 with user data
- `GET /api/auth/me` without session → 401
- `POST /api/auth/logout` → 204, subsequent `/me` → 401
- Opening `http://localhost:3000/login.html` shows login form
- After seed, `demo` / `demo123` works

## Dependencies

- Step 1 (server running, DB tables exist)

## Checklist pré-handoff

- [ ] All 4 auth endpoints work via curl
- [ ] Session persists across requests (cookie)
- [ ] Logout invalidates session
- [ ] Login page renders correctly
- [ ] Registration rejects duplicate username (409)
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `server/src/middleware/auth.js`
- `server/src/routes/auth.js`
- `server/src/seed.js`
- `server/src/index.js` (update: mount auth routes + seed)
- `public/login.html`

**Out of scope:** fingerprinting, daemon, JA4, terminal APIs, guard, admin, dashboard.

**Done criteria:** curl login demo:demo123 returns session cookie; subsequent /api/auth/me returns user; logout works. Login page renders.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-2.md
@specs/terminal-auth-poc.md

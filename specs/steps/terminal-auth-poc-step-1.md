# Step 1: Project scaffolding + DB schema + seed

## Goal

Project bootstrapping: Docker Compose, Express server skeleton, SQLite database with full schema (users, terminals, daemon_secrets, auth_events), and demo seed data.

## Tasks

1. **Create `docker-compose.yml`** — single service `server` mounting `./server` as volume, port 3000, environment `NODE_ENV=development`, `PORT=3000`, `ADMIN_KEY=pocdna-admin-secret`.

2. **Create `server/package.json`** — dependencies: `express@^4`, `better-sqlite3@^11`, `bcrypt@^5`, `express-session@^1`, `uuid@^10`, `cookie-parser@^1`, `connect-sqlite3@^0.9` (session store). Scripts: `start`, `dev` (with `--watch`).

3. **Create `server/Dockerfile`** — `node:20-alpine`, install build deps for better-sqlite3, copy package*.json, `npm ci`, copy source, expose 3000, `CMD ["node", "src/index.js"]`.

4. **Create `server/src/db.js`** — exports `getDb()` that returns a better-sqlite3 instance with `WAL` pragma. On first call, creates tables:

   ```sql
   CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY,
     username TEXT UNIQUE NOT NULL,
     password_hash TEXT NOT NULL,
     created_at TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS terminals (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL REFERENCES users(id),
     label TEXT NOT NULL,
     browser_fp_hash TEXT NOT NULL,
     browser_fp_data TEXT NOT NULL,
     daemon_fp_hash TEXT,
     daemon_fp_data TEXT,
     ja4_hash TEXT,
     registered_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     revoked_at TEXT
   );

   CREATE TABLE IF NOT EXISTS daemon_secrets (
     terminal_id TEXT PRIMARY KEY REFERENCES terminals(id),
     secret_hash TEXT NOT NULL,
     created_at TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS auth_events (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL REFERENCES users(id),
     terminal_id TEXT REFERENCES terminals(id),
     event_type TEXT NOT NULL,
     confidence REAL,
     layers_matched TEXT,
     ip_address TEXT NOT NULL,
     user_agent TEXT NOT NULL,
     ja4_observed TEXT,
     created_at TEXT NOT NULL
   );
   ```

5. **Create `server/src/index.js`** — Express app skeleton:
   - JSON body parser, cookie-parser
   - SQLite session store (connect-sqlite3)
   - Serve static files from `public/`
   - Health check `GET /api/health`
   - Run seed on first startup
   - Listen on `process.env.PORT || 3000`

## Out of scope

- Authentication routes (step 2)
- Fingerprinting engine (step 3)
- Daemon (step 4)
- JA4 middleware (step 5)
- Terminal APIs (step 6)
- Guard middleware (step 7)
- Admin routes + UI (step 8)

## Done criteria

- `docker compose up` starts the server on port 3000
- `GET /api/health` returns `{ "status": "ok" }`
- SQLite database file is created with all 4 tables
- Server restarts on file changes (`--watch`)

## Dependencies

None — this is the first step.

## Checklist pré-handoff

- [ ] `docker compose up` succeeds
- [ ] Health endpoint responds
- [ ] Database tables exist (verify with `sqlite3 data/pocdna.db ".tables"`)
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `docker-compose.yml`
- `server/package.json`
- `server/Dockerfile`
- `server/src/db.js`
- `server/src/index.js`

**Out of scope:** auth, fingerprinting, daemon, JA4, terminal APIs, guard, admin UI.

**Done criteria:** `docker compose up` → `curl localhost:3000/api/health` → `{"status":"ok"}`. DB com 4 tabelas.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-1.md
@specs/terminal-auth-poc.md

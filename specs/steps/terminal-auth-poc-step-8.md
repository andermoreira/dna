# Step 8: Admin panel + final polish

## Goal

Admin dashboard showing all registered terminals across all users with revoke capability. Final UI polish, README with setup instructions and architecture diagram.

## Tasks

1. **Create `server/src/routes/admin.js`** — Express Router:
   - Admin key check middleware: reads `x-admin-key` header, compares against `process.env.ADMIN_KEY`. Returns 401 if missing or invalid.
   - `GET /api/admin/terminals` — returns all terminals (including revoked) with user info:
     ```json
     { "terminals": [{ "id", "username", "label", "hasDaemon", "layersRegistered", "registeredAt", "lastSeenAt", "revokedAt" }] }
     ```
   - `POST /api/admin/terminals/:terminalId/revoke` — soft-deletes terminal (sets `revoked_at`). Logs audit event. Returns 204. Returns 404 if terminal not found.

2. **Create `public/admin.html`** — admin dashboard:
   - Accessible at `/admin.html`
   - Requires admin key input on first load (stored in sessionStorage)
   - Table of all terminals: username, label, daemon status, registered date, last seen, revoked status
   - Revoke button per terminal (with confirmation dialog)
   - Stats header: total terminals, active, revoked, daemon-enabled percentage
   - Same dark theme as dashboard
   - Polls `/api/admin/terminals` on load and after revoke action

3. **Update `server/src/index.js`**:
   - Mount `adminRouter` at `/api/admin`
   - Add comment block at top tracing the architecture layers

4. **Create `README.md`** — project readme with:
   - One-liner: "POC demonstrating terminal authentication via 3-layer fingerprinting (browser + local daemon + TLS)"
   - Architecture diagram (ASCII art showing the 3 layers)
   - Quick start: `docker compose up` + `node daemon/daemon.js`
   - Demo flow: login → register terminal → verify → sensitive action → admin revoke
   - Prerequisites: Docker, Node.js 20+
   - Endpoints reference (abbreviated from spec)
   - License: MIT

5. **Final polish on `public/index.html`**:
   - Add "Admin Panel" link in header (opens `/admin.html`)
   - Ensure all error messages are user-friendly
   - Add brief tooltip explaining the 3-layer badge (browser, daemon, TLS)

## Out of scope

- Admin authentication beyond static API key
- Pagination on admin terminal list
- Admin analytics/charts
- Export/import
- Production hardening

## Done criteria

- `GET /api/admin/terminals` with valid `x-admin-key` → 200 with all terminals
- `GET /api/admin/terminals` without key → 401
- `POST /api/admin/terminals/:id/revoke` → terminal revoked, 204
- `/admin.html` loads and displays terminal table
- Revoke button in admin panel works
- `README.md` contains setup instructions that work from scratch
- Full flow: docker compose up → node daemon.js → login → register → verify → sensitive action → admin revoke

## Dependencies

- Step 7 (complete dashboard, all terminal APIs)

## Checklist pré-handoff

- [ ] Admin endpoints protected by API key
- [ ] Admin page loads terminal table
- [ ] Revoke from admin works and reflects in user dashboard
- [ ] README setup instructions are correct (tested from scratch)
- [ ] All 8 ACs from spec are satisfied
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `server/src/routes/admin.js`
- `server/src/index.js` (update: mount admin routes)
- `public/admin.html`
- `public/index.html` (update: admin link, tooltips, polish)
- `README.md`

**Out of scope:** admin auth beyond API key, pagination, analytics, export.

**Done criteria:** admin panel shows all terminals, revoke works. README guides from zero to full demo. All 8 ACs pass.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-8.md
@specs/terminal-auth-poc.md

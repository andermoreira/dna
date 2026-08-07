# Step 6: Terminal registration & verification APIs

## Goal

REST endpoints for registering a new terminal, verifying a current terminal against known registrations, listing user's terminals, and deleting/revoking terminals. Integrates all three fingerprint layers (browser, daemon, TLS).

## Tasks

1. **Create `server/src/routes/terminals.js`** — Express Router with 4 endpoints. All require `requireAuth` middleware (except admin revoke route which uses `requireAuth` + admin key check).

   **`POST /api/auth/register-terminal`**
   - Body: `{ label, browserFP: { visitorId, components }, daemonPayload, daemonSignature }`
   - Validate: label non-empty (max 64 chars), browserFP present with visitorId and components
   - Check user terminal count (`SELECT COUNT(*) FROM terminals WHERE user_id = ? AND revoked_at IS NULL`) — max 5
   - Hash browser components: `hashComponents(browserFP.components)`
   - Check duplicate: `SELECT id FROM terminals WHERE user_id = ? AND browser_fp_hash = ? AND revoked_at IS NULL`
   - Check daemon if provided: if `daemonPayload` and `daemonSignature` present:
     - `validateDaemonHmac(daemonPayload, daemonSignature, SERVER_KNOWN_SECRET)` → note: at registration time, we don't have the secret yet. The daemon's secret is new. Strategy: store the daemon payload hash + the signature. We'll validate the HMAC by requesting the daemon's secret key as an additional field, or we trust the initial registration and validate on subsequent verifications. **POC simplification**: during registration, the client also sends `daemonSecret` (the base64 secret key). Server validates: `HMAC(daemonPayload, daemonSecret) === daemonSignature`. If valid, store the secret key. If daemon not present, skip.
   - Insert into `terminals`: id (uuid), user_id, label, browser_fp_hash, browser_fp_data (JSON), daemon_fp_hash (null if no daemon), daemon_fp_data, ja4_hash (from `req.ja4?.hash` or null)
   - If daemon secret provided and validated: insert into `daemon_secrets`
   - Insert `auth_events`: event_type=REGISTER
   - Return 201: `{ terminalId, label, layers: { browser: true, daemon: !!daemonPayload, tls: !!req.ja4 }, registeredAt }`

   **`POST /api/auth/verify-terminal`**
   - Body: `{ browserFP: { visitorId, components }, daemonPayload, daemonSignature }`
   - Load all user's non-revoked terminals with their stored fingerprint data + daemon secrets
   - For each terminal:
     - Browser score: `fuzzyMatchBrowserFP(terminal.browser_fp_data, browserFP.components)`
     - Daemon valid: if `daemonPayload` and terminal has secret → `validateDaemonHmac(daemonPayload, daemonSignature, terminalSecret)`
     - TLS match: if `req.ja4` and `terminal.ja4_hash` → `req.ja4.hash === terminal.ja4_hash`
     - Compute confidence with `computeConfidence(browserScore, daemonValid, tlsMatch)`
   - Find best match (highest confidence)
   - If best confidence ≥ 0.66 (2/3 layers) → known:
     - Update `last_seen_at` on that terminal
     - Insert `auth_events`: event_type=VERIFY_OK
     - Return 200: `{ known: true, terminalId, confidence, layers: { browser, daemon, tls } }`
   - If best < 0.66 → unknown:
     - Insert `auth_events`: event_type=VERIFY_FAIL
     - Return 200: `{ known: false, confidence: best, layers: { ... }, reason }`

   **`GET /api/user/terminals`**
   - Load user's non-revoked terminals
   - Return 200: `{ terminals: [{ id, label, hasDaemon: !!daemon_fp_hash, registeredAt, lastSeenAt }] }`

   **`DELETE /api/user/terminals/:terminalId`**
   - Find terminal by id, verify it belongs to the authenticated user
   - Soft-delete: `UPDATE terminals SET revoked_at = datetime('now') WHERE id = ?`
   - Insert `auth_events`: event_type=REVOKE
   - Return 204

2. **Update `server/src/index.js`**:
   - Import and mount `terminalsRouter` at `/api/auth` (since endpoints are under `/api/auth/...`)

## Out of scope

- Admin revoke endpoint (step 8)
- Terminal guard middleware integration (step 7)
- Rate limiting implementation (documented, not coded)
- Daemon secret key rotation
- Batch verification for multiple sensitive actions in one session

## Done criteria

- POST register-terminal with valid data → 201 with terminalId
- POST register-terminal with duplicate browser FP → 409
- POST register-terminal with 6th terminal → 403
- POST verify-terminal with matching terminal → `{ known: true, confidence: >= 0.66 }`
- POST verify-terminal with unknown terminal → `{ known: false }`
- GET terminals → returns list of user's registered terminals
- DELETE terminal → 204, terminal no longer in list, subsequent verify returns unknown
- Daemon HMAC validation works: valid signature → daemon layer passes, invalid signature → daemon layer fails
- Both browser-only and browser+daemon registrations work

## Dependencies

- Step 2 (auth middleware)
- Step 3 (browserFP structure — `{ visitorId, components }`)
- Step 4 (daemon HMAC format — `{ payload, signature }`)
- Step 5 (fingerprint service: `hashComponents`, `fuzzyMatchBrowserFP`, `validateDaemonHmac`, `computeConfidence`)

## Checklist pré-handoff

- [ ] All 4 endpoints respond correctly
- [ ] Registration enforces max 5 terminals
- [ ] Verification finds best match across multiple registered terminals
- [ ] 2/3 layers needed for `known: true`
- [ ] Delete soft-deletes (revoked_at set, not removed)
- [ ] Audit events logged for register/verify/revoke
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `server/src/routes/terminals.js`
- `server/src/index.js` (update: mount terminal routes)

**Out of scope:** admin endpoints, guard middleware, UI updates.

**Done criteria:** register → verify → list → delete cycle works end-to-end via curl.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-6.md
@specs/terminal-auth-poc.md

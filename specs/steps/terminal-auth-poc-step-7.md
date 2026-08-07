# Step 7: Terminal guard middleware + dashboard UI

## Goal

Server-side middleware that blocks sensitive actions if the current terminal is not recognized. Plus the complete dashboard UI: terminal status badge, registration prompt, device list, and simulated sensitive action with guard in action.

## Tasks

1. **Create `server/src/middleware/requireTerminal.js`** — exports `requireKnownTerminal` middleware factory:
   - Returns an Express middleware that:
     - Checks if request has a `terminalId` in the session (set on successful verification)
     - If no `terminalId` in session → responds 403 `{ "error": "This terminal is not authorized for this action. Use a registered device or register this one through your account settings." }`
     - If `terminalId` exists → loads terminal from DB, checks not revoked → if ok, calls `next()`, if revoked → clears session terminalId → 403
   - Also exports `setTerminalSession(req, terminalId)` helper to store verified terminal in session

2. **Update `server/src/routes/terminals.js`** — on successful verification (`known: true`), call `setTerminalSession(req, terminalId)` so subsequent requests from the same session don't need re-verification.

3. **Create sensitive action endpoint in `server/src/index.js`**:
   - `POST /api/actions/sensitive` — with `requireAuth` + `requireKnownTerminal()` middleware chain
   - Returns 200 `{ "message": "Sensitive action completed successfully", "terminalId" }` if both pass
   - Returns 403 with terminal error if guard blocks

4. **Rewrite `public/index.html`** — complete dashboard with:

   **Sections:**
   - **Header:** "Terminal Authentication POC", logout button
   - **Terminal Status Card:** shows current terminal status:
     - On page load: collect browser fingerprint + query daemon (fetch `https://127.0.0.1:30900/fingerprint` with `mode: 'cors'`, handle connection refused gracefully)
     - POST to `/api/auth/verify-terminal`
     - If known: green badge "Terminal Recognized" + show which layers matched + confidence percentage
     - If unknown: yellow badge "Unknown Terminal" + button "Register This Terminal"
   - **Registration Form (hidden by default):** appears when terminal is unknown. Input for terminal label + "Register" button → POST `/api/auth/register-terminal`
   - **Device List:** shows all registered terminals (GET `/api/user/terminals`). Each with:
     - Label, registration date, last seen, daemon status (green/red dot), delete button
     - Delete confirms then calls DELETE endpoint, removes from list
   - **Sensitive Action Demo:**
     - Button "Perform Sensitive Action (Transfer)"
     - On click: POST `/api/actions/sensitive`
     - Success: green toast "Action completed — terminal verified"
     - Failure (403): red toast with server error message
   - **Daemon Status Indicator:** top-right corner: green dot if daemon reachable, red dot if not

   **Styling:** dark theme (`#1a1a2e` bg, `#16213e` cards, `#e94560` accents, `#0f3460` secondary). Clean, POC-style, no frameworks.

5. **Update `server/src/index.js`** — add the sensitive action route, mount `requireKnownTerminal` middleware.

## Out of scope

- Admin panel (step 8)
- Real-time daemon status polling (one-time check on page load)
- Multi-tab session sync
- Accessibility / i18n

## Done criteria

- Dashboard loads, collects fingerprints, verifies terminal
- Known terminal → green badge, sensitive action succeeds
- Unknown terminal → yellow badge, registration form appears
- Register terminal → appears in device list, badge turns green
- Delete terminal from list → disappears, next sensitive action on that terminal → 403
- Daemon not running → red daemon indicator, registration still works (browser-only, daemon layer marked absent)
- Sensitive action without any registered terminal → 403 with clear message
- Logout clears session

## Dependencies

- Step 6 (terminal APIs: register, verify, list, delete)
- Step 3 (fingerprint.js loaded on page)
- Step 4 (daemon running for daemon query)

## Checklist pré-handoff

- [ ] Dashboard renders terminal status on page load
- [ ] Registration flow: unknown → register → known
- [ ] Device list shows registered terminals with delete
- [ ] Sensitive action button works correctly (200 or 403)
- [ ] Daemon unreachable handled gracefully
- [ ] All interactions work without page reload (AJAX/fetch)
- [ ] Logout works
- [ ] Dark theme applied
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `server/src/middleware/requireTerminal.js`
- `server/src/routes/terminals.js` (update: set session terminalId on verify)
- `server/src/index.js` (update: sensitive action route)
- `public/index.html` (rewrite: complete dashboard)

**Out of scope:** admin panel, WebSocket, real-time updates, accessibility.

**Done criteria:** full flow: login → dashboard shows unknown → register → known → sensitive action works → delete terminal → sensitive action blocked.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-7.md
@specs/terminal-auth-poc.md

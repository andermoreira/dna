# Terminal Authentication POC

## Goal

Demonstrate an extra security layer for web applications where each user terminal is uniquely identified by a three-layer fingerprint — browser signals (Canvas/WebGL/Audio), OS-level data from a local daemon (HMAC-signed, Warsaw-style), and server-side TLS fingerprint (JA4). Only pre-registered terminals are permitted to execute sensitive actions.

## Architecture overview

```
┌─BROWSER (Layer 1: weak signals)──┐
│  canvas, webgl, audio, fonts,    │
│  screen, timezone, plugins,      │
│  platform, hardwareConcurrency,  │
│  touch support                   │
│                                  │
│  ┌─Daemon query (Layer 2)──────┐ │
│  │ fetch('https://127.0.0.1:   │ │      ┌─SERVER (validation + Layer 3)──┐
│  │   30900/fingerprint')       │─┼──────→  Layer 1: fuzzy match browser FP
│  │  → { payload, signature }   │ │      │  Layer 2: validate daemon HMAC
│  └─────────────────────────────┘ │      │  Layer 3: extract JA4 from TLS
└──────────────────────────────────┘      │  → confidence score (0–1)       │
                                          │  → known → allow               │
┌─LOCAL DAEMON (Layer 2: strong signals)┐ │  → unknown → block/register     │
│  os.cpus(), os.hostname(),            │ │      └──────────────────────────┘
│  os.networkInterfaces(),              │
│  os.totalmem(), os.platform(),        │
│  os.arch(), os.userInfo(),            │
│  fs.readdir('/Applications'),         │
│  process.uptime()                     │
│                                       │
│  HMAC-SHA256(payload, secret.key)    │
│  Listens on 127.0.0.1:30900 (TLS)    │
│  Secret key generated at install time │
└───────────────────────────────────────┘
```

**Why three layers:** browser JS signals are spoofable by a motivated attacker (headless browser, Puppeteer). The daemon runs outside the browser, collects real OS data the JS cannot access, and signs with a secret the browser never sees — exactly how Warsaw/G-Buster works. TLS fingerprinting (JA4) adds a server-side signal the client cannot control. A terminal is trusted only when **at least 2 of 3 layers match**.

## Non-goals

- Production-grade security or cryptographic device binding (no kernel driver, no CA injection, no WebAuthn).
- Replacement for 2FA or password-based authentication — this is a complementary layer.
- Cross-browser terminal linking (same machine, different browsers → different terminals by design).
- Mobile native SDK — browser-only; mobile browsers are incidental.
- Compliance with any specific regulation (GDPR, LGPD, PCI) — POC demonstrativa apenas.
- The daemon is a **Node.js process**, not a compiled binary with kernel driver. It demonstrates the architecture, not the hardening.

## User stories

### US-01 — First access from an unknown terminal (with daemon)

**Given** a registered user accessing the application from a terminal never seen before, with the local daemon running,
**When** the user completes primary authentication (username + password),
**Then** the system collects all three fingerprint layers, prompts the user to name and register this terminal, stores the composite fingerprint, and grants access. The terminal appears in the user's device list with a confidence badge showing which layers matched.

### US-02 — Returning from a known terminal

**Given** a registered user on a previously registered terminal,
**When** the user completes primary authentication,
**Then** the system matches all three fingerprint layers against the stored registration, silently confirms the match (≥2 layers match), and grants access without additional prompts.

### US-03 — Unrecognized terminal blocked from sensitive action

**Given** a user authenticated but not on a recognized terminal,
**When** the user attempts a sensitive action (simulated: transfer, settings change, password reset),
**Then** the action is blocked with a clear message: "This terminal is not authorized for this action. Use a registered device or register this one through your account settings."

### US-04 — Daemon not running (degraded mode)

**Given** a user accessing the application from a terminal where the local daemon is not installed or not running,
**When** fingerprint collection occurs,
**Then** the system detects the missing daemon, collects only browser-level signals, marks the confidence as degraded, and warns the user: "Terminal security module not detected. Consider installing the daemon for stronger protection." Registration is still allowed but with reduced confidence.

### US-05 — Device trust revocation

**Given** a user with registered terminals,
**When** the user removes a terminal from their device list,
**Then** that terminal can no longer authenticate as trusted; the next access from it triggers the unknown-terminal flow (US-01).

### US-06 — Fingerprint drift tolerance

**Given** a user on a known terminal that has undergone minor changes (e.g., browser update, different screen resolution),
**When** fingerprints are collected and compared,
**Then** at least 2 of 3 layers still match — granting access without re-registration.

### US-07 — Complete fingerprint mismatch

**Given** a user on what was a known terminal after a major change (e.g., different OS, different hardware),
**When** fingerprints are collected and compared,
**Then** 0 or 1 layers match — triggering the unknown-terminal flow (US-01).

## Assumptions

- The application is served over HTTPS (TLS). Fingerprinting over plain HTTP would expose the fingerprint to network observers and prevents JA4 extraction.
- The user's browser has JavaScript enabled and is a modern browser (Chrome, Firefox, Safari, Edge — last 2 major versions).
- The local daemon requires Node.js 20+ installed on the user's machine. It is started manually for the POC (`node daemon.js`) and listens on `127.0.0.1:30900`.
- The daemon's TLS certificate is self-signed and the user must accept the browser warning on first daemon connection (explicitly documented as a POC limitation — production would inject the CA into the trust store like Warsaw does).
- The database stores fingerprint hashes, not raw fingerprinting data. Raw attribute values exist only transiently in memory during collection and comparison.
- A user can register up to 5 terminals.
- Primary authentication uses username + bcrypt-hashed password with cookie-based sessions (express-session). The POC ships with seed users for immediate demonstration.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Browser-only fingerprinting is spoofable (headless browser) | Low: attacker must also bypass daemon + TLS layers | Require ≥2 of 3 layers to match; daemon HMAC and JA4 are not forgeable from browser context |
| Daemon secret key extraction — attacker reads `secret.key` from disk | Medium: if attacker has local access, they can forge daemon signatures | Document as POC limitation; production would use TPM/HSM for key storage (like WebAuthn) |
| TLS fingerprint (JA4) identifies browser family, not individual device | Low entropy (~4-6 bits) from JA4 alone | Use JA4 as a consistency check, not the primary identifier; cross-validate against User-Agent |
| Daemon not running — user operates in degraded mode | Reduced confidence, easier to spoof | Detect and warn; still allow registration but mark terminal as "weak"; require daemon for sensitive actions |
| Self-signed cert causes browser warning on daemon connection | User friction, confusion | Document clearly; auto-open instructions on first use |
| Fingerprint drift from legitimate updates | False rejection of known terminal | Weighted scoring: hardware signals > OS signals > browser signals; 2/3 layers must still match |

## API contract

### Daemon endpoint: GET https://127.0.0.1:30900/fingerprint

Queried by the browser JS. Returns OS-level fingerprint data signed with HMAC.

- **Protocol**: HTTPS (self-signed cert, user must accept)
- **Response 200**: `{ "payload": { "hostname": string, "platform": string, "arch": string, "cpus": string, "totalmem": number, "networkInterfaces": object, "username": string, "installedApps": string[], "uptime": number, "timestamp": number }, "signature": string }`
- **Signature**: `HMAC-SHA256(JSON.stringify(payload), secretKey)` — hex-encoded

### Server endpoint: POST /api/auth/register-terminal

Registers the current terminal for the authenticated user.

- **Auth**: Session cookie (express-session)
- **Request**:
```json
{
  "label": "Meu Notebook",
  "browserFP": { "visitorId": "abc123", "components": { "canvas": "...", "webgl": "...", "audio": "...", "fonts": ["...", "..."], "screen": "1920x1080x24", "timezone": "America/Sao_Paulo", "plugins": ["..."], "platform": "MacIntel", "hardwareConcurrency": 8, "touchSupport": false, "userAgent": "..." } },
  "daemonPayload": { "hostname": "...", "platform": "...", "...": "..." },
  "daemonSignature": "hex..."
}
```
- **Response 201**: `{ "terminalId": string, "label": string, "layers": { "browser": boolean, "daemon": boolean, "tls": boolean }, "registeredAt": string }`
- **Response 409**: Terminal already registered (composite fingerprint match)
- **Response 400**: Missing required fields or invalid daemon signature
- **Rate limit**: 10 registrations per user per hour

### Server endpoint: POST /api/auth/verify-terminal

Checks whether the current terminal is known for the authenticated user.

- **Auth**: Session cookie
- **Request**: same structure as register-terminal
- **Response 200**: `{ "known": true, "terminalId": string, "confidence": 0.95, "layers": { "browser": 0.82, "daemon": true, "tls": true } }`
- **Response 200**: `{ "known": false, "confidence": 0.3, "layers": { "browser": 0.4, "daemon": false, "tls": true }, "reason": "daemon signature invalid, browser FP mismatch" }`

### GET /api/user/terminals

Lists registered terminals for the authenticated user.

- **Auth**: Session cookie
- **Response 200**: `{ "terminals": [{ "id": string, "label": string, "hasDaemon": boolean, "registeredAt": string, "lastSeenAt": string }] }`

### DELETE /api/user/terminals/:terminalId

Removes a registered terminal.

- **Auth**: Session cookie
- **Response 204**: Terminal removed
- **Response 404**: Terminal not found or not owned by user

### POST /api/admin/terminals/:terminalId/revoke

Admin endpoint to revoke a terminal globally.

- **Auth**: Admin API key (header `x-admin-key`)
- **Response 204**: Terminal revoked

## Data model

### Table: users

| Column | Type | Constraints |
|---|---|---|
| id | TEXT | PK, UUID |
| username | TEXT | UNIQUE, NOT NULL |
| password_hash | TEXT | NOT NULL |
| created_at | TEXT | NOT NULL (ISO 8601) |

### Table: terminals

| Column | Type | Constraints |
|---|---|---|
| id | TEXT | PK, UUID |
| user_id | TEXT | FK → users.id, NOT NULL |
| label | TEXT | NOT NULL (user-given name) |
| browser_fp_hash | TEXT | NOT NULL (SHA-256 of normalized browser components) |
| browser_fp_data 🔒 | TEXT | NOT NULL (JSON: browser components) |
| daemon_fp_hash | TEXT | NULLABLE (SHA-256 of normalized daemon payload — null if daemon was absent) |
| daemon_fp_data 🔒 | TEXT | NULLABLE (JSON: daemon payload fields) |
| daemon_secret_hash | TEXT | NULLABLE (SHA-256 of the daemon's secret key — used for HMAC validation) |
| ja4_hash | TEXT | NULLABLE (JA4 fingerprint from TLS ClientHello) |
| registered_at | TEXT | NOT NULL (ISO 8601) |
| last_seen_at | TEXT | NOT NULL (ISO 8601) |
| revoked_at | TEXT | NULLABLE (ISO 8601) |

### Table: daemon_secrets

Tracks which secret key belongs to which terminal. Separate table so secret hashes are not mixed with fingerprint data.

| Column | Type | Constraints |
|---|---|---|
| terminal_id | TEXT | PK, FK → terminals.id, UNIQUE |
| secret_hash 🔒 | TEXT | NOT NULL (SHA-256 of the daemon's secret key) |
| created_at | TEXT | NOT NULL (ISO 8601) |

### Table: auth_events

| Column | Type | Constraints |
|---|---|---|
| id | TEXT | PK, UUID |
| user_id | TEXT | FK → users.id |
| terminal_id | TEXT | FK → terminals.id, NULLABLE |
| event_type | TEXT | NOT NULL (REGISTER, VERIFY_OK, VERIFY_FAIL, REVOKE) |
| confidence | REAL | NULLABLE |
| layers_matched | TEXT | NULLABLE (JSON: `{"browser":true,"daemon":false,"tls":true}`) |
| ip_address 🔒 | TEXT | NOT NULL |
| user_agent 🔒 | TEXT | NOT NULL |
| ja4_observed | TEXT | NULLABLE |
| created_at | TEXT | NOT NULL (ISO 8601) |

🔒 = campos com PII.

## Error handling

| Scenario | HTTP Status | User-facing message | Internal behavior |
|---|---|---|---|
| Daemon not running | 200 (verify) | "Terminal security module not detected. Consider installing the daemon." | Degraded mode; browser-only FP used; daemon fields null |
| Daemon signature invalid | 403 | "Terminal identity could not be verified. Ensure the security module is properly installed." | Log mismatch; invalidate daemon layer |
| Browser FP collection fails (JS blocked) | 400 | "Could not identify your terminal. Please enable JavaScript and reload." | Log warning with user ID and IP |
| All layers mismatch on sensitive action | 403 | "This terminal is not authorized for this action. Use a registered device." | Log VERIFY_FAIL with all layer results |
| Terminal already registered | 409 | "This terminal is already registered." | Log duplicate attempt |
| Terminal registration limit reached | 403 | "You have reached the maximum number of registered terminals (5). Remove an existing one first." | Log limit exceeded |
| Daemon secret key not found (reinstall needed) | 400 | "Terminal security module needs reinstallation. Please restart the daemon." | Log missing secret |
| Database unavailable | 500 | "Service temporarily unavailable." | Log error; return generic response |
| Invalid fingerprint payload | 400 | "Invalid terminal data." | Log validation errors server-side only |
| JA4 extraction failed | 200 (verify) | No user message — handled transparently | Degraded mode; JA4 layer null; still usable with 2 remaining layers |

## Observability

Structured JSON logging to stdout. In production, these feed into a metrics pipeline.

**Log events:**
- `terminal.registered` — user_id, terminal_id, layers_matched, fingerprint_entropy_bits
- `terminal.verified` — user_id, terminal_id, confidence, layers, match_duration_ms
- `terminal.mismatch` — user_id, candidate_hash, best_confidence, failed_layers (which layers failed)
- `terminal.revoked` — user_id, terminal_id, revoked_by (user|admin)
- `daemon.not_found` — user_id, reason (connection_refused|timeout|invalid_cert)
- `ja4.extracted` — ja4_hash, user_agent (for cross-validation)
- `ja4.extraction_failed` — reason

## Quality attributes

POC — sem requisitos não funcionais rigorosos. O sistema deve responder em <3s para o fluxo completo (browser FP collection + daemon query + server verification) em um laptop moderno com conexão local. A demonstração roda inteiramente em `localhost` com 3 terminais: servidor, daemon e browser.

## Threat model

| Vector | Risk | Mitigation |
|---|---|---|
| Browser FP spoofing (headless browser) | Low: daemon + JA4 layers remain | Require ≥2 of 3 layers to pass; daemon HMAC cannot be forged without the secret key |
| Daemon secret extraction from disk | Medium: local attacker reads `secret.key` | Document as POC limitation; production uses TPM/HSM. For POC, file permissions (`chmod 600`) |
| Daemon impersonation — attacker runs fake daemon on port 30900 | Medium: could sign arbitrary payloads | Secret key is unique per installation; server rejects unknown secrets. Cross-validate daemon data against browser FP + JA4 |
| Fingerprint replay — attacker captures entire payload and replays | Medium | Daemon payload includes `timestamp`; server rejects if >60s old. Browser FP includes server-issued `nonce` |
| TLS fingerprint (JA4) only identifies browser family | Low: complementary signal only | Not used as standalone identifier; cross-validated with User-Agent for consistency |
| Session hijacking from registered terminal | High: bypasses terminal verification entirely | Not mitigated by this layer. Terminal auth confirms the machine, not the person. Primary auth must be secure |
| Daemon secret brute-force | Low: HMAC-SHA256 with 256-bit random key | Key length makes brute-force infeasible |
| Daemon TLS MITM on localhost | Very low: attacker would need root on the same machine to intercept loopback traffic | Out of scope for POC; localhost MITM implies full machine compromise |

## Rollout

POC — `docker compose up` inicia o servidor + banco. O daemon é iniciado separadamente com `node daemon.js` na máquina host (não conteinerizado, pois precisa acessar `os.cpus()`, `os.networkInterfaces()`, etc. reais do host). Isso é intencional: demonstra que o daemon é um componente externo ao browser, assim como o Warsaw.

## Rollback

POC — `docker compose down -v` remove todos os dados do servidor. O arquivo `secret.key` do daemon fica em `/tmp/pocdna-secret.key` e pode ser removido manualmente.

## Acceptance criteria

1. **AC-01**: Usuário faz login com daemon rodando → sistema coleta 3 camadas → registra terminal com sucesso → terminal aparece na lista com badge "Secure" (3/3 layers).
2. **AC-02**: Após registro, mesmo usuário + mesmo navegador + daemon rodando → login → terminal reconhecido automaticamente → sem prompt de registro.
3. **AC-03**: Usuário com daemon PARADO → login → aviso "Daemon not detected" → ainda pode registrar terminal, mas com badge "Weak" (1/3 layers) → ações sensíveis bloqueadas.
4. **AC-04**: Usuário em navegador diferente (novo browser FP, mesmo daemon) → tenta ação sensível → 403 "terminal não autorizado" (browser layer diverge, ≤1 match).
5. **AC-05**: Usuário remove terminal da lista → mesmo terminal tenta ação sensível → 403.
6. **AC-06**: Após mudança menor (ex: resize da janela), browser FP ainda dá match via fuzzy → terminal reconhecido (≥2 layers).
7. **AC-07**: Admin acessa `/admin` com `x-admin-key` → vê todos os terminais → revoga qualquer um.
8. **AC-08**: `docker compose up` inicia em <30s. Daemon inicia com `node daemon.js` e imprime "Daemon listening on https://127.0.0.1:30900".

## Open questions

| # | Question | Owner | Decision |
|---|---|---|---|
| Q1 | FingerprintJS v4 ou implementação customizada? | @andersonalves | **Customizada.** Coleta manual de Canvas, WebGL, Audio, fonts, screen, timezone, plugins, platform, hardwareConcurrency, touch. Didático. |
| Q2 | Frontend: HTML vanilla ou React? | @andersonalves | **HTML vanilla + JS.** Zero build step, servido pelo Express. |
| Q3 | Banco: SQLite ou PostgreSQL? | @andersonalves | **SQLite com better-sqlite3.** Sem container extra. |
| Q4 | TLS fingerprinting server-side? | @andersonalves | **Sim — JA4.** Extraído do TLS ClientHello pelo servidor Express com socket inspection. Sinal complementar que o cliente não controla. |
| Q5 | Auth primária: mock ou real? | @andersonalves | **Real com bcrypt + express-session.** Seed user para demo. |
| Q6 | Daemon: Node.js ou binário compilado? | @andersonalves | **Node.js.** `node daemon.js` — acessa `os.*`, `fs.*`, assina com HMAC. Demonstra a arquitetura sem complexidade de compilação. |
| Q7 | TLS no daemon: cert autoassinado ou HTTP puro? | @andersonalves | **HTTPS com cert autoassinado (gerado no startup).** Espelha o Warsaw (que gera `rootca.crt` por instalação). Usuário aceita warning manualmente (POC limitation). |

## Implementation plan

1. [**Project scaffolding**](./steps/terminal-auth-poc-step-1.md) — Docker Compose, estrutura de diretórios, package.json, SQLite schema (users, terminals, daemon_secrets, auth_events), seed.
2. [**User authentication baseline**](./steps/terminal-auth-poc-step-2.md) — Registro/login com bcrypt, sessões cookie (express-session), middleware requireAuth, seed user demo:demo123, login.html.
3. [**Client-side browser fingerprinting engine**](./steps/terminal-auth-poc-step-3.md) — JS vanilla: Canvas, WebGL, Audio, fonts, screen, timezone, plugins, platform, hardwareConcurrency, touch. Gera visitorId + components. Dashboard placeholder.
4. [**Local daemon**](./steps/terminal-auth-poc-step-4.md) — `daemon.js`: gera secret key, coleta `os.*` + `fs.*`, assina com HMAC-SHA256, serve HTTPS em 127.0.0.1:30900. Endpoints `/fingerprint` e `/health`.
5. [**JA4 extraction + fingerprint service**](./steps/terminal-auth-poc-step-5.md) — Middleware que extrai JA4 do TLS ClientHello (read-tls-client-hello). Serviço: hashComponents, fuzzyMatchBrowserFP (weighted Jaccard), validateDaemonHmac, computeConfidence.
6. [**Terminal registration & verification APIs**](./steps/terminal-auth-poc-step-6.md) — POST register, POST verify, GET list, DELETE. Integra as 3 camadas. Requer ≥2/3 layers para known=true.
7. [**Terminal guard + dashboard UI**](./steps/terminal-auth-poc-step-7.md) — Middleware requireKnownTerminal bloqueia ações sensíveis. Dashboard: status badge, registro, device list, ação sensível simulada, daemon indicator.
8. [**Admin panel + final polish**](./steps/terminal-auth-poc-step-8.md) — /admin com lista de todos os terminais e revoke. README com setup e diagrama. Links e tooltips no dashboard.

**Rastreabilidade AC ↔ Steps:**

| AC | Steps |
|---|---|
| AC-01 (primeiro acesso → registro) | Step 6 (register), Step 7 (dashboard flow) |
| AC-02 (retorno → reconhecido) | Step 6 (verify), Step 7 (auto-verify on load) |
| AC-03 (daemon parado → modo degradado) | Step 6 (daemon-less register), Step 7 (badge "Weak") |
| AC-04 (navegador diferente → 403) | Step 6 (verify unknown), Step 7 (guard middleware) |
| AC-05 (remoção → 403) | Step 6 (delete), Step 7 (guard re-check) |
| AC-06 (drift tolerado) | Step 5 (fuzzyMatchBrowserFP weights) |
| AC-07 (admin revoga) | Step 8 (admin panel + revoke) |
| AC-08 (docker compose up) | Step 1 (scaffolding), Step 4 (daemon startup)

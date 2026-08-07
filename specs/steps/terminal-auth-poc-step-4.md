# Step 4: Local daemon

## Goal

Node.js daemon that mirrors the Warsaw architecture: collects real OS-level data the browser cannot access, signs it with HMAC-SHA256 using a secret key generated at install time, and serves it over HTTPS on `127.0.0.1:30900`. The browser queries this daemon as Layer 2 of the fingerprint.

## Tasks

1. **Create `daemon/package.json`** — name `pocdna-daemon`, private, no external dependencies (uses only Node.js built-ins: `crypto`, `os`, `fs`, `https`, `path`). Script: `start: "node daemon.js"`.

2. **Create `daemon/daemon.js`** — single-file daemon with:

   **Secret key management:**
   - On startup, look for `SECRET_KEY_PATH` env var (default: `/tmp/pocdna-secret.key`)
   - If file does not exist: generate 32 random bytes via `crypto.randomBytes(32)`, write to file with `0o600` permissions, log `[daemon] new secret key generated`
   - If file exists: read it, log `[daemon] secret key loaded`

   **Data collection** (`/fingerprint` endpoint):
   ```js
   {
     hostname: os.hostname(),
     platform: os.platform(),
     arch: os.arch(),
     cpus: os.cpus().map(c => c.model).join('|'),
     cpuCores: os.cpus().length,
     totalmem: os.totalmem(),
     freemem: os.freemem(),
     networkInterfaces: JSON.stringify(os.networkInterfaces()),
     username: os.userInfo().username,
     homedir: os.userInfo().homedir,
     uptime: Math.floor(os.uptime()),
     nodeVersion: process.version,
     timestamp: Date.now()
   }
   ```
   - `networkInterfaces`: stringify the object, then hash internal IPs to avoid leaking them in plaintext (replace IPv4/IPv6 values with SHA-256 hashes, keep MAC addresses)
   - `installedApps`: if platform is `darwin`, list `/Applications/*.app`; if `linux`, list `/usr/share/applications/*.desktop`; if `win32`, list `C:\Program Files\*`. Truncate to top 20 sorted entries.
   - Sort all object keys alphabetically before signing

   **HMAC signing:**
   - `payload = { ...collectedData }` (sorted keys)
   - `signature = crypto.createHmac('sha256', secretKey).update(JSON.stringify(payload)).digest('hex')`
   - Response: `{ "payload": payload, "signature": signature }`

   **HTTPS server:**
   - Generate self-signed certificate on startup (valid 365 days) if not exists at `/tmp/pocdna-cert.pem` and `/tmp/pocdna-key.pem`
   - `https.createServer({ cert, key }, handler)` on `127.0.0.1:30900`
   - CORS headers: `Access-Control-Allow-Origin: *` (safe since it's loopback-only)
   - `GET /fingerprint` → returns `{ payload, signature }` as JSON
   - `GET /health` → returns `{ "status": "ok" }`
   - Log every request: `[daemon] GET /fingerprint from ::1`

   **Signal handling:**
   - `SIGTERM` / `SIGINT` → graceful shutdown, log `[daemon] shutting down`

## Out of scope

- TLS certificate trust injection into browser (user manually accepts warning — documented POC limitation)
- WebSocket protocol (plain HTTPS GET is sufficient for POC)
- Multiple concurrent daemon instances
- Anti-sandbox/VM detection (POC doesn't need it)
- Cross-platform binary distribution (needs Node.js installed)

## Done criteria

- `node daemon.js` starts, prints `[daemon] listening on https://127.0.0.1:30900`
- First run generates `secret.key` file
- Second run loads existing `secret.key`
- `curl -k https://127.0.0.1:30900/health` → `{"status":"ok"}`
- `curl -k https://127.0.0.1:30900/fingerprint` → `{ "payload": {...}, "signature": "hex..." }`
- Same `secret.key` produces same signature for same OS data (deterministic given stable system state)
- `SIGTERM` shuts down gracefully

## Dependencies

- Step 3 (browser FP engine — daemon is independent but conceptually Layer 2)

## Checklist pré-handoff

- [ ] Daemon starts and generates/locates secret key
- [ ] `/fingerprint` returns OS data with valid HMAC signature
- [ ] Signature verification: `crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex') === signature`
- [ ] `/health` returns ok
- [ ] Only listens on 127.0.0.1 (verify with `lsof -i :30900`)
- [ ] Graceful shutdown on Ctrl+C

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `daemon/package.json`
- `daemon/daemon.js`

**Out of scope:** CA trust injection, WebSocket, anti-VM, cross-platform installers, browser integration.

**Done criteria:** `node daemon.js` → daemon alive on :30900. `curl -k https://127.0.0.1:30900/fingerprint` returns payload + valid HMAC signature.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-4.md
@specs/terminal-auth-poc.md

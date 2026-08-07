# Step 5: JA4 extraction middleware + fingerprint service

## Goal

Server-side middleware that extracts the JA4 TLS fingerprint from the incoming request's TLS ClientHello. Plus the core fingerprint service with hashing, fuzzy matching, and confidence scoring logic used by subsequent steps.

## Tasks

1. **Install `read-tls-client-hello`** — `npm install read-tls-client-hello` in `server/`. This package parses the raw TLS ClientHello from a Node.js socket and extracts JA3/JA4 hashes.

2. **Create `server/src/middleware/ja4.js`** — exports `extractJa4` middleware:
   - Accesses the raw TLS socket via `req.socket` or `req.connection`
   - The `read-tls-client-hello` package provides `readTlsClientHello(socket)` which returns parsed ClientHello including the JA4 hash
   - Store result as `req.ja4 = { hash: "t13d1516h2_...", raw: {...} }` on the request object
   - If extraction fails (non-TLS, HTTP/1.1 without TLS, or error): set `req.ja4 = null`, do NOT block the request
   - Log warning on extraction failure: `[ja4] extraction failed: <reason>`
   - Apply this middleware globally in `index.js` BEFORE route handlers

3. **Create `server/src/services/fingerprint.js`** — exports:
   - `hashComponents(components)` — takes browser fingerprint components object, JSON-stringifies with sorted keys, returns SHA-256 hex digest. Uses `crypto.createHash('sha256')`.
   - `fuzzyMatchBrowserFP(storedComponents, candidateComponents)` — compares two sets of browser fingerprint components. Calculates weighted Jaccard similarity:
     - Signals and their weights:
       - Canvas: 0.25 (hardware-dependent, high stability)
       - WebGL: 0.20 (hardware-dependent)
       - Audio: 0.15 (hardware-dependent)
       - Platform: 0.10
       - Screen: 0.10
       - Fonts: 0.08
       - Timezone: 0.05
       - HardwareConcurrency: 0.04
       - TouchSupport: 0.02
       - Plugins: 0.01 (low stability, changes often)
     - For exact-match signals (canvas, webgl, audio, platform, screen, timezone, hardwareConcurrency, touchSupport): compare string equality → score = weight if match, 0 if not
     - For list signals (fonts, plugins): Jaccard similarity = |intersection| / |union|, then multiply by weight
     - Return sum of all weighted scores (0.0 to 1.0)
   - `validateDaemonHmac(payload, signature, secretHash)` — recomputes `HMAC-SHA256(JSON.stringify(sorted payload), secretKey)` and compares against provided signature. Returns boolean. Note: this function compares against the stored hash (SHA-256 of the secret key), not the raw secret. We need the raw secret to compute HMAC — so the actual validation will use the stored `secret_hash` to look up the terminal, then use the raw secret (retrieved from `daemon_secrets` with a reversible lookup, or we store both hash and an encrypted version). For POC simplicity: store the raw secret in `daemon_secrets.secret_key` (column already exists as `secret_hash`, rename to `secret_key` TEXT NOT NULL). Validate by: `crypto.createHmac('sha256', storedSecretKey).update(JSON.stringify(sortedPayload)).digest('hex') === providedSignature`.
   - `computeConfidence(browserScore, daemonValid, tlsHashKnown)` — determines overall terminal confidence:
     - Count how many layers are "passing":
       - Browser: `browserScore >= 0.7`
       - Daemon: `daemonValid === true`
       - TLS: `tlsHashKnown && storedJa4 === observedJa4`
     - Return `{ layersMatched: number, known: boolean, confidence: number }`
       - `known = layersMatched >= 2`
       - `confidence = layersMatched / 3`

4. **Update `server/src/db.js`** — rename `daemon_secrets.secret_hash` to `daemon_secrets.secret_key` (store the raw base64-encoded key for HMAC recomputation). Add migration: `ALTER TABLE daemon_secrets RENAME COLUMN secret_hash TO secret_key;` (handle if column already renamed — check schema first).

## Out of scope

- JA4 validation against a known-hash database (just stores and compares the observed hash)
- Advanced TLS fingerprinting beyond JA4 (JA4H, JA4T, etc.)
- Certificate transparency, HPKP, or other TLS pinning
- Browser FP drift auto-update (step 7 handles re-registration)

## Done criteria

- `req.ja4` is populated for HTTPS requests (when running behind TLS)
- `hashComponents()` produces deterministic SHA-256 for same input
- `fuzzyMatchBrowserFP()` returns 1.0 for identical components
- `fuzzyMatchBrowserFP()` returns ~0.0 for completely different components
- `fuzzyMatchBrowserFP()` returns >0.7 when only screen resolution changes
- `validateDaemonHmac()` returns true for payload signed with correct key
- `validateDaemonHmac()` returns false for payload signed with wrong key
- `computeConfidence()` returns `{ known: true }` when ≥2 layers pass

## Dependencies

- Step 1 (DB schema — updated here)
- Step 3 (browser FP components structure)
- Step 4 (daemon HMAC signing algorithm — must match)

## Checklist pré-handoff

- [ ] JA4 middleware extracts hash from TLS requests
- [ ] JA4 middleware degrades gracefully on non-TLS (dev mode)
- [ ] `hashComponents()` is deterministic
- [ ] `fuzzyMatchBrowserFP()` weights hardware signals higher
- [ ] `validateDaemonHmac()` correctly validates known signature
- [ ] `validateDaemonHmac()` rejects invalid signature
- [ ] DB column renamed (secret_hash → secret_key)
- [ ] No lint errors

---

Implemente APENAS o step abaixo — não expanda o escopo.

**Files:**
- `server/package.json` (update: add read-tls-client-hello)
- `server/src/middleware/ja4.js`
- `server/src/services/fingerprint.js`
- `server/src/db.js` (update: rename column)
- `server/src/index.js` (update: mount ja4 middleware)

**Out of scope:** terminal APIs, guard middleware, admin, UI updates.

**Done criteria:** `req.ja4` populated. `fuzzyMatchBrowserFP()` returns sensible scores. HMAC validation works. DB column renamed.

Siga as convenções do repositório.

---

@specs/steps/terminal-auth-poc-step-5.md
@specs/terminal-auth-poc.md

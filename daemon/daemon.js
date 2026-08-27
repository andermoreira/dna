/**
 * POCDNA Local Daemon — Layer 2 of Terminal Authentication
 *
 * This daemon mirrors the Warsaw/G-Buster architecture: a privileged process
 * running outside the browser that collects real OS-level data the browser
 * JavaScript cannot access.
 *
 * What it does:
 *   1. Generates a 256-bit secret key on first startup (stored in ~/.pocdna)
 *   2. Collects 15 OS-level attributes (CPU, hostname, RAM, network, apps...)
 *   3. Signs the payload with HMAC-SHA256 using the secret key
 *   4. Serves the signed payload over HTTPS on localhost:30900
 *
 * The browser queries this daemon and forwards the signed payload to the
 * application server. The server validates the HMAC to prove the data
 * came from a real daemon on the actual machine — not forged by JavaScript.
 *
 * Security model:
 *   - Listens ONLY on 127.0.0.1 (not exposed to network)
 *   - Secret key stays on the daemon; during initial terminal registration the
 *     user pastes the base64 key into the app so the server can verify HMACs
 *   - Payload includes timestamp for replay protection (validated server-side)
 *   - TLS with self-signed cert prevents local MITM
 *
 * Comparison with Warsaw (production):
 *   Warsaw: C binary, runs as root, kernel driver (gbpkm.sys), CA injected
 *           into browser trust stores via certutil
 *   POCDNA: Node.js script, no kernel driver, manual cert trust acceptance,
 *           demonstrates the architecture without the hardening
 *
 * Usage:
 *   node daemon.js
 *   → Listens on https://127.0.0.1:30900
 *   → First run: generates secret key, prints base64 for registration
 */

import https from 'https';
import http from 'http';
import crypto from 'crypto';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

// ---------------------------------------------------------------------------
// Configuration
//
// State lives in ~/.pocdna (0700) rather than os.tmpdir(): /tmp is wiped on
// reboot (and periodically on macOS), which would silently invalidate the
// registered terminal by destroying its secret key.
// ---------------------------------------------------------------------------
const PORT = 30900;
const STATE_DIR = process.env.POCDNA_DIR || path.join(os.homedir(), '.pocdna');
fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });

const SECRET_KEY_PATH = process.env.SECRET_KEY_PATH || path.join(STATE_DIR, 'secret.key');
const CERT_PATH = process.env.CERT_PATH || path.join(STATE_DIR, 'cert.pem');
const KEY_PATH = process.env.KEY_PATH || path.join(STATE_DIR, 'key.pem');
const DEFAULT_ORIGINS = [
  'https://localhost:3000', 'https://127.0.0.1:3000',
  'http://localhost:3000', 'http://127.0.0.1:3000',
].join(',');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || DEFAULT_ORIGINS)
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

// ---------------------------------------------------------------------------
// Secret Key Management
//
// The secret key is the root of trust for Layer 2. It's a 256-bit random
// value generated once per daemon installation. The daemon uses it to sign
// every fingerprint payload with HMAC-SHA256.
//
// Production would store this in a TPM/HSM. POC stores it in ~/.pocdna with
// file permissions 0600 (owner read/write only).
// ---------------------------------------------------------------------------

/**
 * Loads the existing secret key or generates a new one on first startup.
 *
 * The base64-encoded key is printed on first startup so the user can
 * copy it and paste it into the terminal registration form.
 *
 * @returns {Buffer} 32-byte secret key
 */
function loadOrCreateSecret() {
  if (fs.existsSync(SECRET_KEY_PATH)) {
    const key = fs.readFileSync(SECRET_KEY_PATH);
    console.log('[daemon] secret key loaded');
    return key;
  }

  // Generate 256 bits of cryptographically secure randomness
  const key = crypto.randomBytes(32);

  // Store with restrictive permissions (owner rw only)
  fs.writeFileSync(SECRET_KEY_PATH, key, { mode: 0o600 });

  console.log('[daemon] new secret key generated');
  // Print the base64-encoded key — user copies this for terminal registration
  console.log(`[daemon] secret key (base64): ${key.toString('base64')}`);
  return key;
}

// ---------------------------------------------------------------------------
// TLS Certificate Generation
//
// Strategy (ordered by preference):
//   1. mkcert — generates locally-trusted certificate, zero browser warnings.
//      mkcert creates a local CA, installs it in the OS/browser trust store
//      (macOS Keychain, Linux NSS, Windows Trust Store), then issues a valid
//      cert for 127.0.0.1 that all browsers accept automatically. This mirrors
//      Warsaw's certutil approach but uses the standard mkcert tool.
//      Install: brew install mkcert && mkcert -install
//   2. openssl — self-signed cert. Works everywhere but browser shows a
//      warning (user must click "Advanced → Proceed").
//   3. HTTP fallback — no TLS. Only on loopback, still safe from network
//      attackers but browser may block mixed-content requests from HTTPS pages.
//
// Warsaw injects the CA cert into browser trust stores via certutil.
// mkcert achieves the same result through the OS trust store API.
// ---------------------------------------------------------------------------

/**
 * Validates that cert and key PEM files form a usable TLS pair.
 */
function validateCertKeyPair(cert, key) {
  crypto.createPrivateKey(key);
  new crypto.X509Certificate(cert);
}

/**
 * Generates or loads a TLS certificate for the HTTPS server.
 *
 * Tries mkcert → openssl → HTTP. Reuses existing valid certificates.
 *
 * @returns {{ cert?: Buffer, key?: Buffer, tls: boolean, method: string }}
 */
function generateTls() {
  // Reuse existing certificate if present and valid
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    try {
      const cert = fs.readFileSync(CERT_PATH);
      const key = fs.readFileSync(KEY_PATH);
      validateCertKeyPair(cert, key);
      return { cert, key, tls: true, method: 'reused' };
    } catch {
      fs.unlinkSync(CERT_PATH);
      fs.unlinkSync(KEY_PATH);
    }
  }

  // Tier 1: mkcert — locally-trusted certificate, zero browser warnings
  try {
    execSync('mkcert --version', { stdio: 'ignore', timeout: 3000 });
    execSync(
      `mkcert -cert-file "${CERT_PATH}" -key-file "${KEY_PATH}" 127.0.0.1 localhost ::1`,
      { timeout: 10000 }
    );
    const cert = fs.readFileSync(CERT_PATH);
    const key = fs.readFileSync(KEY_PATH);
    fs.chmodSync(KEY_PATH, 0o600);
    fs.chmodSync(CERT_PATH, 0o600);
    console.log('[daemon] TLS certificate generated via mkcert (locally trusted, no browser warnings)');
    return { cert, key, tls: true, method: 'mkcert' };
  } catch (e) {
    console.log(`[daemon] mkcert not available (${e.message.trim().split('\n')[0]}), trying openssl...`);
  }

  // Tier 2: openssl — self-signed cert (browser shows warning)
  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${KEY_PATH}" ` +
      `-out "${CERT_PATH}" -days 365 -nodes -subj "/CN=POCDNA Daemon" 2>/dev/null`,
      { timeout: 5000 }
    );
    const cert = fs.readFileSync(CERT_PATH);
    const key = fs.readFileSync(KEY_PATH);
    fs.chmodSync(KEY_PATH, 0o600);
    fs.chmodSync(CERT_PATH, 0o600);
    console.log('[daemon] TLS certificate generated via openssl (self-signed, browser will show warning)');
    return { cert, key, tls: true, method: 'openssl' };
  } catch (e) {
    console.log(`[daemon] openssl not available (${e.message.trim().split('\n')[0]}), falling back to HTTP`);
    return { tls: false, method: 'http' };
  }
}

// ---------------------------------------------------------------------------
// OS Data Collection (Layer 2)
//
// Collects 15 fields from the operating system that the browser cannot access.
// These are the "strong" signals that make browser spoofing ineffective.
// ---------------------------------------------------------------------------

/**
 * Sanitizes network interface data by hashing IP and MAC addresses.
 *
 * MAC addresses and Public/Private IPs are hashed with SHA-256 to avoid leaking
 * cleartext network identifiers in the payload while preserving entropy for fingerprinting.
 * Loopback addresses (127.0.0.1, ::1) are preserved as-is.
 *
 * @param {object} interfaces — os.networkInterfaces() output
 * @returns {object} sanitized interfaces
 */
function hashNetworkIPs(interfaces) {
  const sanitized = {};
  for (const [name, addrs] of Object.entries(interfaces)) {
    sanitized[name] = (addrs || []).map(addr => {
      const clean = { ...addr };
      // Hash non-loopback IPv4 and IPv6 addresses
      if (clean.address && !clean.address.includes('::1') && clean.address !== '127.0.0.1') {
        clean.address = crypto.createHash('sha256')
          .update(clean.address).digest('hex').substring(0, 16);
      }
      // Hash MAC addresses for privacy (LGPD/GDPR compliance)
      if (clean.mac && clean.mac !== '00:00:00:00:00:00') {
        clean.mac = crypto.createHash('sha256')
          .update(`mac:${clean.mac}`).digest('hex').substring(0, 16);
      }
      return clean;
    });
  }
  return sanitized;
}

/**
 * Lists installed applications from the OS.
 *
 * Platform-specific paths:
 *   macOS:    /Applications/*.app
 *   Linux:    /usr/share/applications/*.desktop
 *   Windows:  C:\Program Files\*
 *
 * Truncates to top 20 entries for payload size control.
 *
 * @returns {string[]} sorted list of installed application names
 */
function collectInstalledApps() {
  try {
    const platform = os.platform();

    if (platform === 'darwin') {
      const apps = fs.readdirSync('/Applications').filter(f => f.endsWith('.app'));
      return apps.sort().slice(0, 20);
    }

    if (platform === 'linux') {
      const appsDir = '/usr/share/applications';
      if (fs.existsSync(appsDir)) {
        return fs.readdirSync(appsDir)
          .filter(f => f.endsWith('.desktop'))
          .sort()
          .slice(0, 20);
      }
    }

    if (platform === 'win32') {
      const progDir = 'C:\\Program Files';
      if (fs.existsSync(progDir)) {
        return fs.readdirSync(progDir).sort().slice(0, 20);
      }
    }

    return [];
  } catch {
    return [];
  }
}

/**
 * Collects all OS-level fingerprint data.
 *
 * Each field contributes to the uniqueness of the terminal identity:
 *   hostname          — machine name
 *   platform/arch     — OS and CPU architecture
 *   cpus/cpuCores     — CPU model string and core count
 *   totalmem/freemem  — RAM (total and available)
 *   networkInterfaces — hashed MAC addresses + hashed IPs
 *   username/homedir  — current user identity
 *   uptime            — system uptime in seconds
 *   nodeVersion       — daemon runtime version
 *   installedApps     — top 20 installed applications
 *   timestamp         — Unix epoch ms (for replay protection)
 *   challenge         — optional verification nonce passed by the caller
 *
 * @param {string|null} [challenge] — optional single-use challenge nonce from the server
 * @returns {object} fingerprint payload
 */
function collectOSData(challenge = null) {
  const data = {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().map(c => c.model).join('|'),
    cpuCores: os.cpus().length,
    totalmem: os.totalmem(),
    freemem: os.freemem(),
    networkInterfaces: hashNetworkIPs(os.networkInterfaces()),
    username: os.userInfo().username,
    homedir: os.userInfo().homedir,
    uptime: Math.floor(os.uptime()),
    nodeVersion: process.version,
    installedApps: collectInstalledApps(),
    timestamp: Date.now(),
  };

  if (challenge && typeof challenge === 'string' && challenge.length <= 128) {
    data.challenge = challenge;
  }

  return data;
}

/**
 * Recursively sorts object keys for deterministic JSON serialization.
 *
 * This ensures that the same data always produces the same JSON string,
 * which is critical for consistent HMAC signature verification.
 *
 * @param {*} obj — any JSON-serializable value
 * @returns {*} value with all object keys sorted
 */
function sortKeys(obj) {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj === null || typeof obj !== 'object') return obj;
  const sorted = {};
  Object.keys(obj).sort().forEach(k => {
    sorted[k] = sortKeys(obj[k]);
  });
  return sorted;
}

// ---------------------------------------------------------------------------
// Server Setup
// ---------------------------------------------------------------------------

// Initialize cryptographic material
const secretKey = loadOrCreateSecret();
const tlsCfg = generateTls();

/**
 * HTTP request handler — serves /health and /fingerprint endpoints.
 *
 * CORS is restricted to an allowlist of application origins (default: localhost:3000).
 * Loopback binding alone does not prevent cross-origin reads from malicious pages.
 *
 * Endpoints:
 *   GET /health                  — health check, returns { status: "ok" }
 *   GET /fingerprint?challenge=x — collects OS data, signs with HMAC, returns { payload, signature }
 */
function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function handleRequest(req, res) {
  setCorsHeaders(req, res);

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, 'http://127.0.0.1');
  const pathname = parsedUrl.pathname;

  console.log(`[daemon] ${req.method} ${pathname} from ${req.socket.remoteAddress}`);

  // Health check endpoint — used by the dashboard to detect daemon availability
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  // Fingerprint endpoint — the core of Layer 2
  if (pathname === '/fingerprint') {
    const challenge = parsedUrl.searchParams.get('challenge');

    // Collect OS data, incorporating challenge if provided
    const payload = collectOSData(challenge);

    // Sort keys for deterministic serialization
    const sorted = sortKeys(payload);

    // Sign with HMAC-SHA256 using the daemon's secret key
    const signature = crypto.createHmac('sha256', secretKey)
      .update(JSON.stringify(sorted))
      .digest('hex');

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ payload: sorted, signature }));
    return;
  }

  // Unknown endpoint
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
}

/**
 * Creates the HTTP or HTTPS server depending on TLS availability.
 */
function createServer() {
  if (tlsCfg.tls) {
    return https.createServer(
      { cert: tlsCfg.cert, key: tlsCfg.key },
      handleRequest
    );
  }
  return http.createServer(handleRequest);
}

// Start the server — bind only to loopback (127.0.0.1)
const protocol = tlsCfg.tls ? 'https' : 'http';
const server = createServer();

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[daemon] listening on ${protocol}://127.0.0.1:${PORT} (${tlsCfg.method})`);
  if (tlsCfg.method === 'openssl') {
    console.log('[daemon] note: install mkcert (brew install mkcert && mkcert -install) to eliminate browser warnings');
  }
  if (!tlsCfg.tls) {
    console.log('[daemon] note: install mkcert or openssl for HTTPS support');
  }
});

// Graceful shutdown on SIGTERM (systemd stop) or SIGINT (Ctrl+C)
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('[daemon] shutting down');
  server.close(() => process.exit(0));
}

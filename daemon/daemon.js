/**
 * POCDNA Local Daemon — Layer 2 of Terminal Authentication
 *
 * This daemon mirrors the Warsaw/G-Buster architecture: a privileged process
 * running outside the browser that collects real OS-level data the browser
 * JavaScript cannot access.
 *
 * What it does:
 *   1. Generates a 256-bit secret key on first startup (stored in /tmp)
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
 *   - Secret key never leaves the machine (only the HMAC signature does)
 *   - Payload includes timestamp for replay protection
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
// ---------------------------------------------------------------------------
const PORT = 30900;
const SECRET_KEY_PATH = process.env.SECRET_KEY_PATH || path.join(os.tmpdir(), 'pocdna-secret.key');
const CERT_PATH = process.env.CERT_PATH || path.join(os.tmpdir(), 'pocdna-cert.pem');
const KEY_PATH = process.env.KEY_PATH || path.join(os.tmpdir(), 'pocdna-key.pem');

// ---------------------------------------------------------------------------
// Secret Key Management
//
// The secret key is the root of trust for Layer 2. It's a 256-bit random
// value generated once per daemon installation. The daemon uses it to sign
// every fingerprint payload with HMAC-SHA256.
//
// Production would store this in a TPM/HSM. POC stores it in /tmp with
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
// Uses openssl to generate a self-signed certificate valid for 365 days.
// If openssl is not available, falls back to plain HTTP (still secure on
// loopback, but browser will warn about mixed content).
//
// Warsaw injects the CA cert into browser trust stores via certutil.
// POCDNA requires the user to manually accept the browser warning.
// ---------------------------------------------------------------------------

/**
 * Generates or loads a self-signed TLS certificate for the HTTPS server.
 *
 * Tries openssl first (most systems have it). Falls back to HTTP-only
 * mode if openssl is unavailable.
 *
 * @returns {{ cert?: Buffer, key?: Buffer, tls: boolean }}
 */
function generateTls() {
  // Reuse existing certificate if present and valid
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    try {
      const cert = fs.readFileSync(CERT_PATH);
      const key = fs.readFileSync(KEY_PATH);
      // Quick validation: try creating a server with these certs
      https.createServer({ cert, key }, (_req, res) => {
        res.writeHead(200);
        res.end();
      }).listen(0, '127.0.0.1').close();
      return { cert, key, tls: true };
    } catch {
      // Certs exist but are invalid — clean up and regenerate
      fs.unlinkSync(CERT_PATH);
      fs.unlinkSync(KEY_PATH);
    }
  }

  // Generate new certificate pair using openssl
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
    console.log('[daemon] TLS certificate generated via openssl');
    return { cert, key, tls: true };
  } catch (e) {
    // Openssl not available — degrade to HTTP
    console.log(`[daemon] openssl not available (${e.message}), falling back to HTTP`);
    return { tls: false };
  }
}

// ---------------------------------------------------------------------------
// OS Data Collection (Layer 2)
//
// Collects 15 fields from the operating system that the browser cannot access.
// These are the "strong" signals that make browser spoofing ineffective.
// ---------------------------------------------------------------------------

/**
 * Sanitizes network interface data by hashing IP addresses.
 *
 * MAC addresses are preserved (useful for fingerprinting).
 * Public IPs are hashed to avoid leaking them in the fingerprint payload.
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
 *   networkInterfaces — MAC addresses + hashed IPs
 *   username/homedir  — current user identity
 *   uptime            — system uptime in seconds
 *   nodeVersion       — daemon runtime version
 *   installedApps     — top 20 installed applications
 *   timestamp         — Unix epoch ms (for replay protection)
 *
 * @returns {object} fingerprint payload
 */
function collectOSData() {
  return {
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
 * CORS headers are set to allow cross-origin requests from the browser
 * page (which may be served from a different port).
 *
 * Endpoints:
 *   GET /health      — health check, returns { status: "ok" }
 *   GET /fingerprint — collects OS data, signs with HMAC, returns { payload, signature }
 */
function handleRequest(req, res) {
  // Allow CORS from any origin (safe because we only listen on loopback)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  console.log(`[daemon] ${req.method} ${req.url} from ${req.socket.remoteAddress}`);

  // Health check endpoint — used by the dashboard to detect daemon availability
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  // Fingerprint endpoint — the core of Layer 2
  if (req.url === '/fingerprint') {
    // Collect OS data
    const payload = collectOSData();

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
  console.log(`[daemon] listening on ${protocol}://127.0.0.1:${PORT}`);
});

// Graceful shutdown on SIGTERM (systemd stop) or SIGINT (Ctrl+C)
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  console.log('[daemon] shutting down');
  server.close(() => process.exit(0));
}

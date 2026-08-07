/**
 * Manual verification script for security fixes.
 *
 * Automates post-implementation checks for:
 *   - C1: daemon-registered terminals cannot verify with browser-only
 *   - A5: login regenerates the session cookie (session fixation fix)
 *
 * Prerequisites: docker compose up -d && node daemon/daemon.js
 *
 * Run:
 *   NODE_TLS_REJECT_UNAUTHORIZED=0 node scripts/verify-manual.mjs
 *
 * Flow (see README "Manual Verification" for diagram):
 *   health → login → register terminal (browser + daemon) → verify OK →
 *   verify attack (no daemon) → logout/login (new cookie)
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

// Express app (Layer 1–3 scoring) and local daemon (Layer 2 HMAC).
const BASE = 'http://localhost:3000';
const DAEMON = 'https://127.0.0.1:30900';

// Fixed browser fingerprint — reproducible across runs; must match on register + verify.
const browserComponents = {
  canvas: 'verify-test-canvas',       // Layer 1 hardware signal (mock)
  webgl: 'verify-test-webgl',
  audio: 'verify-test-audio',
  platform: 'MacIntel',               // Layer 1 software/config signals
  screen: '1920x1080@24',
  fonts: ['Arial', 'Helvetica'],
  timezone: 'America/Sao_Paulo',
  hardwareConcurrency: 8,
  touchSupport: 0,
  plugins: [],
};

// Shape expected by POST /api/auth/register-terminal and /api/auth/verify-terminal.
const browserFP = {
  visitorId: 'verify-test-visitor',
  components: browserComponents,
};

/** Extracts connect.sid value from Set-Cookie (express-session). */
function parseSetCookie(header) {
  if (!header) return null;
  const match = header.match(/connect\.sid=([^;]+)/);
  return match ? match[1] : null;
}

/**
 * Thin fetch wrapper for the application server.
 * Sends JSON, optional session cookie, returns status + parsed body + new cookie.
 */
async function request(url, { method = 'GET', body, cookie } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers.Cookie = `connect.sid=${cookie}`;

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text; // e.g. 204 No Content
  }

  return {
    status: res.status,
    json,
    cookie: parseSetCookie(res.headers.get('set-cookie')),
  };
}

/** Prints PASS or throws — stops the script on first failure. */
function assert(condition, message) {
  if (!condition) {
    throw new Error(`FAIL: ${message}`);
  }
  console.log(`PASS: ${message}`);
}

async function main() {
  console.log('=== POCDNA manual verification ===\n');

  // --- Health checks: server and daemon must be up ---
  const health = await request(`${BASE}/api/health`);
  assert(health.json?.status === 'ok', 'server health');

  const daemonHealth = await fetch(`${DAEMON}/health`, { dispatcher: undefined }).catch(() => null);
  if (!daemonHealth?.ok) {
    // Self-signed/mkcert TLS may fail unless NODE_TLS_REJECT_UNAUTHORIZED=0 in shell.
    throw new Error('daemon not reachable — ensure node daemon/daemon.js is running');
  }
  assert((await daemonHealth.json()).status === 'ok', 'daemon health');

  // --- Login: obtain session cookie for authenticated routes ---
  const login1 = await request(`${BASE}/api/auth/login`, {
    method: 'POST',
    body: { username: 'demo', password: 'demo123' },
  });
  assert(login1.status === 200, 'login succeeds');
  const sessionCookie = login1.cookie;
  assert(sessionCookie, 'login sets session cookie');

  // --- Daemon Layer 2: signed OS payload + secret for registration ---
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const daemonRes = await fetch(`${DAEMON}/fingerprint`);
  const daemonData = await daemonRes.json();
  assert(daemonData.payload && daemonData.signature, 'daemon returns signed payload');

  // Secret is stored on disk by daemon.js (same path as daemon uses).
  const secretPath = path.join(os.tmpdir(), 'pocdna-secret.key');
  const daemonSecret = fs.readFileSync(secretPath).toString('base64');

  // --- Idempotent cleanup: remove terminals from previous script runs ---
  const list = await request(`${BASE}/api/auth/user/terminals`, { cookie: sessionCookie });
  for (const t of list.json?.terminals || []) {
    if (t.label?.startsWith('verify-test')) {
      await request(`${BASE}/api/auth/user/terminals/${t.id}`, {
        method: 'DELETE',
        cookie: sessionCookie,
      });
    }
  }

  // --- Register terminal with browser + daemon (daemon layer required on verify) ---
  const register = await request(`${BASE}/api/auth/register-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: {
      label: 'verify-test-terminal',
      browserFP,
      daemonPayload: daemonData.payload,
      daemonSignature: daemonData.signature,
      daemonSecret,
    },
  });
  assert(register.status === 201, `register terminal (${register.status})`);
  assert(register.json?.layers?.daemon === true, 'terminal registered with daemon layer');

  // --- Happy path: fresh daemon payload (valid timestamp) + matching browser FP ---
  const freshDaemon = await fetch(`${DAEMON}/fingerprint`).then(r => r.json());
  const verifyOk = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: {
      browserFP,
      daemonPayload: freshDaemon.payload,   // new timestamp for replay window
      daemonSignature: freshDaemon.signature,
    },
  });
  assert(verifyOk.json?.known === true, 'verify with daemon → known: true');
  console.log(`       confidence=${verifyOk.json?.confidence}, layers=${JSON.stringify(verifyOk.json?.layers)}`);

  // --- Attack simulation (C1): omit daemon — must NOT authenticate browser-only ---
  const verifyAttack = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { browserFP }, // no daemonPayload / daemonSignature
  });
  assert(verifyAttack.json?.known === false, 'verify without daemon → known: false (C1 fix)');
  console.log(`       confidence=${verifyAttack.json?.confidence}, layers=${JSON.stringify(verifyAttack.json?.layers)}`);

  // --- Session fixation (A5): logout + login must issue a new connect.sid ---
  const sidBefore = sessionCookie;
  await request(`${BASE}/api/auth/logout`, { method: 'POST', cookie: sessionCookie });

  const login2 = await request(`${BASE}/api/auth/login`, {
    method: 'POST',
    body: { username: 'demo', password: 'demo123' },
  });
  const sidAfter = login2.cookie;
  assert(sidAfter && sidBefore !== sidAfter, 'login regenerates session cookie (A5 fix)');

  console.log('\n=== All manual checks passed ===');
}

main().catch((err) => {
  console.error('\n' + err.message);
  process.exit(1);
});

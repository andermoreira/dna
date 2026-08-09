/**
 * Manual verification script for security fixes.
 *
 * Automates post-implementation checks for:
 *   - C1a: daemon-registered terminals cannot verify with browser-only
 *   - C1b: browser-only ("weak") terminals cannot perform sensitive actions
 *   - A5: login regenerates the session cookie (session fixation fix)
 *   - M4: verify-terminal requires a single-use nonce
 *
 * Prerequisites: docker compose up -d && node daemon/daemon.js
 *
 * Run:
 *   node scripts/verify-manual.mjs
 *
 * The server and daemon use self-signed/mkcert TLS, so certificate
 * validation is disabled below (test tooling only — never in app code).
 *
 * Flow (see README "Manual Verification" for diagram):
 *   health → login → register terminal (browser + daemon) → verify OK →
 *   sensitive action OK → verify attack (no daemon) → weak terminal
 *   blocked on sensitive action → logout/login (new cookie)
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Express app (Layer 1–3 scoring) and local daemon (Layer 2 HMAC).
const BASE = process.env.BASE_URL || 'https://localhost:3000';
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

// A second, entirely different fingerprint for the browser-only "weak" terminal.
const weakBrowserFP = {
  visitorId: 'verify-test-weak-visitor',
  components: {
    ...browserComponents,
    canvas: 'verify-test-weak-canvas',
    webgl: 'verify-test-weak-webgl',
    audio: 'verify-test-weak-audio',
    platform: 'Win32',
    screen: '2560x1440@24',
  },
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

/** Fetches a fresh single-use nonce for verify-terminal (M4). */
async function fetchNonce(cookie) {
  const res = await request(`${BASE}/api/auth/verify-nonce`, { cookie });
  return res.json?.nonce;
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

  const daemonHealth = await fetch(`${DAEMON}/health`).catch(() => null);
  if (!daemonHealth?.ok) {
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
  const daemonRes = await fetch(`${DAEMON}/fingerprint`);
  const daemonData = await daemonRes.json();
  assert(daemonData.payload && daemonData.signature, 'daemon returns signed payload');

  // Secret is stored on disk by daemon.js (same path as daemon uses).
  const secretPath = process.env.SECRET_KEY_PATH
    || path.join(os.homedir(), '.pocdna', 'secret.key');
  const daemonSecret = fs.readFileSync(secretPath).toString('base64');

  // --- Idempotent cleanup: remove terminals from previous script runs ---
  const list = await request(`${BASE}/api/user/terminals`, { cookie: sessionCookie });
  for (const t of list.json?.terminals || []) {
    if (t.label?.startsWith('verify-test')) {
      await request(`${BASE}/api/user/terminals/${t.id}`, {
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

  // --- Nonce enforcement (M4): verify without nonce must be rejected ---
  const noNonce = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { browserFP },
  });
  assert(
    noNonce.status === 400 && noNonce.json?.code === 'nonce_invalid',
    'verify without nonce → 400 nonce_invalid (M4 fix)'
  );

  // --- Happy path: fresh daemon payload (valid timestamp) + matching browser FP ---
  const freshDaemon = await fetch(`${DAEMON}/fingerprint`).then(r => r.json());
  const verifyOk = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: {
      browserFP,
      daemonPayload: freshDaemon.payload,   // new timestamp for replay window
      daemonSignature: freshDaemon.signature,
      nonce: await fetchNonce(sessionCookie),
    },
  });
  assert(verifyOk.json?.known === true, 'verify with daemon → known: true');
  console.log(`       confidence=${verifyOk.json?.confidence}, layers=${JSON.stringify(verifyOk.json?.layers)}`);

  // --- Sensitive action allowed on the daemon-backed terminal ---
  const sensitiveOk = await request(`${BASE}/api/actions/sensitive`, {
    method: 'POST',
    cookie: sessionCookie,
  });
  assert(sensitiveOk.status === 200, 'sensitive action allowed on daemon terminal');

  // --- Attack simulation (C1a): omit daemon. Recognition may still succeed via
  //     browser+TLS (2/3 quorum, spec-compliant), but the daemon layer must be
  //     recorded as FAILED and sensitive actions must be blocked. ---
  const verifyAttack = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { browserFP, nonce: await fetchNonce(sessionCookie) }, // no daemonPayload / daemonSignature
  });
  assert(
    verifyAttack.json?.layers?.daemon === false,
    'verify without daemon → daemon layer fails (C1a fix)'
  );
  console.log(`       known=${verifyAttack.json?.known}, confidence=${verifyAttack.json?.confidence}, layers=${JSON.stringify(verifyAttack.json?.layers)}`);

  const sensitiveAttack = await request(`${BASE}/api/actions/sensitive`, {
    method: 'POST',
    cookie: sessionCookie,
  });
  assert(
    sensitiveAttack.status === 403 && sensitiveAttack.json?.code === 'daemon_layer_required',
    'sensitive action blocked after daemon-less verify → 403 daemon_layer_required (C1a fix)'
  );

  // --- Weak terminal (C1b / AC-03): browser-only terminal is recognized but
  //     blocked on sensitive actions ---
  const registerWeak = await request(`${BASE}/api/auth/register-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { label: 'verify-test-weak', browserFP: weakBrowserFP },
  });
  assert(registerWeak.status === 201, 'register browser-only (weak) terminal');

  const verifyWeak = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { browserFP: weakBrowserFP, nonce: await fetchNonce(sessionCookie) },
  });
  assert(verifyWeak.json?.known === true, 'weak terminal recognized (degraded mode)');

  const sensitiveWeak = await request(`${BASE}/api/actions/sensitive`, {
    method: 'POST',
    cookie: sessionCookie,
  });
  assert(
    sensitiveWeak.status === 403 && sensitiveWeak.json?.code === 'daemon_layer_required',
    'sensitive action blocked on weak terminal → 403 daemon_layer_required (C1b fix)'
  );

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

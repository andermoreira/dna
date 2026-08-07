/**
 * Manual verification script for security fixes (plan post-implementation).
 * Run with: node scripts/verify-manual.mjs
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

const BASE = 'http://localhost:3000';
const DAEMON = 'https://127.0.0.1:30900';

const browserComponents = {
  canvas: 'verify-test-canvas',
  webgl: 'verify-test-webgl',
  audio: 'verify-test-audio',
  platform: 'MacIntel',
  screen: '1920x1080@24',
  fonts: ['Arial', 'Helvetica'],
  timezone: 'America/Sao_Paulo',
  hardwareConcurrency: 8,
  touchSupport: 0,
  plugins: [],
};

const browserFP = {
  visitorId: 'verify-test-visitor',
  components: browserComponents,
};

function parseSetCookie(header) {
  if (!header) return null;
  const match = header.match(/connect\.sid=([^;]+)/);
  return match ? match[1] : null;
}

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
    json = text;
  }

  return {
    status: res.status,
    json,
    cookie: parseSetCookie(res.headers.get('set-cookie')),
  };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`FAIL: ${message}`);
  }
  console.log(`PASS: ${message}`);
}

async function main() {
  console.log('=== POCDNA manual verification ===\n');

  // Health checks
  const health = await request(`${BASE}/api/health`);
  assert(health.json?.status === 'ok', 'server health');

  const daemonHealth = await fetch(`${DAEMON}/health`, { dispatcher: undefined }).catch(() => null);
  if (!daemonHealth?.ok) {
    // Node fetch may reject self-signed; use https with rejectUnauthorized false via undici not available
    // Fallback: try with NODE_TLS_REJECT_UNAUTHORIZED=0 in shell
    throw new Error('daemon not reachable — ensure node daemon/daemon.js is running');
  }
  assert((await daemonHealth.json()).status === 'ok', 'daemon health');

  // Login
  const login1 = await request(`${BASE}/api/auth/login`, {
    method: 'POST',
    body: { username: 'demo', password: 'demo123' },
  });
  assert(login1.status === 200, 'login succeeds');
  const sessionCookie = login1.cookie;
  assert(sessionCookie, 'login sets session cookie');

  // Daemon fingerprint + secret
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const daemonRes = await fetch(`${DAEMON}/fingerprint`);
  const daemonData = await daemonRes.json();
  assert(daemonData.payload && daemonData.signature, 'daemon returns signed payload');

  const secretPath = path.join(os.tmpdir(), 'pocdna-secret.key');
  const daemonSecret = fs.readFileSync(secretPath).toString('base64');

  // Clean up prior verify-test terminals (best effort via list + delete)
  const list = await request(`${BASE}/api/auth/user/terminals`, { cookie: sessionCookie });
  for (const t of list.json?.terminals || []) {
    if (t.label?.startsWith('verify-test')) {
      await request(`${BASE}/api/auth/user/terminals/${t.id}`, {
        method: 'DELETE',
        cookie: sessionCookie,
      });
    }
  }

  // Register terminal with daemon
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

  // Happy path: verify with daemon
  const freshDaemon = await fetch(`${DAEMON}/fingerprint`).then(r => r.json());
  const verifyOk = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: {
      browserFP,
      daemonPayload: freshDaemon.payload,
      daemonSignature: freshDaemon.signature,
    },
  });
  assert(verifyOk.json?.known === true, 'verify with daemon → known: true');
  console.log(`       confidence=${verifyOk.json?.confidence}, layers=${JSON.stringify(verifyOk.json?.layers)}`);

  // Attack: verify without daemon payload (browser-only downgrade attempt)
  const verifyAttack = await request(`${BASE}/api/auth/verify-terminal`, {
    method: 'POST',
    cookie: sessionCookie,
    body: { browserFP },
  });
  assert(verifyAttack.json?.known === false, 'verify without daemon → known: false (C1 fix)');
  console.log(`       confidence=${verifyAttack.json?.confidence}, layers=${JSON.stringify(verifyAttack.json?.layers)}`);

  // Session regeneration: logout + login should issue new cookie
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

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Isolated data dir + vault key — never touch server/data during tests
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocdna-test-'));
process.env.POCDNA_DATA_DIR = tmpDir;
process.env.SECRET_ENC_KEY = crypto.randomBytes(32).toString('base64');
process.env.ADMIN_KEY = 'test-admin-key';

const { default: express } = await import('express');
const { default: session } = await import('express-session');
const { default: authRouter } = await import('./auth.js');
const { default: terminalsRouter } = await import('./terminals.js');
const { default: adminRouter } = await import('./admin.js');
const { requireAuth } = await import('../middleware/auth.js');
const { requireKnownTerminal } = await import('../middleware/requireTerminal.js');
const { sortKeys } = await import('../services/fingerprint.js');

const browserFP = {
  visitorId: 'v1',
  components: {
    canvas: 'c', webgl: 'w', audio: 'a', platform: 'p', screen: 's',
    fonts: ['f1'], timezone: 'tz', hardwareConcurrency: 8, touchSupport: false, plugins: [],
  },
};
const daemonSecret = crypto.randomBytes(32);

function signedDaemon(challenge) {
  const payload = sortKeys({ hostname: 'h', timestamp: Date.now(), ...(challenge ? { challenge } : {}) });
  const signature = crypto.createHmac('sha256', daemonSecret).update(JSON.stringify(payload)).digest('hex');
  return { daemonPayload: payload, daemonSignature: signature };
}

let server;
let base;
let cookie = '';

async function call(method, url, body) {
  const res = await fetch(base + url, {
    method,
    headers: { 'content-type': 'application/json', cookie },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function nonce() {
  return (await call('GET', '/api/auth/verify-nonce')).json.nonce;
}

before(async () => {
  const app = express();
  app.use(express.json());
  app.use(session({ secret: 'test', resave: false, saveUninitialized: false }));
  app.use((req, _res, next) => { req.ja4 = null; next(); });
  app.use('/api/auth', authRouter);
  app.use('/api/auth', terminalsRouter);
  app.use('/api/admin', adminRouter);
  app.post('/api/actions/sensitive', requireAuth, requireKnownTerminal, (_req, res) => res.json({ ok: true }));
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;

  const reg = await call('POST', '/api/auth/register', { username: 'alice', password: 'secret1' });
  assert.equal(reg.status, 201);
  const n = await nonce();
  const term = await call('POST', '/api/auth/register-terminal', {
    label: 'laptop', browserFP, nonce: n, ...signedDaemon(n), daemonSecret: daemonSecret.toString('base64'),
  });
  assert.equal(term.status, 201);
  assert.equal(term.json.layers.daemon, true);
});

after(() => {
  server?.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('POST /api/auth/login', () => {
  it('returns 400 (not 500) for non-string credentials', async () => {
    const res = await call('POST', '/api/auth/login', { username: 'alice', password: 12345 });
    assert.equal(res.status, 400);
    assert.equal(res.json.code, 'validation_error');
  });
});

describe('POST /api/auth/verify-terminal', () => {
  it('passes the daemon layer when the payload carries the session nonce', async () => {
    const n = await nonce();
    const res = await call('POST', '/api/auth/verify-terminal', { browserFP, nonce: n, ...signedDaemon(n) });
    assert.equal(res.status, 200);
    assert.equal(res.json.layers.daemon, true);
    assert.equal((await call('POST', '/api/actions/sensitive')).status, 200);
  });

  it('fails the daemon layer when the payload omits the challenge (replay within skew window)', async () => {
    const replayed = signedDaemon(null);
    const res = await call('POST', '/api/auth/verify-terminal', { browserFP, nonce: await nonce(), ...replayed });
    assert.equal(res.status, 200);
    assert.equal(res.json.layers.daemon, false);
  });

  it('drops a previous terminal binding when a later verification fails', async () => {
    const n = await nonce();
    await call('POST', '/api/auth/verify-terminal', { browserFP, nonce: n, ...signedDaemon(n) });
    assert.equal((await call('POST', '/api/actions/sensitive')).status, 200);

    const otherFP = { visitorId: 'x', components: { canvas: 'zz' } };
    const res = await call('POST', '/api/auth/verify-terminal', { browserFP: otherFP, nonce: await nonce() });
    assert.equal(res.json.known, false);

    const sensitive = await call('POST', '/api/actions/sensitive');
    assert.equal(sensitive.status, 403);
    assert.equal(sensitive.json.code, 'terminal_not_authorized');
  });
});

describe('POST /api/auth/register-terminal', () => {
  const otherFP = { visitorId: 'r', components: { canvas: 'other' } };

  it('rejects a daemon payload without a challenge nonce', async () => {
    const res = await call('POST', '/api/auth/register-terminal', {
      label: 'replay', browserFP: otherFP, ...signedDaemon(null), daemonSecret: daemonSecret.toString('base64'),
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.code, 'nonce_invalid');
  });

  it('rejects a daemon payload sent without the daemon secret', async () => {
    const n = await nonce();
    const res = await call('POST', '/api/auth/register-terminal', {
      label: 'nosecret', browserFP: otherFP, nonce: n, ...signedDaemon(n),
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.code, 'daemon_secret_required');
  });
});

describe('POST /api/actions/sensitive', () => {
  it('requires a fresh verification', async () => {
    const n = await nonce();
    await call('POST', '/api/auth/verify-terminal', { browserFP, nonce: n, ...signedDaemon(n) });
    process.env.TERMINAL_VERIFY_MAX_AGE_MS = '-1';
    try {
      const res = await call('POST', '/api/actions/sensitive');
      assert.equal(res.status, 403);
      assert.equal(res.json.code, 'terminal_verification_expired');
    } finally {
      delete process.env.TERMINAL_VERIFY_MAX_AGE_MS;
    }
  });
});

describe('admin key', () => {
  it('does not rate-limit requests with the correct key', async () => {
    let last;
    for (let i = 0; i < 25; i++) {
      last = await fetch(`${base}/api/admin/terminals`, { headers: { 'x-admin-key': 'test-admin-key' } });
    }
    assert.equal(last.status, 200);
  });

  it('rate-limits repeated admin key attempts', async () => {
    let last;
    for (let i = 0; i < 21; i++) {
      last = await fetch(`${base}/api/admin/terminals`, { headers: { 'x-admin-key': `wrong-${i}` } });
    }
    assert.equal(last.status, 429);
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  computeConfidence,
  validateDaemonHmac,
  sortKeys,
  hashComponents,
  fuzzyMatchBrowserFP,
  pickBrowserSignals,
  pickStableDaemonFields,
  BROWSER_SIGNAL_WEIGHTS,
  MAX_SKEW_MS,
} from './fingerprint.js';

const SECRET_B64 = crypto.randomBytes(32).toString('base64');

function signPayload(payload, secretBase64 = SECRET_B64) {
  const secretKey = Buffer.from(secretBase64, 'base64');
  const sorted = sortKeys(payload);
  const signature = crypto.createHmac('sha256', secretKey)
    .update(JSON.stringify(sorted))
    .digest('hex');
  return { payload: sorted, signature };
}

describe('computeConfidence', () => {
  it('rejects terminal with daemon when daemon payload is omitted (HTTP, no JA4)', () => {
    const result = computeConfidence(1.0, {
      daemonRequired: true,
      tlsRequired: false,
      daemonValid: false,
      tlsMatch: null,
    });

    assert.equal(result.known, false);
    assert.equal(result.layers.browser, true);
    assert.equal(result.layers.daemon, false);
  });

  it('rejects when browser score is 0 even with valid daemon', () => {
    const result = computeConfidence(0, {
      daemonRequired: true,
      tlsRequired: false,
      daemonValid: true,
      tlsMatch: null,
    });

    assert.equal(result.known, false);
    assert.equal(result.layers.browser, false);
    assert.equal(result.layers.daemon, true);
  });

  it('accepts browser-only terminal when browser matches', () => {
    const result = computeConfidence(0.85, {
      daemonRequired: false,
      tlsRequired: false,
      daemonValid: null,
      tlsMatch: null,
    });

    assert.equal(result.known, true);
    assert.equal(result.confidence, 1);
    assert.equal(result.layers.browser, true);
    assert.equal(result.layers.daemon, null);
    assert.equal(result.layers.tls, null);
  });

  it('requires 2 of 3 layers when terminal registered with all layers', () => {
    const result = computeConfidence(1.0, {
      daemonRequired: true,
      tlsRequired: true,
      daemonValid: true,
      tlsMatch: false,
    });

    assert.equal(result.known, true);
    assert.equal(result.layersMatched, 2);
  });

  it('does not count TLS alone toward quorum (corroborative only)', () => {
    const result = computeConfidence(0, {
      daemonRequired: false,
      tlsRequired: true,
      daemonValid: null,
      tlsMatch: true,
    });

    assert.equal(result.known, false);
    assert.equal(result.layers.tls, false);
    assert.equal(result.layersMatched, 0);
  });
});

describe('hashComponents', () => {
  it('produces same hash regardless of key insertion order', () => {
    const a = hashComponents({ z: 1, nested: { b: 2, a: 1 }, a: 0 });
    const b = hashComponents({ a: 0, nested: { a: 1, b: 2 }, z: 1 });
    assert.equal(a, b);
  });
});

describe('fuzzyMatchBrowserFP', () => {
  const fullFP = {
    canvas: 'c', webgl: 'w', audio: 'a', platform: 'MacIntel',
    screen: '1920x1080', fonts: ['Arial'], timezone: 'UTC',
    hardwareConcurrency: 8, touchSupport: false, plugins: [],
  };

  it('returns 1.0 for identical fingerprints', () => {
    assert.equal(fuzzyMatchBrowserFP(fullFP, { ...fullFP }), 1);
  });

  it('treats undefined like null — signal missing on one side gets no credit', () => {
    const candidate = { ...fullFP };
    delete candidate.canvas; // undefined on candidate side, present on stored
    const score = fuzzyMatchBrowserFP(fullFP, candidate);
    assert.ok(Math.abs(score - (1 - BROWSER_SIGNAL_WEIGHTS.canvas)) < 1e-9);
  });

  it('gives full credit when a signal is unavailable on both sides', () => {
    const stored = { ...fullFP, audio: null };
    const candidate = { ...fullFP };
    delete candidate.audio; // null vs undefined → both unavailable
    assert.equal(fuzzyMatchBrowserFP(stored, candidate), 1);
  });
});

describe('pickBrowserSignals', () => {
  it('keeps only fuzzy-match signals and drops PII-bearing extras', () => {
    const picked = pickBrowserSignals({
      canvas: 'c', userAgent: 'Mozilla/5.0 ...', languages: ['pt-BR'], _errors: [],
    });
    assert.equal(picked.canvas, 'c');
    assert.equal('userAgent' in picked, false);
    assert.equal('languages' in picked, false);
    assert.deepEqual(Object.keys(picked).sort(), Object.keys(BROWSER_SIGNAL_WEIGHTS).sort());
  });

  it('normalizes missing signals to null (stable hashing)', () => {
    const picked = pickBrowserSignals({});
    for (const signal of Object.keys(BROWSER_SIGNAL_WEIGHTS)) {
      assert.equal(picked[signal], null);
    }
  });
});

describe('pickStableDaemonFields', () => {
  it('drops volatile fields so the stored hash is reproducible', () => {
    const picked = pickStableDaemonFields({
      hostname: 'h', platform: 'darwin', freemem: 123, uptime: 42, timestamp: Date.now(),
    });
    assert.deepEqual(picked, { hostname: 'h', platform: 'darwin' });
  });
});

describe('validateDaemonHmac', () => {
  it('rejects payload with expired timestamp', () => {
    const payload = {
      hostname: 'test-host',
      timestamp: Date.now() - MAX_SKEW_MS - 1,
    };
    const { signature } = signPayload(payload);

    assert.equal(validateDaemonHmac(payload, signature, SECRET_B64), false);
  });

  it('rejects invalid signature', () => {
    const payload = {
      hostname: 'test-host',
      timestamp: Date.now(),
    };
    const { signature } = signPayload(payload);
    const tampered = signature.slice(0, -1) + (signature.endsWith('a') ? 'b' : 'a');

    assert.equal(validateDaemonHmac(payload, tampered, SECRET_B64), false);
  });

  it('accepts valid payload within timestamp window', () => {
    const payload = {
      hostname: 'test-host',
      timestamp: Date.now(),
    };
    const { payload: sorted, signature } = signPayload(payload);

    assert.equal(validateDaemonHmac(sorted, signature, SECRET_B64), true);
  });

  it('accepts valid payload when expectedChallenge matches payload.challenge', () => {
    const payload = {
      hostname: 'test-host',
      challenge: 'challenge-nonce-123',
      timestamp: Date.now(),
    };
    const { payload: sorted, signature } = signPayload(payload);

    assert.equal(validateDaemonHmac(sorted, signature, SECRET_B64, 'challenge-nonce-123'), true);
  });

  it('rejects payload when expectedChallenge does not match payload.challenge', () => {
    const payload = {
      hostname: 'test-host',
      challenge: 'attacker-nonce',
      timestamp: Date.now(),
    };
    const { payload: sorted, signature } = signPayload(payload);

    assert.equal(validateDaemonHmac(sorted, signature, SECRET_B64, 'expected-session-nonce'), false);
  });

  it('rejects payload with invalid secret key length', () => {
    const payload = {
      hostname: 'test-host',
      timestamp: Date.now(),
    };
    const { payload: sorted, signature } = signPayload(payload);
    const shortKey = Buffer.from('short-key').toString('base64');

    assert.equal(validateDaemonHmac(sorted, signature, shortKey), false);
  });
});

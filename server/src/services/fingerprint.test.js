import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  computeConfidence,
  validateDaemonHmac,
  sortKeys,
  hashComponents,
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
});

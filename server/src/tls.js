/**
 * Server TLS certificate management.
 *
 * The app must terminate TLS directly for the JA4 layer (Layer 3) to work:
 * read-tls-client-hello parses the ClientHello on the raw socket of the
 * HTTPS server. A self-signed certificate is generated with openssl on first
 * startup and reused afterwards (browser shows a warning — POC limitation).
 *
 * Env overrides: TLS_CERT_PATH / TLS_KEY_PATH point to an existing pair
 * (e.g. one generated with mkcert on the host).
 *
 * Returns null when no certificate can be loaded or generated — the caller
 * falls back to plain HTTP and the JA4 layer is disabled.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

function validateCertKeyPair(cert, key) {
  crypto.createPrivateKey(key);
  new crypto.X509Certificate(cert);
}

/**
 * Loads an existing TLS cert/key pair or generates a self-signed one.
 *
 * @param {string} dataDir — directory for the generated pair
 * @returns {{ cert: Buffer, key: Buffer } | null}
 */
export function loadOrCreateTlsCert(dataDir) {
  const certPath = process.env.TLS_CERT_PATH || path.join(dataDir, 'server-cert.pem');
  const keyPath = process.env.TLS_KEY_PATH || path.join(dataDir, 'server-key.pem');

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const cert = fs.readFileSync(certPath);
      const key = fs.readFileSync(keyPath);
      validateCertKeyPair(cert, key);
      return { cert, key };
    } catch (err) {
      console.log(`[server] existing TLS cert invalid (${err.message}), regenerating`);
    }
  }

  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" ` +
      `-out "${certPath}" -days 365 -nodes -subj "/CN=POCDNA Server" ` +
      '-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null',
      { timeout: 10_000 }
    );
    fs.chmodSync(keyPath, 0o600);
    const cert = fs.readFileSync(certPath);
    const key = fs.readFileSync(keyPath);
    return { cert, key };
  } catch (err) {
    console.log(`[server] could not generate TLS cert (${err.message.trim().split('\n')[0]})`);
    return null;
  }
}

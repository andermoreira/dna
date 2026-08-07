/**
 * Fingerprint Service — Hashing, Fuzzy Matching, HMAC Validation, Confidence Scoring
 *
 * This module implements the core logic for comparing terminal fingerprints
 * across all three layers.
 *
 * Functions:
 *   hashComponents(obj)         — Deterministic SHA-256 hash of a fingerprint
 *   fuzzyMatchBrowserFP(a, b)   — Weighted Jaccard similarity (0.0–1.0)
 *   validateDaemonHmac(p, s, k) — Validate HMAC-SHA256 signature
 *   computeConfidence(bw, dm, tl) — Multi-layer confidence scoring
 *
 * Layer 1 (Browser): weighted fuzzy match of 10 signals.
 *   Hardware-dependent signals (Canvas 25%, WebGL 20%, Audio 15%) receive
 *   higher weights because they're stable across browser upgrades and much
 *   harder to spoof than software signals.
 *
 *   Software signals (Plugins 1%) receive low weights because they change
 *   frequently and can be manipulated.
 *
 * Layer 2 (Daemon): binary pass/fail via HMAC validation.
 *   The daemon signs its OS-collected payload with HMAC-SHA256 using a
 *   256-bit secret key generated at install time. The browser never sees
 *   this key — it only forwards the signed payload.
 *
 * Layer 3 (TLS): exact string match of JA4 hash.
 *   The JA4 hash identifies the TLS implementation (browser family + OS).
 *   It's extracted server-side from the ClientHello packet and cannot be
 *   controlled by page JavaScript.
 */

import crypto from 'crypto';

/**
 * Generates a deterministic SHA-256 hash of a fingerprint object.
 *
 * Keys are sorted alphabetically before hashing to ensure deterministic
 * output regardless of property insertion order.
 *
 * Used for:
 *   - Primary key lookup (exact match check for duplicates)
 *   - Storing fingerprints in the database
 *
 * @param {Object} components — fingerprint components (any structure)
 * @returns {string} 64-character hex SHA-256 digest
 */
export function hashComponents(components) {
  // Sort keys for deterministic JSON output
  const ordered = {};
  Object.keys(components).sort().forEach(k => {
    ordered[k] = components[k];
  });
  const str = JSON.stringify(ordered);
  return crypto.createHash('sha256').update(str).digest('hex');
}

/**
 * Compares two browser fingerprint component sets using weighted Jaccard similarity.
 *
 * The weights reflect the stability and entropy of each signal:
 *
 *   Signal              Weight   Type        Stability   Spoof Resistance
 *   ─────────────────   ──────   ─────────   ─────────   ────────────────
 *   Canvas              0.25     Hardware    High        Medium (headless differs)
 *   WebGL                0.20     Hardware    High        Medium
 *   Audio                0.15     Hardware    High        Medium
 *   Platform             0.10     Software    Medium      Low (UA spoofing)
 *   Screen               0.10     Config      Medium      Low
 *   Fonts                0.08     Software    Medium      High (hard to fake complete set)
 *   Timezone             0.05     Config      High        Low
 *   HardwareConcurrency  0.04     Hardware    High        Low
 *   TouchSupport         0.02     Hardware    High        Low
 *   Plugins              0.01     Software    Low         Low (changes frequently)
 *
 * For scalar signals (Canvas, WebGL, etc.): exact match → full weight, else 0.
 * For list signals (Fonts, Plugins): Jaccard similarity × weight.
 *
 * @param {Object} stored    — fingerprint components from the database
 * @param {Object} candidate — fingerprint components just collected
 * @returns {number} 0.0 (completely different) to 1.0 (exact match)
 */
export function fuzzyMatchBrowserFP(stored, candidate) {
  // Signal weights — sum should equal 1.0
  const weights = {
    canvas: 0.25,
    webgl: 0.20,
    audio: 0.15,
    platform: 0.10,
    screen: 0.10,
    fonts: 0.08,
    timezone: 0.05,
    hardwareConcurrency: 0.04,
    touchSupport: 0.02,
    plugins: 0.01,
  };

  let score = 0;
  let totalWeight = 0;

  for (const [signal, weight] of Object.entries(weights)) {
    totalWeight += weight;

    const storedVal = stored[signal];
    const candVal = candidate[signal];

    // Both null → signal unavailable on both sides → full credit
    if (storedVal === null && candVal === null) {
      score += weight;
      continue;
    }

    // Only one side null → cannot compare → no credit
    if (storedVal === null || candVal === null) {
      continue;
    }

    // List signals: Jaccard similarity (intersection over union)
    if (signal === 'fonts' || signal === 'plugins') {
      const storedArr = Array.isArray(storedVal) ? storedVal : [];
      const candArr = Array.isArray(candVal) ? candVal : [];

      if (storedArr.length === 0 && candArr.length === 0) {
        score += weight;
        continue;
      }

      // Jaccard = |A ∩ B| / |A ∪ B|
      const intersection = storedArr.filter(f => candArr.includes(f)).length;
      const union = new Set([...storedArr, ...candArr]).size;
      const similarity = union > 0 ? intersection / union : 0;
      score += similarity * weight;
    } else {
      // Scalar signals: exact string comparison
      if (String(storedVal) === String(candVal)) {
        score += weight;
      }
    }
  }

  // Normalize to 0.0–1.0
  return totalWeight > 0 ? score / totalWeight : 0;
}

/**
 * Validates a daemon HMAC signature.
 *
 * The daemon signs its payload with: HMAC-SHA256(JSON.stringify(sortedPayload), secretKey)
 * The server recomputes and compares.
 *
 * This proves:
 *   1. The payload was generated by a daemon that knows the secret key
 *   2. The payload has not been tampered with in transit (via the browser)
 *
 * The secret key is base64-encoded (as printed by the daemon on startup).
 * The server stores this key during terminal registration and uses it
 * for all subsequent verification calls.
 *
 * @param {Object} payload         — daemon fingerprint payload
 * @param {string} signature       — hex-encoded HMAC-SHA256 signature
 * @param {string} secretKeyBase64 — base64-encoded 256-bit secret key
 * @returns {boolean} true if the signature is valid
 */
export function validateDaemonHmac(payload, signature, secretKeyBase64) {
  try {
    const secretKey = Buffer.from(secretKeyBase64, 'base64');
    const expected = crypto.createHmac('sha256', secretKey)
      .update(JSON.stringify(payload))
      .digest('hex');
    return expected === signature;
  } catch {
    return false;
  }
}

/**
 * Computes the overall terminal confidence score from the three layers.
 *
 * Decision logic:
 *   1. Count how many layers are available (non-null)
 *   2. Count how many layers pass
 *   3. Required matches = min(2, max(1, availableLayers))
 *      — If 1 layer available: need 1 match
 *      — If 2+ layers available: need 2 matches
 *   4. known = matched ≥ required
 *   5. confidence = matched / available
 *
 * This adapts gracefully when layers are missing:
 *   - Browser-only terminal (daemon=null, tls=null):
 *     available=1, required=1 → browser match gives known=true
 *   - Full terminal (daemon=true, tls=true):
 *     available=3, required=2 → need 2 of 3 to match
 *
 * @param {number} browserScore — 0.0–1.0 from fuzzyMatchBrowserFP
 * @param {boolean|null} daemonValid — true/false/null (null = not provided)
 * @param {boolean|null} tlsMatch — true/false/null (null = not available)
 * @returns {{ known: boolean, confidence: number, layersMatched: number, layers: object }}
 */
export function computeConfidence(browserScore, daemonValid, tlsMatch) {
  let layersMatched = 0;
  let layersAvailable = 0;
  const layers = {};

  // Layer 1: Browser fingerprint
  if (browserScore >= 0.7) {
    layersMatched++;
    layersAvailable++;
    layers.browser = true;
  } else if (browserScore > 0) {
    layersAvailable++;
    layers.browser = false;
  } else {
    layers.browser = null;
  }

  // Layer 2: Daemon HMAC
  if (daemonValid === true) {
    layersMatched++;
    layersAvailable++;
    layers.daemon = true;
  } else if (daemonValid === false) {
    layersAvailable++;
    layers.daemon = false;
  } else {
    layers.daemon = null;
  }

  // Layer 3: TLS fingerprint
  if (tlsMatch === true) {
    layersMatched++;
    layersAvailable++;
    layers.tls = true;
  } else if (tlsMatch === false) {
    layersAvailable++;
    layers.tls = false;
  } else {
    layers.tls = null;
  }

  // Adaptive threshold: require 2 matches, but not more than available layers
  const required = Math.min(2, Math.max(1, layersAvailable));
  const known = layersMatched >= required;
  const confidence = layersMatched / Math.max(1, layersAvailable);

  return { known, confidence, layersMatched, layers };
}

/**
 * Structured JSON logging to stdout (spec: Observability section).
 * Never log secrets, raw fingerprints or unmasked PII through this helper.
 */
export function logEvent(event, fields = {}) {
  console.log(JSON.stringify({ event, ts: new Date().toISOString(), ...fields }));
}

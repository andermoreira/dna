/**
 * Minimal fixed-window rate limiter (in-memory).
 *
 * Good enough for this single-process POC — avoids pulling a dependency for
 * two endpoints. Not suitable for multi-instance deployments (state is local).
 */

const MAX_TRACKED_KEYS = 10_000;

/**
 * @param {object} options
 * @param {number} options.windowMs — window size in milliseconds
 * @param {number} options.max — max requests per key per window
 * @param {(req: import('express').Request) => string} options.keyFn — request → bucket key
 */
export function rateLimit({ windowMs, max, keyFn }) {
  const buckets = new Map();

  // Active periodic cleanup of expired buckets every 2 minutes
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (now >= bucket.resetAt) {
        buckets.delete(key);
      }
    }
  }, 2 * 60 * 1000);

  // Unref timer so it does not keep Node.js process alive on shutdown/tests
  if (cleanupTimer && typeof cleanupTimer.unref === 'function') {
    cleanupTimer.unref();
  }

  return (req, res, next) => {
    const now = Date.now();

    // Secondary safety cleanup if limit is exceeded between intervals
    if (buckets.size > MAX_TRACKED_KEYS) {
      for (const [key, bucket] of buckets) {
        if (now >= bucket.resetAt) buckets.delete(key);
      }
    }

    const key = keyFn(req);
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }

    bucket.count++;
    if (bucket.count > max) {
      return res.status(429).json({
        code: 'rate_limited',
        message: 'Too many requests. Please try again later.',
      });
    }

    next();
  };
}

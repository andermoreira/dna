/**
 * Global error handling for Express.
 * Prevents stack traces from leaking in HTTP responses.
 */

/**
 * Wraps async route handlers so rejected promises reach the error middleware.
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Central error boundary — logs internally, returns safe JSON to clients.
 * Errors follow the { code, message } shape used by all route responses.
 */
export function errorHandler(err, _req, res, _next) {
  console.error('[server.error]', err);
  res.status(500).json({ code: 'internal_error', message: 'Internal server error' });
}

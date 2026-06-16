// SECURITY AUDIT FIX: Enhanced CSRF protection with stricter validation
// This middleware works alongside auth.js's HMAC token CSRF for defense-in-depth.
// - Origin/Referer validation catches cross-origin CSRF
// - auth.js HMAC tokens catch same-origin CSRF (form tokens)
module.exports = function(req, res, next) {
  // Only validate POST/PUT/PATCH/DELETE requests
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return next();
  }

  const origin = req.get('Origin');
  const referer = req.get('Referer');

  // Allowed origins (configured per deployment)
  const allowedOrigins = [
    'https://101.133.149.12',
    'https://hacker-lab.xyz'
  ];

  // Helper: check if origin/referer is allowed
  function isAllowed(originOrUrl) {
    if (!originOrUrl) return false;
    // Allow localhost for development
    if (originOrUrl.startsWith('http://127.0.0.1') || originOrUrl.startsWith('http://localhost')) {
      return true;
    }
    return allowedOrigins.includes(originOrUrl);
  }

  // If Origin header is present, validate it
  if (origin) {
    if (!isAllowed(origin)) {
      return res.status(403).json({ error: 'Cross-origin request rejected' });
    }
    return next();
  }

  // If no Origin, check Referer
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const originStr = refererUrl.origin;
      if (!isAllowed(originStr) &&
          !refererUrl.hostname.match(/^(127\.0\.0\.1|localhost)$/)) {
        return res.status(403).json({ error: 'Cross-origin request rejected' });
      }
    } catch (e) {
      return res.status(403).json({ error: 'Invalid referer' });
    }
    return next();
  }

  // No Origin AND no Referer: this is not a browser request (curl, Python, Postman, etc.)
  // Browsers always send at least one of these for cross-origin or same-origin POST.
  // Non-browser clients cannot be CSRF'd, so allow them through.
  // Defense-in-depth: the auth.js HMAC token provides additional protection for browser requests.
  next();
};

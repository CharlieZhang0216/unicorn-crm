// SECURITY AUDIT FIX: Enhanced security headers with CSP, Referrer-Policy, Permissions-Policy
module.exports = function(req, res, next) {
  // Remove potentially dangerous headers
  res.removeHeader('X-Debug-Mode');
  res.removeHeader('X-Server-Hostname');
  res.removeHeader('X-Backend-Server');
  res.removeHeader('X-Database-Host');
  res.removeHeader('X-Runtime-Version');
  res.removeHeader('X-OS-Platform');
  res.removeHeader('X-Process-PID');

  // Prevent MIME-type sniffing (defense-in-depth)
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // SECURITY AUDIT FIX: Basic Content-Security-Policy
  // Restricts resource loading to same-origin and trusted CDNs
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "img-src 'self' data:; " +
    "font-src 'self' https://cdn.jsdelivr.net; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "form-action 'self'"
  );

  // SECURITY AUDIT FIX: Referrer-Policy — only send referrer for same-origin
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // SECURITY AUDIT FIX: Permissions-Policy — disable unnecessary browser features
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  next();
};

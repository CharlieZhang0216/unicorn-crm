/**
 * Lightweight Attack Audit Middleware
 * Logs key security info for each request to a flat file
 * Overhead: plain-text append only — no JSON parsing, no indexing, no in-memory cache
 */
const fs = require('fs');
const path = require('path');

const AUDIT_LOG = path.join(__dirname, '..', 'logs', 'audit.log');
const HONEYPOT_LOG = path.join(__dirname, '..', 'logs', 'honeypot.log');

// Ensure log directory exists
const logDir = path.dirname(AUDIT_LOG);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Attack signature detection rules
const ATTACK_SIGNATURES = [
  { name: 'SQLi', pattern: /(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|--[+\s]|;.*\b(drop|alter|create|insert|delete)\b)/i },
  { name: 'XSS', pattern: /(<script|javascript:|on\w+\s*=|alert\s*\(|document\.cookie)/i },
  { name: 'PathTraversal', pattern: /(\.\.\/|\.\.\\|%2e%2e|%2f|etc\/passwd)/i },
  { name: 'CmdInjection', pattern: /[;&|]\$?\s*(cat|ls\b|id\b|whoami|uname|wget|curl|nc\b)/i },
  { name: 'SSRF', pattern: /(\b(127\.0\.0\.1|localhost|169\.254|10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168)\b.*\b(http|https|gopher|file)\b)/i },
  { name: 'SSTI', pattern: /(\{\{.*\}\}|\$\{.*\}|<%=.*%>|#{.*})/i },
  { name: 'Deserialize', pattern: /(O:\d+:"|a:\d+:\{|__proto__|constructor\s*\[)/i },
  { name: 'ScannerUserAgent', pattern: /(nmap|nikto|sqlmap|burp|nessus|acunetix|zap|gobuster|dirbuster|wfuzz|ffuf|hydra|medusa)/i },
];

function detectAttacks(value) {
  if (!value || typeof value !== 'string') return [];
  const hits = [];
  for (const sig of ATTACK_SIGNATURES) {
    if (sig.pattern.test(value)) {
      hits.push(sig.name);
    }
  }
  return hits;
}

function sanitize(obj, maxLen = 500) {
  if (!obj) return obj;
  if (typeof obj === 'string') return obj.substring(0, maxLen);
  if (typeof obj === 'object') {
    const clone = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string') clone[k] = v.substring(0, maxLen);
      else clone[k] = v;
    }
    return clone;
  }
  return obj;
}

function auditMiddleware(req, res, next) {
  const start = Date.now();

  // Capture raw body (before middleware consumes it)
  const rawBody = req.body ? JSON.stringify(sanitize(req.body)) : '';
  const rawQuery = JSON.stringify(sanitize(req.query));
  const attackHits = [...detectAttacks(rawBody), ...detectAttacks(rawQuery), ...detectAttacks(req.url)];

  // Log after response completes
  res.on('finish', () => {
    const duration = Date.now() - start;
    const entry = {
      ts: new Date().toISOString(),
      ip: req.ip || req.connection.remoteAddress,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      dur: duration,
      ua: (req.get('User-Agent') || '').substring(0, 200),
      ref: (req.get('Referer') || '').substring(0, 200),
      user: req.session?.user?.username || (req.currentUser?.username || 'anon'),
      csrf: req.body?._csrf ? 'present' : (req.query?._csrf ? 'present' : 'none'),
      body: rawBody,
      query: rawQuery,
    };

    // Flag if attack signatures detected
    if (attackHits.length > 0) {
      entry.attacks = [...new Set(attackHits)].join(',');
    }

    // Tag high-value events separately
    if (res.statusCode === 500) entry.flags = 'ERROR_500';
    if (res.statusCode === 403) entry.flags = 'FORBIDDEN';
    if (res.statusCode === 401) entry.flags = 'UNAUTHORIZED';
    if (res.statusCode === 429) entry.flags = 'RATE_LIMITED';

    fs.appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n', () => {});
  });

  next();
}

// ─── Honeypot Routes ───
const HONEYPOT_PATHS = [
  '/admin', '/administrator', '/wp-admin', '/wp-login.php',
  '/phpmyadmin', '/phpMyAdmin', '/pma',
  '/.env', '/.git/config', '/.svn/entries', '/.DS_Store',
  '/actuator', '/actuator/health', '/actuator/env',
  '/api/v1', '/api/v2', '/graphql',
  '/console', '/jmx-console', '/web-console',
  '/solr', '/jenkins', '/api/json',
  '/config', '/backup', '/dump', '/sql',
  '/debug', '/test', '/dev',
  '/cgi-bin', '/cgi-bin/test.cgi',
  '/shell', '/cmd', '/exec',
  '/vendor/phpunit', '/vendor/autoload.php',
  '/robots.txt', '/sitemap.xml',
  '/.well-known/security.txt',
  '/swagger', '/api-docs', '/v2/api-docs',
  '/druid', '/druid/index.html',
  '/login.jsp', '/manager/html',
  '/_ignition/execute-solution',  // Laravel debug RCE
  '/wp-json', '/wp-content',
  '/api/user', '/api/admin',
  '/user/login', '/admin/login',
];

function setupHoneypots(app) {
  // Capture per-route
  HONEYPOT_PATHS.forEach(hp => {
    app.all(hp, (req, res) => {
      const entry = {
        ts: new Date().toISOString(),
        ip: req.ip || req.connection.remoteAddress,
        method: req.method,
        path: req.originalUrl,
        ua: (req.get('User-Agent') || '').substring(0, 200),
        body: req.body ? JSON.stringify(sanitize(req.body)).substring(0, 300) : '',
      };
      fs.appendFile(HONEYPOT_LOG, JSON.stringify(entry) + '\n', () => {});
      res.status(404).send('Not Found');
    });
  });

  console.log(`🍯 ${HONEYPOT_PATHS.length} honeypot routes deployed`);
}

module.exports = { auditMiddleware, setupHoneypots };

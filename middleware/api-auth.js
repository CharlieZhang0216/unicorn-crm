/**
 * API Authentication Middleware for Unicorn CRM
 * Validates JWT Bearer tokens for API endpoints
 * 
 * Usage:
 *   const apiAuth = require('./middleware/api-auth');
 *   app.use('/api/v2', apiAuth);  // All /api/v2 routes require valid API token
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// Load JWT secret (same as api-tokens.js)
let JWT_SECRET;
try {
  const envPath = path.join(__dirname, '..', '.env');
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0 && trimmed.substring(0, eqIndex).trim() === 'JWT_SECRET') {
          JWT_SECRET = trimmed.substring(eqIndex + 1).trim();
        }
      }
    });
  }
} catch (e) {}
if (!JWT_SECRET || JWT_SECRET === 'placeholder_jwt_secret_replace_in_production') {
  JWT_SECRET = crypto.randomBytes(64).toString('hex');
}

const JWT_ALGORITHM = 'HS256';

// Optional: db reference for checking token revocations
let db = null;
try {
  db = require('../config/database');
} catch (e) {
  // DB not available — will skip revocation check
}

function apiAuth(req, res, next) {
  // Extract Bearer token from Authorization header
  const authHeader = req.get('Authorization');
  
  if (!authHeader) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Missing Authorization header. Use: Authorization: Bearer <token>'
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Invalid Authorization format. Use: Authorization: Bearer <token>'
    });
  }

  const token = parts[1];

  // Verify JWT signature and decode payload
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'token_expired',
        message: 'API token has expired. Please create a new token.',
        expiredAt: err.expiredAt
      });
    }
    return res.status(401).json({
      error: 'invalid_token',
      message: 'Invalid or malformed API token.'
    });
  }

  // Validate payload structure
  if (!decoded.sub || !decoded.scope) {
    return res.status(401).json({
      error: 'invalid_token',
      message: 'Token payload is missing required fields.'
    });
  }

  // Check token not revoked (if DB available)
  if (db) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const storedToken = db.prepare(
      'SELECT * FROM api_tokens WHERE token_hash = ? AND user_id = ?'
    ).get(tokenHash, decoded.sub);

    if (!storedToken) {
      return res.status(401).json({
        error: 'token_revoked',
        message: 'API token has been revoked or does not exist.'
      });
    }

    // Update last_used_at
    db.prepare('UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(storedToken.id);
  }

  // Load user from database
  if (db) {
    const user = db.prepare('SELECT id, username, email, full_name, role, department, email_verified, status FROM users WHERE id = ?').get(decoded.sub);
    if (!user) {
      return res.status(401).json({
        error: 'user_not_found',
        message: 'User associated with this token no longer exists.'
      });
    }

    if (user.status !== 'active') {
      return res.status(403).json({
        error: 'account_inactive',
        message: 'User account is not active.'
      });
    }

    req.user = user;
  } else {
    req.user = { id: decoded.sub };
  }

  req.apiToken = {
    scope: decoded.scope,
    iat: decoded.iat,
    exp: decoded.exp
  };

  next();
}

/**
 * Optional scope check middleware factory
 * Usage: app.get('/api/v2/admin', apiAuth, requireScope('admin'), handler)
 */
function requireScope(...requiredScopes) {
  return function(req, res, next) {
    if (!req.apiToken || !req.apiToken.scope) {
      return res.status(403).json({
        error: 'forbidden',
        message: 'Insufficient permissions.'
      });
    }
    const hasScope = requiredScopes.some(s => req.apiToken.scope.includes(s));
    if (!hasScope) {
      return res.status(403).json({
        error: 'forbidden',
        message: `Required scope: ${requiredScopes.join(' or ')}`
      });
    }
    next();
  };
}

module.exports = apiAuth;
module.exports.requireScope = requireScope;
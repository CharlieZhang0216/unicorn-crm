/**
 * JWT API Token management routes for Unicorn CRM
 * - List, create, and revoke API tokens
 * - Tokens are signed with JWT and the actual token is only shown once
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const path = require('path');
const fs = require('fs');

// Authentication middleware — must be logged in
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).redirect('/auth/login');
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) { res.clearCookie('session_token'); return res.status(401).redirect('/auth/login'); }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).redirect('/auth/login');
  req.currentUser = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Load JWT secret from .env or generate one
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
  console.log('[JWT] Generated random JWT_SECRET (not persisted). Set JWT_SECRET in .env for persistence.');
}

const JWT_ALGORITHM = 'HS256';

// Token expiry options
const EXPIRY_OPTIONS = {
  '30d': 30 * 24 * 60 * 60,
  '90d': 90 * 24 * 60 * 60,
  '365d': 365 * 24 * 60 * 60
};

/**
 * GET /api-tokens
 * List current user's API tokens
 */
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const tokens = db.prepare(`
    SELECT id, name, scope, expires_at, last_used_at, created_at
    FROM api_tokens
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(req.currentUser.id);

  res.render('api-tokens/index', {
    title: 'API Tokens',
    tokens: tokens,
    user: req.currentUser
  });
});

/**
 * POST /api-tokens
 * Create a new API token
 */
router.post('/', requireAuth, requireAdmin, (req, res) => {
  const { name, scope, expiry } = req.body;

  if (!name || !name.trim()) {
    return res.render('api-tokens/index', {
      title: 'API Tokens',
      error: 'Token name is required.',
      tokens: getTokens(req.currentUser.id),
      user: req.currentUser
    });
  }

  // Validate and normalize scope
  const validScopes = ['read', 'write', 'admin'];
  let tokenScope = [];
  if (scope && Array.isArray(scope)) {
    tokenScope = scope.filter(s => validScopes.includes(s));
  } else if (scope && validScopes.includes(scope)) {
    tokenScope = [scope];
  }
  if (tokenScope.length === 0) {
    tokenScope = ['read']; // Default scope
  }

  // Validate expiry
  const expirySeconds = EXPIRY_OPTIONS[expiry] || EXPIRY_OPTIONS['30d'];
  const expiresAt = new Date(Date.now() + expirySeconds * 1000).toISOString();

  // Create JWT token
  const payload = {
    sub: req.currentUser.id,
    scope: tokenScope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expirySeconds
  };

  const token = jwt.sign(payload, JWT_SECRET, { algorithm: JWT_ALGORITHM });

  // Hash token for storage (only store hash, never the raw token)
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  db.prepare(`
    INSERT INTO api_tokens (user_id, name, token_hash, scope, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.currentUser.id, name.trim(), tokenHash, JSON.stringify(tokenScope), expiresAt);

  res.render('api-tokens/index', {
    title: 'API Tokens',
    success: 'Token created successfully!',
    newToken: token,
    tokenName: name.trim(),
    tokens: getTokens(req.currentUser.id),
    user: req.currentUser
  });
});

/**
 * DELETE /api-tokens/:id
 * Revoke an API token
 */
router.delete('/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid token ID' });
  }

  const token = db.prepare('SELECT * FROM api_tokens WHERE id = ? AND user_id = ?')
    .get(id, req.currentUser.id);

  if (!token) {
    return res.status(404).json({ error: 'Token not found' });
  }

  db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(id, req.currentUser.id);

  if (req.accepts('html')) {
    return res.redirect('/api-tokens');
  }
  res.json({ success: true, message: 'Token revoked' });
});

// POST for form-based delete (browser forms only support GET/POST)
router.post('/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.redirect('/api-tokens');
  }

  db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(id, req.currentUser.id);
  res.redirect('/api-tokens');
});

function getTokens(userId) {
  return db.prepare(`
    SELECT id, name, scope, expires_at, last_used_at, created_at
    FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC
  `).all(userId);
}

module.exports = router;
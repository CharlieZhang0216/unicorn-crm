const express = require('express');
const router = express.Router();
const db = require('../config/database');
const crypto = require('crypto');
const { verifyToken } = require('../middleware/api-auth');

/**
 * API Authentication Routes
 * --------------------------------------------
 * All token lifecycle routes require Bearer token auth via shared middleware.
 * The JWT_SECRET, algorithm, and verification logic live in middleware/api-auth.js.
 *
 * POST /api/auth/verify   — Verify a token is valid
 * POST /api/auth/refresh  — Issue a new token (admin-managed rotation)
 */

// ─── POST /verify — Verify a token is valid ───
router.post('/verify', verifyToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.currentUser.id,
      username: req.currentUser.username,
      role: req.currentUser.role
    },
    scope: req.tokenScope || 'read',
    message: 'Token is valid'
  });
});

// ─── POST /refresh — Issue a new token ───
router.post('/refresh', verifyToken, (req, res) => {
  // Admin-only: refresh is a privileged operation
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required to refresh tokens.' });
  }

  const { sub, scope } = req.body;
  if (!sub) {
    return res.status(400).json({ error: 'Missing required field: sub (user ID).' });
  }

  const targetUser = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(sub);
  if (!targetUser) {
    return res.status(404).json({ error: 'User not found.' });
  }

  // Generate new token using the shared JWT_SECRET and algorithm
  const jwt = require('jsonwebtoken');
  const JWT_SECRET = process.env.JWT_SECRET;
  const JWT_ALGORITHM = 'HS256';
  const newToken = jwt.sign(
    { sub: `${sub}`, scope: scope || 'read', iat: Math.floor(Date.now() / 1000) },
    JWT_SECRET,
    { algorithm: JWT_ALGORITHM, expiresIn: '7d' }
  );

  // Save to api_tokens
  const tokenHash = crypto.createHash('sha256').update(newToken).digest('hex');
  try {
    db.prepare(
      'INSERT INTO api_tokens (user_id, token_hash, name, scope, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime("now", "+7 days"), CURRENT_TIMESTAMP)'
    ).run(sub, tokenHash, `Refreshed token for ${targetUser.username}`, scope || 'read');
  } catch (e) {
    // Table may not exist
  }

  res.json({
    accessToken: newToken,
    token_type: 'bearer',
    expiresIn: 604800,
    user: { id: targetUser.id, username: targetUser.username, role: targetUser.role }
  });
});

module.exports = router;

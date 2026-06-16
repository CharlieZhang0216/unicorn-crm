const express = require('express');
const router = express.Router();
const db = require('../config/database');

// FIXED: Authentication middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  req.userId = session.user_id;
  next();
}

// FIXED: Admin-only middleware
function requireAdmin(req, res, next) {
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// FIXED: Sanitize user data - only return non-sensitive fields
function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    full_name: user.full_name,
    department: user.department,
    role: user.role
  };
}

// FIXED: Admin-only — user enumeration is admin privilege
router.get('/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.setHeader('X-Total-Count', String(users.length));
  res.json({ total: users.length, data: users.map(sanitizeUser) });
});

// FIXED: Users can only view themselves via API
router.get('/users/:id', requireAuth, (req, res, next) => {
  const reqId = parseInt(req.params.id);
  if (reqId !== req.userId) {
    return res.status(403).json({ error: 'You can only view your own profile via API.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(reqId);
  if (!user) {
    const err = new Error(`User with ID ${req.params.id} not found`);
    err.status = 404;
    return next(err);
  }
  res.json(sanitizeUser(user));
});

// FIXED: Admin-only
router.get('/users/search', requireAuth, requireAdmin, (req, res, next) => {
  const q = req.query.q;
  if (!q) {
    return res.status(400).json({ error: 'Missing search parameter q' });
  }

  try {
    const users = db.prepare(
      "SELECT * FROM users WHERE full_name LIKE ? OR username LIKE ? OR email LIKE ? OR department LIKE ?"
    ).all(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);

    res.setHeader('X-Total-Count', String(users.length));
    res.json({ query: q, total: users.length, data: users.map(sanitizeUser) });
  } catch (err) {
    next(err);
  }
});

// FIXED: Employees only see messages addressed to them
// Message subjects and metadata are considered sensitive
router.get('/messages', requireAuth, (req, res) => {
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
  const isAdmin = user?.role === 'admin';

  let query;
  let params;
  if (isAdmin) {
    query = `
      SELECT m.id, m.subject, m.created_at,
             f.full_name as from_name,
             t.full_name as to_name
      FROM messages m
      JOIN users f ON m.from_user_id = f.id
      JOIN users t ON m.to_user_id = t.id
      ORDER BY m.created_at DESC
      LIMIT 50
    `;
    params = [];
  } else {
    query = `
      SELECT m.id, m.subject, m.created_at,
             f.full_name as from_name,
             t.full_name as to_name
      FROM messages m
      JOIN users f ON m.from_user_id = f.id
      JOIN users t ON m.to_user_id = t.id
      WHERE m.to_user_id = ?
      ORDER BY m.created_at DESC
      LIMIT 50
    `;
    params = [req.userId];
  }

  const messages = db.prepare(query).all(...params);
  res.setHeader('X-Total-Count', String(messages.length));
  res.json({ total: messages.length, data: messages });
});

// FIXED: Requires authentication, only return non-sensitive config
router.get('/config', requireAuth, requireAdmin, (req, res) => {
  const safeKeys = ['app.name', 'app.version', 'app.environment', 'smtp.host'];
  const config = db.prepare('SELECT key, value FROM config').all();
  const safeConfig = config.filter(c => safeKeys.includes(c.key));
  res.json({ total: safeConfig.length, data: safeConfig });
});

module.exports = router;

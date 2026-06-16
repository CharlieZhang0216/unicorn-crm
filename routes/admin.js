const express = require('express');
const router = express.Router();
const db = require('../config/database');

// FIXED: Admin authentication middleware
function requireAdmin(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare(`
    SELECT s.*, u.role FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ?
  `).get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  if (session.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.userId = session.user_id;
  next();
}

// FIXED: Requires admin auth, sanitized output
router.get('/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.full_name, u.department, u.role, u.created_at, u.last_login, u.is_active,
           (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) as active_sessions,
           (SELECT COUNT(*) FROM messages m WHERE m.from_user_id = u.id) as sent_messages,
           (SELECT COUNT(*) FROM audit_log a WHERE a.user_id = u.id) as audit_entries
    FROM users u
  `).all();
  res.json({
    total: users.length,
    data: users
  });
});

// FIXED: Requires admin auth
router.get('/sessions', requireAdmin, (req, res) => {
  const sessions = db.prepare(`
    SELECT s.id, s.user_id, s.ip_address, s.user_agent, s.created_at as last_activity,
           u.username, u.full_name, u.role
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    ORDER BY s.created_at DESC
    LIMIT 100
  `).all();
  res.json({
    total: sessions.length,
    data: sessions
  });
});

// FIXED: Requires admin auth
router.get('/audit', requireAdmin, (req, res) => {
  const logs = db.prepare(`
    SELECT a.id, a.action, a.detail as details, a.created_at, a.user_id,
           u.username, u.full_name
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
    LIMIT 200
  `).all();
  res.json({
    total: logs.length,
    data: logs
  });
});

// FIXED: Requires admin auth
router.get('/database', requireAdmin, (req, res) => {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const schema = {};

  tables.forEach(t => {
    // FIX: Validate table name against a safe pattern to prevent SQL injection
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(t.name)) {
      return;
    }
    const columns = db.prepare(`PRAGMA table_info(\`${t.name}\`)`).all();
    const rowCount = db.prepare(`SELECT COUNT(*) as count FROM \`${t.name}\``).get().count;
    schema[t.name] = {
      columns: columns.map(c => ({ name: c.name, type: c.type })),
      rowCount: rowCount
    };
  });

  res.json({
    tables: schema
  });
});

module.exports = router;

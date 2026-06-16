/**
 * 通知路由
 * GET /notifications — 获取通知历史（最近 50 条）
 * POST /notifications — 手动创建通知（管理员）
 * PUT /notifications/:id/read — 标记已读
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { sendToUser, sendToRole, broadcast } = require('../services/websocket');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
  next();
}

// GET /notifications — 获取当前用户的通知历史
router.get('/', requireAuth, (req, res) => {
  const { page, limit } = req.query;
  const currentPage = Math.max(1, parseInt(page) || 1);
  const pageLimit = Math.min(50, Math.max(1, parseInt(limit) || 20));
  const offset = (currentPage - 1) * pageLimit;

  const notifications = db.prepare(`
    SELECT * FROM notifications
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(req.currentUser.id, pageLimit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ?')
    .get(req.currentUser.id).count;
  const unreadCount = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0')
    .get(req.currentUser.id).count;

  if (req.accepts('html')) {
    return res.render('notifications', {
      title: 'Notifications',
      notifications,
      user: req.currentUser,
      page: currentPage,
      limit: pageLimit,
      total,
      totalPages: Math.ceil(total / pageLimit),
      unreadCount,
    });
  }

  res.json({
    success: true,
    data: notifications,
    total,
    page: currentPage,
    unreadCount,
  });
});

// POST /notifications — 手动创建通知（管理员）
router.post('/', requireAuth, (req, res) => {
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const { user_id, type, title, body, entity_type, entity_id } = req.body;

  if (!user_id || !type || !title) {
    return res.status(400).json({ error: 'user_id, type, and title are required.' });
  }

  const validTypes = ['new_customer', 'ticket_update', 'new_order', 'system_alert'];
  if (!validTypes.includes(type)) {
    return res.status(400).json({ error: `Invalid type. Allowed: ${validTypes.join(', ')}.` });
  }

  // Verify target user exists
  const targetUser = db.prepare('SELECT id FROM users WHERE id = ?').get(parseInt(user_id));
  if (!targetUser) {
    return res.status(404).json({ error: 'Target user not found.' });
  }

  const result = db.prepare(`
    INSERT INTO notifications (user_id, type, title, body, entity_type, entity_id, is_read, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'))
  `).run(parseInt(user_id), type, title, body || '', entity_type || null, entity_id || null);

  // Push via WebSocket
  const delivered = sendToUser(parseInt(user_id), {
    type, title, body: body || '',
    entity_type: entity_type || null,
    entity_id: entity_id || null,
    notification_id: result.lastInsertRowid,
  });

  res.json({
    success: true,
    message: 'Notification created.',
    notification_id: result.lastInsertRowid,
    ws_delivered: delivered,
  });
});

// PUT /notifications/:id/read — 标记已读
router.put('/:id/read', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid notification ID.' });
  }

  const notification = db.prepare('SELECT * FROM notifications WHERE id = ? AND user_id = ?')
    .get(id, req.currentUser.id);

  if (!notification) {
    return res.status(404).json({ error: 'Notification not found.' });
  }

  db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(id);

  res.json({ success: true, message: 'Notification marked as read.' });
});

// PUT /notifications/read-all — 全部标记已读
router.put('/read-all', requireAuth, (req, res) => {
  const result = db.prepare(`
    UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0
  `).run(req.currentUser.id);

  res.json({ success: true, message: `${result.changes} notifications marked as read.` });
});

module.exports = router;

/**
 * Batch Operations — extends tickets.js
 * 
 * Two new routes:
 * POST /tickets/batch-status — Batch status change
 * POST /tickets/batch-assign — Batch assign
 */
const db = require('../config/database');

module.exports.batchRoutes = function(router) {

  function requireAuth(req, res, next) {
    const token = req.cookies?.session_token;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (!session) return res.status(401).json({ error: 'Invalid session' });
    req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
    if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
    next();
  }

  // POST /tickets/batch-status — Batch status change
  router.post('/batch-status', requireAuth, (req, res) => {
    // Permission check: admin or manager
    if (req.currentUser.role !== 'admin' && req.currentUser.role !== 'manager') {
      return res.status(403).json({ error: 'Admin or manager access required for batch status changes.' });
    }

    const { ids, status: newStatus } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'ids array is required.' });
    }
    if (!newStatus) {
      return res.status(400).json({ error: 'status is required.' });
    }

    const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
    if (!validStatuses.includes(newStatus)) {
      return res.status(400).json({ error: `Invalid status. Allowed: ${validStatuses.join(', ')}.` });
    }

    if (ids.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 records per batch operation.' });
    }

    const validIds = ids.filter(id => !isNaN(parseInt(id)));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'All IDs must be valid numbers.' });
    }

    const placeholders = validIds.map(() => '?').join(',');

    // Validate ownership: check tickets belong to current user or user has permission
    const tickets = db.prepare(
      `SELECT id, subject, status FROM tickets WHERE id IN (${placeholders})`
    ).all(...validIds);

    if (tickets.length !== validIds.length) {
      return res.status(404).json({
        error: 'Some ticket IDs not found.',
        found: tickets.length,
        requested: validIds.length
      });
    }

    // Batch update + audit + add comments
    const batchTx = db.transaction(() => {
      let updated = 0;
      for (const ticket of tickets) {
        db.prepare(`
          INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
          VALUES (?, ?, ?, datetime('now'))
        `).run(ticket.id, req.currentUser.id,
          `Batch status update: "${ticket.status}" → "${newStatus}" by ${req.currentUser.username}.`);

        db.prepare(`
          INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
          VALUES (?, ?, ?, ?, datetime('now'))
        `).run(req.currentUser.id, 'BATCH_STATUS_UPDATE',
          `Ticket ${ticket.id} (${ticket.subject}): ${ticket.status} → ${newStatus}`,
          req.ip || req.connection.remoteAddress);

        updated++;
      }

      db.prepare(`
        UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id IN (${placeholders})
      `).run(newStatus, ...validIds);

      return updated;
    });

    const updated = batchTx();

    res.json({
      success: true,
      message: `${updated} tickets updated to "${newStatus}".`,
      updated,
      status: newStatus,
      audit_logged: true,
    });
  });

  // POST /tickets/batch-assign — Batch assign
  router.post('/batch-assign', requireAuth, (req, res) => {
    if (req.currentUser.role !== 'admin' && req.currentUser.role !== 'manager') {
      return res.status(403).json({ error: 'Admin or manager access required for batch assignment.' });
    }

    const { ids, assigned_to } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'ids array is required.' });
    }
    if (!assigned_to || isNaN(parseInt(assigned_to))) {
      return res.status(400).json({ error: 'assigned_to (user ID) is required.' });
    }

    if (ids.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 records per batch operation.' });
    }

    // Verify target user exists
    const targetUser = db.prepare('SELECT id, full_name FROM users WHERE id = ?').get(parseInt(assigned_to));
    if (!targetUser) {
      return res.status(404).json({ error: 'Assigned user not found.' });
    }

    const validIds = ids.filter(id => !isNaN(parseInt(id)));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'All IDs must be valid numbers.' });
    }

    const placeholders = validIds.map(() => '?').join(',');
    const tickets = db.prepare(
      `SELECT id, subject FROM tickets WHERE id IN (${placeholders})`
    ).all(...validIds);

    if (tickets.length !== validIds.length) {
      return res.status(404).json({
        error: 'Some ticket IDs not found.',
        found: tickets.length,
        requested: validIds.length
      });
    }

    const batchTx = db.transaction(() => {
      for (const ticket of tickets) {
        db.prepare(`
          INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
          VALUES (?, ?, ?, datetime('now'))
        `).run(ticket.id, req.currentUser.id,
          `Batch reassigned to ${targetUser.full_name} by ${req.currentUser.username}.`);

        db.prepare(`
          INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
          VALUES (?, ?, ?, ?, datetime('now'))
        `).run(req.currentUser.id, 'BATCH_ASSIGN_TICKET',
          `Ticket ${ticket.id}: assigned to ${targetUser.full_name} (ID: ${assigned_to})`,
          req.ip || req.connection.remoteAddress);
      }

      db.prepare(`
        UPDATE tickets SET assigned_to = ?, updated_at = datetime('now') WHERE id IN (${placeholders})
      `).run(parseInt(assigned_to), ...validIds);

      return tickets.length;
    });

    const updated = batchTx();

    res.json({
      success: true,
      message: `${updated} tickets assigned to ${targetUser.full_name}.`,
      updated,
      assigned_to: parseInt(assigned_to),
      audit_logged: true,
    });
  });
};

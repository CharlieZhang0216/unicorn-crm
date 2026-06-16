/**
 * Batch Operations — extends customers.js
 * 
 * Two new routes:
 * POST /customers/batch-delete — Batch delete (admin only)
 * POST /customers/batch-assign — Batch assign customers to managers
 */
// Append these routes to the existing customers.js router

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

  // POST /customers/batch-delete — Batch delete (admin only)
  router.post('/batch-delete', requireAuth, (req, res) => {
    // Permission check
    if (req.currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required for batch deletion.' });
    }

    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'ids array is required.' });
    }

    if (ids.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 records per batch operation.' });
    }

    // Validate all IDs are numeric and exist
    const validIds = ids.filter(id => !isNaN(parseInt(id)));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'All IDs must be valid numbers.' });
    }

    const placeholders = validIds.map(() => '?').join(',');
    const customers = db.prepare(`SELECT id, company_name FROM customers WHERE id IN (${placeholders})`).all(...validIds);

    if (customers.length !== validIds.length) {
      return res.status(404).json({
        error: 'Some customer IDs not found.',
        found: customers.length,
        requested: validIds.length
      });
    }

    // Audit + delete (with transaction)
    const deleteTransaction = db.transaction(() => {
      for (const cust of customers) {
        db.prepare(`
          INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
          VALUES (?, ?, ?, ?, datetime('now'))
        `).run(
          req.currentUser.id,
          'BATCH_DELETE_CUSTOMER',
          `Deleted customer: ${cust.company_name} (ID: ${cust.id})`,
          req.ip || req.connection.remoteAddress
        );
      }

      const result = db.prepare(`DELETE FROM customers WHERE id IN (${placeholders})`).run(...validIds);
      return result;
    });

    const result = deleteTransaction();

    res.json({
      success: true,
      message: `${result.changes} customers deleted.`,
      deleted: result.changes,
      audit_logged: true,
    });
  });

  // POST /customers/batch-assign — Batch assign customers
  router.post('/batch-assign', requireAuth, (req, res) => {
    // Permission check: admin or manager
    if (req.currentUser.role !== 'admin' && req.currentUser.role !== 'manager') {
      return res.status(403).json({ error: 'Admin or manager access required.' });
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

    // Verify target user exists and is a manager
    const targetUser = db.prepare('SELECT id, role FROM users WHERE id = ?').get(parseInt(assigned_to));
    if (!targetUser) {
      return res.status(404).json({ error: 'Assigned user not found.' });
    }
    if (targetUser.role !== 'manager' && targetUser.role !== 'admin') {
      return res.status(400).json({ error: 'Can only assign to managers or admins.' });
    }

    const validIds = ids.filter(id => !isNaN(parseInt(id)));
    if (validIds.length !== ids.length) {
      return res.status(400).json({ error: 'All IDs must be valid numbers.' });
    }

    const placeholders = validIds.map(() => '?').join(',');
    const customers = db.prepare(`SELECT id, company_name FROM customers WHERE id IN (${placeholders})`).all(...validIds);

    if (customers.length !== validIds.length) {
      return res.status(404).json({
        error: 'Some customer IDs not found.',
        found: customers.length,
        requested: validIds.length
      });
    }

    // Audit + update
    const assignTransaction = db.transaction(() => {
      for (const cust of customers) {
        db.prepare(`
          INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
          VALUES (?, ?, ?, ?, datetime('now'))
        `).run(
          req.currentUser.id,
          'BATCH_ASSIGN_CUSTOMER',
          `Assigned customer ${cust.company_name} (ID: ${cust.id}) to user ${assigned_to}`,
          req.ip || req.connection.remoteAddress
        );
      }

      const result = db.prepare(
        `UPDATE customers SET created_by = ?, updated_at = datetime('now') WHERE id IN (${placeholders})`
      ).run(parseInt(assigned_to), ...validIds);

      return result;
    });

    const result = assignTransaction();

    res.json({
      success: true,
      message: `${result.changes} customers reassigned.`,
      updated: result.changes,
      assigned_to: parseInt(assigned_to),
      audit_logged: true,
    });
  });
};

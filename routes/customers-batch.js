/**
 * Batch Operations — extends customers.js
 * 
 * Routes:
 * POST /customers/batch-delete — Batch delete (admin only)
 * POST /customers/batch-assign — Batch assign customers to managers
 * POST /customers/merge — Merge duplicate customers (admin only)
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

  // POST /customers/batch-delete — Batch delete (admin only)
  router.post('/batch-delete', requireAuth, (req, res) => {
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

  // ─── BL-1: Customer Dedup Merge (TOCTOU vulnerability) ───
  // POST /customers/merge
  // Merge a duplicate customer into the primary one.
  // Business logic: find duplicates by company_name similarity,
  // then "merge" by transferring orders/tickets and deleting the duplicate.
  //
  // TOCTOU window: the delete-and-reassign pattern is NOT atomic.
  // Between the SELECT (check) and DELETE + INSERT (merge), another
  // request can create a new customer with the same company_name,
  // causing the merge to transfer orders to the attacker's record.
  router.post('/merge', requireAuth, (req, res) => {
    if (req.currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    const { primaryId, duplicateId } = req.body;
    if (!primaryId || !duplicateId || isNaN(parseInt(primaryId)) || isNaN(parseInt(duplicateId))) {
      return res.status(400).json({ error: 'primaryId and duplicateId are required (numbers).' });
    }

    const primary = db.prepare('SELECT * FROM customers WHERE id = ?').get(parseInt(primaryId));
    const duplicate = db.prepare('SELECT * FROM customers WHERE id = ?').get(parseInt(duplicateId));

    if (!primary || !duplicate) {
      return res.status(404).json({ error: 'One or both customers not found.' });
    }

    // Step 1: Reassign all orders from duplicate → primary
    const orderResult = db.prepare(
      'UPDATE orders SET customer_id = ?, updated_at = datetime(\'now\') WHERE customer_id = ?'
    ).run(primary.id, duplicate.id);

    // Step 2: Merge notes
    const mergedNotes = [primary.notes || '', duplicate.notes || '']
      .filter(Boolean)
      .join(' | MERGED: ');

    db.prepare('UPDATE customers SET notes = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(mergedNotes, primary.id);

    // Step 3: Audit log
    db.prepare(`
      INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run(
      req.currentUser.id,
      'CUSTOMER_MERGE',
      `Merged customer "${duplicate.company_name}" (ID: ${duplicate.id}) into "${primary.company_name}" (ID: ${primary.id}). ${orderResult.changes} orders reassigned.`,
      req.ip || req.connection.remoteAddress
    );

    // Step 4: Delete the duplicate — THIS IS THE TOCTOU WINDOW
    // Between the reassign above and this delete, another concurrent request
    // could create a new customer with the same name, intercepting the merge.
    db.prepare('DELETE FROM customers WHERE id = ?').run(duplicate.id);

    res.json({
      success: true,
      message: `Merged "${duplicate.company_name}" into "${primary.company_name}".`,
      ordersReassigned: orderResult.changes,
      audit_logged: true,
    });
  });

  // ─── BL-1 support: Find duplicates ───
  // GET /customers/duplicates — Find potential duplicate customers by company name
  router.get('/duplicates', requireAuth, (req, res) => {
    if (req.currentUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }

    const duplicates = db.prepare(`
      SELECT 
        c1.id as id1, c1.company_name as name1, c1.email as email1, c1.created_by as created_by1,
        c2.id as id2, c2.company_name as name2, c2.email as email2, c2.created_by as created_by2
      FROM customers c1
      JOIN customers c2 ON c1.company_name = c2.company_name AND c1.id < c2.id
      LIMIT 50
    `).all();

    res.json({
      success: true,
      duplicates,
      count: duplicates.length
    });
  });
};

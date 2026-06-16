const express = require('express');
const router = express.Router();
const db = require('../config/database');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
  next();
}

// Customer list with search, pagination, sorting, and RBAC filtering
router.get('/', requireAuth, (req, res) => {
  const { q, tier, region, status, page, limit, sort, order } = req.query;

  const currentPage = Math.max(1, parseInt(page) || 1);
  const pageLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const offset = (currentPage - 1) * pageLimit;

  // Build allowed sort columns (whitelist to prevent SQL injection)
  const sortColumns = {
    company_name: 'company_name',
    contact_name: 'contact_name',
    tier: 'tier',
    status: 'status',
    industry: 'industry',
    annual_revenue: 'annual_revenue',
    created_at: 'created_at'
  };
  const sortCol = sortColumns[sort] || 'created_at';
  const sortDir = order === 'asc' ? 'ASC' : 'DESC';

  let whereClauses = [];
  let params = [];

  // RBAC filtering
  if (req.currentUser.role === 'admin') {
    // Admin sees everything — no filter
  } else if (req.currentUser.role === 'manager') {
    if (req.currentUser.region) {
      whereClauses.push('c.region = ?');
      params.push(req.currentUser.region);
    } else {
      // Manager with no region treated like admin
    }
  } else {
    // Employee sees only customers they created
    whereClauses.push('c.created_by = ?');
    params.push(req.currentUser.id);
  }

  // Search across name, email, company
  if (q && q.trim()) {
    whereClauses.push('(c.company_name LIKE ? OR c.contact_name LIKE ? OR c.email LIKE ?)');
    const term = `%${q.trim()}%`;
    params.push(term, term, term);
  }

  // Filters
  if (tier && ['A', 'B', 'C'].includes(tier)) {
    whereClauses.push('c.tier = ?');
    params.push(tier);
  }
  if (region && region.trim()) {
    whereClauses.push('c.region = ?');
    params.push(region.trim());
  }
  if (status && ['active', 'inactive', 'lead'].includes(status)) {
    whereClauses.push('c.status = ?');
    params.push(status);
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // Count total
  const countRow = db.prepare(`SELECT COUNT(*) as total FROM customers c ${whereSQL}`).get(...params);
  const total = countRow ? countRow.total : 0;
  const totalPages = Math.ceil(total / pageLimit);

  // Fetch page
  const query = `SELECT c.* FROM customers c ${whereSQL} ORDER BY ${sortCol} ${sortDir} LIMIT ? OFFSET ?`;
  const queryParams = [...params, pageLimit, offset];
  let customers = [];
  try {
    customers = db.prepare(query).all(...queryParams);
  } catch (e) {
    console.error('[Customers] Query error:', e.message);
  }

  // Fetch distinct regions for the filter dropdown
  const regions = db.prepare('SELECT DISTINCT region FROM customers WHERE region IS NOT NULL ORDER BY region').all()
    .map(r => r.region);

  res.render('customers', {
    title: 'Customers',
    customers,
    user: req.currentUser,
    q: q || '',
    tier: tier || '',
    region: region || '',
    status: status || '',
    page: currentPage,
    limit: pageLimit,
    total,
    totalPages,
    sort: sortCol,
    order: sortDir.replace('DESC', 'desc').replace('ASC', 'asc'),
    regions
  });
});

// ─── Customer Dedup Merge (BL-1) ───
// POST /customers/merge — Must be registered BEFORE /:id to avoid route collision
router.post('/merge', requireAuth, (req, res) => {
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const { primaryId, duplicateId } = req.body;
  if (!primaryId || !duplicateId || isNaN(parseInt(primaryId)) || isNaN(parseInt(duplicateId))) {
    return res.status(400).json({ error: 'primaryId and duplicateId are required.' });
  }

  const primary = db.prepare('SELECT * FROM customers WHERE id = ?').get(parseInt(primaryId));
  const duplicate = db.prepare('SELECT * FROM customers WHERE id = ?').get(parseInt(duplicateId));

  if (!primary || !duplicate) {
    return res.status(404).json({ error: 'One or both customers not found.' });
  }

  // Reassign orders from duplicate → primary
  const orderResult = db.prepare(
    'UPDATE orders SET customer_id = ?, updated_at = datetime(\'now\') WHERE customer_id = ?'
  ).run(primary.id, duplicate.id);

  // Merge notes
  const mergedNotes = [primary.notes || '', duplicate.notes || '']
    .filter(Boolean)
    .join(' | MERGED: ');
  db.prepare('UPDATE customers SET notes = ?, updated_at = datetime(\'now\') WHERE id = ?')
    .run(mergedNotes, primary.id);

  // Audit
  db.prepare(`
    INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).run(
    req.currentUser.id, 'CUSTOMER_MERGE',
    `Merged "${duplicate.company_name}" into "${primary.company_name}". ${orderResult.changes} orders reassigned.`,
    req.ip
  );

  // Delete duplicate (TOCTOU window)
  db.prepare('DELETE FROM customers WHERE id = ?').run(duplicate.id);

  res.json({ success: true, message: `Merged into ${primary.company_name}.`, ordersReassigned: orderResult.changes });
});

// GET /customers/duplicates — Find duplicate customers
router.get('/duplicates', requireAuth, (req, res) => {
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const duplicates = db.prepare(`
    SELECT c1.id as id1, c1.company_name as name1, c1.email as email1,
           c2.id as id2, c2.company_name as name2, c2.email as email2
    FROM customers c1
    JOIN customers c2 ON c1.company_name = c2.company_name AND c1.id < c2.id
    LIMIT 50
  `).all();

  res.json({ success: true, duplicates, count: duplicates.length });
});

// Customer detail with related orders and tickets
router.get('/:id', requireAuth, (req, res) => {
  const customerId = parseInt(req.params.id);
  if (isNaN(customerId)) {
    return res.status(400).render('error', {
      title: 'Bad Request', status: 400, message: 'Invalid customer ID.',
      stack: null
    });
  }

  // RBAC check: build filter based on role
  let customerQuery = 'SELECT c.* FROM customers c WHERE c.id = ?';
  let queryParams = [customerId];

  if (req.currentUser.role !== 'admin') {
    if (req.currentUser.role === 'manager' && req.currentUser.region) {
      customerQuery += ' AND c.region = ?';
      queryParams.push(req.currentUser.region);
    } else if (req.currentUser.role === 'employee') {
      customerQuery += ' AND c.created_by = ?';
      queryParams.push(req.currentUser.id);
    }
    // manager without region falls through = sees all
  }

  const customer = db.prepare(customerQuery).get(...queryParams);
  if (!customer) {
    return res.status(404).render('error', {
      title: 'Not Found', status: 404, message: 'Customer not found.',
      stack: null
    });
  }

  const createdBy = db.prepare('SELECT id, full_name, username FROM users WHERE id = ?').get(customer.created_by);

  // Related orders
  const orders = db.prepare(`
    SELECT o.id, o.order_ref, o.total, o.status, o.created_at
    FROM orders o
    WHERE o.customer_id = ?
    ORDER BY o.created_at DESC
  `).all(customer.id);

  // Related tickets
  const tickets = db.prepare(`
    SELECT t.id, t.ticket_ref, t.subject, t.priority, t.status, t.created_at,
           u.full_name as assigned_name
    FROM tickets t
    LEFT JOIN users u ON t.assigned_to = u.id
    WHERE t.created_by IN (SELECT id FROM users WHERE id = ?)
      OR t.id IN (
        SELECT DISTINCT t2.id FROM tickets t2
        JOIN orders o2 ON o2.customer_id = ?
        WHERE t2.ticket_ref LIKE ?
      )
    ORDER BY t.created_at DESC
    LIMIT 20
  `).all(customer.created_by, customer.id, '%');

  // Simpler: fetch tickets linked via orders to this customer
  // Actually, let's just get tickets that might relate - show tickets
  // from the same creator or we can add a customer_id to tickets later.
  // For now, show recent tickets created by users who serve this customer.
  const relatedTickets = db.prepare(`
    SELECT t.id, t.ticket_ref, t.subject, t.priority, t.status, t.created_at,
           u.full_name as assigned_name
    FROM tickets t
    LEFT JOIN users u ON t.assigned_to = u.id
    WHERE t.created_by = ? OR t.subject LIKE ? OR t.subject LIKE ?
    ORDER BY t.created_at DESC
    LIMIT 20
  `).all(customer.created_by, `%${customer.company_name}%`, `%${customer.contact_name}%`);

  res.render('customer-detail', {
    title: customer.company_name,
    customer,
    createdBy,
    orders,
    tickets: relatedTickets,
    user: req.currentUser
  });
});

module.exports = router;

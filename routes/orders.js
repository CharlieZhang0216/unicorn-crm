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

// Order list with status filter, search, pagination, and RBAC
router.get('/', requireAuth, (req, res) => {
  const { status, q, page, limit } = req.query;

  const currentPage = Math.max(1, parseInt(page) || 1);
  const pageLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const offset = (currentPage - 1) * pageLimit;

  let whereClauses = [];
  let params = [];

  // RBAC filtering
  if (req.currentUser.role === 'employee') {
    whereClauses.push('o.created_by = ?');
    params.push(req.currentUser.id);
  }
  // admin and manager see all orders

  // Status filter
  const validStatuses = ['draft', 'pending', 'approved', 'rejected'];
  if (status && validStatuses.includes(status)) {
    whereClauses.push('o.status = ?');
    params.push(status);
  }

  // Search: order ref or customer name
  if (q && q.trim()) {
    whereClauses.push('(o.order_ref LIKE ? OR c.company_name LIKE ? OR c.contact_name LIKE ?)');
    const term = `%${q.trim()}%`;
    params.push(term, term, term);
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // Count
  const countRow = db.prepare(`
    SELECT COUNT(*) as total
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    ${whereSQL}
  `).get(...params);
  const total = countRow ? countRow.total : 0;
  const totalPages = Math.ceil(total / pageLimit);

  // Fetch page
  const query = `
    SELECT o.*, c.company_name as customer_name, cu.full_name as creator_name
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    LEFT JOIN users cu ON o.created_by = cu.id
    ${whereSQL}
    ORDER BY o.created_at DESC
    LIMIT ? OFFSET ?
  `;
  const queryParams = [...params, pageLimit, offset];
  let orders = [];
  try {
    orders = db.prepare(query).all(...queryParams);
  } catch (e) {
    console.error('[Orders] Query error:', e.message);
  }

  // Status counts for filter tabs
  const statusCounts = db.prepare(`
    SELECT o.status, COUNT(*) as count
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    ${req.currentUser.role === 'employee' ? 'WHERE o.created_by = ?' : ''}
    GROUP BY o.status
  `).all(...(req.currentUser.role === 'employee' ? [req.currentUser.id] : []));
  const counts = {};
  statusCounts.forEach(r => { counts[r.status] = r.count; });

  res.render('orders', {
    title: 'Orders',
    orders,
    user: req.currentUser,
    status: status || '',
    q: q || '',
    page: currentPage,
    limit: pageLimit,
    total,
    totalPages,
    counts
  });
});

// Order detail with items, related tickets, and approval actions
router.get('/:id', requireAuth, (req, res) => {
  const orderId = parseInt(req.params.id);
  if (isNaN(orderId)) {
    return res.status(400).render('error', {
      title: 'Bad Request', status: 400, message: 'Invalid order ID.',
      stack: null
    });
  }

  let orderQuery = `
    SELECT o.*, c.company_name as customer_name, c.contact_name as customer_contact,
           cu.full_name as creator_name
    FROM orders o
    JOIN customers c ON o.customer_id = c.id
    LEFT JOIN users cu ON o.created_by = cu.id
    WHERE o.id = ?
  `;
  let queryParams = [orderId];

  if (req.currentUser.role === 'employee') {
    orderQuery += ' AND o.created_by = ?';
    queryParams.push(req.currentUser.id);
  }

  const order = db.prepare(orderQuery).get(...queryParams);
  if (!order) {
    return res.status(404).render('error', {
      title: 'Not Found', status: 404, message: 'Order not found.',
      stack: null
    });
  }

  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
  const approver = order.approved_by
    ? db.prepare('SELECT id, full_name FROM users WHERE id = ?').get(order.approved_by)
    : null;

  // Related tickets (tickets opened by the order creator, possibly about this order)
  const relatedTickets = db.prepare(`
    SELECT t.id, t.ticket_ref, t.subject, t.priority, t.status, t.created_at,
           u.full_name as assigned_name
    FROM tickets t
    LEFT JOIN users u ON t.assigned_to = u.id
    WHERE t.subject LIKE ? OR t.description LIKE ?
    ORDER BY t.created_at DESC
    LIMIT 10
  `).all(`%${order.order_ref}%`, `%${order.order_ref}%`);

  // Determine if approve/reject buttons should be shown
  const canApprove = (req.currentUser.role === 'admin' || req.currentUser.role === 'manager')
    && (order.status === 'pending' || order.status === 'draft')
    && order.approval_step < 2;

  res.render('order-detail', {
    title: 'Order ' + order.order_ref,
    order,
    items,
    approver,
    relatedTickets,
    canApprove,
    user: req.currentUser
  });
});

// Approve order (manager/admin, only pending status)
router.post('/:id/approve', requireAuth, (req, res) => {
  if (req.currentUser.role !== 'admin' && req.currentUser.role !== 'manager') {
    return res.status(403).json({ error: 'Only managers and admins can approve orders.' });
  }

  const orderId = parseInt(req.params.id);
  if (isNaN(orderId)) {
    return res.status(400).json({ error: 'Invalid order ID.' });
  }

  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found.' });
  }
  if (order.status !== 'pending') {
    return res.status(400).json({ error: `Cannot approve order with status "${order.status}". Only pending orders can be approved.` });
  }

  // Server-side step increment (ignore client-provided step)
  const nextStep = order.approval_step + 1;

  if (nextStep >= 2) {
    // Final approval
    db.prepare(`
      UPDATE orders
      SET status = 'approved', approval_step = ?, approved_by = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(nextStep, req.currentUser.id, order.id);

    db.prepare(`
      INSERT INTO audit_log (user_id, action, detail, ip_address)
      VALUES (?, ?, ?, ?)
    `).run(req.currentUser.id, 'ORDER_APPROVE',
      JSON.stringify({ order: order.order_ref, step: nextStep, action: 'approved' }),
      req.ip);

    return res.json({ success: true, message: 'Order approved.', status: 'approved' });
  } else {
    // Intermediate step approval
    db.prepare(`
      UPDATE orders SET approval_step = ?, updated_at = datetime('now') WHERE id = ?
    `).run(nextStep, order.id);

    return res.json({ success: true, message: `Approval step ${nextStep} completed.`, status: order.status });
  }
});

// Reject order (manager/admin, only pending status)
router.post('/:id/reject', requireAuth, (req, res) => {
  if (req.currentUser.role !== 'admin' && req.currentUser.role !== 'manager') {
    return res.status(403).json({ error: 'Only managers and admins can reject orders.' });
  }

  const orderId = parseInt(req.params.id);
  if (isNaN(orderId)) {
    return res.status(400).json({ error: 'Invalid order ID.' });
  }

  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found.' });
  }
  if (order.status !== 'pending') {
    return res.status(400).json({ error: `Cannot reject order with status "${order.status}". Only pending orders can be rejected.` });
  }

  db.prepare(`
    UPDATE orders
    SET status = 'rejected', approved_by = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(req.currentUser.id, order.id);

  db.prepare(`
    INSERT INTO audit_log (user_id, action, detail, ip_address)
    VALUES (?, ?, ?, ?)
  `).run(req.currentUser.id, 'ORDER_REJECT',
    JSON.stringify({ order: order.order_ref, action: 'rejected' }),
    req.ip);

  return res.json({ success: true, message: 'Order rejected.', status: 'rejected' });
});

module.exports = router;

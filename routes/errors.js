const express = require('express');
const router = express.Router();
const db = require('../config/database');

// SECURITY AUDIT FIX: Authentication required for search
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
  next();
}

// Global search across customers, orders, tickets
router.get('/', requireAuth, (req, res, next) => {
  const q = (req.query.q || '').trim();
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;

  if (!q) {
    return res.render('search', {
      title: 'Global Search',
      q: '', query: '', results: null, total: 0, page: 1, totalPages: 0, limit: limit,
      error: null,
      user: req.currentUser
    });
  }

  try {
    const searchTerm = `%${q}%`;
    const results = [];

    // Customers
    const customers = db.prepare(`
      SELECT id, company_name, contact_name, email, tier, status
      FROM customers
      WHERE company_name LIKE ? OR contact_name LIKE ? OR email LIKE ?
    `).all(searchTerm, searchTerm, searchTerm);
    customers.forEach(c => results.push({ ...c, result_type: 'customer' }));

    // Orders
    const orders = db.prepare(`
      SELECT o.id, o.order_ref, o.total, o.status, o.created_at,
             c.company_name AS customer_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.order_ref LIKE ? OR c.company_name LIKE ?
    `).all(searchTerm, searchTerm);
    orders.forEach(o => results.push({ ...o, result_type: 'order' }));

    // Tickets
    const tickets = db.prepare(`
      SELECT id, ticket_ref, subject, priority, status, created_at
      FROM tickets
      WHERE ticket_ref LIKE ? OR subject LIKE ?
    `).all(searchTerm, searchTerm);
    tickets.forEach(t => results.push({ ...t, result_type: 'ticket' }));

    const total = results.length;
    const totalPages = Math.ceil(total / limit);
    const paged = results.slice(offset, offset + limit);

    res.render('search', {
      title: 'Global Search',
      q: q, query: q,
      results: paged,
      total: total,
      page: page,
      totalPages: totalPages,
      limit: limit,
      error: null,
      user: req.currentUser
    });
  } catch (err) {
    console.error('Search error:', err.message);
    next(err);
  }
});

module.exports = router;

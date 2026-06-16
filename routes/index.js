const express = require('express');
const router = express.Router();
const db = require('../config/database');

// Helper: get current user from session cookie
function getSessionUser(req) {
  const token = req.cookies?.session_token;
  if (!token) return null;
  const session = db.prepare(`
    SELECT user_id, role FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ?
  `).get(token);
  if (!session) return null;
  return { id: session.user_id, role: session.role };
}

// Landing page — shown to unauthenticated users
router.get('/', (req, res) => {
  const session = getSessionUser(req);

  // Unauthenticated → show landing page with system introduction
  if (!session) {
    return res.render('landing', { title: 'Welcome', user: null });
  }

  const userId = session.id;
  const userRole = session.role;

  let viewData = { title: 'Dashboard', role: userRole };

  // Fetch the full user record for the nav/header
  viewData.user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

  if (userRole === 'admin') {
    // ── Admin stats ──
    viewData.stats = {
      activeCustomers: db.prepare("SELECT COUNT(*) AS c FROM customers WHERE status = 'active'").get().c || 0,
      monthlyRevenue: db.prepare(`
        SELECT COALESCE(SUM(total), 0) AS c FROM orders
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
          AND status = 'approved'
      `).get().c || 0,
      pendingTickets: db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status IN ('open','in_progress')").get().c || 0,
      employeeCount: db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'employee' AND is_active = 1").get().c || 0,
    };

    // Recent orders (latest 5)
    viewData.recentOrders = db.prepare(`
      SELECT o.order_ref, o.total, o.status, o.created_at,
             c.company_name AS customer_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      ORDER BY o.created_at DESC
      LIMIT 5
    `).all();

    // Pending tickets (latest 5)
    viewData.pendingTickets = db.prepare(`
      SELECT t.ticket_ref, t.subject, t.priority, t.status,
             u.full_name AS assignee_name
      FROM tickets t
      LEFT JOIN users u ON t.assigned_to = u.id
      WHERE t.status IN ('open','in_progress')
      ORDER BY
        CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
        t.created_at ASC
      LIMIT 5
    `).all();

  } else if (userRole === 'employee') {
    // ── Employee stats ──
    viewData.orderCount = db.prepare('SELECT COUNT(*) AS c FROM orders WHERE created_by = ?').get(userId).c || 0;

    viewData.assignedTickets = db.prepare(`
      SELECT t.ticket_ref, t.subject, t.priority, t.status, t.created_at
      FROM tickets t
      WHERE t.assigned_to = ?
      ORDER BY t.created_at DESC
      LIMIT 5
    `).all(userId);

    viewData.recentMessages = db.prepare(`
      SELECT m.subject, m.body, m.created_at, m.is_read,
             u.full_name AS from_name
      FROM messages m
      JOIN users u ON m.from_user_id = u.id
      WHERE m.to_user_id = ?
      ORDER BY m.created_at DESC
      LIMIT 5
    `).all(userId);

  } else {
    // ── Manager view ──
    viewData.pendingApprovals = db.prepare(`
      SELECT COUNT(*) AS c FROM orders o
      JOIN users u ON o.created_by = u.id
      WHERE o.status = 'pending' AND u.report_to = ?
    `).get(userId).c || 0;

    viewData.completedThisMonth = db.prepare(`
      SELECT COUNT(*) AS c FROM orders o
      JOIN users u ON o.created_by = u.id
      WHERE o.status = 'approved'
        AND strftime('%Y-%m', o.updated_at) = strftime('%Y-%m', 'now')
        AND u.report_to = ?
    `).get(userId).c || 0;

    // Pending approval orders list (for manager's team)
    viewData.pendingOrders = db.prepare(`
      SELECT o.order_ref, o.total, o.status, o.created_at,
             c.company_name AS customer_name,
             u.full_name AS created_by_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      JOIN users u ON o.created_by = u.id
      WHERE o.status = 'pending' AND u.report_to = ?
      ORDER BY o.created_at ASC
      LIMIT 10
    `).all(userId);

    // Team ticket overview
    viewData.teamTickets = db.prepare(`
      SELECT t.ticket_ref, t.subject, t.priority, t.status,
             u1.full_name AS assignee_name,
             u2.full_name AS reporter_name
      FROM tickets t
      LEFT JOIN users u1 ON t.assigned_to = u1.id
      LEFT JOIN users u2 ON t.created_by = u2.id
      WHERE t.assigned_to IN (
        SELECT id FROM users WHERE report_to = ?
      )
      ORDER BY t.created_at DESC
      LIMIT 5
    `).all(userId);
  }

  res.render('index', viewData);
});

// API Documentation page
router.get('/api-docs', (req, res) => {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).render('error', {
      title: '401 Unauthorized',
      status: 401,
      message: 'Authentication required to view API documentation.',
      stack: null
    });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).render('error', {
      title: '401 Unauthorized',
      status: 401,
      message: 'Invalid session.',
      stack: null
    });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  res.render('api-docs', { title: 'API Documentation', user });
});

module.exports = router;

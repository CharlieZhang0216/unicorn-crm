const express = require('express');
const router = express.Router();
const db = require('../config/database');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT user_id, role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.sessionUserId = session.user_id;
  req.sessionUserRole = session.role;
  next();
}

router.get('/', requireAuth, (req, res) => {
  const userId = req.sessionUserId;
  const userRole = req.sessionUserRole;

  // Fetch full user record for the nav
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

  let viewData = {
    title: 'Reports',
    user,
    role: userRole,
  };

  if (userRole === 'admin') {
    // ── Admin Reports ──

    // 1. Customer growth trend (monthly)
    viewData.customerGrowth = db.prepare(`
      SELECT strftime('%Y-%m', created_at) AS month,
             COUNT(*) AS new_customers
      FROM customers
      WHERE created_at IS NOT NULL
      GROUP BY strftime('%Y-%m', created_at)
      ORDER BY month ASC
    `).all();

    // 2. Revenue by customer tier
    viewData.revenueByTier = db.prepare(`
      SELECT c.tier,
             COALESCE(SUM(o.total), 0) AS total_revenue,
             COUNT(DISTINCT o.id) AS order_count
      FROM customers c
      LEFT JOIN orders o ON o.customer_id = c.id AND o.status = 'approved'
      GROUP BY c.tier
      ORDER BY c.tier
    `).all();

    // 3. Ticket resolution rate by status
    viewData.ticketStatusStats = db.prepare(`
      SELECT status, COUNT(*) AS count
      FROM tickets
      GROUP BY status
      ORDER BY count DESC
    `).all();

    viewData.totalTickets = db.prepare('SELECT COUNT(*) AS c FROM tickets').get().c || 0;

  } else if (userRole === 'employee') {
    // ── Employee Reports ──

    // Personal order summary
    viewData.myOrdersTotal = db.prepare('SELECT COUNT(*) AS c FROM orders WHERE created_by = ?').get(userId).c || 0;
    viewData.myOrdersApproved = db.prepare("SELECT COUNT(*) AS c FROM orders WHERE created_by = ? AND status = 'approved'").get(userId).c || 0;
    viewData.myOrdersPending = db.prepare("SELECT COUNT(*) AS c FROM orders WHERE created_by = ? AND status = 'pending'").get(userId).c || 0;
    viewData.myRevenue = db.prepare("SELECT COALESCE(SUM(total), 0) AS c FROM orders WHERE created_by = ? AND status = 'approved'").get(userId).c || 0;

    // Personal tickets handled
    viewData.myTicketsHandled = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE assigned_to = ? AND status IN ('resolved','closed')").get(userId).c || 0;
    viewData.myTicketsOpen = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE assigned_to = ? AND status IN ('open','in_progress')").get(userId).c || 0;

    // Monthly personal performance
    viewData.myMonthlyOrders = db.prepare(`
      SELECT COUNT(*) AS c FROM orders
      WHERE created_by = ?
        AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    `).get(userId).c || 0;

    viewData.myMonthlyRevenue = db.prepare(`
      SELECT COALESCE(SUM(total), 0) AS c FROM orders
      WHERE created_by = ?
        AND status = 'approved'
        AND strftime('%Y-%m', updated_at) = strftime('%Y-%m', 'now')
    `).get(userId).c || 0;

  } else {
    // ── Manager Reports (default) ──

    // Team performance: users who report to this manager
    viewData.teamMembers = userId
      ? db.prepare(`
          SELECT u.id, u.full_name, u.department,
                 COUNT(DISTINCT o.id) AS order_count,
                 COALESCE(SUM(CASE WHEN o.status = 'approved' THEN o.total ELSE 0 END), 0) AS revenue
          FROM users u
          LEFT JOIN orders o ON o.created_by = u.id
          WHERE u.report_to = ?
          GROUP BY u.id
          ORDER BY revenue DESC
        `).all(userId)
      : [];

    // Order approval rate
    viewData.approvalRate = userId
      ? (() => {
          const total = db.prepare(`
            SELECT COUNT(*) AS c FROM orders o
            JOIN users u ON o.created_by = u.id
            WHERE u.report_to = ?
          `).get(userId).c || 0;
          const approved = db.prepare(`
            SELECT COUNT(*) AS c FROM orders o
            JOIN users u ON o.created_by = u.id
            WHERE u.report_to = ? AND o.status = 'approved'
          `).get(userId).c || 0;
          return { total, approved, rate: total > 0 ? ((approved / total) * 100).toFixed(1) : 0 };
        })()
      : { total: 0, approved: 0, rate: 0 };

    // Monthly team orders
    viewData.teamMonthlyOrders = userId
      ? db.prepare(`
          SELECT COUNT(*) AS c FROM orders o
          JOIN users u ON o.created_by = u.id
          WHERE u.report_to = ?
            AND strftime('%Y-%m', o.created_at) = strftime('%Y-%m', 'now')
        `).get(userId).c || 0
      : 0;

    // Team pending approvals count
    viewData.teamPendingApprovals = userId
      ? db.prepare(`
          SELECT COUNT(*) AS c FROM orders o
          JOIN users u ON o.created_by = u.id
          WHERE u.report_to = ? AND o.status = 'pending'
        `).get(userId).c || 0
      : 0;

    // Ensure role is set for template
    viewData.role = 'manager';
  }

  res.render('reports', viewData);
});

module.exports = router;

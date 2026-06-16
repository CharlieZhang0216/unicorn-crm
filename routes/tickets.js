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

// Ticket list with status/priority filter, search, pagination, and RBAC
router.get('/', requireAuth, (req, res) => {
  const { status, priority, q, page, limit } = req.query;

  const currentPage = Math.max(1, parseInt(page) || 1);
  const pageLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const offset = (currentPage - 1) * pageLimit;

  let whereClauses = [];
  let params = [];

  // RBAC: employee sees tickets they created or are assigned to
  if (req.currentUser.role === 'employee') {
    whereClauses.push('(t.created_by = ? OR t.assigned_to = ?)');
    params.push(req.currentUser.id, req.currentUser.id);
  }
  // admin and manager see all

  // Status filter
  const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
  if (status && validStatuses.includes(status)) {
    whereClauses.push('t.status = ?');
    params.push(status);
  }

  // Priority filter
  const validPriorities = ['Low', 'Medium', 'High', 'Critical'];
  if (priority && validPriorities.includes(priority)) {
    whereClauses.push('t.priority = ?');
    params.push(priority);
  }

  // Search: subject or ticket_ref
  if (q && q.trim()) {
    whereClauses.push('(t.subject LIKE ? OR t.ticket_ref LIKE ? OR t.description LIKE ?)');
    const term = `%${q.trim()}%`;
    params.push(term, term, term);
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // Count
  const countRow = db.prepare(`
    SELECT COUNT(*) as total FROM tickets t ${whereSQL}
  `).get(...params);
  const total = countRow ? countRow.total : 0;
  const totalPages = Math.ceil(total / pageLimit);

  // Fetch page
  const query = `
    SELECT t.*, u.full_name as assigned_name, cu.full_name as creator_name
    FROM tickets t
    LEFT JOIN users u ON t.assigned_to = u.id
    LEFT JOIN users cu ON t.created_by = cu.id
    ${whereSQL}
    ORDER BY
      CASE t.priority
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        ELSE 5
      END,
      t.created_at DESC
    LIMIT ? OFFSET ?
  `;
  const queryParams = [...params, pageLimit, offset];
  let tickets = [];
  try {
    tickets = db.prepare(query).all(...queryParams);
  } catch (e) {
    console.error('[Tickets] Query error:', e.message);
  }

  // Status/priority counts for filter display
  const statusCounts = db.prepare(`
    SELECT t.status, COUNT(*) as count FROM tickets t
    ${req.currentUser.role === 'employee' ? 'WHERE t.created_by = ? OR t.assigned_to = ?' : ''}
    GROUP BY t.status
  `).all(...(req.currentUser.role === 'employee' ? [req.currentUser.id, req.currentUser.id] : []));
  const counts = {};
  statusCounts.forEach(r => { counts[r.status] = r.count; });

  const priorityCounts = db.prepare(`
    SELECT t.priority, COUNT(*) as count FROM tickets t
    ${req.currentUser.role === 'employee' ? 'WHERE t.created_by = ? OR t.assigned_to = ?' : ''}
    GROUP BY t.priority
  `).all(...(req.currentUser.role === 'employee' ? [req.currentUser.id, req.currentUser.id] : []));
  const pCounts = {};
  priorityCounts.forEach(r => { pCounts[r.priority] = r.count; });

  res.render('tickets', {
    title: 'Support Tickets',
    tickets,
    user: req.currentUser,
    status: status || '',
    priority: priority || '',
    q: q || '',
    page: currentPage,
    limit: pageLimit,
    total,
    totalPages,
    counts,
    pCounts
  });
});

// Ticket detail with comments
router.get('/:id', requireAuth, (req, res) => {
  const ticketId = parseInt(req.params.id);
  if (isNaN(ticketId)) {
    return res.status(400).render('error', {
      title: 'Bad Request', status: 400, message: 'Invalid ticket ID.',
      stack: null
    });
  }

  let ticketQuery = `
    SELECT t.*, u.full_name as assigned_name, cu.full_name as creator_name
    FROM tickets t
    LEFT JOIN users u ON t.assigned_to = u.id
    LEFT JOIN users cu ON t.created_by = cu.id
    WHERE t.id = ?
  `;
  let queryParams = [ticketId];

  if (req.currentUser.role === 'employee') {
    ticketQuery += ' AND (t.created_by = ? OR t.assigned_to = ?)';
    queryParams.push(req.currentUser.id, req.currentUser.id);
  }

  const ticket = db.prepare(ticketQuery).get(...queryParams);
  if (!ticket) {
    return res.status(404).render('error', {
      title: 'Not Found', status: 404, message: 'Ticket not found.',
      stack: null
    });
  }

  const comments = db.prepare(`
    SELECT tc.*, u.full_name as author_name, u.role as author_role
    FROM ticket_comments tc
    JOIN users u ON tc.user_id = u.id
    WHERE tc.ticket_id = ?
    ORDER BY tc.created_at ASC
  `).all(ticket.id);

  // Determine if current user can change status
  const canChangeStatus = (req.currentUser.role === 'admin' || req.currentUser.role === 'manager')
    || (ticket.assigned_to === req.currentUser.id)
    || (ticket.created_by === req.currentUser.id);

  // Get all possible status transitions (simplified: any status to any status for admin/manager,
  // limited transitions for owner/assignee)
  let allowedStatuses = [];
  if (canChangeStatus) {
    if (req.currentUser.role === 'admin' || req.currentUser.role === 'manager') {
      allowedStatuses = ['open', 'in_progress', 'resolved', 'closed'];
    } else {
      // Employee/assignee can only transition in forward direction
      switch (ticket.status) {
        case 'open':
          allowedStatuses = ['in_progress'];
          break;
        case 'in_progress':
          allowedStatuses = ['resolved'];
          break;
        case 'resolved':
          allowedStatuses = ['closed'];
          break;
        default:
          allowedStatuses = [];
      }
    }
  }

  res.render('ticket-detail', {
    title: ticket.subject,
    ticket,
    comments,
    canChangeStatus,
    allowedStatuses,
    user: req.currentUser
  });
});

// SECURITY AUDIT FIX: HTML entity sanitizer for defense-in-depth XSS prevention
function sanitizeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Add comment to ticket
router.post('/:id/comment', requireAuth, (req, res) => {
  const ticketId = parseInt(req.params.id);
  if (isNaN(ticketId)) {
    return res.status(400).json({ error: 'Invalid ticket ID.' });
  }

  // RBAC check for viewing ticket
  let ticketQuery = 'SELECT * FROM tickets WHERE id = ?';
  let ticketParams = [ticketId];
  if (req.currentUser.role === 'employee') {
    ticketQuery += ' AND (created_by = ? OR assigned_to = ?)';
    ticketParams.push(req.currentUser.id, req.currentUser.id);
  }
  const ticket = db.prepare(ticketQuery).get(...ticketParams);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found.' });
  }

  const content = (req.body.content || '').trim();
  if (!content) {
    return res.status(400).json({ error: 'Comment content is required.' });
  }
  if (content.length > 5000) {
    return res.status(400).json({ error: 'Comment too long (max 5000 characters).' });
  }

  // SECURITY AUDIT FIX: Sanitize HTML entities before storing to prevent stored XSS
  const safeContent = sanitizeHtml(content);

  db.prepare(`
    INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
    VALUES (?, ?, ?, datetime('now'))
  `).run(ticket.id, req.currentUser.id, safeContent);

  db.prepare('UPDATE tickets SET updated_at = datetime(\'now\') WHERE id = ?').run(ticket.id);

  // ─── BL-4: Auto-escalate ticket priority based on comment keywords ───
  // Scans new comment for escalation trigger words.
  // This is a legitimate "auto-triage" business feature that can be
  // exploited to force false escalations through carefully crafted comments.
  function autoEscalatePriority(currentPriority, commentText) {
    const priorityOrder = { 'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3 };
    const line = commentText.toLowerCase();

    let targetLevel = priorityOrder[currentPriority] || 0;

    // Keywords scanned (case-insensitive, anywhere in comment)
    // These are the business-defined escalation triggers.
    const triggers = {
      2: ['urgent', '急', '紧急', 'asap', 'immediately', 'critical issue'],
      3: ['数据泄露', 'data breach', 'security breach', 'system outage',
          '系统宕机', 'down', 'unavailable', 'customer data exposed',
          'production down', 'service down', 'P0', 'severity 0'],
    };

    for (const [level, words] of Object.entries(triggers)) {
      if (parseInt(level) > targetLevel) {
        for (const w of words) {
          if (line.includes(w)) {
            targetLevel = parseInt(level);
            break;
          }
        }
      }
    }

    const levels = ['Low', 'Medium', 'High', 'Critical'];
    return levels[targetLevel] || currentPriority;
  }

  const originalPriority = ticket.priority;
  const escalatedPriority = autoEscalatePriority(originalPriority, content);

  if (escalatedPriority !== originalPriority) {
    db.prepare(`
      UPDATE tickets SET priority = ?, updated_at = datetime('now') WHERE id = ?
    `).run(escalatedPriority, ticket.id);

    // Silent system comment for the escalation
    db.prepare(`
      INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
      VALUES (?, ?, ?, datetime('now'))
    `).run(ticket.id, req.currentUser.id,
      `[System] Priority auto-adjusted from "${originalPriority}" to "${escalatedPriority}" based on comment content analysis.`);
  }

  // If JSON request, return JSON; otherwise redirect
  if (req.accepts('html')) {
    return res.redirect('/tickets/' + ticket.id);
  }
  return res.json({ success: true, message: 'Comment added.', priorityUpdated: escalatedPriority !== originalPriority });
});

// Update ticket status
router.post('/:id/status', requireAuth, (req, res) => {
  const ticketId = parseInt(req.params.id);
  if (isNaN(ticketId)) {
    return res.status(400).json({ error: 'Invalid ticket ID.' });
  }

  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found.' });
  }

  // Determine if user can change status
  const canChangeStatus = (req.currentUser.role === 'admin' || req.currentUser.role === 'manager')
    || (ticket.assigned_to === req.currentUser.id)
    || (ticket.created_by === req.currentUser.id);

  if (!canChangeStatus) {
    return res.status(403).json({ error: 'You do not have permission to change this ticket status.' });
  }

  const newStatus = (req.body.status || '').trim();
  const validStatuses = ['open', 'in_progress', 'resolved', 'closed'];
  if (!validStatuses.includes(newStatus)) {
    return res.status(400).json({ error: `Invalid status. Allowed: ${validStatuses.join(', ')}.` });
  }

  // For non-admin/non-manager, validate forward-only transition
  if (!(req.currentUser.role === 'admin' || req.currentUser.role === 'manager')) {
    let allowed = false;
    switch (ticket.status) {
      case 'open': allowed = newStatus === 'in_progress'; break;
      case 'in_progress': allowed = newStatus === 'resolved'; break;
      case 'resolved': allowed = newStatus === 'closed'; break;
      default: allowed = false;
    }
    if (!allowed) {
      return res.status(400).json({ error: `Cannot transition from "${ticket.status}" to "${newStatus}".` });
    }
  }

  db.prepare(`
    UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id = ?
  `).run(newStatus, ticket.id);

  // Add automatic comment for status change
  db.prepare(`
    INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
    VALUES (?, ?, ?, datetime('now'))
  `).run(ticket.id, req.currentUser.id,
    `Status changed from "${ticket.status}" to "${newStatus}".`);

  if (req.accepts('html')) {
    return res.redirect('/tickets/' + ticket.id);
  }
  return res.json({ success: true, message: 'Status updated.', status: newStatus });
});

module.exports = router;

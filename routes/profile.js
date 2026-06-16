const express = require('express');
const router = express.Router();
const db = require('../config/database');

// FIXED: Authentication middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).send('Authentication required');
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).send('Invalid session');
  }
  next();
}

// FIX: Root profile redirects to own profile
router.get('/', requireAuth, (req, res) => {
  const token = req.cookies?.session_token;
  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ?').get(token);
  if (session) {
    res.redirect(`/profile/${session.user_id}`);
  } else {
    res.status(401).send('Authentication required');
  }
});

// User profile page - requires authentication
// FIXED: IDOR - users can only view their own profile (admin exception)
router.get('/:id', requireAuth, (req, res, next) => {
  try {
    const token = req.cookies?.session_token;
    const session = db.prepare('SELECT user_id, role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?').get(token);
    const currentUserId = session?.user_id;
    const currentUserRole = session?.role;

    // FIX: Block non-admin users from viewing other profiles
    if (Number(req.params.id) !== currentUserId && currentUserRole !== 'admin') {
      const err = new Error(`Employee not found`);
      err.status = 404;
      return next(err);
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);

    if (!user) {
      const err = new Error(`Employee not found`);
      err.status = 404;
      return next(err);
    }

    // SECURITY AUDIT FIX: Include all non-sensitive fields that the template expects
    const safeUser = {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      email: user.email,
      department: user.department,
      role: user.role,
      phone: user.phone,
      tier: user.tier,                // SECURITY FIX: Added for template compatibility
      region: user.region,            // SECURITY FIX: Added for template compatibility
      onboarding_date: user.onboarding_date,  // SECURITY FIX: Added for template compatibility
      last_login: user.last_login     // SECURITY FIX: Added for template compatibility
    };

    // Get recent messages (only admins see body content)
    const bodyField = currentUserRole === 'admin' ? ', m.body' : '';
    const messages = db.prepare(`
      SELECT m.id, m.subject${bodyField}, m.created_at, u.full_name as from_name
      FROM messages m
      JOIN users u ON m.from_user_id = u.id
      WHERE m.to_user_id = ?
      ORDER BY m.created_at DESC
      LIMIT 5
    `).all(user.id);

    res.render('profile', {
      title: user.full_name,
      user: safeUser,
      messages: messages
    });
  } catch (err) {
    err.detail = `Error loading profile`;
    next(err);
  }
});

module.exports = router;

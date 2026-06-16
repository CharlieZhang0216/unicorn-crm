const db = require('../config/database');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    if (req.accepts('html')) {
      return res.status(401).redirect('/auth/login');
    }
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    res.clearCookie('session_token');
    if (req.accepts('html')) {
      return res.status(401).redirect('/auth/login');
    }
    return res.status(401).json({ error: 'Session expired' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  req.currentUser = user;
  next();
}

module.exports = { requireAuth };

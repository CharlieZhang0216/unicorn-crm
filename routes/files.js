const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../config/database');

const UPLOADS_DIR = path.join(__dirname, '..', 'public', 'uploads');

// FIXED: Authentication middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  next();
}

// File browser page - requires authentication
router.get('/', requireAuth, (req, res) => {
  let files = [];
  try {
    files = fs.readdirSync(UPLOADS_DIR).filter(f => !f.startsWith('.'));
  } catch (e) {
    // ignore
  }
  res.render('files', { title: 'Document Center', files });
});

// FIXED: Directory traversal protection - requires authentication
router.get('/download', requireAuth, (req, res, next) => {
  const filename = req.query.filename;
  if (!filename) {
    return res.status(400).send('Missing filename parameter');
  }

  // FIX: Use path.basename to strip directory traversal
  const safeFilename = path.basename(filename);

  // FIX: Resolve path safely within uploads directory
  // Only allow files actually in the uploads directory
  const filePath = path.resolve(path.join(UPLOADS_DIR, safeFilename));

  // FIX: Verify the resolved path is still within the uploads directory
  if (!filePath.startsWith(UPLOADS_DIR)) {
    const err = new Error('Forbidden');
    err.status = 403;
    return next(err);
  }

  try {
    if (!fs.existsSync(filePath)) {
      const err = new Error(`File not found: ${filename}`);
      err.status = 404;
      return next(err);
    }

    res.sendFile(filePath, { dotfiles: 'deny' });
  } catch (err) {
    err.detail = `Error accessing file: ${filePath}`;
    next(err);
  }
});

module.exports = router;

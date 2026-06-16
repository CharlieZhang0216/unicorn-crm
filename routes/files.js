const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../config/database');

const UPLOADS_DIR = path.join(__dirname, '..', 'storage', 'uploads');

// ─── Authentication Middleware ───
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  req.userId = session.user_id;
  next();
}

// ─── Ensure uploads table exists ───
function ensureUploadsTable() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS uploads (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      entity_type TEXT DEFAULT 'document',
      entity_id TEXT DEFAULT NULL,
      uploaded_by INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (uploaded_by) REFERENCES users(id)
    );
  `);
}
ensureUploadsTable();

// ─── Generate unique stored filename ───
function generateStoredName(ext) {
  const { v4: uuidv4 } = require('uuid');
  return `${uuidv4()}.${ext}`;
}

// ─── Magic byte validation ───
function validateMagicBytes(fileBuffer, mimeType) {
  if (!fileBuffer || fileBuffer.length < 4) return false;
  const header = fileBuffer.toString('hex', 0, Math.min(12, fileBuffer.length));

  if (mimeType === 'image/jpeg') return header.startsWith('ffd8ff');
  if (mimeType === 'image/png') return header.startsWith('89504e47');
  if (mimeType === 'image/gif') return header.startsWith('474946');
  if (mimeType === 'application/pdf') return header.startsWith('25504446');
  if (mimeType === 'application/msword' || mimeType === 'application/vnd.ms-excel')
    return header.startsWith('d0cf11e0');
  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      mimeType === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return header.startsWith('504b0304');
  if (mimeType === 'text/csv' || mimeType === 'text/plain') return true;
  return false;
}

// ─── Helper: format file size ───
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// ═════════════════════════════════════════════════════════════════
// GET /files — Document Center (list + upload form)
// ═════════════════════════════════════════════════════════════════
router.get('/', requireAuth, (req, res) => {
  const userId = req.userId;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const isAdmin = user && user.role === 'admin';

  let files;
  if (isAdmin) {
    files = db.prepare(`
      SELECT u.*, us.full_name AS uploaded_by_name
      FROM uploads u
      LEFT JOIN users us ON u.uploaded_by = us.id
      ORDER BY u.created_at DESC
    `).all();
  } else {
    files = db.prepare(`
      SELECT u.*, us.full_name AS uploaded_by_name
      FROM uploads u
      LEFT JOIN users us ON u.uploaded_by = us.id
      WHERE u.uploaded_by = ?
      ORDER BY u.created_at DESC
    `).all();
  }

  res.render('files', {
    title: 'Document Center',
    user,
    files,
    formatSize: formatFileSize,
    isAdmin
  });
});

// ═════════════════════════════════════════════════════════════════
// POST /files/upload — Upload document (with security)
// ═════════════════════════════════════════════════════════════════
const multer = require('multer');
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xlsx', 'xls', 'csv', 'txt'];
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    if (!allowed.includes(ext)) {
      return cb(new Error(`File type .${ext} is not allowed.`), false);
    }
    cb(null, true);
  }
});

router.post('/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File exceeds 10MB limit.' });
      }
      return res.status(400).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file selected.' });
    }

    const file = req.file;

    // 1. Validate magic bytes
    if (!validateMagicBytes(file.buffer, file.mimetype)) {
      return res.status(400).json({ error: 'File content does not match its declared type. Upload rejected.' });
    }

    // 2. Generate safe filename + store
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    const storedName = generateStoredName(ext);
    const storedPath = path.join(UPLOADS_DIR, storedName);

    // 3. Ensure storage dir
    if (!fs.existsSync(UPLOADS_DIR)) {
      fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    }

    // 4. Write file
    try {
      fs.writeFileSync(storedPath, file.buffer);
    } catch (writeErr) {
      console.error('Failed to write file:', writeErr);
      return res.status(500).json({ error: 'Failed to save file.' });
    }

    // 5. Save metadata to DB
    const { v4: uuidv4 } = require('uuid');
    const fileId = uuidv4();
    db.prepare(`
      INSERT INTO uploads (id, filename, original_name, mime_type, size, entity_type, uploaded_by)
      VALUES (?, ?, ?, ?, ?, 'document', ?)
    `).run(fileId, storedName, file.originalname, file.mimetype, file.size, req.userId);

    res.json({
      success: true,
      fileId,
      originalName: file.originalname,
      size: file.size,
      sizeFormatted: formatFileSize(file.size)
    });
  });
});

// ═════════════════════════════════════════════════════════════════
// GET /files/download — Download file
// ═════════════════════════════════════════════════════════════════
router.get('/download', requireAuth, (req, res, next) => {
  const fileId = req.query.id;

  // Path traversal guard
  if (!fileId || fileId.includes('..') || fileId.includes('/') || fileId.includes('\\')) {
    return res.status(400).send('Invalid file ID');
  }

  try {
    const row = db.prepare('SELECT * FROM uploads WHERE id = ?').get(fileId);
    if (!row) {
      const err = new Error('File not found');
      err.status = 404;
      return next(err);
    }

    // Access control: admin sees all, regular users see own
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
    if (user.role !== 'admin' && row.uploaded_by !== req.userId) {
      const err = new Error('Access denied');
      err.status = 403;
      return next(err);
    }

    const filePath = path.resolve(path.join(UPLOADS_DIR, row.filename));
    const resolvedDir = path.resolve(UPLOADS_DIR);

    // Double-check path traversal
    if (!filePath.startsWith(resolvedDir)) {
      const err = new Error('Forbidden');
      err.status = 403;
      return next(err);
    }

    if (!fs.existsSync(filePath)) {
      const err = new Error('File not found on disk');
      err.status = 404;
      return next(err);
    }

    res.setHeader('Content-Type', row.mime_type);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(row.original_name)}"`);
    res.setHeader('Content-Length', row.size);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.sendFile(filePath, { dotfiles: 'deny' });
  } catch (err) {
    next(err);
  }
});

// ═════════════════════════════════════════════════════════════════
// POST /files/delete — Delete file (owner or admin)
// ═════════════════════════════════════════════════════════════════
router.post('/delete', requireAuth, (req, res) => {
  const fileId = req.body.id;

  if (!fileId || fileId.includes('..') || fileId.includes('/') || fileId.includes('\\')) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  try {
    const row = db.prepare('SELECT * FROM uploads WHERE id = ?').get(fileId);
    if (!row) {
      return res.status(404).json({ error: 'File not found' });
    }

    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
    if (user.role !== 'admin' && row.uploaded_by !== req.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete from disk
    const filePath = path.resolve(path.join(UPLOADS_DIR, row.filename));
    const resolvedDir = path.resolve(UPLOADS_DIR);
    if (filePath.startsWith(resolvedDir) && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from DB
    db.prepare('DELETE FROM uploads WHERE id = ?').run(fileId);

    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

module.exports = router;

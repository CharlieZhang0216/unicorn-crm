/**
 * File Upload System - Enterprise Security Standards
 *
 * Features:
 * - File type whitelist validation via magic bytes
 * - UUID-based randomized filenames
 * - Storage outside webroot
 * - Size limits per upload type
 * - SQLite metadata tracking
 * - Full audit logging
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// ─── Configuration ────────────────────────────────────────────────

const STORAGE_DIR = path.join(__dirname, '..', 'storage', 'uploads');
const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xlsx', 'xls', 'csv', 'txt'];
const ALLOWED_MIME_TYPES = {
  'image/jpeg': ['jpg', 'jpeg'],
  'image/png': ['png'],
  'image/gif': ['gif'],
  'application/pdf': ['pdf'],
  'application/msword': ['doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx'],
  'application/vnd.ms-excel': ['xls'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx'],
  'text/csv': ['csv'],
  'text/plain': ['txt']
};
const AVATAR_MAX_SIZE = 2 * 1024 * 1024;   // 2MB
const ATTACHMENT_MAX_SIZE = 10 * 1024 * 1024; // 10MB

// ─── Ensure Storage Directory Exists ─────────────────────────────

function ensureStorageDir() {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }
}
ensureStorageDir();

// ─── Audit Logger ─────────────────────────────────────────────────

function auditLog(db, action, details, userId, ip) {
  if (!db) return;
  const stmt = db.prepare(
    `INSERT INTO audit_logs (action, details, user_id, ip_address, created_at) VALUES (?, ?, ?, ?, datetime('now'))`
  );
  stmt.run(action, JSON.stringify(details), userId || null, ip || 'unknown');
}

// ─── Database Setup ───────────────────────────────────────────────

function ensureUploadsTable(db) {
  if (!db) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS uploads (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      entity_type TEXT DEFAULT 'avatar',
      entity_id TEXT DEFAULT NULL,
      uploaded_by INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (uploaded_by) REFERENCES users(id)
    );
  `);
}

// ─── Helper: Validate File Type by Magic Bytes ────────────────────

function validateMagicBytes(fileBuffer, mimeType) {
  if (!fileBuffer || fileBuffer.length < 4) return false;

  const header = fileBuffer.toString('hex', 0, Math.min(12, fileBuffer.length));

  // JPEG: FF D8 FF
  if (mimeType === 'image/jpeg') {
    return header.startsWith('ffd8ff');
  }
  // PNG: 89 50 4E 47
  if (mimeType === 'image/png') {
    return header.startsWith('89504e47');
  }
  // GIF: 47 49 46 38 (GIF8)
  if (mimeType === 'image/gif') {
    return header.startsWith('474946');
  }
  // PDF: 25 50 44 46 (%PDF)
  if (mimeType === 'application/pdf') {
    return header.startsWith('25504446');
  }
  // DOC/XLS (OLE2): D0 CF 11 E0
  if (mimeType === 'application/msword' || mimeType === 'application/vnd.ms-excel') {
    return header.startsWith('d0cf11e0');
  }
  // DOCX/XLSX (ZIP-based Office Open XML): 50 4B 03 04
  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      mimeType === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
    return header.startsWith('504b0304');
  }
  // CSV / TXT: no strict magic bytes, accept if extension matches
  if (mimeType === 'text/csv' || mimeType === 'text/plain') {
    return true; // No reliable magic bytes for plain text
  }
  return false;
}

// ─── Helper: Get Extension from MIME Type ────────────────────────

function getExtension(mimeType, fallbackExt) {
  if (ALLOWED_MIME_TYPES[mimeType] && ALLOWED_MIME_TYPES[mimeType].length > 0) {
    return ALLOWED_MIME_TYPES[mimeType][0];
  }
  return fallbackExt || 'bin';
}

// ─── Multer Configuration ────────────────────────────────────────

const storage = multer.memoryStorage(); // Store in memory for magic byte validation

function createMulter(maxSize) {
  return multer({
    storage: storage,
    limits: {
      fileSize: maxSize,
      files: 1
    },
    fileFilter: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return cb(new Error(`File type .${ext} is not allowed. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
      }
      cb(null, true);
    }
  });
}

// ─── Middleware: Authentication ───────────────────────────────────

// ─── Mount: Attach DB reference ──────────────────────────────────

router.use((req, res, next) => {
  // Expect db to be attached to req from upstream middleware
  if (req.app.locals.db) {
    ensureUploadsTable(req.app.locals.db);
  }
  next();
});

// ═══════════════════════════════════════════════════════════════════
// POST /upload/avatar — Upload user avatar
// ═══════════════════════════════════════════════════════════════════

router.post('/avatar', requireAuth, (req, res) => {
  const upload = createMulter(AVATAR_MAX_SIZE).single('avatar');

  upload(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'Avatar must be under 2MB' });
        }
        return res.status(400).json({ error: `Upload error: ${err.message}` });
      }
      return res.status(400).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const db = req.app.locals.db;
    const file = req.file;
    const ext = getExtension(file.mimetype, path.extname(file.originalname).replace('.', ''));
    const storedName = `${uuidv4()}.${ext}`;
    const storedPath = path.join(STORAGE_DIR, storedName);

    // Validate magic bytes
    if (!validateMagicBytes(file.buffer, file.mimetype)) {
      return res.status(400).json({
        error: 'File content does not match its declared type. Upload rejected.'
      });
    }

    // Check file type whitelist
    if (!ALLOWED_MIME_TYPES[file.mimetype]) {
      return res.status(400).json({
        error: `MIME type ${file.mimetype} is not allowed.`
      });
    }

    try {
      // Write file to storage
      fs.writeFileSync(storedPath, file.buffer);

      // Save metadata
      const fileId = uuidv4();
      const stmt = db.prepare(
        `INSERT INTO uploads (id, filename, original_name, mime_type, size, entity_type, entity_id, uploaded_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      );
      stmt.run(fileId, storedName, file.originalname, file.mimetype, file.size,
        'avatar', null, req.currentUser.id);

      // Audit log
      auditLog(db, 'AVATAR_UPLOAD', {
        fileId,
        originalName: file.originalname,
        storedName,
        size: file.size,
        mimeType: file.mimetype
      }, req.currentUser.id, req.ip);

      return res.json({
        success: true,
        fileId,
        filename: storedName,
        originalName: file.originalname,
        size: file.size,
        url: `/upload/download/${fileId}`
      });
    } catch (writeErr) {
      console.error('Failed to save file:', writeErr);
      return res.status(500).json({ error: 'Failed to save file' });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════
// POST /upload/attachment/:entityType/:entityId — Upload attachment
// ═══════════════════════════════════════════════════════════════════

router.post('/attachment/:entityType/:entityId', requireAuth, (req, res) => {
  const { entityType, entityId } = req.params;
  const allowedEntities = ['customer', 'ticket', 'order'];

  if (!allowedEntities.includes(entityType)) {
    return res.status(400).json({
      error: `Invalid entity type. Must be one of: ${allowedEntities.join(', ')}`
    });
  }

  const upload = createMulter(ATTACHMENT_MAX_SIZE).single('file');

  upload(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'Attachment must be under 10MB' });
        }
        return res.status(400).json({ error: `Upload error: ${err.message}` });
      }
      return res.status(400).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const db = req.app.locals.db;
    const file = req.file;
    const ext = getExtension(file.mimetype, path.extname(file.originalname).replace('.', ''));
    const storedName = `${uuidv4()}.${ext}`;
    const storedPath = path.join(STORAGE_DIR, storedName);

    // Validate magic bytes
    if (!validateMagicBytes(file.buffer, file.mimetype)) {
      return res.status(400).json({
        error: 'File content does not match its declared type. Upload rejected.'
      });
    }

    // Check file type whitelist
    if (!ALLOWED_MIME_TYPES[file.mimetype]) {
      return res.status(400).json({
        error: `MIME type ${file.mimetype} is not allowed.`
      });
    }

    try {
      fs.writeFileSync(storedPath, file.buffer);

      const fileId = uuidv4();
      const stmt = db.prepare(
        `INSERT INTO uploads (id, filename, original_name, mime_type, size, entity_type, entity_id, uploaded_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      );
      stmt.run(fileId, storedName, file.originalname, file.mimetype, file.size,
        entityType, entityId, req.currentUser.id);

      auditLog(db, 'ATTACHMENT_UPLOAD', {
        fileId,
        originalName: file.originalname,
        storedName,
        size: file.size,
        entityType,
        entityId,
        mimeType: file.mimetype
      }, req.currentUser.id, req.ip);

      return res.json({
        success: true,
        fileId,
        filename: storedName,
        originalName: file.originalname,
        size: file.size,
        entityType,
        entityId,
        url: `/upload/download/${fileId}`
      });
    } catch (writeErr) {
      console.error('Failed to save attachment:', writeErr);
      return res.status(500).json({ error: 'Failed to save file' });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════
// GET /upload/files — List files for current user
// ═══════════════════════════════════════════════════════════════════

router.get('/files', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = req.currentUser.id;
  const isAdmin = req.currentUser.role === 'admin';

  let query;
  let params;

  if (isAdmin) {
    // Admin sees all files
    query = `SELECT id, filename, original_name, mime_type, size, entity_type, entity_id, uploaded_by, created_at
             FROM uploads ORDER BY created_at DESC`;
    params = [];
  } else {
    // Regular user sees own files
    query = `SELECT id, filename, original_name, mime_type, size, entity_type, entity_id, uploaded_by, created_at
             FROM uploads WHERE uploaded_by = ? ORDER BY created_at DESC`;
    params = [userId];
  }

  try {
    const rows = db.prepare(query).all(...params);
    return res.json({ files: rows });
  } catch (err) {
    console.error('Failed to list files:', err);
    return res.status(500).json({ error: 'Failed to retrieve files' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// GET /upload/download/:fileId — Download file
// ═══════════════════════════════════════════════════════════════════

router.get('/download/:fileId', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { fileId } = req.params;

  // Prevent path traversal
  if (fileId.includes('..') || fileId.includes('/') || fileId.includes('\\')) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  try {
    const row = db.prepare('SELECT * FROM uploads WHERE id = ?').get(fileId);
    if (!row) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Check access: admin or owner
    const isAdmin = req.currentUser.role === 'admin';
    const isOwner = row.uploaded_by === req.currentUser.id;
    if (!isAdmin && !isOwner) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const filePath = path.join(STORAGE_DIR, row.filename);

    // Prevent path traversal (double check)
    const resolvedPath = path.resolve(filePath);
    const resolvedStorage = path.resolve(STORAGE_DIR);
    if (!resolvedPath.startsWith(resolvedStorage)) {
      return res.status(400).json({ error: 'Invalid file path' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    // Audit log
    auditLog(db, 'FILE_DOWNLOAD', {
      fileId,
      filename: row.filename,
      originalName: row.original_name
    }, req.currentUser.id, req.ip);

    // Set headers
    res.setHeader('Content-Type', row.mime_type);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(row.original_name)}"`);
    res.setHeader('Content-Length', row.size);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } catch (err) {
    console.error('Failed to download file:', err);
    return res.status(500).json({ error: 'Download failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// DELETE /upload/:fileId — Delete file (admin or uploader only)
// ═══════════════════════════════════════════════════════════════════

router.delete('/:fileId', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { fileId } = req.params;

  // Prevent path traversal
  if (fileId.includes('..') || fileId.includes('/') || fileId.includes('\\')) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  try {
    const row = db.prepare('SELECT * FROM uploads WHERE id = ?').get(fileId);
    if (!row) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Check access: admin or owner
    const isAdmin = req.currentUser.role === 'admin';
    const isOwner = row.uploaded_by === req.currentUser.id;
    if (!isAdmin && !isOwner) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete from disk
    const filePath = path.join(STORAGE_DIR, row.filename);
    const resolvedPath = path.resolve(filePath);
    const resolvedStorage = path.resolve(STORAGE_DIR);
    if (resolvedPath.startsWith(resolvedStorage) && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database
    db.prepare('DELETE FROM uploads WHERE id = ?').run(fileId);

    // Audit log
    auditLog(db, 'FILE_DELETE', {
      fileId,
      filename: row.filename,
      originalName: row.original_name
    }, req.currentUser.id, req.ip);

    return res.json({ success: true, message: 'File deleted successfully' });
  } catch (err) {
    console.error('Failed to delete file:', err);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

module.exports = router;
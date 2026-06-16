/**
 * Notes routes for Unicorn CRM
 * Rich text notes with DOMPurify sanitization for XSS prevention
 * Frontend: Quill editor (loaded from CDN)
 */

const express = require('express');
const router = express.Router();
const purify = require("isomorphic-dompurify");
const db = require('../config/database');

// Authentication middleware — must be logged in
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
    return res.status(401).redirect('/auth/login');
  }
  req.currentUser = user;
  res.locals.user = user;
  next();
}

// Configure DOMPurify


// Allowed HTML tags for rich text content
const ALLOWED_TAGS = [
  'b', 'i', 'u', 's', 'strong', 'em', 'mark', 'small', 'del', 'ins', 'sub', 'sup',
  'p', 'br', 'hr',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li',
  'a',  // href allowed but validated
  'blockquote', 'pre', 'code',
  'img',  // src allowed but validated
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'div', 'span'
];

// Allowed attributes per tag
const ALLOWED_ATTRS = [
  'href', 'target', 'rel',       // <a>
  'src', 'alt', 'width', 'height', // <img>
  'class', 'style',               // generic (style is stripped by default)
  'colspan', 'rowspan',           // <td>, <th>
  'start', 'type'                 // <ol>
];

/**
 * Sanitize HTML content using DOMPurify
 * Removes: script, style, iframe, object, embed, on* event handlers
 */
function sanitizeHtml(html) {
  if (!html || typeof html !== 'string') return '';

  const clean = purify.sanitize(html, {
    ALLOWED_TAGS: ALLOWED_TAGS,
    ALLOWED_ATTR: ALLOWED_ATTRS,
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],  // Allow target attribute on links
    ALLOW_UNKNOWN_PROTOCOLS: false,
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
  });

  // Ensure all <a> tags have rel="noopener noreferrer" and target="_blank"
  // (This adds security for external links)
  clean.replace(/<a\s/g, (match) => {
    if (!match.includes('rel=')) {
      return '<a rel="noopener noreferrer" target="_blank" ';
    }
    return match;
  });

  return clean;
}

/**
 * GET /notes
 * List current user's notes
 */
router.get('/', requireAuth, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  const notes = db.prepare(`
    SELECT n.id, n.title, n.is_public, n.created_at, n.updated_at,
           CASE WHEN length(n.content) > 200 THEN substr(n.content, 1, 200) || '...' ELSE n.content END as preview
    FROM notes n
    WHERE n.user_id = ?
    ORDER BY n.updated_at DESC
    LIMIT ? OFFSET ?
  `).all(req.currentUser.id, limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM notes WHERE user_id = ?')
    .get(req.currentUser.id).count;

  // Also get public notes from other users
  const publicNotes = db.prepare(`
    SELECT n.id, n.title, n.created_at, n.updated_at,
           u.full_name as author_name,
           CASE WHEN length(n.content) > 200 THEN substr(n.content, 1, 200) || '...' ELSE n.content END as preview
    FROM notes n
    JOIN users u ON u.id = n.user_id
    WHERE n.is_public = 1 AND n.user_id != ?
    ORDER BY n.updated_at DESC
    LIMIT 10
  `).all(req.currentUser.id);

  res.render('notes/index', {
    title: 'My Notes',
    notes: notes,
    publicNotes: publicNotes,
    page: page,
    totalPages: Math.ceil(total / limit),
    total: total,
    user: req.currentUser
  });
});

/**
 * GET /notes/new
 * Show new note form with rich text editor
 */
router.get('/new', requireAuth, (req, res) => {
  res.render('notes/edit', {
    title: 'New Note',
    note: null,
    user: req.currentUser
  });
});

/**
 * POST /notes
 * Create a new note
 */
router.post('/', requireAuth, (req, res) => {
  const { title, content, is_public } = req.body;

  if (!title || !title.trim()) {
    return res.render('notes/edit', {
      title: 'New Note',
      error: 'Title is required.',
      note: { title: title || '', content: content || '', is_public: is_public === '1' },
      user: req.currentUser
    });
  }

  // Sanitize HTML content with DOMPurify
  const cleanContent = sanitizeHtml(content || '');

  const result = db.prepare(`
    INSERT INTO notes (user_id, title, content, is_public)
    VALUES (?, ?, ?, ?)
  `).run(req.currentUser.id, title.trim(), cleanContent, is_public === '1' ? 1 : 0);

  // Audit log
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)')
    .run(req.currentUser.id, 'NOTE_CREATE', JSON.stringify({ note_id: result.lastInsertRowid, title: title.trim() }), req.ip);

  res.redirect(`/notes/${result.lastInsertRowid}`);
});

/**
 * GET /notes/:id
 * View a single note
 */
router.get('/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).render('error', {
      title: 'Invalid Note',
      status: 400,
      message: 'Invalid note ID.',
      stack: null
    });
  }

  const note = db.prepare(`
    SELECT n.*, u.full_name as author_name, u.username as author_username
    FROM notes n
    JOIN users u ON u.id = n.user_id
    WHERE n.id = ?
  `).get(id);

  if (!note) {
    return res.status(404).render('error', {
      title: 'Note Not Found',
      status: 404,
      message: 'The requested note does not exist.',
      stack: null
    });
  }

  // Access control: owner can always view, others only if public
  if (note.user_id !== req.currentUser.id && !note.is_public) {
    return res.status(403).render('error', {
      title: 'Access Denied',
      status: 403,
      message: 'You do not have permission to view this note.',
      stack: null
    });
  }

  res.render('notes/view', {
    title: note.title,
    note: note,
    isOwner: note.user_id === req.currentUser.id,
    user: req.currentUser
  });
});

/**
 * GET /notes/:id/edit
 * Show edit form
 */
router.get('/:id/edit', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).render('error', {
      title: 'Invalid Note',
      status: 400,
      message: 'Invalid note ID.',
      stack: null
    });
  }

  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
  if (!note) {
    return res.status(404).render('error', {
      title: 'Note Not Found',
      status: 404,
      message: 'Note not found.',
      stack: null
    });
  }

  if (note.user_id !== req.currentUser.id) {
    return res.status(403).render('error', {
      title: 'Access Denied',
      status: 403,
      message: 'You can only edit your own notes.',
      stack: null
    });
  }

  res.render('notes/edit', {
    title: 'Edit Note',
    note: note,
    user: req.currentUser
  });
});

/**
 * PUT /notes/:id
 * Update a note (also handles POST for browser compatibility)
 */
router.put('/:id', requireAuth, (req, res) => {
  updateNote(req, res);
});

router.post('/:id/update', requireAuth, (req, res) => {
  updateNote(req, res);
});

function updateNote(req, res) {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid note ID' });
  }

  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
  if (!note) {
    return res.status(404).json({ error: 'Note not found' });
  }
  if (note.user_id !== req.currentUser.id) {
    return res.status(403).json({ error: 'You can only edit your own notes' });
  }

  const { title, content, is_public } = req.body;
  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'Title is required' });
  }

  const cleanContent = sanitizeHtml(content || '');

  db.prepare(`
    UPDATE notes SET title = ?, content = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(title.trim(), cleanContent, is_public === '1' ? 1 : 0, id);

  // Audit log
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)')
    .run(req.currentUser.id, 'NOTE_UPDATE', JSON.stringify({ note_id: id }), req.ip);

  if (req.accepts('html')) {
    return res.redirect(`/notes/${id}`);
  }
  res.json({ success: true, message: 'Note updated' });
}

/**
 * DELETE /notes/:id
 * Delete a note
 */
router.delete('/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid note ID' });
  }

  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
  if (!note) {
    return res.status(404).json({ error: 'Note not found' });
  }
  if (note.user_id !== req.currentUser.id) {
    return res.status(403).json({ error: 'You can only delete your own notes' });
  }

  db.prepare('DELETE FROM notes WHERE id = ?').run(id);

  // Audit log
  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)')
    .run(req.currentUser.id, 'NOTE_DELETE', JSON.stringify({ note_id: id, title: note.title }), req.ip);

  if (req.accepts('html')) {
    return res.redirect('/notes');
  }
  res.json({ success: true, message: 'Note deleted' });
});

// POST for form-based delete
router.post('/:id/delete', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.redirect('/notes');
  }

  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
  if (!note || note.user_id !== req.currentUser.id) {
    return res.redirect('/notes');
  }

  db.prepare('DELETE FROM notes WHERE id = ?').run(id);

  db.prepare('INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)')
    .run(req.currentUser.id, 'NOTE_DELETE', JSON.stringify({ note_id: id, title: note.title }), req.ip);

  res.redirect('/notes');
});

module.exports = router;

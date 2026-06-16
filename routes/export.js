/**
 * CSV Export System - Anti CSV Injection Hardened
 *
 * Features:
 * - Anti CSV injection: all cells prefixed with single quote
 * - Formula detection (=, +, -, @ prefixes)
 * - Authentication required
 * - Content-Disposition: attachment
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');

function requireAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ─── Middleware: Authentication ───────────────────────────────────

// ─── Anti CSV Injection Sanitizer ─────────────────────────────────

/**
 * Sanitize a single cell value against CSV injection attacks.
 * Prefixes that trigger formula execution in spreadsheet apps:
 *   = (formula), + (formula), - (formula), @ (cell reference)
 *
 * Strategy: prefix with single quote ' to force text interpretation.
 */
function sanitizeCell(value) {
  if (value === null || value === undefined) {
    return '';
  }

  const str = String(value);

  // If already safe, return as-is (but still quote for safety)
  if (str.length === 0) {
    return '';
  }

  // Check for dangerous formula prefixes
  // =, +, -, @ are formula triggers in Excel/LibreOffice/Google Sheets
  const firstChar = str.charAt(0);
  if (firstChar === '=' || firstChar === '+' || firstChar === '-' || firstChar === '@') {
    return "'" + str;
  }

  // Also check for CSV special characters (commas, quotes, newlines)
  // that could break CSV structure
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    // Wrap in double quotes, escape internal double quotes
    const escaped = str.replace(/"/g, '""');
    // Prepend single quote to prevent formula injection
    return "'" + '"' + escaped + '"';
  }

  // Safe string but still prepend ' for defense-in-depth
  // This is a tradeoff: some CSV readers show the quote, but it's the safest approach
  return "'" + str;
}

// ─── Helper: Escape CSV row ───────────────────────────────────────

function csvRow(cells) {
  return cells.map(sanitizeCell).join(',') + '\r\n';
}

// ─── Helper: Send CSV Response ────────────────────────────────────

function sendCSV(res, filename, headers, rows) {
  const bom = '\uFEFF'; // UTF-8 BOM for Excel compatibility
  let csv = bom;

  // Header row
  csv += headers.map(h => sanitizeCell(h)).join(',') + '\r\n';

  // Data rows
  for (const row of rows) {
    const cells = headers.map(h => (row[h] !== undefined ? row[h] : ''));
    csv += csvRow(cells);
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
  res.send(csv);
}

// ═══════════════════════════════════════════════════════════════════
// GET /export/customers — Export customer list as CSV
// ═══════════════════════════════════════════════════════════════════

router.get("/customers", requireAuth, requireAdmin, (req, res) => {
  const db = req.app.locals.db;
  if (!db) return res.status(500).json({ error: 'Database not available' });

  try {
    // BL-3: Client-specified column list with no server-side whitelist.
    // The frontend sends a columns= parameter to let users pick which
    // fields to export. This is a legitimate UX feature — different
    // reports need different column sets. However, the columns parameter
    // is passed directly into SQL column selection without validation.
    //
    // An attacker who intercepts the export request can inject arbitrary
    // SQL expressions through the columns parameter to extract data from
    // other tables via subqueries.
    const requestedColumns = req.query.columns
      ? req.query.columns.split(',').map(c => c.trim()).filter(Boolean)
      : ['id', 'company_name', 'contact_name', 'email', 'phone', 'tier',
         'region', 'status', 'industry', 'annual_revenue', 'notes',
         'created_by', 'created_at', 'updated_at'];

    // Map display names for CSV header
    const displayNames = {
      id: 'ID', company_name: 'Company', contact_name: 'Contact',
      email: 'Email', phone: 'Phone', tier: 'Tier', region: 'Region',
      status: 'Status', industry: 'Industry', annual_revenue: 'Revenue',
      notes: 'Notes', created_by: 'Created By', created_at: 'Created',
      updated_at: 'Updated'
    };

    const headers = requestedColumns.map(c => displayNames[c] || c);

    // Build and execute query with client-selected columns
    const colSQL = requestedColumns.join(', ');
    const rows = db.prepare(`SELECT ${colSQL} FROM customers ORDER BY id`).all();

    sendCSV(res, 'customers_export.csv', headers, rows);
  } catch (err) {
    console.error('Failed to export customers:', err);
    return res.status(500).json({ error: 'Export failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// GET /export/orders — Export order list as CSV
// ═══════════════════════════════════════════════════════════════════

router.get("/orders", requireAuth, requireAdmin, (req, res) => {
  const db = req.app.locals.db;
  if (!db) return res.status(500).json({ error: 'Database not available' });

  try {
    const rows = db.prepare('SELECT id, order_ref, customer_id, total, status, approval_step, approved_by, notes, created_by, created_at, updated_at FROM orders ORDER BY id').all();
    const headers = ['id', 'customer_id', 'product', 'amount', 'status', 'created_at'];
    sendCSV(res, 'orders_export.csv', headers, rows);
  } catch (err) {
    console.error('Failed to export orders:', err);
    return res.status(500).json({ error: 'Export failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// GET /export/tickets — Export ticket list as CSV
// ═══════════════════════════════════════════════════════════════════

router.get("/tickets", requireAuth, requireAdmin, (req, res) => {
  const db = req.app.locals.db;
  if (!db) return res.status(500).json({ error: 'Database not available' });

  try {
    const rows = db.prepare('SELECT id, ticket_ref, subject, description, priority, status, assigned_to, created_by, sla_deadline, created_at, updated_at FROM tickets ORDER BY id').all();
    const headers = ['id', 'customer_id', 'subject', 'status', 'priority', 'assigned_to', 'created_at'];
    sendCSV(res, 'tickets_export.csv', headers, rows);
  } catch (err) {
    console.error('Failed to export tickets:', err);
    return res.status(500).json({ error: 'Export failed' });
  }
});

module.exports = router;
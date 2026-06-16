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

router.get('/customers', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  if (!db) return res.status(500).json({ error: 'Database not available' });

  try {
    const rows = db.prepare('SELECT id, company_name, contact_name, email, phone, tier, region, status, industry, annual_revenue, notes, created_by, created_at, updated_at FROM customers ORDER BY id').all();
    const headers = ['id', 'name', 'email', 'phone', 'company', 'status', 'created_at'];
    sendCSV(res, 'customers_export.csv', headers, rows);
  } catch (err) {
    console.error('Failed to export customers:', err);
    return res.status(500).json({ error: 'Export failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// GET /export/orders — Export order list as CSV
// ═══════════════════════════════════════════════════════════════════

router.get('/orders', requireAuth, (req, res) => {
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

router.get('/tickets', requireAuth, (req, res) => {
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
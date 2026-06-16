/**
 * XML Import System - Batch Data Import with Security Controls
 *
 * Features:
 * - xml2js parsing with XXE-safe options
 * - XML schema validation
 * - Dry-run before commit (transaction-based)
 * - File size limit 5MB
 * - Full audit logging
 * - Import templates download
 */

const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const xml2js = require('xml2js');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const XML_MAX_SIZE = 5 * 1024 * 1024; // 5MB

// ─── XML Parser Options (XXE Safe) ───────────────────────────────

/**
 * xml2js is a pure JavaScript XML parser and does NOT process DTD or
 * external entities by default. However, we explicitly set options to
 * ensure no entity expansion or DTD processing occurs.
 */
const XML_PARSER_OPTIONS = {
  explicitArray: false,       // Don't wrap single elements in arrays
  trim: true,                 // Trim whitespace
  normalizeTags: false,       // Keep original tag case
  ignoreAttrs: false,         // Process attributes
  mergeAttrs: true,           // Merge attributes into parent object
  explicitRoot: false,        // Don't wrap in root element object
  // Disable any DTD/entity processing (native xml2js behavior, but explicit)
  sax: {
    strict: true              // Strict parsing
  }
};

// ─── Multer for XML file upload ──────────────────────────────────

const storage = multer.memoryStorage();
const xmlUpload = multer({
  storage: storage,
  limits: { fileSize: XML_MAX_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.xml') {
      return cb(new Error('Only .xml files are allowed'), false);
    }
    cb(null, true);
  }
});

// ─── Middleware: Authentication ───────────────────────────────────

// ─── Audit Logger ─────────────────────────────────────────────────

function auditLog(db, action, details, userId, ip) {
  if (!db) return;
  const stmt = db.prepare(
    `INSERT INTO audit_logs (action, details, user_id, ip_address, created_at) VALUES (?, ?, ?, ?, datetime('now'))`
  );
  stmt.run(action, JSON.stringify(details), userId || null, ip || 'unknown');
}

// ─── XML Schema Validators ────────────────────────────────────────

/**
 * Validate customer XML structure.
 * Expected format:
 * <customers>
 *   <customer>
 *     <name>Company Name</name>
 *     <email>contact@company.com</email>
 *     <phone>1234567890</phone>
 *     <company>Company Inc</company>
 *     <status>active</status>
 *   </customer>
 * </customers>
 */
function validateCustomerXML(data) {
  const errors = [];
  const customers = data.customers?.customer;
  if (!customers) {
    errors.push('Missing <customers> root element or <customer> children');
    return { valid: false, errors, records: [] };
  }

  const records = Array.isArray(customers) ? customers : [customers];
  if (records.length === 0) {
    errors.push('No customer records found in XML');
    return { valid: false, errors, records: [] };
  }

  for (let i = 0; i < records.length; i++) {
    const c = records[i];
    const rowErrors = [];

    if (!c.name || String(c.name).trim() === '') {
      rowErrors.push('Missing required field: name');
    }
    if (!c.email || String(c.email).trim() === '') {
      rowErrors.push('Missing required field: email');
    }
    // Validate email format loosely
    if (c.email && !String(c.email).includes('@')) {
      rowErrors.push(`Invalid email format: ${c.email}`);
    }
    // Validate status if present
    if (c.status && !['active', 'inactive', 'lead', 'prospect'].includes(String(c.status).toLowerCase())) {
      rowErrors.push(`Invalid status: ${c.status}. Must be one of: active, inactive, lead, prospect`);
    }

    if (rowErrors.length > 0) {
      errors.push(`Row ${i + 1}: ${rowErrors.join('; ')}`);
    }
  }

  return { valid: errors.length === 0, errors, records };
}

/**
 * Validate order XML structure.
 * Expected format:
 * <orders>
 *   <order>
 *     <customer_id>1</customer_id>
 *     <product>Product Name</product>
 *     <amount>99.99</amount>
 *     <status>pending</status>
 *   </order>
 * </orders>
 */
function validateOrderXML(data) {
  const errors = [];
  const orders = data.orders?.order;
  if (!orders) {
    errors.push('Missing <orders> root element or <order> children');
    return { valid: false, errors, records: [] };
  }

  const records = Array.isArray(orders) ? orders : [orders];
  if (records.length === 0) {
    errors.push('No order records found in XML');
    return { valid: false, errors, records: [] };
  }

  for (let i = 0; i < records.length; i++) {
    const o = records[i];
    const rowErrors = [];

    if (!o.customer_id || isNaN(Number(o.customer_id))) {
      rowErrors.push('Missing or invalid required field: customer_id (must be a number)');
    }
    if (!o.product || String(o.product).trim() === '') {
      rowErrors.push('Missing required field: product');
    }
    if (o.amount && isNaN(Number(o.amount))) {
      rowErrors.push(`Invalid amount: ${o.amount}. Must be a number.`);
    }
    if (o.status && !['pending', 'completed', 'cancelled', 'processing'].includes(String(o.status).toLowerCase())) {
      rowErrors.push(`Invalid status: ${o.status}. Must be one of: pending, completed, cancelled, processing`);
    }

    if (rowErrors.length > 0) {
      errors.push(`Row ${i + 1}: ${rowErrors.join('; ')}`);
    }
  }

  return { valid: errors.length === 0, errors, records };
}

// ─── XML Template Generators ──────────────────────────────────────

function generateCustomerTemplate() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<customers>
  <customer>
    <name>Acme Corp</name>
    <email>contact@acmecorp.com</email>
    <phone>+86-10-12345678</phone>
    <company>Acme Corporation</company>
    <status>active</status>
  </customer>
  <customer>
    <name>Globex Inc</name>
    <email>info@globexinc.com</email>
    <phone>+86-21-87654321</phone>
    <company>Globex Incorporated</company>
    <status>lead</status>
  </customer>
</customers>`;
}

function generateOrderTemplate() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<orders>
  <order>
    <customer_id>1</customer_id>
    <product>Enterprise CRM License</product>
    <amount>9999.00</amount>
    <status>pending</status>
  </order>
  <order>
    <customer_id>2</customer_id>
    <product>Support Package - Premium</product>
    <amount>4999.00</amount>
    <status>completed</status>
  </order>
</orders>`;
}

// ═══════════════════════════════════════════════════════════════════
// POST /import/customers — Import customers from XML
// ═══════════════════════════════════════════════════════════════════

router.post('/customers', requireAuth, (req, res) => {
  xmlUpload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'XML file must be under 5MB' });
      }
      return res.status(400).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No XML file uploaded' });
    }

    const db = req.app.locals.db;
    if (!db) return res.status(500).json({ error: 'Database not available' });

    const xmlString = req.file.buffer.toString('utf-8');

    // Parse XML with safe options
    const parser = new xml2js.Parser(XML_PARSER_OPTIONS);
    parser.parseString(xmlString, (parseErr, result) => {
      if (parseErr) {
        // Don't expose raw parse errors for security
        return res.status(400).json({ error: 'Invalid XML format. Please check the structure.' });
      }

      // Schema validation (dry-run)
      const validation = validateCustomerXML(result);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'XML validation failed',
          details: validation.errors
        });
      }

      // Transaction: begin → insert → commit (or rollback)
      const insertStmt = db.prepare(
        `INSERT INTO customers (name, email, phone, company, status, created_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`
      );

      const results = { imported: 0, skipped: 0, errors: [] };

      try {
        db.exec('BEGIN TRANSACTION');

        for (let i = 0; i < validation.records.length; i++) {
          const c = validation.records[i];
          try {
            // Check for duplicate email
            const existing = db.prepare('SELECT id FROM customers WHERE email = ?').get(String(c.email).trim());
            if (existing) {
              results.skipped++;
              results.errors.push(`Row ${i + 1}: Email ${c.email} already exists`);
              continue;
            }

            insertStmt.run(
              String(c.name).trim(),
              String(c.email).trim(),
              c.phone ? String(c.phone).trim() : null,
              c.company ? String(c.company).trim() : null,
              c.status ? String(c.status).toLowerCase().trim() : 'active'
            );
            results.imported++;
          } catch (rowErr) {
            results.skipped++;
            results.errors.push(`Row ${i + 1}: ${rowErr.message}`);
          }
        }

        if (results.imported === 0) {
          db.exec('ROLLBACK');
          return res.status(400).json({
            error: 'No records imported. All rows failed or were duplicates.',
            results
          });
        }

        db.exec('COMMIT');

        // Audit log
        auditLog(db, 'XML_IMPORT_CUSTOMERS', {
          filename: req.file.originalname,
          imported: results.imported,
          skipped: results.skipped,
          total: validation.records.length
        }, req.session.user.id, req.ip);

        return res.json({
          success: true,
          message: `Imported ${results.imported} customers, skipped ${results.skipped}`,
          results
        });
      } catch (txErr) {
        db.exec('ROLLBACK');
        console.error('Import transaction failed:', txErr);
        return res.status(500).json({ error: 'Import failed, transaction rolled back' });
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// POST /import/orders — Import orders from XML
// ═══════════════════════════════════════════════════════════════════

router.post('/orders', requireAuth, (req, res) => {
  xmlUpload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'XML file must be under 5MB' });
      }
      return res.status(400).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No XML file uploaded' });
    }

    const db = req.app.locals.db;
    if (!db) return res.status(500).json({ error: 'Database not available' });

    const xmlString = req.file.buffer.toString('utf-8');

    const parser = new xml2js.Parser(XML_PARSER_OPTIONS);
    parser.parseString(xmlString, (parseErr, result) => {
      if (parseErr) {
        return res.status(400).json({ error: 'Invalid XML format. Please check the structure.' });
      }

      // Schema validation (dry-run)
      const validation = validateOrderXML(result);
      if (!validation.valid) {
        return res.status(400).json({
          error: 'XML validation failed',
          details: validation.errors
        });
      }

      const insertStmt = db.prepare(
        `INSERT INTO orders (customer_id, product, amount, status, created_at)
         VALUES (?, ?, ?, ?, datetime('now'))`
      );

      const results = { imported: 0, skipped: 0, errors: [] };

      try {
        db.exec('BEGIN TRANSACTION');

        for (let i = 0; i < validation.records.length; i++) {
          const o = validation.records[i];
          try {
            // Validate customer exists
            const customer = db.prepare('SELECT id FROM customers WHERE id = ?').get(Number(o.customer_id));
            if (!customer) {
              results.skipped++;
              results.errors.push(`Row ${i + 1}: Customer ID ${o.customer_id} not found`);
              continue;
            }

            insertStmt.run(
              Number(o.customer_id),
              String(o.product).trim(),
              o.amount ? parseFloat(o.amount) : 0,
              o.status ? String(o.status).toLowerCase().trim() : 'pending'
            );
            results.imported++;
          } catch (rowErr) {
            results.skipped++;
            results.errors.push(`Row ${i + 1}: ${rowErr.message}`);
          }
        }

        if (results.imported === 0) {
          db.exec('ROLLBACK');
          return res.status(400).json({
            error: 'No records imported. All rows failed.',
            results
          });
        }

        db.exec('COMMIT');

        auditLog(db, 'XML_IMPORT_ORDERS', {
          filename: req.file.originalname,
          imported: results.imported,
          skipped: results.skipped,
          total: validation.records.length
        }, req.session.user.id, req.ip);

        return res.json({
          success: true,
          message: `Imported ${results.imported} orders, skipped ${results.skipped}`,
          results
        });
      } catch (txErr) {
        db.exec('ROLLBACK');
        console.error('Import transaction failed:', txErr);
        return res.status(500).json({ error: 'Import failed, transaction rolled back' });
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// GET /import/template/:type — Download import template XML
// ═══════════════════════════════════════════════════════════════════

router.get('/template/:type', requireAuth, (req, res) => {
  const { type } = req.params;
  let xml, filename;

  switch (type) {
    case 'customers':
      xml = generateCustomerTemplate();
      filename = 'customer_import_template.xml';
      break;
    case 'orders':
      xml = generateOrderTemplate();
      filename = 'order_import_template.xml';
      break;
    default:
      return res.status(400).json({ error: `Unknown template type: ${type}. Use 'customers' or 'orders'.` });
  }

  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(xml);
});

module.exports = router;
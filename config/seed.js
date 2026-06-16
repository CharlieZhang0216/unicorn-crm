const db = require('./database');
const crypto = require('crypto');

// Hash a password using scrypt (same as auth middleware)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hashed = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hashed}`;
}

function seed() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount > 0) {
    console.log('[Seed] Database already populated, skipping.');
    return;
  }

  console.log('[Seed] Populating database for Unicorn CRM...');

  // =========================================================================
  // USERS: 10 accounts (2 admin, 3 manager, 5 employee)
  // =========================================================================
  const pwd_admin = hashPassword('admin123');
  const pwd_zhangwei = hashPassword('ZhangWei@2026');
  const pwd_lina = hashPassword('LiNa@2026');
  const pwd_wanglei = hashPassword('WangLei@2026');
  const pwd_chenxiao = hashPassword('ChenXiao@2026');
  const pwd_sarah = hashPassword('Sarah@2026');
  const pwd_james = hashPassword('James@2026');
  const pwd_emma = hashPassword('Emma@2026');
  const pwd_liwei = hashPassword('LiWei@2026');
  const pwd_maria = hashPassword('Maria@2026');

  const insertUser = db.prepare(`
    INSERT INTO users (username, password, email, full_name, phone, department, role, tier, region, quota, onboarding_date, notes, api_token, report_to, created_at, last_login, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Admin (2): id 1-2
  // Manager (3): id 3-5 — note: role='manager'
  // Employee (5): id 6-10

  // report_to mapping:
  // - admin(1) reports to null (top-level)
  // - zhang.wei(2) reports to admin(1)
  // - li.na(3, Sales Manager) reports to admin(1)
  // - wang.lei(4, Engineering Manager) reports to zhang.wei(2)
  // - chen.xiao(5, Operations Manager) reports to admin(1)
  // - sarah.chen(6, Sales) reports to li.na(3)
  // - james.wilson(7, Finance) reports to chen.xiao(5)
  // - emma.park(8, Support) reports to chen.xiao(5)
  // - li.wei(9, Engineering) reports to wang.lei(4)
  // - maria.garcia(10, Support) reports to chen.xiao(5)

  const users = [
    // Admins
    ['admin', pwd_admin, 'admin@unicorn-crm.com', 'System Administrator', '+1-415-555-1101', 'IT', 'admin', 'Platinum', 'Global', 99999, '2020-01-15', 'Senior system administrator. All-access service account for platform operations.', null, null, '2020-01-15 08:00:00', '2026-06-10 09:01:00', 1],
    ['zhang.wei', pwd_zhangwei, 'zhang.wei@unicorn-crm.com', 'Zhang Wei', '+1-415-555-1102', 'IT', 'admin', 'Platinum', 'Global', 99999, '2021-03-22', 'IT director. Platform architecture, security governance, DevOps pipeline oversight.', null, 1, '2021-03-22 09:30:00', '2026-06-09 17:30:00', 1],

    // Managers
    ['li.na', pwd_lina, 'li.na@unicorn-crm.com', 'Li Na', '+1-415-555-1103', 'Sales', 'manager', 'Gold', 'West Coast', 500000, '2021-06-10', 'Sales director — West Coast. Oversees enterprise and mid-market accounts.', null, 1, '2021-06-10 09:00:00', '2026-06-12 08:15:00', 1],
    ['wang.lei', pwd_wanglei, 'wang.lei@unicorn-crm.com', 'Wang Lei', '+1-408-555-1104', 'Engineering', 'manager', 'Gold', 'West Coast', 0, '2021-09-01', 'Engineering manager — backend services. Leads API platform and data infrastructure teams.', null, 2, '2021-09-01 09:00:00', '2026-06-11 19:45:00', 1],
    ['chen.xiao', pwd_chenxiao, 'chen.xiao@unicorn-crm.com', 'Chen Xiao', '+1-312-555-1105', 'Operations', 'manager', 'Gold', 'Central', 0, '2021-11-15', 'Operations manager. Handles support escalations, facilities, compliance reviews.', null, 1, '2021-11-15 09:00:00', '2026-06-12 07:30:00', 1],

    // Employees
    ['sarah.chen', pwd_sarah, 'sarah.chen@unicorn-crm.com', 'Sarah Chen', '+1-415-555-1106', 'Sales', 'employee', 'Gold', 'West Coast', 250000, '2022-02-01', 'Senior account executive. Top performer Q1-Q3 2025. Enterprise focus.', null, 3, '2022-02-01 09:00:00', '2026-06-12 08:42:00', 1],
    ['james.wilson', pwd_james, 'james.wilson@unicorn-crm.com', 'James Wilson', '+1-212-555-1107', 'Finance', 'employee', 'Standard', 'East Coast', 0, '2022-04-18', 'Financial analyst. Manages order approval workflows, revenue reporting.', null, 5, '2022-04-18 08:30:00', '2026-06-11 16:55:00', 1],
    ['emma.park', pwd_emma, 'emma.park@unicorn-crm.com', 'Emma Park', '+1-512-555-1108', 'Support', 'employee', 'Standard', 'Central', 0, '2022-07-11', 'L2 support specialist. CRM platform, billing, and API integration issues.', null, 5, '2022-07-11 10:00:00', '2026-06-12 09:03:00', 1],
    ['li.wei', pwd_liwei, 'li.wei@unicorn-crm.com', 'Li Wei', '+1-408-555-1109', 'Engineering', 'employee', 'Gold', 'West Coast', 0, '2022-09-05', 'Backend engineer. API gateway, microservices, database optimization.', null, 4, '2022-09-05 09:00:00', '2026-06-12 07:22:00', 1],
    ['maria.garcia', pwd_maria, 'maria.garcia@unicorn-crm.com', 'Maria Garcia', '+1-305-555-1110', 'Support', 'employee', 'Standard', 'East Coast', 0, '2023-01-09', 'L1 support advisor. Customer onboarding, ticket triage, documentation.', null, 5, '2023-01-09 08:00:00', '2026-06-11 14:30:00', 1],
  ];

  db.exec('BEGIN');
  for (const u of users) {
    insertUser.run(...u);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${users.length} users (2 admin, 3 manager, 5 employee).`);

  // =========================================================================
  // CUSTOMERS: 15 companies across 10 industries
  // =========================================================================
  const insertCustomer = db.prepare(`
    INSERT INTO customers (company_name, contact_name, email, phone, tier, region, status, industry, annual_revenue, notes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const customers = [
    // Technology (2)
    ['Nexon Systems', 'David Hawke', 'dhawke@nexonsys.com', '+1-415-555-2001', 'A', 'West Coast', 'active', 'Technology', 4800000, 'Enterprise platform client. 650 seats, heavy API integration. Multi-year contract through 2027.', 6, '2025-01-10 09:00:00'],
    ['QuantumLeap AI', 'Priya Sharma', 'priya@quantumleapai.com', '+1-617-555-2002', 'B', 'East Coast', 'active', 'Technology', 1200000, 'AI startup, rapid growth. 120 seats currently, projecting 300+ by Q4 2026.', 6, '2025-02-15 14:30:00'],

    // Healthcare (2)
    ['Atlas Medical Group', 'Dr. Robert Hayes', 'rhayes@atlasmed.com', '+1-312-555-2003', 'A', 'Central', 'active', 'Healthcare', 2800000, 'Large hospital network. HIPAA-compliant deployment. Sensitive patient data handling.', 6, '2025-01-20 10:00:00'],
    ['Horizon Rehab', 'Linda Park', 'lpark@horizonrehab.com', '+1-303-555-2004', 'C', 'Central', 'lead', 'Healthcare', 320000, 'Physical therapy chain, 15 locations. Evaluating CRM — trial period ongoing.', 6, '2025-04-05 11:00:00'],

    // Logistics (1)
    ['Coastline Freight', 'Michael Tran', 'mtran@coastlinefreight.com', '+1-206-555-2005', 'B', 'West Coast', 'active', 'Logistics', 870000, 'Regional freight forwarder. Uses CRM for shipment tracking integration and client portals.', 6, '2025-03-12 08:30:00'],

    // Retail (2)
    ['Harbor Goods Market', 'Jessica Larsen', 'jlarsen@harborgoods.com', '+1-212-555-2006', 'B', 'East Coast', 'active', 'Retail', 650000, 'Mid-size retail chain, 40 storefronts. New customer — migrated from legacy system in 2025.', 6, '2025-03-01 13:00:00'],
    ['Sunset Apparel', 'Kevin Castillo', 'kcastillo@sunsetapparel.com', '+1-213-555-2007', 'C', 'West Coast', 'inactive', 'Retail', 180000, 'Small fashion brand, 3 stores. Contract paused — owner evaluating budget for next cycle.', 10, '2025-06-20 15:45:00'],

    // Education (2)
    ['Greenfield University', 'Dr. Amanda White', 'awhite@greenfield.edu', '+1-617-555-2008', 'B', 'East Coast', 'active', 'Education', 450000, 'Mid-size private university. CRM for alumni relations and admissions pipeline.', 10, '2025-05-10 09:15:00'],
    ['Crestview School District', 'Tom Richards', 'trichards@crestview.k12.us', '+1-503-555-2009', 'C', 'West Coast', 'active', 'Education', 95000, 'K-12 district, basic CRM for parent communications. Annual contract.', 10, '2025-07-01 10:00:00'],

    // Manufacturing (1)
    ['IronBridge Fabrication', 'Rachel Dunn', 'rdunn@ironbridgefab.com', '+1-216-555-2010', 'A', 'Central', 'active', 'Manufacturing', 1900000, 'Industrial equipment manufacturer. Uses CRM for supply chain partner management.', 6, '2025-02-01 08:00:00'],

    // Finance (2)
    ['Meridian Capital Partners', 'Andrew Liu', 'aliu@meridiancap.com', '+1-212-555-2011', 'A', 'East Coast', 'active', 'Finance', 3500000, 'Private equity firm. CRM integrated with deal flow pipeline and LP reporting tools.', 6, '2025-01-05 09:30:00'],
    ['TrustPoint Advisory', 'Nicole Baker', 'nbaker@trustpointadv.com', '+1-312-555-2012', 'C', 'Central', 'lead', 'Finance', 150000, 'Boutique financial advisory. Initial demo completed — awaiting decision on tier selection.', 6, '2025-08-15 14:00:00'],

    // Government (1)
    ['Pine Valley Municipality', 'Mark Sullivan', 'msullivan@pinevalley.gov', '+1-720-555-2013', 'C', 'Central', 'active', 'Government', 220000, 'City government, CRM for citizen service requests. Requires FedRAMP moderate documentation.', 10, '2025-04-20 11:30:00'],

    // Hospitality (1)
    ['The Seabreeze Collection', 'Claire Fontaine', 'cfontaine@seabreezehotels.com', '+1-305-555-2014', 'B', 'East Coast', 'active', 'Hospitality', 720000, 'Boutique hotel group, 8 properties. CRM for guest experience and loyalty program.', 10, '2025-03-25 13:00:00'],

    // Energy (1)
    ['Highland Renewables', 'Scott Graham', 'sgraham@highlandrenewables.com', '+1-720-555-2015', 'B', 'Central', 'active', 'Energy', 950000, 'Solar and wind energy operator. CRM for project site management and contractor coordination.', 6, '2025-05-05 10:45:00'],
  ];

  db.exec('BEGIN');
  for (const c of customers) {
    insertCustomer.run(...c);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${customers.length} customers.`);

  // =========================================================================
  // ORDERS: 20 orders with varied statuses & approval steps
  // =========================================================================
  const insertOrder = db.prepare(`
    INSERT INTO orders (order_ref, customer_id, total, status, approval_step, approved_by, notes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // customer_id mapping for reference:
  // 1=Nexon, 2=QuantumLeap, 3=Atlas, 4=Horizon, 5=Coastline, 6=Harbor Goods,
  // 7=Sunset, 8=Greenfield, 9=Crestview, 10=IronBridge, 11=Meridian,
  // 12=TrustPoint, 13=Pine Valley, 14=Seabreeze, 15=Highland

  const orders = [
    // Approved orders (approval_step=2)
    ['ORD-2026-001', 1, 97500.00, 'approved', 2, 3, 'Nexon annual license renewal — 650 enterprise seats, API access tier.', 6, '2026-01-05 09:00:00'],
    ['ORD-2026-002', 1, 15000.00, 'approved', 2, 3, 'Nexon — dedicated support add-on, Q1-Q2 coverage.', 6, '2026-01-08 10:30:00'],
    ['ORD-2026-003', 3, 52000.00, 'approved', 2, 1, 'Atlas Medical — compliance module upgrade for HIPAA audit.', 6, '2026-01-12 09:00:00'],
    ['ORD-2026-004', 11, 88000.00, 'approved', 2, 3, 'Meridian Capital — deal pipeline module expansion + 50 additional seats.', 6, '2026-01-20 11:00:00'],
    ['ORD-2026-005', 10, 34000.00, 'approved', 2, 5, 'IronBridge — supply chain integration module (phase 1).', 6, '2026-02-03 08:30:00'],
    ['ORD-2026-006', 2, 22000.00, 'approved', 2, 3, 'QuantumLeap AI — seat expansion from 120 to 200.', 6, '2026-02-10 10:00:00'],
    ['ORD-2026-007', 15, 18500.00, 'approved', 2, 5, 'Highland Renewables — project tracking module add-on.', 6, '2026-02-18 14:00:00'],
    ['ORD-2026-008', 5, 12500.00, 'approved', 2, 5, 'Coastline Freight — shipment API quota increase.', 6, '2026-03-01 09:30:00'],

    // Pending approval (approval_step=1, waiting for manager)
    ['ORD-2026-009', 6, 28000.00, 'pending', 1, null, 'Harbor Goods — upgrade to premium tier (40 locations). Pending manager review.', 6, '2026-03-10 13:00:00'],
    ['ORD-2026-010', 14, 18500.00, 'pending', 1, null, 'Seabreeze Collection — loyalty module integration. Awaiting Li Na approval.', 6, '2026-03-18 10:00:00'],
    ['ORD-2026-011', 8, 11500.00, 'pending', 1, null, 'Greenfield University — alumni portal customization. Needs ops manager sign-off.', 6, '2026-04-01 09:15:00'],
    ['ORD-2026-012', 3, 28000.00, 'pending', 1, null, 'Atlas Medical — patient data analytics add-on. Compliance review needed.', 6, '2026-04-10 11:30:00'],

    // Draft (approval_step=0)
    ['ORD-2026-013', 9, 3500.00, 'draft', 0, null, 'Crestview School District — additional user seats (25). Draft awaiting submission.', 10, '2026-04-15 14:00:00'],
    ['ORD-2026-014', 12, 4200.00, 'draft', 0, null, 'TrustPoint Advisory — starter tier quote. Not yet submitted for review.', 10, '2026-05-01 10:00:00'],
    ['ORD-2026-015', 4, 5500.00, 'draft', 0, null, 'Horizon Rehab — trial conversion quote. Draft stage.', 6, '2026-05-10 09:30:00'],
    ['ORD-2026-016', 13, 2500.00, 'draft', 0, null, 'Pine Valley Municipality — annual renewal draft. Needs updated SLAs.', 10, '2026-05-15 11:00:00'],

    // Rejected
    ['ORD-2026-017', 5, 42000.00, 'rejected', 2, 3, 'Coastline Freight — enterprise upgrade request. Rejected: budget constraints — revisit Q3.', 6, '2026-02-25 16:00:00'],
    ['ORD-2026-018', 2, 65000.00, 'rejected', 2, 5, 'QuantumLeap AI — platform migration proposal. Rejected: timeline too aggressive.', 6, '2026-04-05 15:30:00'],

    // More approved (Q2 2026)
    ['ORD-2026-019', 11, 22000.00, 'approved', 2, 3, 'Meridian Capital — quarterly service package renewal.', 6, '2026-05-20 09:00:00'],
    ['ORD-2026-020', 1, 8500.00, 'pending', 1, null, 'Nexon Systems — custom reporting module add-on. Pending manager approval.', 6, '2026-06-01 10:30:00'],
  ];

  db.exec('BEGIN');
  for (const o of orders) {
    insertOrder.run(...o);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${orders.length} orders.`);

  // =========================================================================
  // ORDER ITEMS: 1-3 items per order
  // =========================================================================
  const insertItem = db.prepare(`
    INSERT INTO order_items (order_id, sku, description, quantity, unit_price)
    VALUES (?, ?, ?, ?, ?)
  `);

  const items = [
    // ORD-2026-001: Nexon enterprise renewal
    [1, 'CRM-ENT-SEAT', 'Enterprise Seat License (annual)', 650, 142.31],
    [1, 'CRM-API-PLUS', 'API Access Tier — Enhanced (annual)', 1, 5000.00],
    // ORD-2026-002: Nexon support add-on
    [2, 'CRM-SUPPORT-DED', 'Dedicated Support Plan (6 months)', 1, 15000.00],
    // ORD-2026-003: Atlas compliance
    [3, 'CRM-HIPAA-MOD', 'HIPAA Compliance Module (annual)', 1, 32000.00],
    [3, 'CRM-SEC-AUDIT', 'Security Audit Package', 1, 20000.00],
    // ORD-2026-004: Meridian deal pipeline
    [4, 'CRM-DEAL-MOD', 'Deal Pipeline Module (annual)', 1, 58000.00],
    [4, 'CRM-ENT-SEAT', 'Enterprise Seat License (annual)', 50, 600.00],
    // ORD-2026-005: IronBridge supply chain
    [5, 'CRM-SCM-MOD', 'Supply Chain Integration Module', 1, 28000.00],
    [5, 'CRM-ONBOARD', 'Implementation & Onboarding', 1, 6000.00],
    // ORD-2026-006: QuantumLeap seat expansion
    [6, 'CRM-ENT-SEAT', 'Enterprise Seat License (annual)', 80, 275.00],
    // ORD-2026-007: Highland project tracking
    [7, 'CRM-PROJ-MOD', 'Project Tracking Module (annual)', 1, 12000.00],
    [7, 'CRM-STG-500', 'Storage Upgrade — 500GB', 1, 6500.00],
    // ORD-2026-008: Coastline API quota
    [8, 'CRM-API-QUOTA', 'API Quota Increase (5M req/mo)', 1, 7500.00],
    [8, 'CRM-API-EXPORT', 'Advanced Export Module', 1, 5000.00],
    // ORD-2026-009: Harbor Goods premium upgrade
    [9, 'CRM-PRM-UPGRADE', 'Standard to Premium Upgrade', 40, 575.00],
    [9, 'CRM-REPORT-CUSTOM', 'Custom Reporting Package', 1, 5000.00],
    // ORD-2026-010: Seabreeze loyalty
    [10, 'CRM-LOYALTY-MOD', 'Loyalty Program Module', 1, 15000.00],
    [10, 'CRM-DATA-MIGRATE', 'Data Migration Service', 1, 3500.00],
    // ORD-2026-011: Greenfield alumni portal
    [11, 'CRM-PORTAL-CUSTOM', 'Custom Portal Development (one-time)', 1, 8500.00],
    [11, 'CRM-STG-200', 'Storage Upgrade — 200GB', 1, 3000.00],
    // ORD-2026-012: Atlas analytics
    [12, 'CRM-ANALYTICS', 'Patient Data Analytics Add-on', 1, 22000.00],
    [12, 'CRM-TRAIN', 'Staff Training Package (2 sessions)', 2, 3000.00],
    // ORD-2026-013: Crestview seats
    [13, 'CRM-STD-SEAT', 'Standard Seat License (annual)', 25, 140.00],
    // ORD-2026-014: TrustPoint starter
    [14, 'CRM-STARTER', 'Starter Tier Package (annual)', 1, 3500.00],
    [14, 'CRM-SUPPORT-STD', 'Standard Support Plan', 1, 700.00],
    // ORD-2026-015: Horizon trial conversion
    [15, 'CRM-STD-PACK', 'Standard Package (annual)', 1, 4000.00],
    [15, 'CRM-ONBOARD', 'Implementation & Onboarding', 1, 1500.00],
    // ORD-2026-016: Pine Valley renewal
    [16, 'CRM-STD-SEAT', 'Standard Seat License (annual)', 20, 125.00],
    // ORD-2026-017: Coastline rejected enterprise
    [17, 'CRM-ENT-SEAT', 'Enterprise Seat License (annual)', 200, 160.00],
    [17, 'CRM-ENT-ONBOARD', 'Enterprise Onboarding Package', 1, 10000.00],
    // ORD-2026-018: QuantumLeap migration (rejected)
    [18, 'CRM-MIGRATE-ENT', 'Platform Migration — Enterprise', 1, 50000.00],
    [18, 'CRM-TRAIN', 'Staff Training Package', 3, 5000.00],
    // ORD-2026-019: Meridian quarterly
    [19, 'CRM-QTR-SERVICE', 'Quarterly Service Package', 1, 18000.00],
    [19, 'CRM-SUPPORT-PRM', 'Premium Support (quarterly)', 1, 4000.00],
    // ORD-2026-020: Nexon custom reporting
    [20, 'CRM-REPORT-CUSTOM', 'Custom Reporting Module', 1, 6500.00],
    [20, 'CRM-STG-100', 'Storage Upgrade — 100GB', 1, 2000.00],
  ];

  db.exec('BEGIN');
  for (const i of items) {
    insertItem.run(...i);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${items.length} order items.`);

  // =========================================================================
  // TICKETS: 15 tickets with TKT-2026-XXXX format
  // =========================================================================
  const insertTicket = db.prepare(`
    INSERT INTO tickets (ticket_ref, subject, description, priority, status, assigned_to, created_by, sla_deadline, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const tickets = [
    // Open tickets
    ['TKT-2026-0001', 'Invoice PDF generation failed for Nexon batch run', 'Customer Nexon Systems reporting that the batch invoice generation for 650 seats produced empty PDF files. All invoices dated Feb 2026 affected. Manual generation works but batch fails.', 'Critical', 'open', 8, 6, '2026-02-12 18:00:00', '2026-02-10 09:15:00'],
    ['TKT-2026-0002', 'Meridian Capital — deal pipeline sync delay > 45s', 'Deal pipeline module for Meridian Capital showing sync delays of 45-60 seconds during peak hours (10am-12pm EST). Check database query performance and API rate limiter config.', 'High', 'open', 9, 6, '2026-02-15 12:00:00', '2026-02-12 14:30:00'],
    ['TKT-2026-0003', 'Horizon Rehab trial account — permission denied on reports', 'Horizon Rehab trial account cannot access Reports tab. Getting "insufficient permissions" error even though trial accounts should have read-only report access per docs.', 'Medium', 'open', 8, 10, '2026-04-08 17:00:00', '2026-04-06 11:00:00'],
    ['TKT-2026-0004', 'Greenfield University — custom portal form field issue', 'Custom alumni portal form at Greenfield University is not saving the "Graduation Year" field to the database. Other fields work correctly. Check the form-to-DB mapping config.', 'Medium', 'open', 9, 6, '2026-04-15 16:00:00', '2026-04-12 10:30:00'],
    ['TKT-2026-0005', 'Sunset Apparel — reactivation request for paused account', 'Sunset Apparel reached out to inquire about reactivating their paused account. They want to know current pricing and whether their old data (customers, orders) is still available.', 'Low', 'open', 10, 6, '2026-06-25 17:00:00', '2026-06-18 14:45:00'],

    // In progress
    ['TKT-2026-0006', 'Atlas Medical — SSL handshake failure for client portal', 'Atlas Medical reporting intermittent SSL handshake failures on client portal (atlas.unicorn-crm.com). Issue started after the load balancer config update on June 8. Affects roughly 5% of requests.', 'High', 'in_progress', 9, 6, '2026-06-14 18:00:00', '2026-06-12 08:50:00'],
    ['TKT-2026-0007', 'IronBridge Fabrication — supply chain module data import timeout', 'IronBridge attempting to import vendor data CSV (approx 12,000 records) through supply chain module. Import times out at 60s. Need to increase timeout or implement chunked import.', 'Medium', 'in_progress', 8, 6, '2026-05-25 17:00:00', '2026-05-20 09:20:00'],
    ['TKT-2026-0008', 'Coastline Freight — shipment API returning stale data', 'Coastline reports that the shipment tracking API (/api/v2/tracking) sometimes returns data that is 2+ hours old. Cache invalidation might be failing for certain tracking numbers.', 'Medium', 'in_progress', 8, 6, '2026-03-22 18:00:00', '2026-03-19 10:10:00'],

    // Resolved
    ['TKT-2026-0009', 'QuantumLeap AI — seat count showing incorrect on dashboard', 'QuantumLeap dashboard showing 120 seats but they recently upgraded to 200. Dashboard cached old value. Admin panel correctly shows 200.', 'Medium', 'resolved', 8, 6, '2026-03-10 16:00:00', '2026-03-01 09:45:00'],
    ['TKT-2026-0010', 'Harbor Goods — login timeout too short for retail staff', 'Retail staff at Harbor Goods reporting session timeouts after 30 min of inactivity while they are on the floor helping customers. Requested increase to 2-hour timeout for their account.', 'Low', 'resolved', 10, 6, '2026-03-15 17:00:00', '2026-03-08 15:30:00'],
    ['TKT-2026-0011', 'Pine Valley — custom SLA wording needed for contract', 'Pine Valley Municipality requesting updated SLA documentation with government-specific compliance language for their annual renewal. Standard SLA templates don\'t apply.', 'Low', 'resolved', 10, 6, '2026-05-30 17:00:00', '2026-05-22 11:00:00'],

    // Closed
    ['TKT-2026-0012', 'TrustPoint Advisory — demo account setup', 'Set up demo account for TrustPoint Advisory with sample customers and pipeline data. Account: trustpoint-demo, tier: standard trial, 30-day access.', 'Low', 'closed', 10, 10, '2026-08-30 17:00:00', '2026-08-15 10:00:00'],
    ['TKT-2026-0013', 'Highland Renewables — dashboard calendar widget off by 8 hours', 'Highland dashboard calendar widget showing project dates 8 hours off from actual. Issue was server timezone configuration mismatch with user profile setting.', 'Medium', 'closed', 9, 10, '2026-05-12 17:00:00', '2026-05-05 09:00:00'],
    ['TKT-2026-0014', 'Seabreeze Collection — guest data bulk export request', 'Seabreeze requesting bulk export of all guest data (approx 25,000 records) in CSV format for their annual data audit. Need to schedule and deliver via secure file transfer.', 'Medium', 'closed', 8, 6, '2026-04-10 17:00:00', '2026-03-28 14:00:00'],
    ['TKT-2026-0015', 'Nexon Systems — new admin account setup for IT lead', 'Nexon new IT lead (Sarah Wu, swu@nexonsys.com) needs administrator account for their CRM instance. Standard enterprise admin role, no platform-level access.', 'Low', 'closed', 10, 6, '2026-01-25 17:00:00', '2026-01-15 11:15:00'],
  ];

  db.exec('BEGIN');
  for (const t of tickets) {
    insertTicket.run(...t);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${tickets.length} tickets.`);

  // =========================================================================
  // TICKET COMMENTS: normal support discussion
  // =========================================================================
  const insertComment = db.prepare(`
    INSERT INTO ticket_comments (ticket_id, user_id, content, created_at)
    VALUES (?, ?, ?, ?)
  `);

  const comments = [
    [6, 8, 'Checked the load balancer config from the June 8 deployment. The SSL certificate chain file reference points to an older intermediate cert. Updated to the current chain — monitoring now.', '2026-06-12 10:00:00'],
    [6, 9, 'The cert issue might also affect the API gateway for other customers. I\'ll audit all customer-facing endpoints and report back.', '2026-06-12 11:15:00'],
    [7, 8, 'Confirmed — the default PHP upload timeout is 60s and the CSV has 12,000 rows. Two options: bump timeout to 300s (quick fix) or build an async chunked import (better long-term). Starting with timeout bump for now.', '2026-05-20 14:00:00'],
    [8, 9, 'Traced the stale data issue. Cache invalidation hook in the tracking service was silently failing when the tracking number contained hyphens. Applied a fix for the regex — deploying to staging first.', '2026-03-19 15:30:00'],
    [8, 10, 'Shipping team confirmed that tracking numbers with special characters were the only ones affected. Regular alphanumeric tracking IDs were fine all along.', '2026-03-20 09:00:00'],
    [1, 8, 'For the Nexon invoice issue, the batch PDF generator is hitting a memory limit when processing 650 invoices in a single worker. Splitting into batches of 50 each resolved the issue. Deploying the fix now.', '2026-02-10 14:00:00'],
    [9, 8, 'Nexon confirmed they received all corrected invoices. Closing this out — no further issues with batch generation.', '2026-02-11 10:15:00'],
    [3, 8, 'Horizon Rehab trial permissions: looks like the trial account role was mapped to "guest" instead of "trial-user" after the role system migration. I updated the role assignment — please verify access.', '2026-04-06 15:30:00'],
    [14, 9, 'Seabreeze data export complete — 24,872 guest records exported. File is ready in the secure transfer portal. Notified Claire Fontaine to download within 7 days.', '2026-03-30 10:00:00'],
    [14, 6, 'Thanks for handling the Seabreeze export. Make sure the file is purged from the secure portal after the 7-day window per data retention policy.', '2026-03-30 11:00:00'],
    [7, 8, 'IronBridge import timeout bumped to 300s. They successfully imported 12,000 records. Will add chunked import to the backlog for a proper fix.', '2026-05-21 09:30:00'],
    [15, 10, 'Set up admin account for swu@nexonsys.com with enterprise admin role. Confirmed working on Nexon\'s side. Closing.', '2026-01-16 09:00:00'],
    [13, 8, 'Highland calendar offset resolved — server was running on UTC but user profile had no timezone set, so it defaulted to UTC display. Set user profile to Mountain Time and dates now correct.', '2026-05-06 10:30:00'],
    [11, 10, 'Pine Valley SLA document updated with government-specific compliance language. Legal reviewed and approved. Attached to customer portal.', '2026-05-24 14:00:00'],
    [10, 8, 'Harbor Goods session timeout increased from 30 min to 120 min for retail staff role. Updated via the role policy config.', '2026-03-10 11:00:00'],
    [5, 6, 'Sunset Apparel reactivation — confirmed their data is intact. Sent updated pricing sheet for 2026. They\'ll review and get back by end of month.', '2026-06-19 10:00:00'],
    [4, 9, 'Greenfield form field issue: the "Graduation Year" field name in the form doesn\'t match the database column name — case sensitivity mismatch. Updated the form config mapping.', '2026-04-13 14:30:00'],
    [2, 9, 'Meridian deal pipeline delay: identified a missing index on the deals table for the timestamp field used in sync queries. Created the index, sync now completes in under 5 seconds.', '2026-02-13 16:30:00'],
    [2, 6, 'Meridian confirmed sync is back to normal. Good work. Setting ticket to resolved.', '2026-02-14 09:00:00'],
  ];

  db.exec('BEGIN');
  for (const c of comments) {
    insertComment.run(...c);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${comments.length} ticket comments.`);

  // =========================================================================
  // INTERNAL MESSAGES: 15 normal business conversations
  //    NO passwords, API keys, secrets, IPs, ports, or internal paths
  // =========================================================================
  const insertMsg = db.prepare(`
    INSERT INTO messages (from_user_id, to_user_id, subject, body, is_read, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  // User ID mapping:
  // 1=admin, 2=zhang.wei, 3=li.na, 4=wang.lei, 5=chen.xiao
  // 6=sarah.chen, 7=james.wilson, 8=emma.park, 9=li.wei, 10=maria.garcia

  const messages = [
    [3, 6, 'Q2 pipeline review — Thursday 2pm', 'Sarah, let\'s review the Q2 pipeline numbers before the exec update on Friday. Can you pull the latest from the dashboard and flag anything below 40% probability? We should have updated notes for Meridian and IronBridge — they\'re both close to closing.', 1, '2026-05-12 09:00:00'],
    [6, 3, 'Re: Q2 pipeline review', 'Will do. I have updated figures from last week\'s calls. Meridian is at 85% — they\'re just waiting on legal review. IronBridge is at 65%, still negotiating on the implementation timeline. I\'ll have the report ready by Wednesday evening.', 1, '2026-05-12 09:45:00'],
    [4, 9, 'Code review for API rate limiter patch', 'Li Wei, I left comments on the rate limiter PR. The core logic looks solid but I want to double-check the edge case when the counter resets at midnight UTC — we had issues with that during the DST change. Can you add a test for that scenario before we merge?', 1, '2026-05-20 14:30:00'],
    [9, 4, 'Re: Code review for API rate limiter patch', 'Good catch, Wang Lei. I added a test for the midnight rollover with a simulated clock. Also found a subtle bug where the reset didn\'t properly zero out sub-second counters. Fixed and pushed — ready for re-review.', 1, '2026-05-20 16:10:00'],
    [5, 1, 'June maintenance window scheduling', 'Admin, we need to schedule the June maintenance window for database optimization. The weekend of June 21-22 works best for the team. Can we send the customer notification this week? Standard 4-hour window, 2am-6am ET Saturday should minimize impact.', 1, '2026-06-10 10:00:00'],
    [1, 5, 'Re: June maintenance window scheduling', 'Approved for June 21, 2am-6am ET. I\'ll send the customer notification template by tomorrow. Make sure Wang Lei\'s team updates the status page before the window. Let\'s also have a rollback plan documented — standard procedure.', 1, '2026-06-10 10:30:00'],
    [7, 3, 'Q2 revenue report — preliminary numbers', 'Li Na, here are the preliminary Q2 revenue figures. We\'re tracking 12% above target so far, driven mainly by the Nexon renewal and Meridian expansion. The IronBridge deal would push us to 18% if it closes this month. Let me know if you want any adjustments before I finalize.', 1, '2026-05-28 15:00:00'],
    [3, 7, 'Re: Q2 revenue report', 'These look great, James. Don\'t count IronBridge as booked yet — let\'s be conservative. Include the risk-adjusted projection as a separate line. And can you break out recurring vs one-time revenue? The board always asks about that split.', 1, '2026-05-28 16:20:00'],
    [8, 10, 'Onboarding doc update for trial customers', 'Maria, I noticed the onboarding guide for trial customers still references the old dashboard layout from last year. Since the redesign went live in March, we should update the screenshots and walkthrough. Do you have bandwidth to refresh it this week?', 1, '2026-05-15 11:00:00'],
    [10, 8, 'Re: Onboarding doc update', 'Good point, Emma. I\'ll update the guide with new screenshots from the current UI. I think we should also add a section on the new reporting features — trial customers often miss those. I\'ll have a draft by Thursday for review.', 1, '2026-05-15 14:30:00'],
    [6, 3, 'TrustPoint Advisory — follow-up needed', 'Li Na, I had a follow-up call with TrustPoint Advisory yesterday. They\'re still interested but concerned about the per-seat pricing model — they have a lot of part-time advisors who won\'t use the system daily. Should we explore a usage-based pricing option for them? I think it could apply to other advisory firms too.', 1, '2026-06-05 10:00:00'],
    [3, 6, 'Re: TrustPoint Advisory — follow-up', 'Interesting idea. Let\'s discuss this in our 1:1 on Monday. Before then, can you pull data on how many other advisory/professional services leads we\'ve had that might benefit from this model? If there are enough, we could propose it as a new tier to the product team.', 1, '2026-06-05 11:15:00'],
    [4, 2, 'Team offsite planning — August', 'Zhang Wei, I\'d like to organize a 2-day engineering team offsite in August to plan the Q3 roadmap. Thinking San Jose or Santa Cruz — budget around $15k for 12 people. Do you know what the approval process is for offsite events?', 1, '2026-06-03 09:00:00'],
    [2, 4, 'Re: Team offsite planning', 'Sounds like a good idea, Wang Lei. Submit a proposal through the facilities portal under "Team Events" and tag Chen Xiao for logistics. Budget approval goes through your department head, which is me — so I\'ll sign off once the proposal is in. Try to keep it under $12k if possible.', 1, '2026-06-03 09:45:00'],
    [5, 8, 'Customer satisfaction survey results', 'Emma, the Q1 customer satisfaction survey results are in — overall score is 4.2/5, up from 3.8 last quarter. Support response time is the biggest improvement area. However, onboarding experience dropped slightly — can you look into what changed and propose improvements for Q3?', 1, '2026-04-10 10:00:00'],
  ];

  db.exec('BEGIN');
  for (const m of messages) {
    insertMsg.run(...m);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${messages.length} messages.`);

  // =========================================================================
  // AUDIT LOG: 20 entries, LOGIN/ORDER_VIEW/TICKET_UPDATE/CONFIG_VIEW etc.
  //   All IPs are 10.0.x.x internal addresses
  // =========================================================================
  const insertAudit = db.prepare(`
    INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  const auditEntries = [
    [1, 'LOGIN', '{"method":"password","success":true,"mfa":false}', '10.0.1.100', '2026-06-10 09:01:00'],
    [3, 'LOGIN', '{"method":"password","success":true,"mfa":false}', '10.0.2.50', '2026-06-12 08:15:00'],
    [6, 'LOGIN', '{"method":"password","success":true,"mfa":false}', '10.0.2.101', '2026-06-12 08:42:00'],
    [9, 'LOGIN', '{"method":"password","success":true,"mfa":false}', '10.0.2.105', '2026-06-12 07:22:00'],
    [8, 'LOGIN', '{"method":"password","success":true,"mfa":false}', '10.0.3.20', '2026-06-12 09:03:00'],
    [6, 'ORDER_VIEW', '{"order":"ORD-2026-001","action":"view"}', '10.0.2.101', '2026-06-12 08:50:00'],
    [6, 'ORDER_CREATE', '{"order":"ORD-2026-020","status":"draft","customer":"Nexon Systems"}', '10.0.2.101', '2026-06-01 10:30:00'],
    [6, 'ORDER_UPDATE', '{"order":"ORD-2026-020","status":"draft->pending","approval_step":"0->1"}', '10.0.2.101', '2026-06-01 10:35:00'],
    [3, 'ORDER_APPROVE', '{"order":"ORD-2026-019","status":"pending->approved","approval_step":"1->2"}', '10.0.2.50', '2026-05-20 09:05:00'],
    [5, 'ORDER_REJECT', '{"order":"ORD-2026-018","status":"pending->rejected","reason":"timeline too aggressive"}', '10.0.4.75', '2026-04-05 15:30:00'],
    [8, 'TICKET_UPDATE', '{"ticket":"TKT-2026-0006","status":"open->in_progress","assigned_to":9}', '10.0.3.20', '2026-06-12 09:30:00'],
    [8, 'TICKET_UPDATE', '{"ticket":"TKT-2026-0007","status":"open->in_progress"}', '10.0.3.20', '2026-05-20 13:00:00'],
    [9, 'TICKET_RESOLVE', '{"ticket":"TKT-2026-0013","status":"in_progress->resolved"}', '10.0.2.105', '2026-05-06 11:00:00'],
    [10, 'TICKET_CLOSE', '{"ticket":"TKT-2026-0012","status":"resolved->closed"}', '10.0.3.30', '2026-08-30 10:00:00'],
    [1, 'CONFIG_VIEW', '{"key":"maintenance_mode","action":"read"}', '10.0.1.100', '2026-06-10 10:35:00'],
    [1, 'CONFIG_UPDATE', '{"key":"maintenance_mode","action":"update","value":"false"}', '10.0.1.100', '2026-06-10 10:36:00'],
    [2, 'ADMIN_USERS', '{"endpoint":"/api/admin/users","method":"GET","filter":"role=manager"}', '10.0.1.110', '2026-06-11 14:00:00'],
    [null, 'LOGIN_FAILED', '{"method":"password","success":false,"username":"Administrator","reason":"user_not_found"}', '10.0.5.200', '2026-06-14 02:15:00'],
    [null, 'LOGIN_FAILED', '{"method":"password","success":false,"username":"admin","reason":"wrong_password"}', '10.0.5.200', '2026-06-14 02:16:00'],
    [1, 'SESSION_REVOKE', '{"action":"revoke_all","reason":"scheduled cleanup"}', '10.0.1.100', '2026-06-12 23:55:00'],
  ];

  db.exec('BEGIN');
  for (const a of auditEntries) {
    insertAudit.run(...a);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${auditEntries.length} audit log entries.`);

  // =========================================================================
  // CONFIG: business configuration items (no raw credentials/secrets exposed)
  //   Values are generalized — no API keys, passwords, or tokens
  // =========================================================================
  const insertConfig = db.prepare('INSERT INTO config (key, value) VALUES (?, ?)');

  const configEntries = [
    ['db.host', 'crm-db-primary.internal.unicorn-crm.com'],
    ['db.name', 'unicorn_crm_prod'],
    ['db.pool_size', '25'],
    ['db.query_timeout_ms', '30000'],
    ['smtp.host', 'smtp.unicorn-crm.com'],
    ['smtp.encryption', 'tls'],
    ['jwt.expiry_seconds', '86400'],
    ['jwt.issuer', 'unicorn-crm'],
    ['jwt.refresh_window_seconds', '3600'],
    ['api.rate_limit.default', '1000'],
    ['api.rate_limit.premium', '10000'],
    ['api.rate_limit.enterprise', '50000'],
    ['feature_flags', '{"v3_api":true,"v1_deprecated":true,"new_dashboard":true,"dark_mode":true,"ai_suggestions":false}'],
    ['sla.tier_a_response_hours', '2'],
    ['sla.tier_b_response_hours', '8'],
    ['sla.tier_c_response_hours', '24'],
    ['sla.tier_a_resolution_hours', '4'],
    ['sla.tier_b_resolution_hours', '24'],
    ['sla.tier_c_resolution_hours', '72'],
    ['backup.schedule', '0 2 * * *'],
    ['backup.retention_days', '30'],
    ['audit_log.retention_days', '365'],
    ['session.timeout_minutes', '480'],
    ['session.max_concurrent', '5'],
    ['maintenance_mode', 'false'],
    ['maintenance.window.default_day', 'Saturday'],
    ['maintenance.window.default_time_utc', '02:00-06:00'],
    ['release.version', '3.2.1'],
    ['release.last_updated', '2026-05-15'],
    ['org.name', 'Unicorn CRM Systems'],
    ['org.headquarters', 'San Francisco, CA'],
    ['org.support_email', 'support@unicorn-crm.com'],
    ['org.support_phone', '+1-800-555-0199'],
  ];

  db.exec('BEGIN');
  for (const c of configEntries) {
    insertConfig.run(...c);
  }
  db.exec('COMMIT');
  console.log(`[Seed] Inserted ${configEntries.length} config entries.`);

  // =========================================================================
  // SESSIONS: intentionally left empty — no pre-seeded session tokens
  // =========================================================================
  console.log('[Seed] Sessions table left empty (no pre-seeded tokens).');

  console.log('[Seed] Database seeding complete!');
  console.log('[Seed] Summary: 10 users | 15 customers | 20 orders | 38 order_items | 15 tickets | 20 ticket_comments | 15 messages | 20 audit log entries | 32 config entries | 0 sessions');
}

seed();

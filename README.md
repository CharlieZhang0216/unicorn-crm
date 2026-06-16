# Unicorn CRM

Enterprise Customer Relationship Management platform — an intentionally vulnerable web application for security training and red/blue team exercises.

> ⚠️ **WARNING**: This application contains intentional security vulnerabilities. It is designed for authorized security training and penetration testing in controlled environments. Do **NOT** deploy on public networks with real data.

## Overview

Unicorn CRM is a full-featured enterprise CRM simulating a real-world corporate application. It provides a realistic attack surface for security professionals to practice vulnerability discovery, exploitation, and remediation across multiple modules.

## Quick Start

```bash
# Install dependencies
npm install

# Start the application (database auto-seeds on first run)
npm start

# Visit http://localhost:3000
```

### Other Commands

```bash
# Development mode with auto-reload
npm run dev

# Reset database to initial state
npm run reset
```

## Features

### Core Modules

| Module | Description | Routes |
|--------|-------------|--------|
| **Dashboard** | Overview with team stats and quick actions | `/` |
| **Customer Management** | CRUD, detail views, batch operations (delete, assign, merge) | `/customers` |
| **Order Management** | Orders with multi-step approval workflow (approve/reject) | `/orders` |
| **Ticket System** | Support tickets with priority, SLA tracking, comments, batch status/assign | `/tickets` |
| **User Profiles** | View and manage profiles with role-based access | `/profile` |
| **Authentication** | Login, register (invite-code gated), forgot password, CSRF protection | `/auth` |
| **File Upload** | Avatar upload, entity attachments, download/delete | `/upload` |
| **Document Browser** | Secure file listing and download | `/files` |

### Extended Modules

| Module | Description | Routes |
|--------|-------------|--------|
| **GraphQL API** | Query users, customers, tickets, orders with RBAC | `/graphql` |
| **REST API** | JSON API with Bearer token + session auth | `/api/v1` |
| **Admin Panel** | User management, sessions, audit log, DB inspection | `/admin` |
| **CSV Export** | Export customers, orders, tickets (admin only) | `/export` |
| **XML Import** | Batch import customers/orders via XML upload | `/import` |
| **OAuth Provider** | Mock Google OAuth integration | `/oauth` |
| **API Tokens** | JWT-based token management (admin only) | `/api-tokens` |
| **Calendar** | Events with month/week/day views, iCal export | `/calendar` |
| **Notes** | Rich text notes with CRUD, tagging, XSS sanitization | `/notes` |
| **Notifications** | In-app notifications + WebSocket push | `/notifications` |
| **WebSocket** | Real-time notification push with token auth | `/ws` |
| **Reports** | Sales pipeline analytics and charts | `/reports` |
| **Cron Jobs** | Scheduled daily reports, tier upgrades, token cleanup | `/jobs` |
| **API Documentation** | Interactive Swagger-style docs | `/api-docs` |
| **Debug Panel** | System status and diagnostics (admin only) | `/debug` |
| **GraphQL Playground** | Interactive GraphQL explorer (admin only) | `/graphql/introspection` |

### Security Architecture

- CSRF protection on all state-changing operations
- Session-based authentication with HTTP-only cookies
- Role-Based Access Control (admin / manager / employee)
- JWT API token authentication with scrypt hashing, algorithm whitelist
- Rate limiting on auth endpoints (5 attempts / 2 min, per-IP)
- GraphQL depth (max 5) and complexity (max 100) limits
- Production-mode GraphQL introspection disabled on public endpoint
- Audit logging for all security-relevant actions
- Honeypot routes for attack detection
- Secure HTTP headers (HSTS, CSP, XSS protection, server info removed)
- Password strength enforcement (min 12 chars, uppercase + lowercase + digit + special char + blacklist)
- scrypt password hashing with per-user salt
- XSS sanitization in Notes (DOMPurify)
- IDOR protection on profiles (non-admin users can only view own)
- Debug panel requires admin authentication
- Admin panel requires admin authentication
- WebSocket connection requires token-based authentication

## Test Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Adm1n!Crm#2026` | Admin |
| `zhang.wei` | `rGDdXKq7+e$d^M5Y` | Admin |
| `li.na` | `sZPdAPc7X*4kSN*q` | Manager (Sales – West Coast) |
| `wang.lei` | `vFm4Y4-Pyj5vDZnF` | Manager (Engineering) |
| `chen.xiao` | `JLc!2n%ExsS@T!X%` | Manager (Operations – Central) |
| `sarah.chen` | `g*F^-Ng@nq7LHNfR` | Employee (Sales) |
| `james.wilson` | `2gN48NqzFCt8j-4s` | Employee (Finance) |
| `emma.park` | `REuwwSnw+2fn&hTR` | Employee (Support) |
| `li.wei` | `_BG-T_CxQg#5HbsK` | Employee (Engineering) |
| `maria.garcia` | `7+gq$*&GbSc2Fp9&` | Employee (Support) |

All passwords are 16-character strong passwords. The database includes 10 users, 15 customers, 20 orders, 15 tickets, and 20 audit log entries — all fictional.

## Project Structure

```
unicorn-crm/
├── app.js                 # Express entry point
├── package.json
├── config/
│   ├── database.js        # SQLite initialization
│   └── seed.js            # Fake data seeding (10 users, 15+ entities)
├── middleware/
│   ├── auth.js            # Session authentication
│   ├── csrf.js            # CSRF token protection
│   ├── api-auth.js        # Bearer token + JWT auth (algorithm whitelist)
│   ├── graphql-auth.js    # GraphQL auth context injection
│   ├── audit.js           # Attack audit + honeypot routes
│   ├── headers.js         # Security HTTP headers
│   └── banner.js          # Security warning banner
├── routes/
│   ├── index.js           # Dashboard & API docs
│   ├── auth.js            # Login / Register / Forgot password
│   ├── customers.js       # Customer CRUD + merge
│   ├── customers-batch.js # Batch delete / assign / merge
│   ├── orders.js          # Order management + approval workflow
│   ├── tickets.js         # Ticket CRUD + comments
│   ├── tickets-batch.js   # Batch status / assign
│   ├── profile.js         # User profiles (IDOR-protected)
│   ├── files.js           # Document browser + upload broadcast
│   ├── upload.js          # Avatar + attachment upload
│   ├── export.js          # CSV export (admin only)
│   ├── import.js          # XML batch import (XXE-safe)
│   ├── api.js             # REST API
│   ├── admin.js           # Admin panel (users, sessions, audit, DB)
│   ├── api-tokens.js      # JWT token management
│   ├── oauth.js           # Mock OAuth provider
│   ├── graphql.js         # GraphQL endpoint (introspection disabled in prod)
│   ├── calendar.js        # Calendar events + iCal export
│   ├── notes.js           # Rich text notes (XSS sanitized)
│   ├── notifications.js   # In-app notifications
│   ├── reports.js         # Sales reports
│   ├── jobs.js            # Cron job management
│   ├── debug.js           # System diagnostics (admin only)
│   └── errors.js          # Search + error handling
├── services/
│   ├── mail.js            # Email service (mock)
│   ├── scheduler.js       # Cron job scheduler (daily reports, tier upgrades)
│   └── websocket.js       # Real-time notification push
├── views/                 # EJS templates (23 views)
├── public/                # Static assets
└── data/                  # SQLite database (auto-created)
```

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express 4
- **Templates**: EJS
- **Database**: SQLite (via better-sqlite3)
- **API**: REST + GraphQL (express-graphql)
- **Auth**: Session cookies + JWT Bearer tokens + OAuth 2.0 mock
- **Real-time**: WebSocket (ws)
- **Scheduling**: node-cron
- **File Upload**: Multer
- **Styling**: Bootstrap 5 (CDN)

## Attack Surface (Current)

This application is designed with intentional vulnerabilities for security training. Below is the current vulnerability inventory:

### 🔴 High Severity — Business Logic Vulnerabilities

| ID | Module | Vulnerability | Technique |
|----|--------|--------------|-----------|
| **BL-1** | Customer Merge | Customer dedup TOCTOU race condition | Non-atomic merge window allows order/ticket data hijacking |
| **BL-2** | Tier Upgrades | Automatic tier upgrade based on total orders (incl. cancelled) | Submit large order → wait for auto-upgrade → cancel order → keep high tier |
| **BL-3** | CSV Export | Column injection via unvalidated `columns` parameter | Client-supplied column names injected directly into SQL SELECT |
| **BL-4** | Ticket SLA | Keyword-triggered priority auto-escalation | Comments containing trigger words (e.g. "urgent") silently upgrade priority |
| **BL-5** | Order Approval | Concurrent approval step overwrite | Read-modify-write pattern without optimistic locking allows approval step skip |
| **BL-6** | File Upload | WebSocket broadcast of file metadata | Passive monitoring reveals file names, sizes, and uploader identities |

### 🟡 Medium Severity — Classic Web Vulnerabilities

| Type | Location | Description |
|------|----------|-------------|
| **Authentication Bypass** | `/auth/register` | Invite-code gating — discover valid invite codes to register privileged accounts |
| **API Documentation Exposure** | `/api-docs` | Swagger-style API documentation accessible to all roles |
| **Server Header Leakage** | HTTP response | `Server: nginx` version visible in response headers |
| **JWT Secret Enumeration** | `.env` | JWT secret stored in environment file — discoverable via configuration scan |

### 🟢 Low Severity — Informational

| Type | Location | Description |
|------|----------|-------------|
| **GraphQL Introspection** | `/graphql/introspection` | Admin-only introspection endpoint (public endpoint disabled in production) |
| **Honeypot Traps** | Various | 20+ honeypot routes detect scanners and log attempts |

### ✅ Mitigated / Not Vulnerable

The following are **NOT** exploitable in the current version:

- ❌ **Weak default credentials** — All 10 users have 16-character scrypt-hashed strong passwords
- ❌ **SQL injection in search** — Query uses parameterized statements
- ❌ **XSS in notes** — Content sanitized with DOMPurify before storage and rendering
- ❌ **XXE in XML import** — xml2js (pure JS, no DTD processing) with explicit secure config
- ❌ **IDOR on profiles** — Non-admin users restricted to own profile only
- ❌ **JWT none-algorithm** — JWT verify enforces algorithm whitelist (`algorithms: [JWT_ALGORITHM]`)
- ❌ **Mass assignment** — Role field not user-modifiable via profile update
- ❌ **Debug endpoint exposure** — Requires admin authentication
- ❌ **Error stack traces** — Error handler sanitizes output in production
- ❌ **WebSocket auth bypass** — Requires token authentication on connect (10s timeout)

## Training Scenarios

### Scenario 1: Business Logic Exploitation (Advanced)
Target the BL-series vulnerabilities. These require understanding real business workflows and cannot be found by automated scanners.

### Scenario 2: Privilege Escalation
Identify the invite-code mechanism, enumerate valid codes, and register a privileged account.

### Scenario 3: Data Leakage
Discover and exploit the CSV export column injection to extract data from other tables.

### Scenario 4: API Discovery
Locate exposed API documentation and internal endpoints through enumeration.

### Scenario 5: Concurrency Attacks
Exploit race conditions in the order approval workflow or customer merge operations.

## License

MIT — For educational and authorized security training use only. See [LICENSE](LICENSE).

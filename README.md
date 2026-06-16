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
| **Customer Management** | CRUD, detail views, batch operations (delete, assign) | `/customers` |
| **Order Management** | Orders with approval workflow (approve/reject) | `/orders` |
| **Ticket System** | Support tickets with priority, SLA tracking, batch status/assign | `/tickets` |
| **User Profiles** | View and manage profiles with role-based access | `/profile` |
| **Authentication** | Login, register (invite-code gated), forgot password | `/auth` |
| **File Upload** | Avatar upload, entity attachments, download/delete | `/upload` |
| **Document Browser** | Secure file listing and download | `/files` |

### Extended Modules

| Module | Description | Routes |
|--------|-------------|--------|
| **GraphQL API** | Query users, customers, tickets, orders with RBAC | `/graphql` |
| **REST API** | JSON API with Bearer token + session auth | `/api/v1` |
| **Admin Panel** | User management, sessions, audit log, DB inspection | `/api/admin` |
| **CSV Export** | Export customers, orders, tickets (admin only) | `/export` |
| **XML Import** | Batch import customers/orders via XML upload | `/import` |
| **OAuth Provider** | Mock Google OAuth integration | `/oauth` |
| **API Tokens** | JWT-based token management (admin only) | `/api-tokens` |
| **Calendar** | Events with month/week/day views, iCal export | `/calendar` |
| **Notes** | Rich text notes with CRUD, tagging | `/notes` |
| **Notifications** | In-app notifications + WebSocket push | `/notifications` |
| **Reports** | Sales pipeline analytics and charts | `/reports` |
| **Cron Jobs** | Scheduled daily reports, weekly token cleanup | `/jobs` |
| **API Documentation** | Interactive Swagger-style docs | `/api-docs` |
| **Debug Panel** | System status and diagnostics | `/debug` |
| **GraphQL Playground** | Interactive GraphQL explorer | `/graphql` (admin) |

### Security Architecture

- CSRF protection on all state-changing operations
- Session-based authentication with HTTP-only cookies
- Role-Based Access Control (admin / manager / employee)
- JWT API token authentication with scrypt hashing
- Rate limiting on auth endpoints
- GraphQL depth (max 5) and complexity (max 100) limits
- Production-mode GraphQL introspection disabled
- Audit logging for all security-relevant actions
- Honeypot routes for attack detection
- Secure HTTP headers (HSTS, CSP, XSS protection)
- Password strength enforcement (uppercase + lowercase + digit + special character + blacklist)
- scrypt password hashing with per-user salt

## Test Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Adm1n!Crm#2026` | Admin |
| `zhang.wei` | `Unicorn@2024` | Admin |
| `li.na` | `Unicorn@2024` | Manager (Sales – West Coast) |
| `wang.lei` | `Unicorn@2024` | Manager (Engineering) |
| `chen.xiao` | `Unicorn@2024` | Manager (Operations – Central) |
| `sarah.chen` | `Unicorn@2024` | Employee (Sales) |
| `james.wilson` | `Unicorn@2024` | Employee (Finance) |
| `emma.park` | `Unicorn@2024` | Employee (Support) |
| `li.wei` | `Unicorn@2024` | Employee (Engineering) |
| `maria.garcia` | `Unicorn@2024` | Employee (Support) |

The database includes 10 users, 15 customers, 20 orders, 15 tickets, and 20 audit log entries — all fictional.

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
│   ├── api-auth.js        # Bearer token + JWT auth
│   ├── graphql-auth.js    # GraphQL auth context injection
│   ├── audit.js           # Attack audit + honeypot routes
│   ├── headers.js         # Security HTTP headers
│   └── banner.js          # Security warning banner
├── routes/
│   ├── index.js           # Dashboard & API docs
│   ├── auth.js            # Login / Register / Forgot password
│   ├── customers.js       # Customer CRUD
│   ├── customers-batch.js # Batch delete / assign
│   ├── orders.js          # Order management + approval workflow
│   ├── tickets.js         # Ticket CRUD + comments
│   ├── tickets-batch.js   # Batch status / assign
│   ├── profile.js         # User profiles
│   ├── files.js           # Document browser
│   ├── upload.js          # Avatar + attachment upload
│   ├── export.js          # CSV export (admin only)
│   ├── import.js          # XML batch import
│   ├── api.js             # REST API
│   ├── admin.js           # Admin panel (users, sessions, audit, DB)
│   ├── api-tokens.js      # JWT token management
│   ├── oauth.js           # Mock OAuth provider
│   ├── graphql.js         # GraphQL endpoint
│   ├── calendar.js        # Calendar events + iCal export
│   ├── notes.js           # Rich text notes
│   ├── notifications.js   # In-app notifications
│   ├── reports.js         # Sales reports
│   ├── jobs.js            # Cron job management
│   ├── debug.js           # System diagnostics
│   └── errors.js          # Search + error handling
├── services/
│   ├── mail.js            # Email service (mock)
│   ├── scheduler.js       # Cron job scheduler
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

## Attack Surface (Intended)

This application is designed with intentional vulnerabilities for training:

- **Information Disclosure**: Debug endpoints, error stack traces, API docs, GraphQL introspection
- **Authentication Bypass**: Weak default credentials, invite-code gating, rate limit testing
- **Authorization Flaws**: IDOR on profiles, privilege escalation via mass assignment
- **Injection**: SQL injection on search, XSS in notes, XXE in XML import
- **Business Logic**: Order approval bypass, batch operation abuse, CSV export leakage
- **API Abuse**: Token enumeration, JWT none-algorithm, WebSocket auth bypass

All intentional vulnerabilities are documented for educational debriefing.

## License

MIT — For educational and authorized security training use only. See [LICENSE](LICENSE).

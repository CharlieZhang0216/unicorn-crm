# InfoLeak Lab

Information Disclosure Security Training Lab - an intentionally vulnerable web application for security education.

> **WARNING**: This application contains intentional security vulnerabilities. It is designed for security training purposes ONLY. Do NOT deploy on public networks or use real personal data.

## Overview

InfoLeak Lab simulates a corporate beauty advisor portal ("L'Oreal Beauty Advisor Portal") with 8 information disclosure vulnerability modules. It is built for security professionals to practice identifying and exploiting information leakage vulnerabilities in a safe, controlled environment.

## Requirements

- Node.js 22.5+ (uses built-in `node:sqlite` module, no native compilation needed)
- npm

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

## Training Scenario

You are a penetration tester hired to evaluate **L'Oreal Group's** internal beauty advisor portal. Your objective is to discover and document all information disclosure vulnerabilities. The portal appears to be a standard corporate application with advisor profiles, product assets, messaging, and API integrations.

The application dashboard provides entry points to several features. Not all vulnerable endpoints are linked from the UI - part of the challenge is discovering hidden attack surfaces.

## Vulnerability Modules

The application contains **8 categories** of information disclosure vulnerabilities:

| # | Category | Entry Point |
|---|----------|-------------|
| 1 | Directory Traversal | `/files` |
| 2 | Debug Info Leakage | `/debug/status` |
| 3 | API Information Disclosure | `/api-docs` |
| 4 | Improper Error Handling | `/search` |
| 5 | Backup File Exposure | *(no UI link - must be discovered)* |
| 6 | HTML/JS Comment Leakage | *(view page source)* |
| 7 | HTTP Header Info Leakage | *(inspect response headers)* |
| 8 | User Enumeration | `/auth/login` |

### Test Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| sophie.martin | password123 | Beauty Advisor |
| marie.dubois | letmein | HR Manager |

The database contains 20 fake employee records with simulated sensitive data (SSN, credit cards, salaries, etc.). All data is fictional.

## Project Structure

```
├── app.js                  # Express entry point
├── config/
│   ├── database.js         # SQLite initialization
│   └── seed.js             # Fake data seeding
├── middleware/
│   ├── banner.js           # Security warning banner
│   └── headers.js          # Leaky HTTP headers
├── routes/
│   ├── index.js            # Dashboard & API docs
│   ├── auth.js             # Login / Register / Forgot password
│   ├── files.js            # File download
│   ├── debug.js            # System diagnostics
│   ├── api.js              # REST API
│   ├── admin.js            # Hidden admin API
│   ├── errors.js           # Search (error handling)
│   └── profile.js          # User profiles
├── public/                 # Static assets (includes planted files)
├── views/                  # EJS templates (includes planted comments)
├── .env                    # Exposed environment config
└── package.json
```

## Tech Stack

- **Runtime**: Node.js with built-in `node:sqlite`
- **Framework**: Express 4
- **Templates**: EJS
- **Database**: SQLite (zero external DB dependencies)
- **Styling**: Bootstrap 5 (CDN)

## License

MIT - For educational and authorized security training use only.

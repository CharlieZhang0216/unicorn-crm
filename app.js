const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

// Load .env manually
const fs = require('fs');
try {
  const envContent = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
  envContent.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.substring(0, eqIndex).trim();
        const value = trimmed.substring(eqIndex + 1).trim();
        if (!process.env[key]) {
          process.env[key] = value;
        }
      }
    }
  });
  console.log('[App] Loaded .env configuration');
} catch (e) {
  console.log('[App] No .env file found, using defaults');
}

const app = express();
const PORT = process.env.PORT || 3000;

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Disable x-powered-by and trust proxy
app.disable('x-powered-by');
app.set('trust proxy', 1);

// Body parsing with size limits
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(cookieParser());

// Method override for PUT/DELETE in browser forms
app.use((req, res, next) => {
  if (req.body && req.body._method) {
    req.method = req.body._method.toUpperCase();
  }
  next();
});

// Request logging
app.use(morgan('combined'));

// Blocklist static paths
app.use(function(req, res, next) {
  const blocklist = ["/backups", "/_fake_git", "/.git", "/db"];
  if (blocklist.some(p => req.path.startsWith(p))) {
    return res.status(404).send("Not found");
  }
  if (req.path.startsWith('/uploads') && req.path !== '/uploads') {
    return res.status(401).send("Authentication required");
  }
  next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false
}));

// Middleware
const bannerMiddleware = require('./middleware/banner');
const headersMiddleware = require('./middleware/headers');
const csrfMiddleware = require('./middleware/csrf');
app.use(bannerMiddleware);
app.use(headersMiddleware);
app.use(csrfMiddleware);

// Initialize database and seed
const db = require('./config/database');
app.locals.db = db;
const { requireAuth } = require('./middleware/auth');

// Check if DB needs seeding
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
if (userCount === 0) {
  console.log('[App] Empty database detected, running seed...');
  require('./config/seed');
} else {
  console.log(`[App] Database ready: ${userCount} users`);
}

// Routes
const indexRouter = require('./routes/index');
const authRouter = require('./routes/auth');
const filesRouter = require('./routes/files');
const debugRouter = require('./routes/debug');
const apiRouter = require('./routes/api');
const adminRouter = require('./routes/admin');
const errorsRouter = require('./routes/errors');
const profileRouter = require('./routes/profile');

// Business routes
const customersRouter = require('./routes/customers');
const ordersRouter = require('./routes/orders');
const ticketsRouter = require('./routes/tickets');

// MODULE 2: New routes
const oauthRouter = require('./routes/oauth');
const apiTokensRouter = require('./routes/api-tokens');
const notesRouter = require('./routes/notes');

app.use('/', indexRouter);
app.use('/auth', authRouter);
app.use('/oauth', oauthRouter);       // MODULE 2: OAuth routes
app.use('/api-tokens', apiTokensRouter); // MODULE 2: JWT API tokens
app.use('/notes', notesRouter);       // MODULE 2: Rich text notes
app.use('/files', filesRouter);
app.use('/debug', debugRouter);
app.use('/api/v1', apiRouter);
app.use('/api/admin', adminRouter);
app.use('/search', errorsRouter);
app.use('/profile', profileRouter);
app.use('/customers', customersRouter);
app.use('/orders', ordersRouter);
app.use('/tickets', ticketsRouter);
app.use('/reports', require('./routes/reports'));

// ─── Module 1: File Upload, CSV Export, XML Import ───
undefined

// MODULE 1: File upload system
app.get('/upload', requireAuth, (req, res) => {
  res.render('upload/index', { user: req.currentUser });
});
app.use('/upload', require('./routes/upload'));

app.use('/export', require('./routes/export'));     // MODULE 1: CSV export
app.use('/import', require('./routes/import'));     // MODULE 1: XML import

// ─── Module 3: GraphQL, WebSocket, Notifications, Calendar, Jobs ───
app.use('/graphql', require('./routes/graphql'));   // MODULE 3: GraphQL API
app.use('/notifications', require('./routes/notifications')); // MODULE 3: Notifications
app.use('/calendar', require('./routes/calendar')); // MODULE 3: Calendar
app.use('/jobs', require('./routes/jobs'));         // MODULE 3: Job scheduler
module.exports = app;
// Custom 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    title: '404 Not Found',
    status: 404,
    message: 'The requested page could not be found.',
    stack: null
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err.message);
  if (err.detail) console.error('Detail:', err.detail);
  if (err.sql) console.error('SQL:', err.sql);
  console.error('Stack:', err.stack);

  const status = err.status || 500;

  const clientError = {
    status: status,
    message: status === 500
      ? 'An internal server error occurred. Our team has been notified.'
      : err.message || 'An error occurred.'
  };

  res.status(status);
  if (req.accepts('html')) {
    res.render('error', {
      title: `${status} Error`,
      status: status,
      message: clientError.message,
      stack: null
    });
  } else {
    res.json(clientError);
  }
});

app.listen(PORT, () => {
  console.log(`[Server] Unicorn CRM running on http://localhost:${PORT}`);
  console.log(`[Module 2] Email system: ${require('./services/mail').hasSmtpConfig ? 'SMTP configured' : 'Console mode'}`);
  console.log(`[Module 2] OAuth: ${process.env.GOOGLE_CLIENT_ID ? 'Google configured' : 'Mock provider active'}`);
  console.log(`[Module 2] JWT API tokens: Ready`);
  console.log(`[Module 2] Rich text notes: Ready`);
});

module.exports = app;

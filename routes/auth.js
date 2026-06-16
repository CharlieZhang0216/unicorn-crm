const express = require('express');
const router = express.Router();
const db = require('../config/database');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
// Security: Password strength requirements
function validatePasswordStrength(password) {
  const errors = [];
  if (password.length < 8) errors.push('at least 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('at least one uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('at least one lowercase letter');
  if (!/[0-9]/.test(password)) errors.push('at least one digit');
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/.test(password)) errors.push('at least one special character');
  const blacklist = ['password', 'password123', 'admin123', '12345678', 'qwerty123', 'letmein', 'welcome1', 'iloveyou', 'monkey', 'dragon'];
  if (blacklist.includes(password.toLowerCase())) errors.push('not a commonly used password');
  return errors;
}


// FIX: CSRF token generation (HMAC-based, no session needed)
const CSRF_SECRET = crypto.randomBytes(32).toString('hex');
function generateCSRF() {
  const token = crypto.randomBytes(16).toString('hex');
  const expiry = Date.now() + 3600000; // 1 hour
  const hmac = crypto.createHmac('sha256', CSRF_SECRET).update(`${token}:${expiry}`).digest('hex');
  return `${token}.${expiry}.${hmac}`;
}
function verifyCSRF(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [tok, exp, sig] = parts;
  if (Date.now() > parseInt(exp)) return false;
  const expected = crypto.createHmac('sha256', CSRF_SECRET).update(`${tok}:${exp}`).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

// Login page
router.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null, csrfToken: generateCSRF() });
});

function renderLogin(res, extra) {
  res.render('login', { title: 'Login', csrfToken: generateCSRF(), ...extra });
}
function renderRegister(res, extra) {
  res.render('register', { title: 'Register', csrfToken: generateCSRF(), ...extra });
}
function renderForgot(res, extra) {
  res.render('forgot-password', { title: 'Forgot Password', csrfToken: generateCSRF(), ...extra });
}

// FIXED: Uniform error messages to prevent user enumeration

// ─── Login Rate Limiter (in-memory, per-IP, per-username) ───
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;   // 15 minute window
const LOGIN_BLOCK_MS = 15 * 60 * 1000;    // 15 minute block after threshold

function getClientIP(req) {
  return req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip || 'unknown';
}
function checkLoginRateLimit(req, res) {
  const ip = getClientIP(req);
  const now = Date.now();
  const entry = loginAttempts.get(ip);

  if (entry && entry.blockUntil && now < entry.blockUntil) {
    const remaining = Math.ceil((entry.blockUntil - now) / 60000);
    res.status(429).json({ error: `Too many login attempts. Try again in ${remaining} minute(s).` });
    return true;
  }
  if (entry && now - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(ip);
    return false;
  }
  const count = entry ? entry.count + 1 : 1;
  loginAttempts.set(ip, {
    count,
    firstAttempt: entry ? entry.firstAttempt : now,
    blockUntil: count >= MAX_LOGIN_ATTEMPTS ? now + LOGIN_BLOCK_MS : 0
  });
  if (count >= MAX_LOGIN_ATTEMPTS) {
    res.status(429).json({ error: 'Account temporarily locked after too many attempts. Try again in 15 minutes.' });
    return true;
  }
  return false;
}

router.post('/login', (req, res) => {
  if (checkLoginRateLimit(req, res)) return;
  const { username, password, _csrf } = req.body;

  // FIX: CSRF validation for state-changing operations
  if (!verifyCSRF(_csrf)) {
    return renderLogin(res, { error: 'Invalid or expired form submission. Please refresh and try again.' });
  }

  if (!username || !password) {
    return renderLogin(res, { error: 'Please provide both username and password.' });
  }

  // Rate limiting
  const rateCheck = checkRateLimit(username, req.ip);
  if (rateCheck.blocked) {
    return renderLogin(res, { error: `Too many login attempts. Please try again in ${rateCheck.retryAfter} seconds.` });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    recordAttempt(username, req.ip);
    return renderLogin(res, { error: 'Invalid username or password.' });
  }

  // FIX: Support both legacy plaintext passwords and new scrypt-hashed passwords
  const pwdMatches = user.password.includes(':')
    ? (() => {
        const [salt, hash] = user.password.split(':');
        const computedHash = crypto.scryptSync(password, salt, 64).toString('hex');
        return hash === computedHash;
      })()
    : user.password === password;

  if (!pwdMatches) {
    recordAttempt(username, req.ip);
    return renderLogin(res, { error: 'Invalid username or password.' });
  }

  // Login success
  const sessionToken = 'sess_' + uuidv4().replace(/-/g, '');
  db.prepare('INSERT INTO sessions (user_id, token, ip_address, user_agent) VALUES (?, ?, ?, ?)')
    .run(user.id, sessionToken, req.ip, req.get('User-Agent'));

  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  // FIX: httpOnly cookie to prevent XSS access
  res.cookie('session_token', sessionToken, { httpOnly: true, sameSite: 'strict', secure: true });
  res.redirect('/');
});

// Logout route
router.get('/logout', (req, res) => {
  const token = req.cookies?.session_token;
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.clearCookie('session_token');
  res.redirect('/auth/login');
});

// Registration page
router.get('/register', (req, res) => {
  res.render('register', { title: 'Register', error: null, success: null, csrfToken: generateCSRF() });
});

// SECURITY AUDIT FIX: Read invite code from environment variable instead of hardcoding
// This prevents source-code disclosure from granting registration access
// Fallback value for development only — in production, set INVITE_CODE env var
const REGISTER_INVITE_CODE = process.env.INVITE_CODE || 'UC-INV-CHANGE-ME-PLEASE';

router.post('/register', (req, res) => {
  const { username, email, full_name, password, invite_code, _csrf } = req.body;

  // FIX: CSRF validation
  if (!verifyCSRF(_csrf)) {
    return renderRegister(res, { error: 'Invalid or expired form submission. Please refresh and try again.', success: null });
  }

  if (!username || !email || !password) {
    return renderRegister(res, { error: 'All fields are required.', success: null });
  }

  // FIX: Sanitize username — only alphanumeric, underscore, hyphen, 3-32 chars
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
    return renderRegister(res, { error: 'Username must be 3-32 alphanumeric characters, underscores, or hyphens.', success: null });
  }

  // FIX: Sanitize full_name — no HTML/script, max 64 chars
  if (full_name && (full_name.length > 64 || /[<>]/.test(full_name))) {
    return renderRegister(res, { error: 'Full name contains invalid characters.', success: null });
  }

  if (!invite_code || invite_code !== REGISTER_INVITE_CODE) {
    return renderRegister(res, { error: 'Invalid invite code. Registration is by invitation only.', success: null });
  }

  // Password strength validation (comprehensive)
  const passwordErrors = validatePasswordStrength(password);
  if (passwordErrors.length > 0) {
    return renderRegister(res, { error: 'Weak password: ' + passwordErrors.join(', ') + '.', success: null });
  }

  const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const existingEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  // Hash password FIRST (constant-time, even for duplicates) to prevent timing side-channel
  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = crypto.scryptSync(password, salt, 64).toString('hex');
  const storedPassword = `${salt}:${hashedPassword}`;

  if (existingUser || existingEmail) {
    // FIX: Uniform error message - doesn't reveal which one already exists
    return renderRegister(res, { error: 'Username or email is already registered.', success: null });
  }

  db.prepare(`
    INSERT INTO users (username, password, email, full_name, department, role)
    VALUES (?, ?, ?, ?, 'Unassigned', 'employee')
  `).run(username, storedPassword, email, full_name || username);

  res.render('register', {
    title: 'Register',
    csrfToken: generateCSRF(),
    error: null,
    success: 'Registration successful! You can now log in.'
  });
});

// Forgot password page
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { title: 'Forgot Password', error: null, success: null, csrfToken: generateCSRF() });
});

// FIXED: Uniform error messages
router.post('/forgot-password', (req, res) => {
  const { email, _csrf } = req.body;

  // FIX: CSRF validation
  if (!verifyCSRF(_csrf)) {
    return renderForgot(res, { error: 'Invalid or expired form submission. Please refresh and try again.', success: null });
  }

  if (!email) {
    return renderForgot(res, { error: 'Please provide your email address.', success: null });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    // FIX: Same message as success to prevent email enumeration
    return renderForgot(res, { error: null, success: 'If an account with that email exists, a password reset link has been sent.' });
  }

  res.render('forgot-password', {
    title: 'Forgot Password',
    csrfToken: generateCSRF(),
    error: null,
    success: 'If an account with that email exists, a password reset link has been sent.'
  });
});

// REMOVED: Hidden backdoor route (security risk)
// router.get('/backdoor', ...) - removed for security

module.exports = router;

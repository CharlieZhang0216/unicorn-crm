/**
 * OAuth 2.0 routes for Unicorn CRM
 * Supports Google OAuth (with env credentials) and a mock provider for testing
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../config/database');
const { v4: uuidv4 } = require('uuid');

// OAuth config — read from .env
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || (process.env.BASE_URL || 'http://localhost:3000') + '/oauth/google/callback';

const hasGoogleConfig = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

// In-memory state store (for production, use DB or Redis)
const oauthStates = {};

// Clean up expired states every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const key in oauthStates) {
    if (oauthStates[key].expiresAt < now) {
      delete oauthStates[key];
    }
  }
}, 5 * 60 * 1000);

// =========================================================================
// Google OAuth
// =========================================================================

/**
 * GET /oauth/google
 * Initiate Google OAuth 2.0 flow
 * If Google credentials not configured, redirect to mock provider
 */
router.get('/google', (req, res) => {
  if (!hasGoogleConfig) {
    // Fallback to mock OAuth provider
    const state = crypto.randomBytes(16).toString('hex');
    oauthStates[state] = { createdAt: Date.now(), expiresAt: Date.now() + 600000 }; // 10 min
    return res.redirect(`/oauth/mock?state=${state}&redirect_uri=${encodeURIComponent(req.query.redirect_uri || '/')}`);
  }

  const state = crypto.randomBytes(16).toString('hex');
  oauthStates[state] = {
    createdAt: Date.now(),
    expiresAt: Date.now() + 600000, // 10 min
    redirectUri: GOOGLE_REDIRECT_URI
  };

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state: state,
    access_type: 'offline',
    prompt: 'consent'
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

/**
 * GET /oauth/google/callback
 * Handle Google OAuth callback
 */
router.get('/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // Validate state parameter (CSRF protection)
  if (!state || !oauthStates[state]) {
    return res.status(403).render('error', {
      title: 'OAuth Error',
      status: 403,
      message: 'Invalid or expired OAuth state. Please try again.',
      stack: null
    });
  }

  const savedState = oauthStates[state];
  delete oauthStates[state]; // One-time use

  if (Date.now() > savedState.expiresAt) {
    return res.status(403).render('error', {
      title: 'OAuth Error',
      status: 403,
      message: 'OAuth state expired. Please try again.',
      stack: null
    });
  }

  if (error) {
    return res.status(400).render('error', {
      title: 'OAuth Error',
      status: 400,
      message: `Google OAuth error: ${error}`,
      stack: null
    });
  }

  if (!code) {
    return res.status(400).render('error', {
      title: 'OAuth Error',
      status: 400,
      message: 'No authorization code received.',
      stack: null
    });
  }

  try {
    // Exchange code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      }).toString()
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('[OAuth] Token exchange failed:', tokens.error_description || tokens.error);
      return res.status(400).render('error', {
        title: 'OAuth Error',
        status: 400,
        message: 'Failed to authenticate with Google. Please try again.',
        stack: null
      });
    }

    // Get user info
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    });
    const googleUser = await userInfoResponse.json();

    if (!googleUser.email) {
      return res.status(400).render('error', {
        title: 'OAuth Error',
        status: 400,
        message: 'Google account has no verified email address.',
        stack: null
      });
    }

    // Find or create local user
    await handleOAuthLogin(res, {
      email: googleUser.email,
      fullName: googleUser.name || googleUser.email,
      provider: 'google',
      providerId: googleUser.sub
    });

  } catch (err) {
    console.error('[OAuth] Google callback error:', err);
    res.status(500).render('error', {
      title: 'OAuth Error',
      status: 500,
      message: 'An error occurred during authentication.',
      stack: null
    });
  }
});

// =========================================================================
// Mock OAuth Provider (for testing without real credentials)
// =========================================================================

/**
 * GET /oauth/mock
 * Mock OAuth consent screen for testing
 */
router.get('/mock', (req, res) => {
  const { state, redirect_uri } = req.query;

  // Validate state
  if (!state || !oauthStates[state]) {
    return res.status(403).render('error', {
      title: 'OAuth Error',
      status: 403,
      message: 'Invalid OAuth state.',
      stack: null
    });
  }

  res.render('oauth-mock', {
    title: 'Mock OAuth Login',
    state: state,
    redirectUri: redirect_uri || '/',
    csrfToken: req.csrfToken || ''
  });
});

/**
 * POST /oauth/mock/authorize
 * Mock OAuth authorization endpoint
 */
router.post('/mock/authorize', (req, res) => {
  const { state, email, full_name, provider_id } = req.body;

  // Validate state
  if (!state || !oauthStates[state]) {
    return res.status(403).render('error', {
      title: 'OAuth Error',
      status: 403,
      message: 'Invalid or expired OAuth state.',
      stack: null
    });
  }

  delete oauthStates[state]; // One-time use

  if (!email) {
    return res.render('oauth-mock', {
      title: 'Mock OAuth Login',
      state: state,
      error: 'Email is required.',
      csrfToken: req.csrfToken || ''
    });
  }

  handleOAuthLogin(res, {
    email: email,
    fullName: full_name || email,
    provider: 'google', // Use 'google' so it integrates with existing code
    providerId: provider_id || `mock-${Date.now()}`
  });
});

// =========================================================================
// Shared: OAuth Login Handler
// =========================================================================

async function handleOAuthLogin(res, oauthData) {
  const { email, fullName, provider, providerId } = oauthData;

  // Check if user exists by email
  let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) {
    // Create new user from OAuth data
    const username = email.split('@')[0].replace(/[^a-zA-Z0-9_-]/g, '_');
    const uniqueUsername = makeUniqueUsername(username);

    const result = db.prepare(`
      INSERT INTO users (username, password, email, full_name, department, role, email_verified, status)
      VALUES (?, ?, ?, ?, 'Unassigned', 'employee', 1, 'active')
    `).run(
      uniqueUsername,
      `oauth:${provider}:${providerId}`, // Placeholder — OAuth users don't use password login
      email,
      fullName || email
    );

    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    console.log(`[OAuth] Created new user via ${provider}: ${user.username} (${email})`);
  } else {
    // Update email_verified if not already
    if (!user.email_verified) {
      db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
    }
    // Ensure status is active
    if (user.status !== 'active') {
      db.prepare('UPDATE users SET status = ? WHERE id = ?').run('active', user.id);
    }
  }

  // Create session
  const sessionToken = 'sess_' + uuidv4().replace(/-/g, '');
  db.prepare('INSERT INTO sessions (user_id, token, ip_address, user_agent) VALUES (?, ?, ?, ?)')
    .run(user.id, sessionToken, 'oauth', 'Unicorn CRM OAuth');

  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  res.cookie('session_token', sessionToken, { httpOnly: true, sameSite: 'strict', secure: true });
  res.redirect('/');
}

function makeUniqueUsername(base) {
  let username = base;
  let counter = 1;
  while (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    username = `${base}_${counter}`;
    counter++;
  }
  return username;
}

module.exports = router;
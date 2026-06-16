/**
 * GraphQL Authentication Middleware
 * Extracts auth from Authorization header (Bearer token) or cookie session
 * Injects context.user
 */
const db = require('../config/database');

function graphqlAuth(req) {
  // Method 1: Bearer token (Authorization header)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    // Check session token first
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (session) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
      if (user) return user;
    }
    // Then check api_tokens (hash)
    const crypto = require('crypto');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const apiToken = db.prepare('SELECT * FROM api_tokens WHERE token_hash = ?').get(tokenHash);
    if (apiToken) {
      // Check expiration
      if (apiToken.expires_at) {
        const now = new Date().toISOString();
        if (apiToken.expires_at < now) return null;
      }
      // Update last_used_at
      db.prepare('UPDATE api_tokens SET last_used_at = datetime(\'now\') WHERE id = ?').run(apiToken.id);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(apiToken.user_id);
      if (user) return user;
    }
  }

  // Method 2: Cookie session
  const sessionToken = req.cookies?.session_token;
  if (sessionToken) {
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(sessionToken);
    if (session) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
      if (user) return user;
    }
  }

  return null;
}

module.exports = { graphqlAuth };

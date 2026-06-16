/**
 * GraphQL 认证中间件
 * 从 Authorization header (Bearer token) 或 cookie session 提取认证
 * 注入 context.user
 */
const db = require('../config/database');

function graphqlAuth(req) {
  // 方法 1: Bearer token (Authorization header)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    // 先查 session token
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
    if (session) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
      if (user) return user;
    }
    // 再查 api_tokens (hash)
    const crypto = require('crypto');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const apiToken = db.prepare('SELECT * FROM api_tokens WHERE token_hash = ?').get(tokenHash);
    if (apiToken) {
      // 检查过期
      if (apiToken.expires_at) {
        const now = new Date().toISOString();
        if (apiToken.expires_at < now) return null;
      }
      // 更新 last_used_at
      db.prepare('UPDATE api_tokens SET last_used_at = datetime(\'now\') WHERE id = ?').run(apiToken.id);
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(apiToken.user_id);
      if (user) return user;
    }
  }

  // 方法 2: Cookie session
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

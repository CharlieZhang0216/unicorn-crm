/**
 * WebSocket Real-time Notification Service
 * Uses ws library (lightweight)
 * 
 * Notification types: new_customer, ticket_update, new_order, system_alert
 * Authentication: send auth token on connect
 * Channel isolation: users only receive notifications they have permission for
 */
const WebSocket = require('ws');
const db = require('../config/database');

// Track all connections: Map<ws, { userId, username, role }>
const connections = new Map();

let wss = null;

/**
 * Initialize WebSocket server
 * @param {http.Server} server - HTTP Server instance
 */
function initWebSocket(server) {
  wss = new WebSocket.Server({
    server,
    path: '/ws', // Clients connect to wss://host/ws
    maxPayload: 64 * 1024, // 64KB max message size
  });

  wss.on('connection', (ws, req) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[WebSocket] New connection from ${ip}`);

    let authenticated = false;
    let authTimeout = setTimeout(() => {
      if (!authenticated) {
        console.log(`[WebSocket] Auth timeout for ${ip}, closing`);
        ws.close(4001, 'Authentication timeout');
      }
    }, 10000); // 10 seconds to authenticate

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());

        // Handle auth message
        if (msg.type === 'auth') {
          const token = msg.token;
          if (!token) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token required' }));
            return;
          }

          // Verify session token
          const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
          if (!session) {
            // Try API token
            const crypto = require('crypto');
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const apiToken = db.prepare('SELECT * FROM api_tokens WHERE token_hash = ?').get(tokenHash);
            if (apiToken) {
              const user = db.prepare('SELECT * FROM users WHERE id = ?').get(apiToken.user_id);
              if (user && (!apiToken.expires_at || apiToken.expires_at >= new Date().toISOString())) {
                authenticated = true;
                clearTimeout(authTimeout);
                connections.set(ws, { userId: user.id, username: user.username, role: user.role });
                console.log(`[WebSocket] User ${user.username} authenticated via API token`);
                ws.send(JSON.stringify({ type: 'auth_ok', message: 'Authenticated' }));
                return;
              }
            }
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
            return;
          }

          const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
          if (!user) {
            ws.send(JSON.stringify({ type: 'error', message: 'User not found' }));
            return;
          }

          authenticated = true;
          clearTimeout(authTimeout);
          connections.set(ws, { userId: user.id, username: user.username, role: user.role });
          console.log(`[WebSocket] User ${user.username} authenticated`);
          ws.send(JSON.stringify({ type: 'auth_ok', message: `Authenticated as ${user.username}` }));
          return;
        }

        // Non-auth messages require authentication
        if (!authenticated) {
          ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated. Send auth message first.' }));
          return;
        }

        // Handle ping/heartbeat
        if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
          return;
        }

      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });

    ws.on('close', () => {
      const info = connections.get(ws);
      if (info) {
        console.log(`[WebSocket] User ${info.username} disconnected`);
      } else {
        console.log(`[WebSocket] Unauthenticated connection closed`);
      }
      clearTimeout(authTimeout);
      connections.delete(ws);
    });

    ws.on('error', (err) => {
      console.error(`[WebSocket] Connection error:`, err.message);
    });

    // Send welcome message
    ws.send(JSON.stringify({ type: 'welcome', message: 'Please authenticate by sending { type: "auth", token: "..." }' }));
  });

  console.log('[WebSocket] Server initialized at /ws');
  return wss;
}

/**
 * Send notification to a specific user
 * @param {number|string} userId - Target user ID
 * @param {object} notification - Notification object { type, title, body, entity_type, entity_id }
 */
function sendToUser(userId, notification) {
  if (!wss) return;

  const payload = JSON.stringify({
    type: 'notification',
    data: {
      ...notification,
      timestamp: new Date().toISOString()
    }
  });

  let delivered = 0;
  for (const [ws, info] of connections.entries()) {
    if (info.userId === userId) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
        delivered++;
      }
    }
  }

  return delivered;
}

/**
 * Broadcast notification to all users with a specific role
 * @param {string} role - Role name (admin, manager, etc.)
 * @param {object} notification - Notification object
 */
function sendToRole(role, notification) {
  if (!wss) return 0;

  const payload = JSON.stringify({
    type: 'notification',
    data: {
      ...notification,
      timestamp: new Date().toISOString()
    }
  });

  let delivered = 0;
  for (const [ws, info] of connections.entries()) {
    if (info.role === role && ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
      delivered++;
    }
  }

  return delivered;
}

/**
 * Broadcast notification to all authenticated users
 * @param {object} notification - Notification object
 */
function broadcast(notification) {
  if (!wss) return 0;

  const payload = JSON.stringify({
    type: 'notification',
    data: {
      ...notification,
      timestamp: new Date().toISOString()
    }
  });

  let delivered = 0;
  for (const [ws, info] of connections.entries()) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
      delivered++;
    }
  }

  return delivered;
}

/**
 * Get active connection statistics
 */
function getStats() {
  const stats = {
    total: connections.size,
    authenticated: 0,
    byRole: {}
  };
  for (const [, info] of connections.entries()) {
    if (info.userId) {
      stats.authenticated++;
      stats.byRole[info.role] = (stats.byRole[info.role] || 0) + 1;
    }
  }
  return stats;
}

module.exports = {
  initWebSocket,
  sendToUser,
  sendToRole,
  broadcast,
  getStats
};

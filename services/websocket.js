/**
 * WebSocket 实时通知服务
 * 使用 ws 库（轻量级）
 * 
 * 通知类型：new_customer, ticket_update, new_order, system_alert
 * 认证：连接时发送 auth token
 * 频道隔离：用户只能收到自己有权限的通知
 */
const WebSocket = require('ws');
const db = require('../config/database');

// Track all connections: Map<ws, { userId, username, role }>
const connections = new Map();

let wss = null;

/**
 * 初始化 WebSocket 服务器
 * @param {http.Server} server - HTTP Server instance
 */
function initWebSocket(server) {
  wss = new WebSocket.Server({
    server,
    path: '/ws', // 客户端连接 wss://host/ws
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
 * 发送通知给指定用户
 * @param {number|string} userId - 目标用户 ID
 * @param {object} notification - 通知对象 { type, title, body, entity_type, entity_id }
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
 * 广播通知给具有特定角色的所有用户
 * @param {string} role - 角色名 (admin, manager, etc.)
 * @param {object} notification - 通知对象
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
 * 广播通知给所有已认证用户
 * @param {object} notification - 通知对象
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
 * 获取活跃连接统计
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

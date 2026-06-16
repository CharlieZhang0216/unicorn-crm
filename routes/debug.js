const express = require('express');
const router = express.Router();
const os = require('os');
const path = require('path');
const db = require('../config/database');

// FIXED: Authentication middleware for debug endpoints
function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  next();
}

// Basic health status (safe to expose)
router.get('/status', (req, res) => {
  res.render('debug', {
    title: 'System Status',
    uptime: process.uptime(),
    memory: {
      rss: process.memoryUsage().rss,
      heapTotal: process.memoryUsage().heapTotal,
      heapUsed: process.memoryUsage().heapUsed,
      external: process.memoryUsage().external
    },
    nodeVersion: process.version
  });
});

// SECURITY AUDIT FIX: Minimal info exposure — removed hostname, cwd, loadavg, PID
router.get('/info', requireAuth, (req, res) => {
  const info = {
    server: {
      // SECURITY FIX: Removed hostname (info leak)
      platform: os.platform(),
      arch: os.arch(),
      uptime: os.uptime(),
      // SECURITY FIX: Removed loadavg (attack recon)
      totalMemory: os.totalmem(),
      freeMemory: os.freemem()
    },
    process: {
      // SECURITY FIX: Removed PID (privilege escalation recon)
      version: process.version,
      // SECURITY FIX: Removed cwd (directory structure leak)
      memoryUsage: {
        heapTotal: process.memoryUsage().heapTotal,
        heapUsed: process.memoryUsage().heapUsed
      },
      uptime: process.uptime()
    }
    // SECURITY FIX: Removed environment variables, network interfaces, user info, module paths, package.json exposure
  };
  res.json(info);
});

// FIXED: Removed - environment variable dump endpoint is a security risk
// FIXED: Removed - route enumeration endpoint is a security risk

module.exports = router;

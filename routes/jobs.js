/**
 * Scheduled Job Management Routes
 * GET /jobs — List jobs and status
 * POST /jobs/:name/run — Trigger manually
 * GET /jobs/:name/history — Run history
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { getJobsStatus, triggerJob, getJobHistory } = require('../services/scheduler');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
  next();
}

function requireAdmin(req, res, next) {
  if (req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// GET /jobs — List all scheduled jobs and status
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const jobs = getJobsStatus();
  res.json({ success: true, data: jobs });
});

// POST /jobs/:name/run — Trigger job manually
router.post('/:name/run', requireAuth, requireAdmin, (req, res) => {
  const { name } = req.params;
  const validJobs = ['daily_report', 'weekly_token_cleanup', 'tier_upgrade'];

  if (!validJobs.includes(name)) {
    return res.status(400).json({ error: `Invalid job name. Allowed: ${validJobs.join(', ')}.` });
  }

  const result = triggerJob(name);
  res.json({ success: true, job: name, result });
});

// GET /jobs/:name/history — View job run history
router.get('/:name/history', requireAuth, requireAdmin, (req, res) => {
  const { name } = req.params;
  const history = getJobHistory(name);

  if (!history) {
    return res.status(404).json({ error: `Job "${name}" not found.` });
  }

  res.json({ success: true, job: name, history });
});

module.exports = router;

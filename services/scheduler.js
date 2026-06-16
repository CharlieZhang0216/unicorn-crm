/**
 * Cron Job Scheduler
 * Uses node-cron
 * 
 * Jobs:
 * - daily_report: Generate daily report (DAU stats, new customer count)
 * - weekly_token_cleanup: Weekly cleanup of expired tokens
 * - Can be triggered manually via admin API
 */
const cron = require('node-cron');
const db = require('../config/database');
const fs = require('fs');
const path = require('path');

// Job definitions
const jobs = {
  daily_report: {
    name: 'daily_report',
    description: 'Generate daily report (DAU stats, new customer count)',
    schedule: '0 1 * * *', // Every day at 1:00 AM
    running: false,
    lastRun: null,
    lastResult: null,
    history: [],
    maxHistory: 20,
  },
  weekly_token_cleanup: {
    name: 'weekly_token_cleanup',
    description: 'Clean up expired session tokens and email tokens',
    schedule: '0 3 * * 0', // Every Sunday at 3:00 AM
    running: false,
    lastRun: null,
    lastResult: null,
    history: [],
    maxHistory: 20,
  },
};

// Save history record
function saveHistory(jobName, status, result) {
  const job = jobs[jobName];
  if (!job) return;
  job.history.unshift({
    ts: new Date().toISOString(),
    status,
    result,
  });
  if (job.history.length > job.maxHistory) {
    job.history = job.history.slice(0, job.maxHistory);
  }
}

// ─── Daily Report ───
function runDailyReport() {
  if (jobs.daily_report.running) {
    return { status: 'skipped', reason: 'Already running' };
  }
  jobs.daily_report.running = true;
  jobs.daily_report.lastRun = new Date().toISOString();

  try {
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    // DAU: users who logged in today (created session or last_login today)
    const dauSessions = db.prepare(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM sessions
      WHERE date(created_at) = ?
    `).get(today);

    // Active users today (last_login is today)
    const activeUsers = db.prepare(`
      SELECT COUNT(*) as count FROM users
      WHERE date(last_login) = ? AND is_active = 1
    `).get(today);

    // New customers
    const newCustomers = db.prepare(`
      SELECT COUNT(*) as count FROM customers
      WHERE date(created_at) = ?
    `).get(today);

    // New orders
    const newOrders = db.prepare(`
      SELECT COUNT(*) as count FROM orders
      WHERE date(created_at) = ?
    `).get(today);

    // New tickets
    const newTickets = db.prepare(`
      SELECT COUNT(*) as count FROM tickets
      WHERE date(created_at) = ?
    `).get(today);

    const report = {
      date: today,
      dau: Math.max(dauSessions.count, activeUsers.count),
      new_customers: newCustomers.count,
      new_orders: newOrders.count,
      new_tickets: newTickets.count,
      generated_at: new Date().toISOString(),
    };

    // Save to file
    const reportDir = path.join(__dirname, '..', 'logs');
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    const reportFile = path.join(reportDir, `daily-report-${today}.json`);
    fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));

    console.log(`[Scheduler] Daily report generated: ${reportFile}`);
    console.log(`[Scheduler] DAU: ${report.dau}, New Customers: ${report.new_customers}, New Orders: ${report.new_orders}, New Tickets: ${report.new_tickets}`);

    jobs.daily_report.running = false;
    jobs.daily_report.lastResult = report;
    saveHistory('daily_report', 'success', report);

    return { status: 'completed', report };
  } catch (e) {
    console.error('[Scheduler] Daily report error:', e.message);
    jobs.daily_report.running = false;
    const errResult = { error: e.message };
    saveHistory('daily_report', 'error', errResult);
    return { status: 'error', error: e.message };
  }
}

// ─── Weekly Token Cleanup ───
function runTokenCleanup() {
  if (jobs.weekly_token_cleanup.running) {
    return { status: 'skipped', reason: 'Already running' };
  }
  jobs.weekly_token_cleanup.running = true;
  jobs.weekly_token_cleanup.lastRun = new Date().toISOString();

  try {
    const now = new Date().toISOString();

    // Clean up expired sessions
    const sessionResult = db.prepare(`
      DELETE FROM sessions WHERE expires_at < ?
    `).run(now);

    // Clean up expired email tokens (expires_at)
    // Attempt cleanup (table may not exist)
    let emailTokenResult = { changes: 0 };
    try {
      emailTokenResult = db.prepare(`
        DELETE FROM email_tokens WHERE expires_at < ? AND used = 0
      `).run(now);
    } catch (e) {
      // Table may not exist
    }

    // Clean up expired API tokens
    let apiTokenResult = { changes: 0 };
    try {
      apiTokenResult = db.prepare(`
        DELETE FROM api_tokens WHERE expires_at < ?
      `).run(now);
    } catch (e) {
      // Table may not exist
    }

    const result = {
      expired_sessions_cleaned: sessionResult.changes,
      expired_email_tokens_cleaned: emailTokenResult.changes,
      expired_api_tokens_cleaned: apiTokenResult.changes,
      cleaned_at: now,
    };

    console.log(`[Scheduler] Token cleanup: ${sessionResult.changes} sessions, ${emailTokenResult.changes} email tokens, ${apiTokenResult.changes} API tokens expired`);

    jobs.weekly_token_cleanup.running = false;
    jobs.weekly_token_cleanup.lastResult = result;
    saveHistory('weekly_token_cleanup', 'success', result);

    return { status: 'completed', result };
  } catch (e) {
    console.error('[Scheduler] Token cleanup error:', e.message);
    jobs.weekly_token_cleanup.running = false;
    const errResult = { error: e.message };
    saveHistory('weekly_token_cleanup', 'error', errResult);
    return { status: 'error', error: e.message };
  }
}

/**
 * Initialize all cron jobs
 */
function initScheduler() {
  // Daily report
  cron.schedule(jobs.daily_report.schedule, () => {
    console.log('[Scheduler] Running daily_report...');
    runDailyReport();
  });
  console.log(`[Scheduler] Job "daily_report" scheduled: ${jobs.daily_report.schedule}`);

  // Weekly token cleanup
  cron.schedule(jobs.weekly_token_cleanup.schedule, () => {
    console.log('[Scheduler] Running weekly_token_cleanup...');
    runTokenCleanup();
  });
  console.log(`[Scheduler] Job "weekly_token_cleanup" scheduled: ${jobs.weekly_token_cleanup.schedule}`);

  console.log('[Scheduler] All cron jobs initialized');
}

/**
 * Trigger job manually
 */
function triggerJob(name) {
  switch (name) {
    case 'daily_report':
      return runDailyReport();
    case 'weekly_token_cleanup':
      return runTokenCleanup();
    default:
      return { status: 'error', error: `Unknown job: ${name}` };
  }
}

/**
 * Get job status
 */
function getJobsStatus() {
  const result = {};
  for (const [name, job] of Object.entries(jobs)) {
    result[name] = {
      name: job.name,
      description: job.description,
      schedule: job.schedule,
      running: job.running,
      lastRun: job.lastRun,
      lastResult: job.lastResult,
      historyCount: job.history.length,
    };
  }
  return result;
}

/**
 * Get job history
 */
function getJobHistory(name) {
  const job = jobs[name];
  if (!job) return null;
  return job.history;
}

module.exports = {
  initScheduler,
  triggerJob,
  getJobsStatus,
  getJobHistory,
};

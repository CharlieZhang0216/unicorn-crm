/**
 * 定时任务调度器
 * 使用 node-cron
 * 
 * 任务：
 * - daily_report: 每日报表生成（DAU 统计、新增客户数）
 * - weekly_token_cleanup: 每周清理过期 tokens
 * - 可通过 admin API 手动触发
 */
const cron = require('node-cron');
const db = require('../config/database');
const fs = require('fs');
const path = require('path');

// 任务定义
const jobs = {
  daily_report: {
    name: 'daily_report',
    description: 'Generate daily report (DAU stats, new customer count)',
    schedule: '0 1 * * *', // 每天凌晨 1 点
    running: false,
    lastRun: null,
    lastResult: null,
    history: [],
    maxHistory: 20,
  },
  weekly_token_cleanup: {
    name: 'weekly_token_cleanup',
    description: 'Clean up expired session tokens and email tokens',
    schedule: '0 3 * * 0', // 每周日凌晨 3 点
    running: false,
    lastRun: null,
    lastResult: null,
    history: [],
    maxHistory: 20,
  },
};

// 保存历史记录
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

// ─── 每日报表 ───
function runDailyReport() {
  if (jobs.daily_report.running) {
    return { status: 'skipped', reason: 'Already running' };
  }
  jobs.daily_report.running = true;
  jobs.daily_report.lastRun = new Date().toISOString();

  try {
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    // DAU: 今天有登录行为（创建新 session 或 last_login 在今天）
    const dauSessions = db.prepare(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM sessions
      WHERE date(created_at) = ?
    `).get(today);

    // 今天活跃用户（last_login 在今天）
    const activeUsers = db.prepare(`
      SELECT COUNT(*) as count FROM users
      WHERE date(last_login) = ? AND is_active = 1
    `).get(today);

    // 新增客户
    const newCustomers = db.prepare(`
      SELECT COUNT(*) as count FROM customers
      WHERE date(created_at) = ?
    `).get(today);

    // 新增订单
    const newOrders = db.prepare(`
      SELECT COUNT(*) as count FROM orders
      WHERE date(created_at) = ?
    `).get(today);

    // 新工单
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

    // 保存到文件
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

// ─── 周清理过期 tokens ───
function runTokenCleanup() {
  if (jobs.weekly_token_cleanup.running) {
    return { status: 'skipped', reason: 'Already running' };
  }
  jobs.weekly_token_cleanup.running = true;
  jobs.weekly_token_cleanup.lastRun = new Date().toISOString();

  try {
    const now = new Date().toISOString();

    // 清理过期会话
    const sessionResult = db.prepare(`
      DELETE FROM sessions WHERE expires_at < ?
    `).run(now);

    // 清理过期 email tokens (expires_at)
    // 尝试清理（如果表存在）
    let emailTokenResult = { changes: 0 };
    try {
      emailTokenResult = db.prepare(`
        DELETE FROM email_tokens WHERE expires_at < ? AND used = 0
      `).run(now);
    } catch (e) {
      // 表可能不存在
    }

    // 清理过期 API tokens
    let apiTokenResult = { changes: 0 };
    try {
      apiTokenResult = db.prepare(`
        DELETE FROM api_tokens WHERE expires_at < ?
      `).run(now);
    } catch (e) {
      // 表可能不存在
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
 * 初始化所有定时任务
 */
function initScheduler() {
  // 每日报表
  cron.schedule(jobs.daily_report.schedule, () => {
    console.log('[Scheduler] Running daily_report...');
    runDailyReport();
  });
  console.log(`[Scheduler] Job "daily_report" scheduled: ${jobs.daily_report.schedule}`);

  // 每周 token 清理
  cron.schedule(jobs.weekly_token_cleanup.schedule, () => {
    console.log('[Scheduler] Running weekly_token_cleanup...');
    runTokenCleanup();
  });
  console.log(`[Scheduler] Job "weekly_token_cleanup" scheduled: ${jobs.weekly_token_cleanup.schedule}`);

  console.log('[Scheduler] All cron jobs initialized');
}

/**
 * 手动触发任务
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
 * 获取任务状态
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
 * 获取任务历史
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

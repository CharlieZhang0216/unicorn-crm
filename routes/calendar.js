/**
 * 日历/日程系统路由
 * 
 * GET /calendar — 查看日程（月/周/日视图）
 * POST /calendar — 创建日程事件
 * PUT /calendar/:id — 更新事件
 * DELETE /calendar/:id — 删除事件
 * GET /calendar/export.ics — 导出 iCalendar 文件
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { sendToUser } = require('../services/websocket');

function requireAuth(req, res, next) {
  const token = req.cookies?.session_token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.currentUser = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!req.currentUser) return res.status(401).json({ error: 'User not found' });
  next();
}

// GET /calendar — 查看日程（支持月/周/日视图）
router.get('/', requireAuth, (req, res) => {
  const { view, start, end } = req.query;
  const calendarView = ['month', 'week', 'day'].includes(view) ? view : 'month';

  // 计算日期范围
  let startDate, endDate;
  const now = new Date();

  if (start && end) {
    // 自定义范围
    startDate = start;
    endDate = end;
  } else {
    // 基于视图计算
    switch (calendarView) {
      case 'month': {
        const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
        const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        startDate = firstDay.toISOString().split('T')[0];
        endDate = lastDay.toISOString().split('T')[0] + 'T23:59:59';
        break;
      }
      case 'week': {
        const dayOfWeek = now.getDay();
        const monday = new Date(now);
        monday.setDate(now.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek - 1));
        const sunday = new Date(monday);
        sunday.setDate(monday.getDate() + 6);
        startDate = monday.toISOString().split('T')[0];
        endDate = sunday.toISOString().split('T')[0] + 'T23:59:59';
        break;
      }
      case 'day':
      default: {
        startDate = now.toISOString().split('T')[0];
        endDate = startDate + 'T23:59:59';
        break;
      }
    }
  }

  // 获取该范围内的所有事件（用户自己的 + 公开事件/部门事件）
  let events;
  if (req.currentUser.role === 'admin') {
    events = db.prepare(`
      SELECT e.*, u.full_name as creator_name, u.department as creator_department
      FROM events e
      JOIN users u ON e.user_id = u.id
      WHERE (e.start_time >= ? AND e.start_time <= ?)
         OR (e.end_time >= ? AND e.end_time <= ?)
         OR (e.start_time <= ? AND e.end_time >= ?)
      ORDER BY e.start_time ASC
    `).all(startDate, endDate, startDate, endDate, startDate, endDate);
  } else {
    events = db.prepare(`
      SELECT e.*, u.full_name as creator_name, u.department as creator_department
      FROM events e
      JOIN users u ON e.user_id = u.id
      WHERE (
        e.user_id = ? OR
        (e.event_type = 'meeting' AND u.department = ?)
      )
      AND (
        (e.start_time >= ? AND e.start_time <= ?)
        OR (e.end_time >= ? AND e.end_time <= ?)
        OR (e.start_time <= ? AND e.end_time >= ?)
      )
      ORDER BY e.start_time ASC
    `).all(req.currentUser.id, req.currentUser.department,
      startDate, endDate, startDate, endDate, startDate, endDate);
  }

  if (req.accepts('html')) {
    return res.render('calendar', {
      title: 'Calendar',
      events,
      user: req.currentUser,
      view: calendarView,
      startDate,
      endDate,
      currentMonth: now.getMonth(),
      currentYear: now.getFullYear(),
    });
  }

  res.json({ success: true, data: events, view: calendarView, startDate, endDate });
});

// POST /calendar — 创建日程事件
router.post('/', requireAuth, (req, res) => {
  const { title, description, location, start_time, end_time, all_day, event_type, entity_type, entity_id } = req.body;

  if (!title || !start_time) {
    return res.status(400).json({ error: 'title and start_time are required.' });
  }

  const validTypes = ['meeting', 'call', 'task', 'reminder'];
  const eType = event_type && validTypes.includes(event_type) ? event_type : 'task';

  const result = db.prepare(`
    INSERT INTO events (user_id, title, description, location, start_time, end_time, all_day, event_type, entity_type, entity_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `).run(
    req.currentUser.id,
    title.trim(),
    description || '',
    location || '',
    start_time,
    end_time || start_time,
    all_day ? 1 : 0,
    eType,
    entity_type || null,
    entity_id || null
  );

  // 如果是指向 ticket/customer 的 reminder，推送给相关人员
  if (eType === 'reminder' && entity_type) {
    sendToUser(req.currentUser.id, {
      type: 'system_alert',
      title: 'New Reminder',
      body: `Reminder: ${title} (${start_time})`,
      entity_type: 'event',
      entity_id: result.lastInsertRowid,
    });
  }

  res.json({
    success: true,
    message: 'Event created.',
    event_id: result.lastInsertRowid,
  });
});

// PUT /calendar/:id — 更新事件
router.put('/:id', requireAuth, (req, res) => {
  const eventId = parseInt(req.params.id);
  if (isNaN(eventId)) {
    return res.status(400).json({ error: 'Invalid event ID.' });
  }

  const event = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);
  if (!event) {
    return res.status(404).json({ error: 'Event not found.' });
  }

  // 只有创建者可以编辑
  if (event.user_id !== req.currentUser.id && req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'You can only edit your own events.' });
  }

  const { title, description, location, start_time, end_time, all_day, event_type } = req.body;

  db.prepare(`
    UPDATE events SET
      title = COALESCE(?, title),
      description = COALESCE(?, description),
      location = COALESCE(?, location),
      start_time = COALESCE(?, start_time),
      end_time = COALESCE(?, end_time),
      all_day = COALESCE(?, all_day),
      event_type = COALESCE(?, event_type),
      updated_at = datetime('now')
    WHERE id = ?
  `).run(
    title || null,
    description !== undefined ? description : null,
    location !== undefined ? location : null,
    start_time || null,
    end_time || null,
    all_day !== undefined ? (all_day ? 1 : 0) : null,
    event_type || null,
    eventId
  );

  const updated = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);

  res.json({ success: true, message: 'Event updated.', event: updated });
});

// DELETE /calendar/:id — 删除事件
router.delete('/:id', requireAuth, (req, res) => {
  const eventId = parseInt(req.params.id);
  if (isNaN(eventId)) {
    return res.status(400).json({ error: 'Invalid event ID.' });
  }

  const event = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);
  if (!event) {
    return res.status(404).json({ error: 'Event not found.' });
  }

  // 只有创建者或 admin 可以删除
  if (event.user_id !== req.currentUser.id && req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'You can only delete your own events.' });
  }

  db.prepare('DELETE FROM events WHERE id = ?').run(eventId);

  res.json({ success: true, message: 'Event deleted.' });
});

// GET /calendar/export.ics — 导出 iCalendar 文件
router.get('/export.ics', requireAuth, (req, res) => {
  // 获取当前用户的所有事件
  const events = db.prepare(`
    SELECT * FROM events
    WHERE user_id = ?
    ORDER BY start_time ASC
  `).all(req.currentUser.id);

  // iCalendar 内容转义
  function icsEscape(text) {
    if (!text) return '';
    return text
      .replace(/\\/g, '\\\\')   // 反斜杠
      .replace(/\n/g, '\\n')     // 换行
      .replace(/;/g, '\\;')      // 分号
      .replace(/,/g, '\\,')      // 逗号
      .replace(/[\r]/g, '');     // 移除回车
  }

  function formatICSDate(dateStr) {
    if (!dateStr) return '';
    // 移除时区信息，转为 UTC 格式
    try {
      const d = new Date(dateStr);
      return d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    } catch (e) {
      return dateStr.replace(/[-:]/g, '').split('.')[0] + 'Z';
    }
  }

  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Unicorn CRM//Calendar//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
  ];

  for (const event of events) {
    const dtStart = formatICSDate(event.start_time);
    const dtEnd = formatICSDate(event.end_time || event.start_time);
    const created = formatICSDate(event.created_at);
    const lastModified = formatICSDate(event.updated_at || event.created_at);

    lines.push('BEGIN:VEVENT');
    lines.push(`UID:${event.id}@unicorn-crm`);
    lines.push(`DTSTART:${dtStart}`);
    lines.push(`DTEND:${dtEnd}`);
    lines.push(`DTSTAMP:${formatICSDate(new Date().toISOString())}`);
    lines.push(`CREATED:${created}`);
    lines.push(`LAST-MODIFIED:${lastModified}`);
    lines.push(`SUMMARY:${icsEscape(event.title)}`);
    if (event.description) {
      lines.push(`DESCRIPTION:${icsEscape(event.description)}`);
    }
    if (event.location) {
      lines.push(`LOCATION:${icsEscape(event.location)}`);
    }
    lines.push(`CATEGORIES:${icsEscape(event.event_type || 'task')}`);
    if (event.all_day) {
      lines.push('TRANSP:TRANSPARENT');
    }
    lines.push('END:VEVENT');
  }

  lines.push('END:VCALENDAR');

  const icsContent = lines.join('\r\n');

  res.set({
    'Content-Type': 'text/calendar; charset=utf-8',
    'Content-Disposition': `attachment; filename="unicorn-calendar-${req.currentUser.username}.ics"`,
  });

  res.send(icsContent);
});

module.exports = router;

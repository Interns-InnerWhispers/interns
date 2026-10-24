// Security self-check: `npm test`. Starts the real server against an in-memory fake database
// (no MySQL, no emails, no Cloudinary) and tries the attacks that used to work.
process.env.NODE_ENV = 'test';
process.env.SECRET_KEY = 'test-secret-key-that-is-long-enough-1234567890';
process.env.DB_HOST = 'fake'; process.env.DB_USER = 'fake'; process.env.DB_NAME = 'fake';
process.env.PORT = '39123';
process.env.INTERN_INVITE_CODE = 'JOIN-2026';
process.env.BREVO_API_KEY = ''; process.env.SMTP_PASS = '';
const assert = require('assert');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Fake mysql2: records every query so we can check what reached the database
const queries = [], tickets = [], tmsgs = [];
const HASH = bcrypt.hashSync('right-password', 4);
function answer(sql, p = []) {
  // Help & Support
  if (/SELECT id, full_name, email FROM users WHERE id/.test(sql)) return [{ id: p[0], full_name: 'User ' + p[0], email: 'u' + p[0] + '@x.in' }];
  if (/^INSERT INTO support_tickets/.test(sql)) { tickets.push({ id: tickets.length + 1, user_id: p[0], subject: p[5], status: 'Open', unread_for_user: 0 }); return { insertId: tickets.length }; }
  if (/^INSERT INTO support_messages/.test(sql)) { tmsgs.push({ ticket_id: p[0], sender_user_id: p[1], body: p[p.length - 1] }); return { insertId: tmsgs.length }; }
  if (/SELECT \* FROM support_tickets WHERE id/.test(sql)) return tickets.filter(t => t.id === Number(p[0]));
  if (/^UPDATE support_tickets SET status = \?, unread_for_user = \? WHERE id/.test(sql)) { const t = tickets.find(x => x.id === p[2]); if (t) { t.status = p[0]; t.unread_for_user = p[1]; } return { affectedRows: 1 }; }
  if (/FROM support_messages WHERE ticket_id/.test(sql)) return tmsgs.filter(m => m.ticket_id === p[1]);
  if (/FROM support_tickets t/.test(sql)) return /t\.user_id = \?/.test(sql) ? tickets.filter(t => t.user_id === p[0]) : tickets;
  if (/FROM users WHERE email = \?/.test(sql)) return [{ id: 1, email: 'hr@x.in', role: 'hr', password_hash: HASH, status: 'active', full_name: 'HR' }];
  if (/SELECT intern_id FROM `Documents`/.test(sql)) return [{ intern_id: 'INT002' }];
  if (/SELECT intern_id FROM `Tasks`/.test(sql)) return [{ intern_id: 'INT001' }];
  if (/^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER)/i.test(sql)) return { affectedRows: 1, insertId: 1 };
  if (/AS used FROM leave_requests/.test(sql)) return [{ used: 3 }];
  if (/AS present, COALESCE/.test(sql)) return [{ present: 8, late: 2, absent: 2, leave_days: 1, n: 13, hours: 41.25 }];   // attendance counts
  if (/COUNT\(\*\) AS total, COALESCE\(SUM\(status = 'Completed'\)/.test(sql)) return [{ total: 4, done: 3 }];   // task counts
  if (/SELECT task_id, task_title, due_date/.test(sql)) return [{ task_id: 1, task_title: 'Design', due_date: '2026-01-02', status: 'In Progress', priority: 'High' }];
  if (/SELECT email, internrole, phone/.test(sql)) return [{ email: 'a@x.in', internrole: 'Dev', phone: '1' }];
  if (/(SUM|COUNT)\(/i.test(sql)) return [{ n: 0, count: 0, total: 0 }];   // totals queries always return one row
  return [];
}
const fakeDb = {
  query(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    queries.push({ sql, params });
    const r = answer(sql, params);
    if (cb) setImmediate(() => cb(null, r));
    return { on() {} };
  },
  promise() { return { query: async (sql, params) => { queries.push({ sql, params }); return [answer(sql, params)]; } }; },
  end(cb) { cb && cb(); },
};
require.cache[require.resolve('mysql2')] = { exports: { createPool: () => fakeDb, createConnection: () => fakeDb } };

require('./server');

const base = 'http://localhost:39123';
const sign = (p) => jwt.sign(p, process.env.SECRET_KEY, { expiresIn: '1h' });
const HRT = sign({ id: 1, role: 'hr' });
const INT = sign({ id: 2, role: 'Intern', intern_id: 'INT001' });
const DOC = sign({ id: 3, role: 'psychiatry' });
const call = (method, url, { token, body, headers = {} } = {}) => fetch(base + url, {
  method, redirect: 'manual',
  headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers },
  body: body && JSON.stringify(body),
}).then(async r => ({ status: r.status, headers: r.headers, body: await r.json().catch(() => ({})) }));

setTimeout(async () => {
  try {
    // Holes that used to be open to anyone
    assert.equal((await call('GET', '/users')).status, 404, '/users is gone');
    assert.equal((await call('GET', '/api/reports/download-file?path=package.json')).status, 404, 'no reading files from disk');
    assert.equal((await call('GET', '/api/debug/reports')).status, 404, 'debug route gone');
    assert.equal((await call('POST', '/api/forgotpass', { body: { email: 'hr@x.in', npass: 'hacked123' } })).status, 410, 'old reset refused');
    assert.ok(!queries.some(q => /UPDATE users SET password_hash/.test(q.sql)), 'no password was changed');

    // Patient data: doctors only
    assert.equal((await call('GET', '/api/appointments/1')).status, 401);
    assert.equal((await call('GET', '/api/appointments/1', { token: INT })).status, 403, 'interns cannot see patients');
    assert.equal((await call('GET', '/api/prescriptions', { token: HRT })).status, 403, 'HR cannot see prescriptions');
    assert.equal((await call('GET', '/api/appointments/1', { token: DOC })).status, 200, 'doctor can');

    // Register: no self-made HR/admin; interns need the invite code
    const form = (fields) => { const f = new FormData(); for (const [k, v] of Object.entries(fields)) f.append(k, v); return f; };
    const reg = (fields, token) => fetch(base + '/api/register', { method: 'POST', body: form(fields), headers: token ? { Authorization: 'Bearer ' + token } : {} })
      .then(async r => ({ status: r.status, body: await r.json().catch(() => ({})) }));
    const basic = { username: 'eve', email: 'eve@x.in', password: 'longpassword', fullname: 'Eve', ph: '9999999999' };
    assert.equal((await reg({ ...basic, department: 'hr' })).status, 403, 'cannot sign up as HR');
    assert.equal((await reg({ ...basic, department: 'admin' })).status, 403, 'cannot sign up as admin');
    assert.equal((await reg({ ...basic, department: 'admin' }, HRT)).status, 403, 'HR cannot create admins');
    r = await reg({ ...basic, department: 'Intern', internid: 'INT9', internRole: 'Dev', inviteCode: 'wrong' });
    assert.equal(r.status, 403, 'wrong invite code');
    r = await reg({ ...basic, department: 'Intern', internid: 'INT9', internRole: 'Dev', inviteCode: 'JOIN-2026', password: 'short' });
    assert.equal(r.status, 400, 'short password');

    // Interns only see themselves
    assert.equal((await call('GET', '/api/getintern/INT002', { token: INT })).status, 403);
    assert.equal((await call('GET', '/api/getintern/INT001', { token: INT })).status, 200);
    assert.equal((await call('GET', '/api/attendance/monthly?intern_id=INT002', { token: INT })).status, 403);
    assert.equal((await call('GET', '/api/documents/download/5', { token: INT })).status, 403, "someone else's document");
    assert.equal((await call('GET', '/api/interns', { token: INT })).status, 403, 'intern list is HR only');
    assert.equal((await call('GET', '/api/transactions', { token: INT })).status, 403, 'finance is HR only');
    assert.equal((await call('PUT', '/api/leave-requests/7/status', { token: INT, body: { status: 'Approved' } })).status, 403, 'interns cannot approve leave');
    queries.length = 0;
    await call('POST', '/api/addtask', { token: INT, body: { intern_id: 'INT001', task_title: 't', assigned_date: '2026-01-01', due_date: '2026-01-02' } });
    assert.equal(queries.find(q => /INSERT INTO Tasks/.test(q.sql)).params[0], 'INT001');
    assert.equal((await call('POST', '/api/addtask', { token: INT, body: { intern_id: 'INT002', task_title: 't' } })).status, 403, 'cannot add tasks for others');
    assert.equal((await call('GET', '/api/interns', { token: HRT })).status, 200, 'HR can');

    // Dashboard numbers: 8 on time + 2 late + 2 absent (+1 leave), 3 of 4 tasks done
    r = await call('GET', '/api/insterdashboard-stats', { token: INT });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.attendance_summary.total_present, 10, 'late days count as attended');
    assert.equal(r.body.attendance_summary.attendance_percentage, 83, '10 of 12 (leave is excused)');
    assert.equal(r.body.attendance_summary.punctuality_percentage, 80, '8 of 10 on time');
    assert.equal(r.body.performance_summary.task_completion_percentage, 75);
    assert.equal(r.body.performance_summary.performance_score, 79, 'average of 83 and 75');
    assert.deepEqual(r.body.checkinout, {}, 'no check-in today is an empty object, not null');
    r = await call('GET', '/api/attendance/monthly', { token: INT });
    assert.deepEqual([r.body.present, r.body.late, r.body.monthly_percentage], [10, 2, 83]);

    // Tasks: 'in-progress' is saved as the database's 'In Progress', and read back the way the page expects
    queries.length = 0;
    r = await call('PUT', '/api/changetask/3', { token: INT, body: { status: 'in-progress' } });
    assert.equal(queries.find(q => /UPDATE Tasks/.test(q.sql)).params[0], 'In Progress');
    r = await call('GET', '/api/gettasks/INT001', { token: INT });
    assert.equal(r.body.tasks[0].status, 'in-progress');
    assert.equal(r.body.tasks[0].due_date, '2026-01-02', 'due_date is sent for the dashboard');

    // HR list: real attendance and performance instead of 0
    r = await call('GET', '/api/interns', { token: HRT });
    assert.equal(r.status, 200);

    // Overview: real numbers only
    process.env.ANNUAL_LEAVE_DAYS = '12';
    r = await call('GET', '/api/intern/overview', { token: INT });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual([r.body.month.attendance, r.body.month.punctuality, r.body.month.late], [83, 80, 2]);
    assert.equal(r.body.month.change_vs_last_month, 0, 'same numbers last month in the fake db');
    assert.deepEqual([r.body.all_time.hours, r.body.tasks.done, r.body.tasks.completion], [41.3, 3, 75]);
    assert.equal(r.body.weekly.length, 4);
    assert.deepEqual([r.body.leave.per_year, r.body.leave.used_this_year, r.body.leave.remaining], [12, 3, 9]);
    delete process.env.ANNUAL_LEAVE_DAYS;
    r = await call('GET', '/api/intern/overview', { token: INT });
    assert.equal(r.body.leave.remaining, null, 'no allowance set: no made-up balance');
    assert.equal((await call('GET', '/api/intern/overview?intern_id=INT002', { token: INT })).status, 403);

    // The team ranking names other interns: HR only
    assert.equal((await call('GET', '/api/attendance/insights', { token: INT })).status, 403);
    assert.equal((await call('GET', '/api/attendance/insights', { token: HRT })).status, 200);

    // Personal notifications stay personal
    queries.length = 0;
    await call('GET', '/api/notifications', { token: INT });
    assert.ok(queries.some(q => /target_user_id IS NULL/.test(q.sql)), 'role-wide only when no user is named');

    // Help & Support: raise, read only your own, HR replies
    r = await call('POST', '/api/support/tickets', { token: INT, body: { category: 'Leave', subject: 'Leave not showing', message: 'My approved leave is missing.' } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const tid = r.body.id;
    assert.equal((await call('POST', '/api/support/tickets', { token: INT, body: { subject: 'x', message: 'y' } })).status, 400, 'too short');
    r = await call('GET', '/api/support/tickets', { token: INT });
    assert.equal(r.body.tickets.length, 1);
    const OTHER = sign({ id: 9, role: 'Intern', intern_id: 'INT009' });
    assert.equal((await call('GET', '/api/support/tickets/' + tid + '/messages', { token: OTHER })).status, 404, "another intern can't read it");
    assert.equal((await call('POST', '/api/support/tickets/' + tid + '/messages', { token: OTHER, body: { message: 'hi' } })).status, 404);
    assert.equal((await call('GET', '/api/support/tickets', { token: OTHER })).body.tickets.length, 0, 'their list is empty');
    assert.equal((await call('GET', '/api/support/tickets/' + tid + '/messages', { token: INT })).status, 200, 'the owner can read it');
    r = await call('POST', '/api/support/tickets/' + tid + '/messages', { token: HRT, body: { message: 'Fixed it, please check.' } });
    assert.equal(r.status, 200);
    assert.equal(tickets[tid - 1].status, 'Answered', 'HR reply marks it answered');
    await call('POST', '/api/support/tickets/' + tid + '/messages', { token: INT, body: { message: 'Thanks!' } });
    assert.equal(tickets[tid - 1].status, 'Open', 'intern reply sends it back to HR');
    assert.equal((await call('PUT', '/api/support/tickets/' + tid + '/status', { token: INT, body: { status: 'Closed' } })).status, 200);
    assert.equal((await call('GET', '/api/support/tickets', { token: HRT })).body.staff, true);

    // SQL injection: the category goes in as a value, not as SQL
    queries.length = 0;
    await call('GET', "/api/expenseSummary?category=" + encodeURIComponent("x' OR '1'='1"), { token: HRT });
    assert.ok(queries.length && queries.every(q => !q.sql.includes("OR '1'='1")), 'no injected SQL');
    assert.ok(queries.some(q => (q.params || []).includes("x' OR '1'='1")), 'passed as a parameter');

    // Unknown routes and bad tokens
    assert.equal((await call('GET', '/api/whatever', { token: HRT })).status, 404);
    assert.equal((await call('GET', '/api/interns', { token: 'garbage' })).status, 401);
    assert.equal((await call('GET', '/api/interns', { token: jwt.sign({ id: 1, role: 'hr' }, 'wrong-secret') })).status, 401, 'forged token');

    // Login: works, then rate-limited
    assert.equal((await call('POST', '/api/login', { body: { email: 'hr@x.in', password: 'right-password' } })).status, 200);
    let last;
    for (let i = 0; i < 11; i++) last = await call('POST', '/api/login', { body: { email: 'hr@x.in', password: 'nope' } });
    assert.equal(last.status, 429, 'password guessing is limited');

    // CORS
    r = await call('GET', '/health', { headers: { Origin: 'https://evil.example' } });
    assert.equal(r.headers.get('access-control-allow-origin'), null);
    r = await call('GET', '/health', { headers: { Origin: 'https://innerwhispers.in' } });
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://innerwhispers.in');

    console.log('All security checks passed.');
    process.exit(0);
  } catch (e) {
    console.error('FAILED:', e.message);
    process.exit(1);
  }
}, 300);
let r;

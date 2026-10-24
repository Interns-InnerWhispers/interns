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
const queries = [];
const HASH = bcrypt.hashSync('right-password', 4);
function answer(sql) {
  if (/FROM users WHERE email = \?/.test(sql)) return [{ id: 1, email: 'hr@x.in', role: 'hr', password_hash: HASH, status: 'active', full_name: 'HR' }];
  if (/SELECT intern_id FROM `Documents`/.test(sql)) return [{ intern_id: 'INT002' }];
  if (/SELECT intern_id FROM `Tasks`/.test(sql)) return [{ intern_id: 'INT001' }];
  if (/^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER)/i.test(sql)) return { affectedRows: 1, insertId: 1 };
  if (/SELECT email, internrole, phone/.test(sql)) return [{ email: 'a@x.in', internrole: 'Dev', phone: '1' }];
  if (/(SUM|COUNT)\(/i.test(sql)) return [{ n: 0, count: 0, total: 0 }];   // totals queries always return one row
  return [];
}
const fakeDb = {
  query(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    queries.push({ sql, params });
    const r = answer(sql);
    if (cb) setImmediate(() => cb(null, r));
    return { on() {} };
  },
  promise() { return { query: async (sql, params) => { queries.push({ sql, params }); return [answer(sql)]; } }; },
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

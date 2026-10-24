const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mysql = require('mysql2');
const http = require('http');
const { Server } = require("socket.io");
require('dotenv').config();
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const app = express();
const streamifier = require('streamifier');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const JWT_SECRET = process.env.SECRET_KEY;
// A missing or short secret lets anyone forge logins
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ SECRET_KEY must be set to a random string of at least 32 characters.');
  process.exit(1);
}

// Escape anything put into email HTML, so names or notes can't inject links or markup
const esc = (v) => String(v == null ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// ponytail: in-memory rate limits, per server instance; reset on restart. Use Redis if you run several instances.
const hits = new Map();
function tooMany(key, max, windowMs) {
  const now = Date.now(), list = (hits.get(key) || []).filter(t => now - t < windowMs);
  list.push(now); hits.set(key, list);
  return list.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 864e5)) hits.delete(k); }, 36e5).unref();
const clientIp = (req) => req.ip || req.socket.remoteAddress || '';
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUDNAME,
  api_key: process.env.CLOUDINARY_API,
  api_secret: process.env.CLOUDINARY_APISEC
});
const PORT = process.env.PORT || 3006;

/* ------------------------------
   📧 Brevo Mail Transporter (HTTPS API + SMTP Fallback)
------------------------------- */
const DEFAULT_HR_EMAIL = process.env.HR_EMAIL || 'hr.interns.innerwhispers@gmail.com';
const DEFAULT_SMTP_FROM = process.env.SMTP_FROM || '"InnerWhispers Wellness LLP" <no-reply@innerwhispers.in>';
const BREVO_API_KEY = process.env.BREVO_API_KEY || process.env.SMTP_PASS;
const SMTP_PASS = process.env.SMTP_PASS || process.env.BREVO_API_KEY;

const mailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || 'b0cea3001@smtp-brevo.com',
    pass: SMTP_PASS,
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000
});

async function sendEmail({ to, subject, html, text }) {
  const recipient = to || DEFAULT_HR_EMAIL;
  if (!recipient) {
    console.warn('⚠️ sendEmail skipped: No recipient email address available.');
    return { success: false, error: 'No recipient email address' };
  }

  // 1. Primary: Try Brevo HTTPS REST API over Port 443 (Immune to cloud host SMTP port blocking)
  const activeApiKey = BREVO_API_KEY;
  if (activeApiKey && (activeApiKey.startsWith('xkeysib-') || activeApiKey.startsWith('xsmtpsib-'))) {
    try {
      const parsedFrom = DEFAULT_SMTP_FROM.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/) || [];
      const senderName = parsedFrom[1] || 'InnerWhispers Wellness LLP';
      const senderEmail = parsedFrom[2] || 'no-reply@innerwhispers.in';

      const res = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'api-key': activeApiKey,
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          sender: { name: senderName, email: senderEmail },
          to: [{ email: recipient }],
          subject: subject,
          htmlContent: html || text || ''
        })
      });

      if (res.ok) {
        const data = await res.json();
        console.log(`✅ Email sent via Brevo HTTPS API to ${recipient} (MessageID: ${data.messageId || 'ok'})`);
        return { success: true, messageId: data.messageId };
      } else {
        const errText = await res.text();
        console.warn(`⚠️ Brevo HTTPS API error (${res.status}): ${errText}. Retrying via SMTP...`);
      }
    } catch (apiErr) {
      console.warn(`⚠️ Brevo HTTPS API request failed: ${apiErr.message}. Retrying via SMTP...`);
    }
  }

  // 2. Secondary: SMTP Transporter Fallback
  try {
    const info = await mailTransporter.sendMail({
      from: DEFAULT_SMTP_FROM,
      to: recipient,
      subject,
      text: text || '',
      html: html || text || '',
    });
    console.log(`✅ Email sent via SMTP to ${recipient} (MessageID: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error(`❌ Error sending email to ${recipient}:`, err.message);
    return { success: false, error: err.message };
  }
}

/* ------------------------------
   ✉️ Clean Corporate Plain Text Email Builder
------------------------------- */
function buildPlainTextEmailHtml({ title, internName, internId, date, time, lateCount, monthName, message, policyNote, recipientType = 'intern' }) {
  const isHR = recipientType === 'hr';
  
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: Arial, Helvetica, sans-serif; font-size: 15px; line-height: 1.6; color: #222222; margin: 0; padding: 20px; background-color: #ffffff;">
  <div style="max-width: 650px; margin: 0; padding: 0;">
    
    <p>Dear ${isHR ? 'HR Team' : (internName ? `<strong>${esc(internName)}</strong>` : 'Intern')},</p>
    
    <p>${message}</p>
    
    <p><strong>Attendance Record Details:</strong></p>
    <ul style="margin: 10px 0 16px 0; padding-left: 20px;">
      <li><strong>Intern Name:</strong> ${esc(internName || 'N/A')} ${internId ? `(${esc(internId)})` : ''}</li>
      <li><strong>Check-in Date & Time:</strong> ${date} at ${time} IST</li>
      <li><strong>Official Shift Timings:</strong> 6:30 PM to 10:00 PM (10-minute grace window till 6:40 PM)</li>
      <li><strong>Monthly Late Count (${monthName}):</strong> ${lateCount}</li>
    </ul>

    <p>${policyNote}</p>
    
    <br />
    <p style="margin-bottom: 4px;">Best regards,</p>
    <p style="margin-top: 0; margin-bottom: 4px;"><strong>Human Resources Department</strong></p>
    <p style="margin-top: 0; color: #555555; font-size: 13px;">
      InnerWhispers Wellness LLP<br />
      Email: <a href="mailto:hr.interns.innerwhispers@gmail.com" style="color: #0056b3;">hr.interns.innerwhispers@gmail.com</a><br />
      Website: <a href="https://innerwhispers.in/" style="color: #0056b3;">https://innerwhispers.in/</a>
    </p>

  </div>
</body>
</html>
  `;
}

/* ------------------------------
   ⏰ Intern Attendance & Late Email Notification Handler
   Shift Timing: 6:30 PM - 10:00 PM IST
   - 6:30 - 6:40 PM: On-time (Present, 10-min grace window)
   - 6:41 - 7:00 PM: Late (1st & 2nd late -> Alert email; 3rd+ late -> Warning email + HR email)
   - 7:01 - 10:00 PM: Severe Late (Strict action email to intern + HR email regardless of count)
------------------------------- */
async function processInternCheckIn({ internId, internName, internEmail, date, time }) {
  const [hh, mm] = time.split(':').map(Number);
  const currentMinutes = hh * 60 + mm;

  // 🎯 Shift window calculation
  let status = "Present";
  if (currentMinutes > (18 * 60 + 40)) { // After 6:40 PM IST
    status = "Late";
  }

  // 1. Check if attendance record exists for today
  const [existingRows] = await executeQuery(
    `SELECT id, status, check_in FROM Attendance WHERE intern_id = ? AND attendance_date = ?`,
    [internId, date]
  );

  if (existingRows && existingRows.length > 0) {
    const existing = existingRows[0];
    return { status: existing.status, isNew: false, time: existing.check_in };
  }

  // 2. Insert new Attendance record (with concurrency duplicate key protection)
  try {
    await executeQuery(
      `INSERT INTO Attendance (intern_id, attendance_date, status, check_in) VALUES (?, ?, ?, ?)`,
      [internId, date, status, time]
    );
  } catch (insertErr) {
    if (insertErr.code === 'ER_DUP_ENTRY' || (insertErr.message && insertErr.message.includes('duplicate'))) {
      console.warn(`⚠️ Attendance already recorded for intern ${internId} on ${date}. Skipping duplicate email notification.`);
      return { status, isNew: false, time };
    }
    throw insertErr;
  }

  // 🔔 Emit Socket.IO events safely
  try {
    if (typeof io !== 'undefined' && io) {
      io.to('hr-dashboard')?.emit('attendance-update', {
        intern_id: internId,
        status,
        time,
        date
      });
      io.to(`intern-${internId}`)?.emit('personal-attendance', {
        status,
        time,
        date
      });
    }
  } catch (socketErr) {
    console.warn('⚠️ Socket emit warning:', socketErr.message);
  }

  // 3. Handle Email Notifications if status is "Late"
  if (status === "Late") {
    try {
      const monthStr = date.slice(0, 7); // 'YYYY-MM'
      const dateObj = new Date(date);
      const monthName = isNaN(dateObj.getTime())
        ? 'this month'
        : dateObj.toLocaleString('default', { month: 'long', year: 'numeric' });

      // Get count of late entries in the current month (including this one)
      const [countRows] = await executeQuery(
        `SELECT COUNT(*) as lateCount FROM Attendance 
         WHERE intern_id = ? AND status = 'Late' AND DATE_FORMAT(attendance_date, '%Y-%m') = ?`,
        [internId, monthStr]
      );

      const lateCount = (countRows && countRows[0]) ? countRows[0].lateCount : 1;
      const recipient = internEmail;

      // Determine if check-in was after 7:00 PM (19:00 IST = 1140 minutes)
      const isSevereLate = currentMinutes > (19 * 60);

      if (isSevereLate) {
        // 🚨 SEVERE LATE (7:01 PM - 10:00 PM+)
        const internHtml = buildPlainTextEmailHtml({
          title: 'STRICT WARNING: Severe Late Login Notice',
          internName: internName,
          internId: internId,
          date: date,
          time: time,
          lateCount: lateCount,
          monthName: monthName,
          message: 'This email is a formal strict warning regarding your check-in today, which was recorded significantly past the allowed shift start window (after 7:00 PM IST).',
          policyNote: 'Logging in after 7:00 PM is a critical policy violation. Official shift hours are 6:30 PM to 10:00 PM (with a 10-minute grace window until 6:40 PM). A strict warning notice has been logged against your intern profile and reported directly to Human Resources (HR).',
          recipientType: 'intern'
        });

        await sendEmail({
          to: recipient,
          subject: `STRICT WARNING: Severe Late Login Notice (${date}) - InnerWhispers`,
          html: internHtml
        });

        // HR Email: Incident Report
        const hrHtml = buildPlainTextEmailHtml({
          title: 'HR Incident Report: Severe Late Login',
          internName: internName,
          internId: internId,
          date: date,
          time: time,
          lateCount: lateCount,
          monthName: monthName,
          message: `An intern has logged in significantly past the allowed shift window (after 7:00 PM IST). A severe late login warning notice has been dispatched to the intern.`,
          policyNote: `Please review this intern's attendance record if further administrative action is required.`,
          recipientType: 'hr'
        });

        await sendEmail({
          to: DEFAULT_HR_EMAIL,
          subject: `HR NOTICE: Severe Late Login (After 7:00 PM) - ${internName || internId}`,
          html: hrHtml
        });

      } else if (lateCount >= 3) {
        // ⚠️ 3RD OR SUBSEQUENT LATE ENTRY (6:41 PM - 7:00 PM)
        const internHtml = buildPlainTextEmailHtml({
          title: 'STRICT WARNING: 3rd Late Entry Notice',
          internName: internName,
          internId: internId,
          date: date,
          time: time,
          lateCount: lateCount,
          monthName: monthName,
          message: `This email is a formal warning notice regarding your attendance. You have checked in late today for the ${lateCount}${lateCount === 3 ? 'rd' : 'th'} time in ${monthName}.`,
          policyNote: `As per company policy, your 3rd late entry in a calendar month triggers formal HR escalation and strict disciplinary warning. This incident has been escalated to HR.`,
          recipientType: 'intern'
        });

        await sendEmail({
          to: recipient,
          subject: `STRICT WARNING: 3rd Late Entry Notice - InnerWhispers`,
          html: internHtml
        });

        // HR Email: 3rd Late Entry Escalation
        const hrHtml = buildPlainTextEmailHtml({
          title: 'HR Escalation: 3rd Late Entry Notice',
          internName: internName,
          internId: internId,
          date: date,
          time: time,
          lateCount: lateCount,
          monthName: monthName,
          message: `Intern <strong>${internName || internId}</strong> has reached ${lateCount} late entries in ${monthName}. A formal 3rd late warning notice has been dispatched to the intern.`,
          policyNote: `Intern shift hours are 6:30 PM to 10:00 PM (grace period till 6:40 PM).`,
          recipientType: 'hr'
        });

        await sendEmail({
          to: DEFAULT_HR_EMAIL,
          subject: `HR NOTICE: Intern ${internName || internId} - 3rd Late Entry Warning`,
          html: hrHtml
        });

      } else {
        // ℹ️ 1ST OR 2ND LATE ENTRY (6:41 PM - 7:00 PM)
        const internHtml = buildPlainTextEmailHtml({
          title: 'Late Entry Notification',
          internName: internName,
          internId: internId,
          date: date,
          time: time,
          lateCount: lateCount,
          monthName: monthName,
          message: 'This email is to notify you that your check-in today was recorded after the permissible 6:40 PM grace window.',
          policyNote: `Intern shift timing is 6:30 PM to 10:00 PM (10-minute grace allowed until 6:40 PM). This is your ${lateCount === 1 ? '1st' : '2nd'} late entry for ${monthName}. Reaching 3 late entries in a month will result in formal HR warning & escalation. Please ensure timely check-in for upcoming shifts.`,
          recipientType: 'intern'
        });

        await sendEmail({
          to: recipient,
          subject: `Late Entry Alert (${lateCount}/3) - ${date}`,
          html: internHtml
        });
      }
    } catch (emailErr) {
      console.error("❌ Error sending late attendance email alert:", emailErr);
    }
  }

  return { status, isNew: true, time };
}

/* ------------------------------
   🔐 Security & Middleware
------------------------------- */
app.use(helmet());
app.use(compression());
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Only the website may call this API from a browser. Add origins (comma-separated) in ALLOWED_ORIGINS.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://innerwhispers.in,https://www.innerwhispers.in')
  .split(',').map(s => s.trim()).filter(Boolean);
const originAllowed = (origin) => !origin || ALLOWED_ORIGINS.includes(origin)
  || (process.env.NODE_ENV !== 'production' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin));
const corsOptions = {
  origin: (origin, cb) => cb(null, originAllowed(origin)),
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Personal data: never cache API responses
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
// Profile photos: images only, up to 5 MB
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)
    ? cb(null, true) : cb(new Error('Only images and PDF files are allowed (photos must be JPG, PNG, WebP or GIF).')))
});

/* ------------------------------
   🔐 Access control
   Every /api route is listed here with who may call it; anything not listed is refused.
   SELF routes: HR and admins see everyone, interns only themselves (their intern_id is forced on the request).
------------------------------- */
const PUBLIC = 'public', ANY = 'any', SELF = 'self', HR = 'hr', CLINICAL = 'clinical';
const HR_ROLES = ['hr', 'admin'];
const CLINICAL_ROLES = ['admin', 'doctor', 'psychiatry', 'psychology', 'therapy', 'counseling', 'guidance'];
// [method(s), path, who, options]  options.own = URL part that is an intern ID; options.check = record that must belong to the intern
const ACCESS = [
  ['POST', /^\/api\/login$/, PUBLIC],
  ['POST', /^\/api\/forgotpass(\/request|\/reset)?$/, PUBLIC],
  ['POST', /^\/api\/register$/, PUBLIC],                      // role rules are inside the route
  ['GET', /^\/api\/profile$/, ANY],
  ['GET', /^\/api\/notifications(\/unread-count)?$/, ANY],
  ['PUT', /^\/api\/notifications\/(read-all|\d+\/read)$/, ANY],
  ['POST', /^\/api\/dream-reflection$/, ANY],
  [['GET', 'POST'], /^\/api\/support\/tickets$/, ANY],                 // Help & Support (own tickets; HR sees all)
  [['GET', 'POST'], /^\/api\/support\/tickets\/\d+\/messages$/, ANY],
  ['PUT', /^\/api\/support\/tickets\/\d+\/status$/, ANY],

  // HR and admin only (listed before the intern routes they resemble)
  ['GET', /^\/api\/leave-requests\/pending$/, HR],
  ['PUT', /^\/api\/leave-requests\/\d+\/status$/, HR],
  ['GET', /^\/api\/dashboard\/(stats|attendance|leave-requests|pipeline|activities)$/, HR],
  ['GET', /^\/api\/(interns|interns-count)$/, HR],
  ['GET', /^\/api\/attendance\/(daily|records|allweekly|status|trends)$/, HR],
  ['POST', /^\/api\/attendance$/, HR],
  ['PUT', /^\/api\/attendance\/\d+$/, HR],
  ['GET', /^\/api\/departments\/performance$/, HR],
  ['POST', /^\/api\/notifications$/, HR],
  ['PUT', /^\/api\/reports\/\d+\/status$/, HR],
  ['GET', /^\/api\/documents\/all$/, HR],
  ['PUT', /^\/api\/documents\/\d+\/status$/, HR],
  ['GET', /^\/api\/(transactions|filtertransactions|summary|expenseSummary|budgets|payments|invoices|receipts|irsummary|income-trend|settings)$/, HR],
  ['POST', /^\/api\/budgets$/, HR],
  ['PUT', /^\/api\/settings$/, HR],

  // Interns (their own records) and HR
  ['GET', /^\/api\/attendance$/, SELF],
  ['POST', /^\/api\/attendance\/checkinout$/, SELF],
  ['GET', /^\/api\/attendance\/(monthly|weekly)$/, SELF],
  ['GET', /^\/api\/attendance\/insights$/, HR],                 // names other interns: HR only
  ['GET', /^\/api\/intern\/overview$/, SELF],
  ['GET', /^\/api\/attendance-status\/([^/]+)$/, SELF, { own: 1 }],
  ['POST', /^\/api\/checkout$/, SELF],
  ['GET', /^\/api\/insterdashboard-stats$/, SELF],
  ['GET', /^\/api\/getintern\/([^/]+)$/, SELF, { own: 1 }],
  [['GET', 'PUT'], /^\/api\/interns\/details\/([^/]+)$/, SELF, { own: 1 }],
  ['PUT', /^\/api\/interns\/(?:updateintern|updateimage)\/([^/]+)$/, SELF, { own: 1 }],
  ['GET', /^\/api\/tasks\/all$/, SELF],
  ['GET', /^\/api\/gettasks\/([^/]+)$/, SELF, { own: 1 }],
  ['POST', /^\/api\/addtask$/, SELF],
  ['PUT', /^\/api\/changetask\/(\d+)$/, SELF, { check: ['Tasks', 'task_id'] }],
  ['GET', /^\/api\/reports$/, SELF],
  ['POST', /^\/api\/(submitreport|reports\/upload)$/, SELF],
  ['GET', /^\/api\/reports\/download\/(\d+)$/, SELF, { check: ['Reports', 'id'] }],
  ['GET', /^\/api\/intern\/performance(\/insights)?$/, SELF],
  ['POST', /^\/api\/leave-requests$/, SELF],
  ['GET', /^\/api\/leave-requests\/([^/]+)$/, SELF, { own: 1 }],
  ['GET', /^\/api\/documents(\/submitted|\/issued)?$/, SELF],
  ['POST', /^\/api\/documents\/upload$/, SELF],
  ['GET', /^\/api\/documents\/download\/(\d+)$/, SELF, { check: ['Documents', 'id'] }],

  // Doctors and admin (patient records)
  ['GET', /^\/api\/dashboard-stats$/, CLINICAL],
  ['POST', /^\/api\/appointments$/, CLINICAL],
  ['GET', /^\/api\/appointments\/\d+$/, CLINICAL],
  ['PUT', /^\/api\/appointments\/\d+\/\d+\/(status|reschedule)$/, CLINICAL],
  ['GET', /^\/api\/patients$/, CLINICAL],
  [['GET', 'POST'], /^\/api\/prescriptions$/, CLINICAL],
  ['GET', /^\/api\/prescriptions\/(\d+|search)$/, CLINICAL],
  ['GET', /^\/api\/(getalldoc|getdoc\/\d+)$/, CLINICAL],
  [['GET', 'PUT'], /^\/api\/dashboard_ui\/\d+$/, CLINICAL],
];

function readToken(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET, { algorithms: ['HS256'] }); } catch { return null; }
}
const roleOf = (user) => String((user && user.role) || '').toLowerCase().replace(/[^a-z]/g, '');

async function accessGate(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  if (!req.path.startsWith('/api/')) {
    return (req.path === '/' || req.path === '/health') ? next() : res.status(404).json({ message: 'Not found' });
  }
  const rule = ACCESS.find(([m, re]) => (Array.isArray(m) ? m.includes(req.method) : m === req.method) && re.test(req.path));
  if (!rule) return res.status(404).json({ message: 'Not found' });
  const [, re, who, opts = {}] = rule;

  const user = readToken(req);
  if (user) req.user = user;
  if (who === PUBLIC) return next();
  if (!user) return res.status(401).json({ message: 'Please sign in again.' });

  const role = roleOf(user);
  if (who === ANY) return next();
  if (who === HR) return HR_ROLES.includes(role) ? next() : res.status(403).json({ message: 'Not allowed' });
  if (who === CLINICAL) return CLINICAL_ROLES.includes(role) ? next() : res.status(403).json({ message: 'Not allowed' });

  // SELF: HR and admin see everyone; interns only themselves; other roles nothing
  if (HR_ROLES.includes(role)) return next();
  if (role !== 'intern' || !user.intern_id) return res.status(403).json({ message: 'Not allowed' });
  const me = String(user.intern_id);
  const deny = () => res.status(403).json({ message: 'Not allowed' });

  if (opts.own && decodeURIComponent(req.path.match(re)[opts.own]) !== me) return deny();
  if (req.query.intern_id !== undefined && String(req.query.intern_id) !== me) return deny();
  req.query.intern_id = me;
  if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
    if (req.body.intern_id !== undefined && String(req.body.intern_id) !== me) return deny();
    if (req.method !== 'GET') req.body.intern_id = me;
  }
  if (opts.check) {
    try {
      const [table, col] = opts.check;
      const [rows] = await executeQuery(`SELECT intern_id FROM \`${table}\` WHERE \`${col}\` = ?`, [req.path.match(re)[1]]);
      if (!rows.length || String(rows[0].intern_id) !== me) return deny();
    } catch (err) {
      console.error('Access check failed:', err.code || err.message);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
  }
  next();
}
app.use(accessGate);

/* ------------------------------
   🗄️ Database Setup
   const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_NAME','db_password'];
------------------------------- */

const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_NAME'];
const missing = requiredEnvVars.filter(env => !process.env[env]);
if (missing.length > 0) {
  console.error('❌ Missing ENV vars:', missing.join(', '));
  process.exit(1);
}

let db;
(async () => {
  try {
    const dbConfig = {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT || 3306,
      waitForConnections: true,
      connectionLimit: process.env.NODE_ENV === 'production' ? 5 : 10,
      queueLimit: 0,
      dateStrings: true,
      timezone: '+05:30',
    };

    db = await mysql.createPool(dbConfig);
    console.log('✅ Connected to MySQL (pool)');

    await initializeDatabase();
    upgradeInternSchema();
    // Help & Support: one row per ticket, one per message
    await executeQuery(`CREATE TABLE IF NOT EXISTS support_tickets (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      requester_name VARCHAR(255),
      requester_role VARCHAR(30),
      intern_id VARCHAR(10) NULL,
      category ENUM('Attendance','Leave','Reports','Tasks','Documents','Account','Technical','Other') NOT NULL DEFAULT 'Other',
      subject VARCHAR(150) NOT NULL,
      status ENUM('Open','Answered','Closed') NOT NULL DEFAULT 'Open',
      unread_for_user TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_ticket_user (user_id, updated_at),
      INDEX idx_ticket_status (status, updated_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await executeQuery(`CREATE TABLE IF NOT EXISTS support_messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      ticket_id INT NOT NULL,
      sender_user_id INT NOT NULL,
      from_staff TINYINT(1) NOT NULL DEFAULT 0,
      sender_name VARCHAR(255),
      body TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_msg_ticket (ticket_id, id),
      FOREIGN KEY (ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    // One-time codes for "forgot password" (only a hash of each code is stored)
    await executeQuery(`CREATE TABLE IF NOT EXISTS password_resets (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      code_hash CHAR(64) NOT NULL,
      attempts INT NOT NULL DEFAULT 0,
      expires_at BIGINT NOT NULL,
      INDEX idx_reset_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (err) {
    console.error('❌ DB Connection Error:', err.message);
  }
})();


// ✅ DB Initializer
async function initializeDatabase() {
  try {
    await executeQuery(`
           CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role VARCHAR(15) NOT NULL DEFAULT 'patient',
    profile_image VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active'
            )
        `);
    console.log("✅ Database initialized");
  } catch (err) {
    console.error("❌ DB Init Error:", err.message);
  }
}

/* ------------------------------
   🧱 Schema upgrades for the intern portal
   Each step is safe to run again and never deletes data. A step that is already done just fails quietly.
------------------------------- */
async function upgradeInternSchema() {
  const steps = [
    // Columns that were too short for what the portal pages allow
    ['Interns.name', 'ALTER TABLE Interns MODIFY COLUMN name VARCHAR(100) NOT NULL'],
    ['Interns.internrole', 'ALTER TABLE Interns MODIFY COLUMN internrole VARCHAR(60) NOT NULL'],   // "Full Stack Development" is 22 characters
    ['Interns.email', 'ALTER TABLE Interns MODIFY COLUMN email VARCHAR(255) NOT NULL'],
    ['Interns.phone', 'ALTER TABLE Interns MODIFY COLUMN phone VARCHAR(20) NULL'],               // "+91 98765 43210"
    ['Reports.report_title', 'ALTER TABLE Reports MODIFY COLUMN report_title VARCHAR(150) NULL'], // the form allows 140
    ['Documents.doc_title', 'ALTER TABLE Documents MODIFY COLUMN doc_title VARCHAR(150) NOT NULL'],
    ['Tasks.task_title', 'ALTER TABLE Tasks MODIFY COLUMN task_title VARCHAR(150) NOT NULL'],    // the form allows 120
    // Indexes for the lists the dashboards load most
    ['idx_reports_intern_time', 'ALTER TABLE Reports ADD INDEX idx_reports_intern_time (intern_id, submitted_at)'],
    ['idx_tasks_intern_due', 'ALTER TABLE Tasks ADD INDEX idx_tasks_intern_due (intern_id, due_date)'],
    ['idx_attendance_date', 'ALTER TABLE Attendance ADD INDEX idx_attendance_date (attendance_date, status)'],
    ['idx_notifications_target', 'ALTER TABLE Notifications ADD INDEX idx_notifications_target (target_role, created_at)'],
    ['idx_leave_status', 'ALTER TABLE leave_requests ADD INDEX idx_leave_status (status, from_date)'],
    // Fill in hours worked for past days that have both a check-in and a check-out
    ['Attendance.hours_worked', `UPDATE Attendance SET hours_worked = ROUND(TIME_TO_SEC(TIMEDIFF(check_out, check_in)) / 3600, 2)
       WHERE check_in IS NOT NULL AND check_out IS NOT NULL AND check_out > check_in AND (hours_worked IS NULL OR hours_worked = 0)`],
  ];
  for (const [name, sql] of steps) {
    try { await executeQuery(sql); } catch (err) {
      if (!/Duplicate key name/.test(err.message)) console.warn(`Schema step ${name} skipped:`, err.code || err.message);
    }
  }
}

/* ------------------------------
   📊 Intern numbers, worked out the same way everywhere
   Attended = Present + Late. Leave is excused (not counted against attendance).
   Attendance %  = attended / (attended + absent)
   Punctuality % = on time / attended
   Task %        = completed tasks / all tasks
   Performance   = average of attendance % and task % (attendance % only if no tasks yet)
------------------------------- */
const pct = (part, whole) => (whole > 0 ? Math.round((part / whole) * 100) : 0);
function internScores(a, t) {
  const present = Number(a.present) || 0, late = Number(a.late) || 0, absent = Number(a.absent) || 0;
  const attended = present + late;
  const attendance = pct(attended, attended + absent);
  const punctuality = pct(present, attended);
  const totalTasks = Number(t && t.total) || 0, doneTasks = Number(t && t.done) || 0;
  const tasks = pct(doneTasks, totalTasks);
  const performance = totalTasks ? Math.round((attendance + tasks) / 2) : attendance;
  return { attended, present, late, absent, leave: Number(a.leave_days) || 0, attendance, punctuality, totalTasks, doneTasks, tasks, performance };
}
const ATT_COUNTS = `COALESCE(SUM(status = 'Present'), 0) AS present, COALESCE(SUM(status = 'Late'), 0) AS late,
  COALESCE(SUM(status = 'Absent'), 0) AS absent, COALESCE(SUM(status = 'Leave'), 0) AS leave_days`;

// Task status: the database uses 'In Progress' etc., the pages use 'in-progress'
const TASK_STATUS_DB = { 'pending': 'Pending', 'in-progress': 'In Progress', 'completed': 'Completed', 'overdue': 'Overdue', 'urgent': 'Urgent' };
const taskStatusForPage = (v) => String(v || 'pending').toLowerCase().replace(/\s+/g, '-');

/* ── Notifications ──
   notify() saves one and pushes it live. A notification with a userId is personal (only that user sees it);
   without one it goes to everyone with targetRole ('hr', 'intern' or 'all'). */
const NOTIFY_TYPES = ['info', 'success', 'warning', 'error'];
async function notify(title, description, type = 'info', { userId = null, role = 'all' } = {}) {
  const t = NOTIFY_TYPES.includes(type) ? type : 'info';
  const r = ['hr', 'intern', 'all'].includes(role) ? role : 'all';
  const [result] = await executeQuery(
    'INSERT INTO Notifications (notify, description, type, target_user_id, target_role) VALUES (?, ?, ?, ?, ?)',
    [String(title).slice(0, 255), String(description).slice(0, 2000), t, userId ? String(userId) : null, r]);
  const data = { id: result.insertId, title, description, type: t, createdAt: new Date().toISOString() };
  try {
    if (userId) io.to(`user-${userId}`).emit('new-notification', data);
    else if (r === 'hr') io.to('hr-dashboard').emit('new-notification', data);
  } catch (e) { /* live push is optional */ }
  return result.insertId;
}
// Personal notification for an intern (looked up by intern ID). Never throws: a failed notice must not fail the action.
async function notifyIntern(internId, title, description, type) {
  try {
    const [[u]] = await executeQuery(
      'SELECT u.id FROM users u JOIN Interns i ON LOWER(u.email) = LOWER(i.email) WHERE i.intern_id = ? LIMIT 1', [internId]);
    if (u) await notify(title, description, type, { userId: u.id, role: 'intern' });
  } catch (err) { console.warn('Notification not saved:', err.code || err.message); }
}

// Current time in India as HH:MM:SS
function nowTimeIST() {
  const ist = new Date(Date.now() + 5.5 * 60 * 60 * 1000);
  return ist.toISOString().slice(11, 19);
}

/* ------------------------------
   🌐 Routes
------------------------------- */
app.get('/', (req, res) => res.send('🚀 API is running on Hostinger'));

app.get('/health', async (req, res) => {
  if (!db) return res.status(500).send('❌ DB not initialized');
  try {
    await executeQuery('SELECT 1');
    res.send('✅ Healthy');
  } catch {
    res.status(500).send('❌ DB Down');
  }
});


/* ------------------------------
   🛠️ Error Handling
------------------------------- */
app.use((err, req, res, next) => {
  if (err.message.includes('Only images and PDF')) {
    return res.status(400).json({ error: err.message, message: err.message });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'The file is larger than 5 MB.', message: 'The file is larger than 5 MB.' });
  }
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// ===============================
// 📊 DASHBOARD STATS APIs  for hr index.html
// ===============================

// GET dashboard overview stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const today = getTodayIST();
    // Get total interns count
    const [totalInterns] = await executeQuery('SELECT COUNT(*) as count FROM Interns WHERE status = "Active"');

    // Get new hires (last 30 days)
    const [newHires] = await executeQuery(
      'SELECT COUNT(*) as count FROM Interns WHERE start_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)'
    );

    // Get today's attendance
    const [todayAttendance] = await executeQuery(
      'SELECT status, COUNT(*) as count FROM Attendance WHERE attendance_date = ? GROUP BY status',
      [today]
    );

    // Get pending leave requests
    const [pendingLeave] = await executeQuery(
      'SELECT COUNT(*) as count FROM leave_requests WHERE status = "Pending"'
    );

    const [onLeave] = await executeQuery(
      `SELECT COUNT(*) as count FROM leave_requests WHERE status = "Approved" AND CURDATE() BETWEEN from_date AND to_date`
    );
    const [ApprovedLeaves] = await executeQuery(
      'SELECT COUNT(*) as count FROM leave_requests WHERE status = "Approved"'
    );

    const [RejectedLeaves] = await executeQuery(
      'SELECT COUNT(*) as count FROM leave_requests WHERE status = "Rejected"'
    );
    // Get department distribution
    const [deptData] = await executeQuery(`
            SELECT department, COUNT(*) as count 
            FROM Interns 
            WHERE department IS NOT NULL AND status = "Active"
            GROUP BY department
        `);

    // Get weekly attendance data for trend chart
    const [thisWeekData] = await executeQuery(`
            SELECT 
                DAYNAME(attendance_date) as day_name,
                SUM(status IN ('Present','Late')) * 100.0 / NULLIF(SUM(status IN ('Present','Late','Absent')), 0) as attendance_rate   -- late counts as attended; leave is excused
            FROM Attendance 
            WHERE attendance_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND CURDATE()
            GROUP BY DAYNAME(attendance_date), attendance_date
            ORDER BY attendance_date
        `);

    const [lastWeekData] = await executeQuery(`
            SELECT 
                DAYNAME(attendance_date) as day_name,
                SUM(status IN ('Present','Late')) * 100.0 / NULLIF(SUM(status IN ('Present','Late','Absent')), 0) as attendance_rate   -- late counts as attended; leave is excused
            FROM Attendance 
            WHERE attendance_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 13 DAY) AND DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DAYNAME(attendance_date), attendance_date
            ORDER BY attendance_date
        `);

    // Format data for chart (ensure 7 days for each week)
    const weeklyAttendance = {
      thisWeek: formatWeeklyData(thisWeekData),
      lastWeek: formatWeeklyData(lastWeekData)
    };

    const attendanceStats = {
      present: 0,
      absent: 0,
      leave: 0,
      late: 0
    };

    todayAttendance.forEach(row => {
      attendanceStats[row.status.toLowerCase()] = row.count;
    });

    // Process department data
    const departments = ['Technology', 'Human Resources', 'Sales', 'UI/UX', 'Finance'];
    const departmentStats = {};

    departments.forEach(dept => {
      const found = deptData.find(d => d.department === dept);
      departmentStats[dept] = found ? found.count : 0;
    });

    res.json({
      totalInterns: totalInterns[0].count,
      newHires: newHires[0].count,
      attendance: attendanceStats,
      pendingLeave: pendingLeave[0].count,
      ApprovedLeaves: ApprovedLeaves[0].count,
      RejectedLeaves: RejectedLeaves[0].count,
      onLeave: onLeave[0].count,
      departments: departmentStats,
      weeklyAttendance: weeklyAttendance
    });

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// GET attendance data for table
app.get('/api/dashboard/attendance', authenticateToken, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const today = getTodayIST(); // Get today's date in IST format

    const [rows] = await executeQuery(`
            SELECT 
                i.name, 
                i.internrole as role,
                i.department as dept,
                a.check_in as checkin,
                a.status,
                a.attendance_date
            FROM Attendance a
            JOIN Interns i ON a.intern_id = i.intern_id
            WHERE a.attendance_date = ?
            ORDER BY i.name
            LIMIT ?
        `, [today, parseInt(limit)]);

    const attendanceData = rows.map(row => ({
      name: row.name,
      role: row.role,
      dept: row.dept || 'Unassigned',
      checkin: row.checkin || '—',
      status: row.status
    }));

    res.json(attendanceData);

  } catch (error) {
    console.error('Error fetching attendance data:', error);
    res.status(500).json({ error: 'Failed to fetch attendance data' });
  }
});

// GET leave requests
app.get('/api/dashboard/leave-requests', authenticateToken, async (req, res) => {
  try {
    const [rows] = await executeQuery(`
            SELECT 
                lr.id,
                lr.intern_id,
                i.department,
                lr.from_date as fromDate,
                lr.to_date as toDate,
                lr.number_of_working_days as days,
                lr.reason,
                lr.status,
                lr.leave_type,
                i.name as name,
                lr.requested_at as requestedAt
            FROM leave_requests lr
            JOIN Interns i ON lr.intern_id = i.intern_id
            ORDER BY lr.requested_at DESC
            LIMIT 20
        `);
    console.log(rows)
    const leaveRequests = rows.map(row => ({
      id: row.id,
      intern_id: row.intern_id,
      department: row.department,
      name: row.name,
      type: row.leave_type,
      startDate: row.fromDate,
      endDate: row.toDate,
      dates: row.fromDate === row.toDate ?
        row.fromDate :
        `${row.fromDate}–${row.toDate}`,
      reason: row.reason,
      days: row.days,
      status: row.status
    }));
    console.log("leave request", leaveRequests)
    res.json(leaveRequests);

  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.status(500).json({ error: 'Failed to fetch leave requests' });
  }
});

// GET recruitment pipeline data
app.get('/api/dashboard/pipeline', authenticateToken, async (req, res) => {
  try {
    // Since we don't have a recruitment table, return mock data for now
    // This can be enhanced later with actual recruitment tracking
    const pipeline = [
      { stage: 'Applied', count: 40, color: '#6366f1', max: 40 },
      { stage: 'Screening', count: 18, color: '#8b5cf6', max: 30 },
      { stage: 'Interview', count: 10, color: '#a78bfa', max: 30 },
      { stage: 'Selected', count: 4, color: '#16a34a', max: 30 }
    ];

    res.json(pipeline);

  } catch (error) {
    console.error('Error fetching pipeline data:', error);
    res.status(500).json({ error: 'Failed to fetch pipeline data' });
  }
});

// GET recent activities
app.get('/api/dashboard/activities', authenticateToken, async (req, res) => {
  try {
    const [rows] = await executeQuery(`
            SELECT 
                'New employee onboarded' as activity,
                CONCAT(i.name, ' (', i.internrole, ')') as details,
                i.created_at as timestamp
            FROM Interns i
            WHERE i.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            ORDER BY i.created_at DESC
            LIMIT 10
        `);

    const activities = rows.map(row => ({
      text: `${row.activity} — ${row.details}`,
      time: formatTimeAgo(row.timestamp)
    }));

    res.json(activities);

  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

// Helper function to format time ago
function formatTimeAgo(timestamp) {
  const now = new Date();
  const past = new Date(timestamp);
  const diffMs = now - past;
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffHours / 24);

  if (diffDays > 0) {
    return `${diffDays} days ago`;
  } else if (diffHours > 0) {
    return `${diffHours} hours ago`;
  } else {
    return 'Just now';
  }
}

// Helper function to format weekly attendance data
function formatWeeklyData(data) {
  const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const result = new Array(7).fill(null); // a day with no records is "no data" (null), not 0%

  data.forEach(row => {
    const dayIndex = daysOfWeek.indexOf(row.day_name);
    if (dayIndex !== -1 && row.attendance_rate != null) {
      result[dayIndex] = Math.round(parseFloat(row.attendance_rate));
    }
  });

  return result;
}

/* ------------------------------
   🚀 Start Server
------------------------------- */

function executeQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) return reject(err);
      resolve([results]);
    });
  });
}


/* ------------------------------
   Error Handling
------------------------------- */
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  });
});

// Add production error handler
if (process.env.NODE_ENV === 'production') {
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
  });
}

/* ------------------------------
   🚀 Start Server
------------------------------- */

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (origin, cb) => cb(null, originAllowed(origin)),
    methods: ["GET", "POST"]
  }
});

// Only signed-in users may connect (token in socket.handshake.auth.token)
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  try {
    socket.user = jwt.verify(String(token || ''), JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  const role = roleOf(socket.user);

  if (socket.user && socket.user.id) socket.join(`user-${socket.user.id}`);

  // HR dashboard room: HR and admin only
  socket.on('join-hr-dashboard', () => {
    if (HR_ROLES.includes(role)) socket.join('hr-dashboard');
  });

  // Personal room: an intern can only join their own
  socket.on('join-intern-room', (internId) => {
    if (HR_ROLES.includes(role) || String(internId) === String(socket.user.intern_id)) socket.join(`intern-${internId}`);
  });

  socket.on('disconnect', () => {
    console.log('🔌 User disconnected:', socket.id);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

// Add graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed.');
    db.end(() => {
      console.log('Database connection closed.');
      process.exit(0);
    });
  });
});


// Function to create database if it doesn't exist
function createDatabase() {
  const tempDb = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || ''
  });

  tempDb.connect((err) => {
    if (err) {
      console.error('Could not create database:', err);
      return;
    }

    tempDb.query('CREATE DATABASE IF NOT EXISTS innerwhispers', (err) => {
      if (err) {
        console.error('Error creating database:', err);
        return;
      }
      console.log('Database created successfully');
      tempDb.end();

      // Retry main connection
      db.connect();
    });
  });
}

// Add session types constant at the top
const SESSION_TYPES = {
  'Initial Consultation': {
    duration: 40,
    price: 1000,
    description: 'Comprehensive assessment'
  },
  'Counseling Session': {
    duration: 50,
    price: 1500,
    description: 'Counseling session'
  },
  'Therapy Session': {
    duration: 80,
    price: 3000,
    description: 'Focused session'
  }
};

// Replace the current table creation code with this:
function initializeDatabase() {
  const dbName = process.env.DB_NAME;
  if (!dbName) {
    console.error('DB_NAME not set; cannot initialize schema');
    return;
  }
  const Q = (table) => `\`${dbName}\`.\`${table}\``;

  // First ensure database exists
  db.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``, (err) => {
    if (err) {
      console.error('Error creating database:', err);
      return;
    }

    // Updated table schema with all required fields
    const createTableQuery = `
                CREATE TABLE IF NOT EXISTS ${Q('appointments')} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    doctor_id int not null default 1,  
                    patient_name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    phone VARCHAR(20) NOT NULL,
                    addhar varchar(20) NOT NULL,
                    age varchar(20) NOT NULL,
                    parenttype varchar(20) NOT NULL,
                    parentName varchar(20) not null,
                    guardianPhone varchar(20) not null,
                    address varchar(20) not null,
                    pincode varchar(20) not null,
                    state varchar(20) not null,
                    concerns TEXT,
                    appointment_date DATE NOT NULL,
                    appointment_time TIME NOT NULL,
                    session_type VARCHAR(50) NOT NULL,
                    session_price DECIMAL(10,2) NOT NULL DEFAULT 1500.00,
                    session_duration INT NOT NULL DEFAULT 50,
                    status ENUM('pending', 'confirmed', 'cancelled') DEFAULT 'pending',
                    meet_link VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_status (status),
                    INDEX idx_date (appointment_date),
                    INDEX idx_patient (patient_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            `;

    db.query(createTableQuery, (err) => {
      if (err) {
        console.error('Error creating appointments table:', err);
        return;
      }
      console.log('Database and tables initialized successfully');
      migrateExistingAppointments();
    });
  });

  // Add prescriptions table
  const createPrescriptionsTable = `
        CREATE TABLE IF NOT EXISTS ${Q('prescriptions')} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            patient_name VARCHAR(255) NOT NULL,
            prescription_date DATE NOT NULL,
            medication_name VARCHAR(255) NOT NULL,
            medication_type VARCHAR(100) NOT NULL,
            medication_dosage VARCHAR(255) NOT NULL,
            medication_supply VARCHAR(100) NOT NULL,
            special_instructions TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_patient (patient_name),
            INDEX idx_date (prescription_date)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `;

  db.query(createPrescriptionsTable, (err) => {
    if (err) {
      console.error('Error creating prescriptions table:', err);
    }
  });
  const createUserTableQuery = `
CREATE TABLE IF NOT EXISTS ${Q('users')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role VARCHAR(15) NOT NULL DEFAULT 'patient',
    profile_image VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`;

  db.query(createUserTableQuery, (err) => {
    if (err) return console.error('Error creating user table:', err);
    console.log('Users table created');
  });

  const createDocSpecTableQuery = `
CREATE TABLE IF NOT EXISTS ${Q('doctor_specializations')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_specialization (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`;

  db.query(createDocSpecTableQuery, (err) => {
    if (err) return console.error('Error creating doctor_specializations table:', err);
    console.log('Doctor specializations table created');
  });

  const createDoctorTableQuery = `
CREATE TABLE IF NOT EXISTS ${Q('doctor_details')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    specialization_id INT UNSIGNED,
    license_number VARCHAR(100) UNIQUE,
    years_of_experience INT,
    consultation_fee DECIMAL(10,2) NOT NULL,
    bio TEXT,
    education VARCHAR(20),
    languages_spoken VARCHAR(20),
    is_verified BOOLEAN DEFAULT FALSE,
    is_available BOOLEAN DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

  db.query(createDoctorTableQuery, (err) => {
    if (err) return console.error('Error creating doctor_details table:', err);
    console.log('Doctor details table created');
  });

  const createDoctorUITableQuery = `
CREATE TABLE IF NOT EXISTS ${Q('doctor_ui')} (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    doctor_id INT NOT NULL,
    patients_count INT NOT NULL DEFAULT 0,
    appointments_today INT NOT NULL DEFAULT 0,
    pending_confirmations INT NOT NULL DEFAULT 0,
    reports_to_finalize INT NOT NULL DEFAULT 0,
    prescriptions INT NOT NULL DEFAULT 0,
    mood_trend VARCHAR(20) NOT NULL DEFAULT 'POSITIVE',
    follow_ups_needed INT NOT NULL DEFAULT 0,
    unread_messages INT NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

`;

  db.query(createDoctorUITableQuery, (err) => {
    if (err) return console.error('Error creating doctor_ui table:', err);
    console.log('Doctor_ui details table created');
  });

  //inern table

  const createTeamTable = `
       CREATE TABLE IF NOT EXISTS ${Q('Teams')} (
        id INT AUTO_INCREMENT PRIMARY KEY,
        team_name VARCHAR(50) NOT NULL,
        team_leader_id INT NOT NULL,
        team_size INT NOT NULL,
        team_description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (team_leader_id) REFERENCES Interns(id)
       )
    

    `;

  db.query(createTeamTable, (err) => {
    if (err) return console.error('Error creating Teams table:', err);
    console.log('Teams details table created');
  });

  //inern table
  const createInternTable = `
        CREATE TABLE IF NOT EXISTS ${Q('Interns')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    internrole VARCHAR(20) NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    phone VARCHAR(10),
    university VARCHAR(255),
    performance_score DECIMAL(5,2) DEFAULT 0.00,
    start_date DATE NOT NULL DEFAULT (CURRENT_DATE),
    end_date DATE NOT NULL DEFAULT (CURRENT_DATE),
    department VARCHAR(50),
    HR_id int,
    Team_id int,
    attendance_percentage DECIMAL(5,2) DEFAULT 0.00,
    profile_image VARCHAR(255),
    status ENUM('Active', 'Inactive', 'Completed') DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

  db.query(createInternTable, (err) => {
    if (err) {
      console.error('Error creating Interns table:', err);
    }
  });
  async function updateInternsTable() {
    const columns = [
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS department VARCHAR(50)`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS HR_id INT`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS Team_id INT`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS attendance_percentage DECIMAL(5,2) DEFAULT 0.00`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS profile_image VARCHAR(255)`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS status ENUM('Active', 'Inactive', 'Completed') DEFAULT 'Active'`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
      `ALTER TABLE Interns ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`
    ];
    for (const q of columns) {
      try {
        await db.promise().query(q);
      } catch (err) {
        // ignore duplicate column error if thrown by older MySQL versions
      }
    }
    console.log("✅ Interns table updated successfully");
  }
  updateInternsTable();

  /* ── Intern profile details (address, college, emergency contact, links) ──
     Each column is added only if it is missing. */
  async function ensureInternDetailColumns() {
    for (const [col, def] of INTERN_DETAIL_COLUMNS) {
      try {
        const [rows] = await db.promise().query(
          'SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
          ['Interns', col]
        );
        if (!rows[0].n) await db.promise().query('ALTER TABLE Interns ADD COLUMN `' + col + '` ' + def);
      } catch (err) {
        console.error('Could not add Interns.' + col + ':', err.message);
      }
    }
  }
  ensureInternDetailColumns();
  // Add foreign key constraints for Interns table
  db.query("ALTER TABLE Interns ADD CONSTRAINT fk_intern_hr FOREIGN KEY (HR_id) REFERENCES Interns(id)", () => { });
  db.query("ALTER TABLE Interns ADD CONSTRAINT fk_intern_team FOREIGN KEY (Team_id) REFERENCES Teams(id)", () => { });

  //attendence table
  const createAttendenceTable = `
        CREATE TABLE IF NOT EXISTS ${Q('Attendance')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    attendance_date DATE NOT NULL,
    status ENUM('Present', 'Absent', 'Leave', 'Late') DEFAULT 'Absent',
    check_in TIME NULL,
    check_out TIME NULL,
    hours_worked DECIMAL(4,2) DEFAULT 0.00,
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


    `;

  db.query(createAttendenceTable, (err) => {
    if (err) {
      console.error('Error creating attendance table:', err);
    }
  });
  async function UpdateAttendanceTable() {
    const queries = [
      `ALTER TABLE Attendance ADD COLUMN IF NOT EXISTS hours_worked DECIMAL(4,2) DEFAULT 0.00`,
      `ALTER TABLE Attendance ADD COLUMN IF NOT EXISTS note TEXT`,
      `ALTER TABLE Attendance MODIFY COLUMN status ENUM('Present','Absent','Leave','Late') DEFAULT 'Absent'`,
      `ALTER TABLE Attendance ADD UNIQUE KEY unique_intern_date (intern_id, attendance_date)`
    ];

    for (let q of queries) {
      try {
        await db.promise().query(q);
      } catch (e) { }
    }

    console.log("✅ Attendance table safely updated");
  }
  UpdateAttendanceTable();
  //attendence table
  const createReportsTable = `
    CREATE TABLE IF NOT EXISTS ${Q('Reports')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    report_title VARCHAR(50),
    report_description TEXT,
    file_path VARCHAR(255),
    report_type VARCHAR(50) DEFAULT 'weekly',
    status ENUM('Pending', 'Reviewed', 'Rejected', 'Submitted') DEFAULT 'Submitted',
    due_date DATE,
    submission_date DATE,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

  db.query(createReportsTable, (err) => {
    if (err) {
      console.error('Error creating reports table:', err);
    }
  });

  async function UpdateReportsTable() {
    const queries = [
      `ALTER TABLE Reports ADD COLUMN IF NOT EXISTS report_type ENUM('wednesday', 'saturday') DEFAULT 'wednesday'`,
      `ALTER TABLE Reports ADD COLUMN IF NOT EXISTS submission_date DATE`,
      `ALTER TABLE Reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
      `ALTER TABLE Reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`,
      `ALTER TABLE Reports MODIFY COLUMN status ENUM('Pending','Reviewed','Rejected','Submitted') DEFAULT 'Submitted'`,
      `UPDATE Reports SET report_type = CASE WHEN DAYOFWEEK(submitted_at) IN (3, 4, 5) THEN 'wednesday' ELSE 'saturday' END WHERE report_type IS NULL OR report_type = 'wednesday' OR report_type = 'weekly'`
    ];

    for (let q of queries) {
      try {
        await db.promise().query(q);
      } catch (e) { }
    }

    console.log("✅ Reports table safely updated");
  }

  UpdateReportsTable();
  // Weekly report tracking table for reports.html
  const createWeeklyReportsTable = `
    CREATE TABLE IF NOT EXISTS ${Q('weekly_reports')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    week_start_date DATE NOT NULL,
    wednesday_status ENUM('Submitted', 'Missing') DEFAULT 'Missing',
    saturday_status ENUM('Submitted', 'Missing') DEFAULT 'Missing',
    wednesday_report_id INT NULL,
    saturday_report_id INT NULL,
    last_submission_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id),
    FOREIGN KEY (wednesday_report_id) REFERENCES Reports(id) ON DELETE SET NULL,
    FOREIGN KEY (saturday_report_id) REFERENCES Reports(id) ON DELETE SET NULL,
    UNIQUE KEY unique_intern_week (intern_id, week_start_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

  db.query(createWeeklyReportsTable, (err) => {
    if (err) {
      console.error('Error creating weekly reports table:', err);
    } else {
      console.log('✅ Weekly reports table created successfully');

      // Safely ensure migration columns exist if table was previously created with older schema
      const migrationQueries = [
        `ALTER TABLE weekly_reports ADD COLUMN IF NOT EXISTS wednesday_report_id INT NULL`,
        `ALTER TABLE weekly_reports ADD COLUMN IF NOT EXISTS saturday_report_id INT NULL`
      ];
      for (const migQ of migrationQueries) {
        db.query(migQ, () => {});
      }

      // After table creation, populate it with all existing interns
      const currentWeekStart = new Date();
      const dayOfWeek = currentWeekStart.getDay();
      const diff = currentWeekStart.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
      currentWeekStart.setDate(diff);
      const weekStartDate = currentWeekStart.toISOString().split('T')[0];

      // Query to insert all existing interns into weekly_reports table
      const populateWeeklyReports = `
                INSERT INTO weekly_reports 
                (intern_id, week_start_date, wednesday_status, saturday_status)
  
                     SELECT i.intern_id, ?, 'Missing', 'Missing'
                        FROM Interns i
  
                    LEFT JOIN weekly_reports wr 
                      ON i.intern_id = wr.intern_id 
                      AND wr.week_start_date = ?

                    WHERE wr.intern_id IS NULL
            `;

      db.query(populateWeeklyReports, [weekStartDate, weekStartDate], (err, result) => {
        if (err) {
          console.error('Error populating weekly reports table:', err);
        } else {
          console.log(`✅ Weekly reports table populated with ${result ? result.affectedRows : 0} interns`);
        }
      });
    }
  });



  //attendence table
  const createDocumentsTable = `
     CREATE TABLE IF NOT EXISTS ${Q('Documents')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NULL,
    doc_title VARCHAR(50) NOT NULL,
    doc_description TEXT,
    file_path VARCHAR(255),
    file_size INT,
    category VARCHAR(50) DEFAULT 'General',
    uploaded_by ENUM('Intern','HR', 'Lead') DEFAULT 'Intern',
    status ENUM('Pending', 'Reviewed', 'Rejected') DEFAULT 'Pending',
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,                
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


 `;

  db.query(createDocumentsTable, (err) => {
    if (err) {
      console.error('Error creating documents table:', err);
    }
  });
  // Ensure missing columns exist (safety for older schema)
  db.query("ALTER TABLE Documents ADD COLUMN IF NOT EXISTS status ENUM('Pending','Reviewed','Rejected') DEFAULT 'Pending'", () => { });
  db.query("ALTER TABLE Documents ADD COLUMN IF NOT EXISTS uploaded_by ENUM('Intern','HR','Lead') DEFAULT 'Intern'", () => { });

  async function UpdateDocumentsTable() {
    const queries = [
      `ALTER TABLE Documents ADD COLUMN IF NOT EXISTS file_size INT`,
      `ALTER TABLE Documents ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'General'`,
      `ALTER TABLE Documents ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
      `ALTER TABLE Documents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`,
      `ALTER TABLE Documents MODIFY COLUMN uploaded_by ENUM('Intern','HR','Lead') DEFAULT 'Intern'`
    ];

    for (let q of queries) {
      try {
        await db.promise().query(q);
      } catch (e) { }
    }

    console.log("✅ Documents table safely updated");
  }
  UpdateDocumentsTable();

  const createTaskTable = `
    CREATE TABLE IF NOT EXISTS ${Q('Tasks')} (
    task_id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    task_title VARCHAR(100) NOT NULL,
    task_description TEXT,         
    priority ENUM('Low','Medium','High','Critical') DEFAULT 'Medium',
    status ENUM('Pending','In Progress','Completed','Overdue','Urgent') DEFAULT 'Pending',
    progress INT CHECK (progress BETWEEN 0 AND 100), 
    collaborators VARCHAR(255),
    assigned_date DATE NOT NULL,
    due_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

 `;

  db.query(createTaskTable, (err) => {
    if (err) {
      console.error('Error creating prescriptions table:', err);
    }
  });


  const createLeaveTable = `
   CREATE TABLE IF NOT EXISTS ${Q('leave_requests')} (
  id int(11) NOT NULL AUTO_INCREMENT,
  intern_id varchar(10) NOT NULL,
  from_date date NOT NULL,
  to_date date NOT NULL,
  number_of_working_days int(11) NOT NULL,
  reason text NOT NULL,
  status enum('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
  requested_at timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (id),
  KEY intern_id (intern_id),
  CONSTRAINT leave_requests_ibfk_1 FOREIGN KEY (intern_id) REFERENCES Interns (intern_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

 `;

  db.query(createLeaveTable, (err) => {
    if (err) {
      console.error('Error creating leave requests table:', err);
    }
  });

  // Add/modify leave_type column
  db.query("ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS leave_type VARCHAR(100) DEFAULT 'Casual Leave'", (err) => {
    if (!err) {
      db.query("ALTER TABLE leave_requests MODIFY COLUMN leave_type VARCHAR(100) DEFAULT 'Casual Leave'", () => {});
      console.log('✅ leave_type column ready in leave_requests table');
    }
  });

  // Add remarks column if it doesn't exist
  db.query("ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS remarks TEXT", (err) => {
    if (!err) console.log('✅ remarks column ready in leave_requests table');
  });

  // Add reporting_lead column if it doesn't exist
  db.query("ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS reporting_lead VARCHAR(255)", (err) => {
    if (!err) console.log('✅ reporting_lead column ready in leave_requests table');
  });

  // Add handover_note column if it doesn't exist
  db.query("ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS handover_note TEXT", (err) => {
    if (!err) console.log('✅ handover_note column ready in leave_requests table');
  });

  const createTransctionsTable = `
                CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type ENUM('income', 'expense') NOT NULL,
    description VARCHAR(255) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    approval_status ENUM('Pending','Approved','Rejected') DEFAULT 'Pending',
    category VARCHAR(100) DEFAULT 'Misc',
    date DATE DEFAULT CURRENT_DATE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            `;
  db.query(createTransctionsTable, (err) => {
    if (err) return console.error('Error creating transactions table:', err);
    console.log('✅ Transactions table ready');
  });
  const createBudgetTable = `
                CREATE TABLE IF NOT EXISTS budgets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    total_amount DECIMAL(10,2) NOT NULL,
    duration DATE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createBudgetTable, (err) => {
    if (err) return console.error('Error creating budgets table:', err);
    console.log('✅ Budgets table ready');
  });
  const createBudgetCategoriesTable = `
                CREATE TABLE IF NOT EXISTS budget_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    budget_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    CONSTRAINT fk_budget_category FOREIGN KEY (budget_id)
        REFERENCES budgets(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createBudgetCategoriesTable, (err) => {
    if (err) return console.error('Error creating budgets table:', err);
    console.log('✅ Budget categories table ready');
  });
  const createPaymentsTable = `
                CREATE TABLE IF NOT EXISTS payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    payment_id VARCHAR(50) NOT NULL UNIQUE,
    client_name VARCHAR(150) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('Succeeded', 'Pending', 'Failed') DEFAULT 'Pending',
    received_date DATE DEFAULT CURRENT_DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createPaymentsTable, (err) => {
    if (err) return console.error('Error creating payments table:', err);
    console.log('✅ Payments table ready');
  });
  const createInvoicesTable = `
                CREATE TABLE IF NOT EXISTS invoices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    invoice_number VARCHAR(50) NOT NULL UNIQUE,
    client_name VARCHAR(150) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('Paid', 'Pending', 'Overdue') DEFAULT 'Pending',
    issue_date DATE DEFAULT CURRENT_DATE,
    due_date DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createInvoicesTable, (err) => {
    if (err) return console.error('Error creating invoices table:', err);
    console.log('✅ Invoices table ready');
  });

  const createSettingsTable = `
                CREATE TABLE if not exists settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  company_name VARCHAR(255),
  support_email VARCHAR(255),
  timezone VARCHAR(100),
  currency VARCHAR(10),
  pay_terms VARCHAR(50),
  tax_rate DECIMAL(5,2),
  invoice_prefix VARCHAR(50),
  auto_send BOOLEAN DEFAULT FALSE,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createSettingsTable, (err) => {
    if (err) return console.error('Error creating settings table:', err);
    console.log('✅ Settings table ready');
  });


  const createReceiptsTable = `
                CREATE TABLE IF NOT EXISTS receipts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  receipt_number VARCHAR(20) NOT NULL,
  client_name VARCHAR(100) NOT NULL,
  invoice_number VARCHAR(20) NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  issue_date DATE NOT NULL,
  avatar_url VARCHAR(255) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

            `;
  db.query(createReceiptsTable, (err) => {
    if (err) return console.error('Error creating receipts table:', err);
    console.log('✅ Receipts table ready');
  });

  // Create notifications table
  const createNotificationsTable = `
        CREATE TABLE IF NOT EXISTS Notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            notify VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            type ENUM('info', 'success', 'warning', 'error') DEFAULT 'info',
            target_user_id VARCHAR(50) NULL,
            target_role ENUM('hr', 'intern', 'all') DEFAULT 'all',
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `;

  db.query(createNotificationsTable, (err) => {
    if (err) return console.error('Error creating notifications table:', err);
    console.log('✅ Notifications table ready');
  });

  // Helper function to create notifications
  async function createNotification(notify, description, type = 'info', targetUserId = null, targetRole = 'all') {
    try {
      const [result] = await executeQuery(
        'INSERT INTO Notifications (notify, description, type, target_user_id, target_role) VALUES (?, ?, ?, ?, ?)',
        [notify, description, type, targetUserId, targetRole]
      );

      const notificationId = result.insertId;

      // Emit real-time notification
      const notificationData = {
        id: notificationId,
        notify,
        description,
        type,
        target_user_id: targetUserId,
        target_role: targetRole,
        created_at: new Date().toISOString()
      };

      // Send to appropriate rooms
      if (targetUserId) {
        io.to(`intern-${targetUserId}`).emit('new-notification', notificationData);
      }

      if (targetRole === 'hr' || targetRole === 'all') {
        io.to('hr-dashboard').emit('new-notification', notificationData);
      }

      if (targetRole === 'intern' || targetRole === 'all') {
        io.emit('new-notification', notificationData); // Send to all connected clients
      }

      console.log('📢 Notification created and sent:', notificationData);
      return notificationId;
    } catch (error) {
      console.error('Error creating notification:', error);
      throw error;
    }
  }
}

// Update migration function for the new schema
function migrateExistingAppointments() {
  const query = `
        UPDATE appointments 
        SET 
            session_price = CASE 
                WHEN session_type = 'Initial Consultation' THEN 1000
                WHEN session_type = 'Counseling Session' THEN 1500
                WHEN session_type = 'Therapy Session' THEN 3000
                ELSE 1500
            END,
            session_duration = CASE 
                WHEN session_type = 'Initial Consultation' THEN 40
                WHEN session_type = 'Counseling Session' THEN 50
                WHEN session_type = 'Therapy Session' THEN 80
                ELSE 50
            END 
        WHERE session_price IS NULL OR session_duration IS NULL
    `;
  db.query(query, (err) => {
    if (err) {
      console.error('Error migrating appointments:', err);
      return;
    }
    console.log('Existing appointments migrated to new schema');
  });
}

// API Endpoints
// Helper: Get today's date in IST (YYYY-MM-DD)
function getTodayIST() {
  const now = new Date();
  // IST offset in minutes
  const istOffset = 5.5 * 60;
  // Get UTC time + IST offset
  const istTime = new Date(now.getTime() + (istOffset - now.getTimezoneOffset()) * 60000);
  return istTime.toISOString().slice(0, 10);
}

// Helper: Format MySQL DATE and TIME as IST string
function formatIST(dateStr, timeStr) {
  // dateStr: 'YYYY-MM-DD', timeStr: 'HH:MM:SS'
  const [year, month, day] = dateStr.split('-');
  const [hour, minute, second] = timeStr.split(':');
  // Create JS Date in UTC
  const utcDate = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  // Add IST offset
  const istDate = new Date(utcDate.getTime() + 5.5 * 60 * 60000);
  // Format date and time in IST
  const dateOut = istDate.getFullYear() + '-' +
    String(istDate.getMonth() + 1).padStart(2, '0') + '-' +
    String(istDate.getDate()).padStart(2, '0');
  const timeOut = String(istDate.getHours()).padStart(2, '0') + ':' +
    String(istDate.getMinutes()).padStart(2, '0');
  return { date: dateOut, time: timeOut };
}

// Function: encodeToken (Updated to use JWT)
function encodeToken(payload) {
  // You can change the '24h' here to any duration you prefer
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '4h' });
}

// Function: decodeToken (Updated to use JWT)
function decodeToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null; // Returns null if token is expired or altered
  }
}

// Function: authenticateToken (Updated to use JWT)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "No token provided" });

  // jwt.verify handles both checking the secret AND the expiration time automatically
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      const message = err.name === 'TokenExpiredError' ? 'Token has expired' : 'Invalid token';
      return res.status(403).json({ message });
    }

    req.user = user;
    next();
  });
}


app.post("/api/dream-reflection", async (req, res) => {
  const text = String(req.body.text || '').slice(0, 2000);
  const emotions = Array.isArray(req.body.emotions) ? req.body.emotions.slice(0, 10).map(e => String(e).slice(0, 30)) : [];
  if (tooMany('dream:' + req.user.id, 20, 60 * 60 * 1000)) {
    return res.status(429).json({ reflection: "You've reached the limit for now. Please try again in an hour." });
  }

  if (!text) {
    return res.status(400).json({ reflection: "Dream text is required." });
  }

  const payload = {
    contents: [
      {
        role: "user",
        parts: [{
          text: `You are a concise dream interpreter. Keep reflections short and meaningful, 3 to 5 lines max. Interpret this dream: ${text}. Emotions involved: ${emotions.join(', ')}.`
        }]
      }
    ]
  };



  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }
    );

    const data = await response.json();
    console.log(data)
    const reflection = data.candidates?.[0]?.content?.parts?.[0]?.text
      || "Every dream has meaning — stay curious about its feeling.";

    res.json({ reflection });

  } catch (error) {
    console.error("Error calling Gemini API:", error);
    res.status(500).json({ reflection: "Failed to get dream reflection." });
  }
});
//apis for hr dashboard
// API endpoints for dashboard data
app.get('/api/interns-count', async (req, res) => {
  try {
    const [rows] = await executeQuery('SELECT COUNT(*) as total FROM Interns');
    const [newHires] = await executeQuery('SELECT COUNT(*) as count FROM Interns WHERE start_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)');
    res.json({
      total: rows[0].total || 0,
      newHires: newHires[0].count || 0
    });
  } catch (error) {
    console.error('Error fetching intern count:', error);
    res.status(500).json({ error: 'Failed to fetch intern count' });
  }
});

// API to get all interns data
app.get('/api/interns', authenticateToken, async (req, res) => {
  try {
    // Monday of this week (India time), for the Wednesday / Saturday report columns
    const t = new Date(getTodayIST() + 'T00:00:00Z');
    t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7));
    const weekStart = t.toISOString().slice(0, 10);

    const [interns] = await executeQuery(`
      SELECT i.*,
        COALESCE(a.present, 0) AS present, COALESCE(a.late, 0) AS late, COALESCE(a.absent, 0) AS absent, COALESCE(a.leave_days, 0) AS leave_days,
        COALESCE(tk.total, 0) AS tasks_total, COALESCE(tk.done, 0) AS tasks_done,
        EXISTS (SELECT 1 FROM Reports r WHERE r.intern_id = i.intern_id AND r.submitted_at >= ? AND r.report_type = 'wednesday') AS wed_done,
        EXISTS (SELECT 1 FROM Reports r WHERE r.intern_id = i.intern_id AND r.submitted_at >= ? AND r.report_type = 'saturday') AS sat_done
      FROM Interns i
      LEFT JOIN (SELECT intern_id, ${ATT_COUNTS} FROM Attendance GROUP BY intern_id) a ON a.intern_id = i.intern_id
      LEFT JOIN (SELECT intern_id, COUNT(*) AS total, SUM(status = 'Completed') AS done FROM Tasks GROUP BY intern_id) tk ON tk.intern_id = i.intern_id
      ORDER BY i.created_at DESC`, [weekStart, weekStart]);

    // Transform data to match frontend expectations
    const transformedInterns = interns.map(intern => {
      const sc = internScores(intern, { total: intern.tasks_total, done: intern.tasks_done });
      return {
        id: intern.intern_id,
        name: intern.name,
        email: intern.email,
        phone: intern.phone,
        dept: intern.department,
        department: intern.department,
        role: intern.internrole,
        mentor: 'Not Assigned',
        start: intern.start_date,
        end: intern.end_date,
        status: intern.status,
        attendance: sc.attendance,
        punctuality: sc.punctuality,
        late_days: sc.late,
        wed: intern.wed_done ? 'Submitted' : 'Missing',
        sat: intern.sat_done ? 'Submitted' : 'Missing',
        university: intern.university || 'N/A',
        performance_score: sc.performance,
        tasks_completed: sc.doneTasks,
        tasks_total: sc.totalTasks,
        hr_id: intern.HR_id || 'N/A',
        team_id: intern.Team_id || 'N/A',
        profile_image: intern.profile_image || null,
        createdAt: intern.created_at,
        updatedAt: intern.updated_at
      };
    });

    res.json({ interns: transformedInterns });
  } catch (error) {
    console.error('Error fetching interns:', error.code || error.message);
    res.status(500).json({ error: 'Failed to fetch interns data' });
  }
});

app.get('/api/attendance/daily', async (req, res) => {
  try {
    const { date } = req.query;
    const attendanceDate = date || getTodayIST();

    const [present] = await executeQuery(
      'SELECT COUNT(*) as count FROM Attendance WHERE attendance_date = ? AND status = "Present"',
      [attendanceDate]
    );

    const [leave] = await executeQuery(
      'SELECT COUNT(*) as count FROM Attendance WHERE attendance_date = ? AND status = "Leave"',
      [attendanceDate]
    );

    res.json({
      present: present[0].count || 0,
      leave: leave[0].count || 0
    });
  } catch (error) {
    console.error('Error fetching daily attendance:', error);
    res.status(500).json({ error: 'Failed to fetch daily attendance' });
  }
});

app.get('/api/attendance/records', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    const attendanceDate = date || getTodayIST();

    const [rows] = await executeQuery(`
            SELECT a.id, a.intern_id, a.attendance_date, a.check_in, a.check_out, a.status, a.note,
                   i.name, i.department
            FROM Attendance a
            LEFT JOIN Interns i ON a.intern_id = i.intern_id
            WHERE a.attendance_date = ?
            ORDER BY i.name
        `, [attendanceDate]);

    res.json(rows);
  } catch (error) {
    console.error('Error fetching attendance records:', error);
    res.status(500).json({ error: 'Failed to fetch attendance records' });
  }
});

// POST endpoint to mark attendance
app.post('/api/attendance', authenticateToken, async (req, res) => {
  try {
    const { intern_id, attendance_date, check_in, check_out, status, note } = req.body;

    if (!intern_id || !attendance_date || !status) {
      return res.status(400).json({ error: 'intern_id, attendance_date, and status are required' });
    }

    // Check if attendance record already exists
    const [existing] = await executeQuery(
      'SELECT id FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
      [intern_id, attendance_date]
    );

    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'Attendance record already exists for this date' });
    }

    // Insert new attendance record
    const [result] = await executeQuery(`
            INSERT INTO Attendance (intern_id, attendance_date, check_in, check_out, status, note)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [intern_id, attendance_date, check_in, check_out, status, note]);

    res.json({
      success: true,
      message: 'Attendance marked successfully',
      id: result.insertId
    });
  } catch (error) {
    console.error('Error marking attendance:', error);
    res.status(500).json({ error: 'Failed to mark attendance' });
  }
});

// PUT endpoint to update attendance
app.put('/api/attendance/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { check_in, check_out, status, note } = req.body;

    if (!id) {
      return res.status(400).json({ error: 'Attendance ID is required' });
    }

    // Update attendance record
    const [result] = await executeQuery(`
            UPDATE Attendance 
            SET check_in = ?, check_out = ?, status = ?, note = ?
            WHERE id = ?
        `, [check_in, check_out, status, note, id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Attendance record not found' });
    }

    res.json({
      success: true,
      message: 'Attendance updated successfully'
    });
  } catch (error) {
    console.error('Error updating attendance:', error);
    res.status(500).json({ error: 'Failed to update attendance' });
  }
});

app.get('/api/attendance/allweekly', async (req, res) => {
  try {
    const [rows] = await executeQuery(`
            SELECT 
                DAYNAME(attendance_date) as day,
                ROUND(AVG(CASE WHEN status = 'Present' THEN 100 ELSE 0 END)) as attendance
            FROM Attendance 
            WHERE attendance_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DAYNAME(attendance_date)
            ORDER BY attendance_date
        `);

    const labels = ["Mon", "Tue", "Wed", "Thu", "Fri"];
    const data = labels.map(day => {
      const found = rows.find(r => r.day.startsWith(day.substring(0, 3)));
      return found ? found.attendance : 0;
    });

    res.json({ labels, data });
  } catch (error) {
    console.error('Error fetching weekly attendance:', error);
    res.json({ labels: ["Mon", "Tue", "Wed", "Thu", "Fri"], data: [0, 0, 0, 0, 0] });
  }
});

app.get('/api/departments/performance', async (req, res) => {
  try {
    const [rows] = await executeQuery(`
            SELECT 
                'HR' as department,
                ROUND(AVG(CASE WHEN status = 'Present' THEN 100 ELSE 0 END)) as performance
            FROM Attendance a
            JOIN Interns i ON a.intern_id = i.intern_id
            WHERE i.internrole LIKE '%HR%' AND a.attendance_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            
            UNION ALL
            
            SELECT 
                'Development' as department,
                ROUND(AVG(CASE WHEN status = 'Present' THEN 100 ELSE 0 END)) as performance
            FROM Attendance a
            JOIN Interns i ON a.intern_id = i.intern_id
            WHERE i.internrole LIKE '%Dev%' AND a.attendance_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            
            UNION ALL
            
            SELECT 
                'Design' as department,
                ROUND(AVG(CASE WHEN status = 'Present' THEN 100 ELSE 0 END)) as performance
            FROM Attendance a
            JOIN Interns i ON a.intern_id = i.intern_id
            WHERE i.internrole LIKE '%Design%' AND a.attendance_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `);

    const labels = ["HR", "Development", "Design"];
    const data = labels.map(dept => {
      const found = rows.find(r => r.department === dept);
      return found ? found.performance : 0;
    });

    res.json({ labels, data });
  } catch (error) {
    console.error('Error fetching department performance:', error);
    res.json({ labels: ["HR", "Development", "Design"], data: [0, 0, 0] });
  }
});

app.get('/api/attendance/status', async (req, res) => {
  try {
    const [rows] = await executeQuery(`
            SELECT 
                SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) as present,
                SUM(CASE WHEN status = 'Leave' THEN 1 ELSE 0 END) as leave,
                SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) as absent
            FROM Attendance 
            WHERE attendance_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `);

    res.json(rows[0] || { present: 0, leave: 0, absent: 0 });
  } catch (error) {
    console.error('Error fetching attendance status:', error);
    res.json({ present: 0, leave: 0, absent: 0 });
  }
});

app.get('/api/attendance/trends', async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const daysNum = parseInt(days);

    // Calculate date ranges for comparison
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Current period (this week/fortnight/month)
    const currentStart = new Date(today);
    currentStart.setDate(today.getDate() - daysNum + 1);

    // Previous period (last week/fortnight/month) - same duration, ending before current period starts
    const previousEnd = new Date(currentStart);
    previousEnd.setDate(previousEnd.getDate() - 1);
    const previousStart = new Date(previousEnd);
    previousStart.setDate(previousEnd.getDate() - daysNum + 1);

    // Get current period data
    const [currentRows] = await executeQuery(`
            SELECT 
                attendance_date,
                SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as attendance
            FROM Attendance 
            WHERE attendance_date >= ? AND attendance_date <= ?
            GROUP BY attendance_date
            ORDER BY attendance_date
        `, [currentStart.toISOString().split('T')[0], today.toISOString().split('T')[0]]);

    // Get previous period data
    const [previousRows] = await executeQuery(`
            SELECT 
                attendance_date,
                SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as attendance
            FROM Attendance 
            WHERE attendance_date >= ? AND attendance_date <= ?
            GROUP BY attendance_date
            ORDER BY attendance_date
        `, [previousStart.toISOString().split('T')[0], previousEnd.toISOString().split('T')[0]]);

    // Generate data arrays
    const labels = [];
    const thisWeekData = [];
    const lastWeekData = [];

    for (let i = 0; i < daysNum; i++) {
      const currentDate = new Date(currentStart);
      currentDate.setDate(currentStart.getDate() + i);

      // Format label as "Month Day"
      const label = currentDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      labels.push(label);

      // Find current period data for this date
      const currentMatch = currentRows.find(r =>
        new Date(r.attendance_date).toDateString() === currentDate.toDateString()
      );
      thisWeekData.push(currentMatch ? Math.round(currentMatch.attendance) : 0);

      // Find previous period data (shifted by daysNum days)
      const previousDate = new Date(currentDate);
      previousDate.setDate(currentDate.getDate() - daysNum);
      const previousMatch = previousRows.find(r =>
        new Date(r.attendance_date).toDateString() === previousDate.toDateString()
      );
      lastWeekData.push(previousMatch ? Math.round(previousMatch.attendance) : 0);
    }

    res.json({
      labels,
      thisWeek: thisWeekData,
      lastWeek: lastWeekData
    });
  } catch (error) {
    console.error('Error fetching attendance trends:', error);
    // Return empty data structure
    const days = parseInt(req.query.days) || 7;
    const labels = [];
    const thisWeek = [];
    const lastWeek = [];

    for (let i = 0; i < days; i++) {
      const date = new Date();
      date.setDate(date.getDate() - (days - 1 - i));
      labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
      thisWeek.push(0);
      lastWeek.push(0);
    }

    res.json({ labels, thisWeek, lastWeek });
  }
});

app.get('/api/leave-requests/pending', async (req, res) => {
  try {
    const [rows] = await executeQuery('SELECT COUNT(*) as count FROM leave_requests WHERE status = "Pending"');
    res.json({ onLeave: rows[0].count || 0 });
  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.json({ onLeave: 0 });
  }
});

// Notification API endpoints
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;
    const { limit = 20, unread_only = false } = req.query;

    let whereClause = 'WHERE 1=1';
    const params = [];

    // Filter by user or role
    if (userId) {
      whereClause += ' AND (target_user_id = ? OR (target_user_id IS NULL AND (target_role = "all" OR target_role = ?)))';
      params.push(userId, userRole);
    } else if (userRole) {
      whereClause += ' AND (target_role = ? OR target_role = "all")';
      params.push(userRole);
    }

    if (unread_only === 'true') {
      whereClause += ' AND is_read = false';
    }

    const [rows] = await executeQuery(`
            SELECT id, notify as title, description, type, target_user_id, target_role, is_read as isRead, 
                   created_at as createdAt, UNIX_TIMESTAMP(created_at) AS createdTs
            FROM Notifications 
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT ?
        `, [...params, parseInt(limit)]);

    res.json(rows);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/notifications', async (req, res) => {
  try {
    const { notify: title, description, type, targetUserId, targetRole } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'notify and description are required' });
    }

    const notificationId = await notify(title, description, type, { userId: targetUserId || null, role: targetRole || 'all' });

    res.json({
      success: true,
      message: 'Notification created successfully',
      id: notificationId
    });
  } catch (error) {
    console.error('Error creating notification:', error);
    res.status(500).json({ error: 'Failed to create notification' });
  }
});

app.put('/api/notifications/:id/read', async (req, res) => {
  try {
    const { id } = req.params;

    await executeQuery('UPDATE Notifications SET is_read = TRUE WHERE id = ?', [id]);

    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let whereClause = 'WHERE 1=1';
    const params = [];

    if (userId) {
      whereClause += ' AND (target_user_id = ? OR (target_user_id IS NULL AND (target_role = "all" OR target_role = ?)))';
      params.push(userId, userRole);
    } else if (userRole) {
      whereClause += ' AND (target_role = ? OR target_role = "all")';
      params.push(userRole, userRole);
    }

    await executeQuery(`UPDATE Notifications SET is_read = TRUE ${whereClause}`, params);

    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Failed to update notifications' });
  }
});

app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let whereClause = 'WHERE is_read = FALSE';
    const params = [];

    if (userId) {
      whereClause += ' AND (target_user_id = ? OR (target_user_id IS NULL AND (target_role = "all" OR target_role = ?)))';
      params.push(userId, userRole);
    } else if (userRole) {
      whereClause += ' AND (target_role = ? OR target_role = "all")';
      params.push(userRole);
    }

    const [rows] = await executeQuery(`SELECT COUNT(*) as count FROM Notifications ${whereClause}`, params);

    res.json({ unreadCount: rows[0]?.count || 0 });

  } catch (error) {
    console.error('FULL ERROR:', error);
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || '').trim();
    const password = String(req.body.password || '');

    // ✅ Basic validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }
    // Guessing passwords: 10 tries per 15 minutes per network, and per account
    if (tooMany('login:' + clientIp(req), 10, 15 * 60 * 1000) || tooMany('login:' + email.toLowerCase(), 10, 15 * 60 * 1000)) {
      return res.status(429).json({ message: "Too many sign-in attempts. Please wait 15 minutes and try again." });
    }

    // ============================
    // ✅ GET USER
    // ============================
    const [[user]] = await executeQuery(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // ============================
    // 🔐 PASSWORD CHECK
    // ============================
    const match = await bcrypt.compare(password.trim(), user.password_hash);

    if (!match) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (user.status && user.status !== 'active') {
      return res.status(403).json({ message: "This account is not active. Please contact HR." });
    }

    // ============================
    // 🔵 INTERN LOGIN LOGIC
    // ============================
    if (user.role.toLowerCase() === "intern") {

      // ✅ Get intern details
      const [[intern]] = await executeQuery(
        "SELECT intern_id, name, email FROM Interns WHERE email = ?",
        [email]
      );

      if (!intern) {
        return res.status(404).json({ message: "Intern record not found" });
      }

      const internId = intern.intern_id;
      const internName = intern.name || user.full_name;
      const internEmail = intern.email || user.email || email;
      console.log("👤 Intern ID:", internId);

      // ============================
      // ⏰ TIME (IST)
      // ============================
      const now = new Date();
      const istOffset = 5.5 * 60 * 60 * 1000;
      const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
      const istNow = new Date(utc + istOffset);

      const date = istNow.toISOString().slice(0, 10);
      const time = istNow.toTimeString().slice(0, 8);

      // ✅ Process check-in attendance and late email notifications
      const checkInResult = await processInternCheckIn({
        internId,
        internName,
        internEmail,
        date,
        time
      });

      console.log("✅ Attendance check-in:", checkInResult.status, "isNew:", checkInResult.isNew);

      // ============================
      // ✅ TOKEN
      // ============================
      const token = encodeToken({
        id: user.id,
        name: user.full_name,
        role: user.role,
        intern_id: internId
      });

      return res.json({
        message: "Login successful",
        token,
        role: user.role,
        intern_id: internId
      });
    }

    // ============================
    // 🟢 NON-INTERN USERS
    // ============================
    const token = encodeToken({
      id: user.id,
      role: user.role
    });

    return res.json({
      message: "Login successful",
      token,
      role: user.role
    });

  } catch (err) {
    console.error("❌ Login error:", err.code || err.message);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});


// Old version changed any account's password with just an email address. Refuse it.
app.post('/api/forgotpass', (req, res) => {
  res.status(410).json({ ok: false, message: 'Please refresh the page and request a reset code.' });
});

// Step 1: email a 6-digit code. Always answers the same, so it doesn't reveal which emails have accounts.
app.post('/api/forgotpass/request', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ ok: false, message: 'Please enter a valid email address.' });
  }
  if (tooMany('reset-ip:' + clientIp(req), 10, 60 * 60 * 1000) || tooMany('reset:' + email, 3, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: 'Too many requests. Please wait 15 minutes and try again.' });
  }
  const reply = { ok: true, message: 'If an account exists for this email, we have sent a 6-digit code. It is valid for 10 minutes.' };
  try {
    const [[user]] = await executeQuery('SELECT id, full_name FROM users WHERE LOWER(email) = ?', [email]);
    if (!user) return res.json(reply);
    const code = String(crypto.randomInt(100000, 1000000));
    await executeQuery('DELETE FROM password_resets WHERE email = ?', [email]);
    await executeQuery('INSERT INTO password_resets (email, code_hash, expires_at) VALUES (?, ?, ?)',
      [email, crypto.createHash('sha256').update(code).digest('hex'), Date.now() + 10 * 60 * 1000]);
    await sendEmail({
      to: email,
      subject: 'Your InnerWhispers password reset code',
      html: `<p>Dear ${esc(user.full_name || 'user')},</p>
        <p>Your password reset code is:</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:6px;font-family:monospace">${code}</p>
        <p>It is valid for 10 minutes. If you didn't ask to reset your password, ignore this email; your password stays the same.</p>
        <p>Best regards,<br>InnerWhispers Wellness LLP</p>`
    });
    res.json(reply);
  } catch (err) {
    console.error('Reset request failed:', err.code || err.message);
    res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
  }
});

// Step 2: code + new password. Five wrong codes and the code is deleted.
app.post('/api/forgotpass/reset', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const npass = String(req.body.npass || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, message: 'Enter the 6-digit code from the email.' });
  if (npass.length < 8 || npass.length > 128) return res.status(400).json({ ok: false, message: 'Your new password must be at least 8 characters.' });
  if (tooMany('reset-check:' + clientIp(req), 20, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: 'Too many attempts. Please wait 15 minutes and try again.' });
  }
  try {
    const [[rec]] = await executeQuery('SELECT id, code_hash, attempts, expires_at FROM password_resets WHERE email = ? ORDER BY id DESC LIMIT 1', [email]);
    const wrong = (msg) => res.status(400).json({ ok: false, message: msg });
    if (!rec || Number(rec.expires_at) < Date.now()) {
      if (rec) await executeQuery('DELETE FROM password_resets WHERE email = ?', [email]);
      return wrong('This code has expired or is not valid. Please request a new one.');
    }
    const given = crypto.createHash('sha256').update(code).digest();
    if (!crypto.timingSafeEqual(given, Buffer.from(rec.code_hash, 'hex'))) {
      if (rec.attempts + 1 >= 5) {
        await executeQuery('DELETE FROM password_resets WHERE email = ?', [email]);
        return wrong('Too many incorrect codes. Please request a new one.');
      }
      await executeQuery('UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?', [rec.id]);
      return wrong('Incorrect code. Please check the email and try again.');
    }
    await executeQuery('UPDATE users SET password_hash = ? WHERE LOWER(email) = ?', [await bcrypt.hash(npass, 10), email]);
    await executeQuery('DELETE FROM password_resets WHERE email = ?', [email]);
    res.json({ ok: true, message: 'Password changed successfully.' });
  } catch (err) {
    console.error('Password reset failed:', err.code || err.message);
    res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
  }
});

//for register
app.post("/api/register", imageUpload.single("profileImage"), async (req, res) => {
  try {
    const t = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
    const username = t(req.body.username, 50), email = t(req.body.email, 255).toLowerCase(), fullname = t(req.body.fullname, 255);
    const ph = t(req.body.ph, 20), internRole = t(req.body.internRole, 20), internid = t(req.body.internid, 10);
    const password = String(req.body.password || '');
    const role = roleOf({ role: req.body.department });
    const department = role === 'intern' ? 'Intern' : role;

    if (tooMany('register:' + clientIp(req), 10, 60 * 60 * 1000)) {
      return res.status(429).json({ message: "Too many sign-ups from this network. Please try again later." });
    }
    const ALLOWED_ROLES = ['intern', 'hr', 'admin', 'patient', 'psychiatry', 'psychology', 'therapy', 'counseling', 'guidance'];
    if (!ALLOWED_ROLES.includes(role)) return res.status(400).json({ message: "Please choose a valid department." });
    if (!username || !fullname || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Please fill in your name, username and a valid email." });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ message: "Your password must be at least 8 characters." });

    // Who may create which account
    const requester = roleOf(req.user);
    if (role === 'admin' && requester !== 'admin') {
      return res.status(403).json({ message: "Only an admin can create admin accounts." });
    }
    if (role !== 'intern' && role !== 'admin' && !HR_ROLES.includes(requester)) {
      return res.status(403).json({ message: "Only HR can create this type of account. Please contact HR." });
    }
    if (role === 'intern' && !HR_ROLES.includes(requester)) {
      // Interns sign up with the invite code HR gives them (INTERN_INVITE_CODE)
      const expected = process.env.INTERN_INVITE_CODE || '';
      const given = t(req.body.inviteCode, 100);
      const same = expected && given.length === expected.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
      if (!same) return res.status(403).json({ message: "The invite code is not correct. Please check it with HR." });
    }
    if (role === 'intern' && !/^[A-Za-z0-9-]{2,10}$/.test(internid)) {
      return res.status(400).json({ message: "Intern ID can only use letters, numbers and hyphens (up to 10)." });
    }

    const [[taken]] = await executeQuery('SELECT id FROM users WHERE LOWER(email) = ? OR username = ?', [email, username]);
    if (taken) return res.status(409).json({ message: "An account with this email or username already exists." });

    const hashed_pass = await bcrypt.hash(password, 10);

    if (!req.file) {
      return res.status(400).json({ error: "Profile image is required" });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: role === 'intern' ? `Interns/${internid}` : `Users/${crypto.randomBytes(8).toString('hex')}`,
          public_id: 'profile_pic',
          resource_type: 'image',
          overwrite: true
        },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
    });

    const picUrl = uploadResult.secure_url;

    const sql = `
            INSERT INTO users (username, email, password_hash, full_name, phone, role, profile_image)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

    // ✅ FIXED: using await
    await executeQuery(sql, [username, email, hashed_pass, fullname, ph, department, picUrl]);

    if (department === "Intern") {
      const mysqlQuery = `
                INSERT INTO Interns(intern_id, name, internrole, email, phone)
                VALUES (?, ?, ?, ?, ?)
            `;

      await executeQuery(mysqlQuery, [internid, fullname, internRole, email, ph]);
    }

    res.json({ ok: true, message: "Registration successful" });

  } catch (err) {
    console.error('Register failed:', err.code || err.message);
    res.status(500).json({ error: "Server error", message: "Registration failed. Please try again." });
  }
});

//interndashboard
app.get('/api/getintern/:id', async (req, res) => {
  const internId = req.params.id;

  try {
    const results = await new Promise((resolve, reject) => {
      db.query(
        `SELECT email, internrole, phone
         FROM Interns
         WHERE intern_id = ?`,
        [internId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (results.length === 0) {
      return res.status(404).json({ message: 'Intern not found' });
    }

    res.json(results[0]);
  } catch (error) {
    console.error('Error fetching intern:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/interns/updateintern/:id', async (req, res) => {
  const internId = req.params.id;
  const { name, email, phone, internrole } = req.body;

  try {
    // Get current email from Interns table
    const iemail = await new Promise((resolve, reject) => {
      db.query(
        `SELECT email FROM Interns WHERE intern_id = ?`,
        [internId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (iemail.length === 0) {
      return res.status(404).json({ message: "Intern not found" });
    }

    const currentEmail = iemail[0].email;
    console.log(iemail);
    // Update users table
    const users = await new Promise((resolve, reject) => {
      db.query(
        `UPDATE users
         SET full_name = ?, phone = ?, email = ?
         WHERE LOWER(email) = LOWER(?)`,
        [name, phone, email, currentEmail],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
    console.log(users);

    if (users.affectedRows === 0) {
      console.log("User not found for this intern");
      // optional: you can insert a new user here if missing
    }

    // Update Interns table
    const results = await new Promise((resolve, reject) => {
      db.query(
        `UPDATE Interns
         SET name = ?, email = ?, phone = ?, internrole = ?
         WHERE intern_id = ?`,
        [name, email, phone, internrole, internId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Intern not found" });
    }

    res.status(200).json({ message: "Intern updated successfully" });
  } catch (error) {
    console.error("Error updating intern:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

/* ─────────────────────────────────────────────────────────────
   Intern profile details
   GET  /api/interns/details/:id   read the details
   PUT  /api/interns/details/:id   save the details (only fields listed below)
   Only the intern who owns the profile, HR or an admin can read or change it.
───────────────────────────────────────────────────────────── */
const INTERN_DETAIL_FIELDS = {
  // field: [column definition, max length, kind]
  date_of_birth:      ['DATE NULL', 10, 'date'],
  gender:             ['VARCHAR(30) NULL', 30],
  address_line:       ['VARCHAR(255) NULL', 255],
  city:               ['VARCHAR(80) NULL', 80],
  state:              ['VARCHAR(80) NULL', 80],
  pincode:            ['VARCHAR(10) NULL', 10, 'pincode'],
  university:         ['VARCHAR(255) NULL', 255],
  degree:             ['VARCHAR(100) NULL', 100],
  branch:             ['VARCHAR(100) NULL', 100],
  year_of_study:      ['VARCHAR(20) NULL', 20],
  graduation_year:    ['VARCHAR(4) NULL', 4, 'year'],
  college_roll_no:    ['VARCHAR(50) NULL', 50],
  emergency_name:     ['VARCHAR(100) NULL', 100],
  emergency_relation: ['VARCHAR(50) NULL', 50],
  emergency_phone:    ['VARCHAR(15) NULL', 15, 'phone'],
  linkedin_url:       ['VARCHAR(255) NULL', 255, 'url'],
  portfolio_url:      ['VARCHAR(255) NULL', 255, 'url'],
  skills:             ['VARCHAR(500) NULL', 500],
  bio:                ['VARCHAR(500) NULL', 500]
};
// "university" already exists in the table, so it is not re-created
const INTERN_DETAIL_COLUMNS = Object.entries(INTERN_DETAIL_FIELDS)
  .filter(([k]) => k !== 'university')
  .map(([k, v]) => [k, v[0]]);

async function canAccessIntern(req, internId) {
  const role = String(req.user?.role || '').toLowerCase();
  if (role === 'admin' || role === 'hr') return true;
  if (!req.user?.id) return false;
  const [rows] = await executeQuery(
    'SELECT 1 FROM users u JOIN Interns i ON LOWER(u.email) = LOWER(i.email) WHERE u.id = ? AND i.intern_id = ? LIMIT 1',
    [req.user.id, internId]
  );
  return rows.length > 0;
}

app.get('/api/interns/details/:id', authenticateToken, async (req, res) => {
  try {
    if (!(await canAccessIntern(req, req.params.id))) return res.status(403).json({ message: 'Not allowed' });
    const cols = Object.keys(INTERN_DETAIL_FIELDS).map(c => '`' + c + '`').join(', ');
    const [rows] = await executeQuery(
      'SELECT ' + cols + ', start_date, end_date FROM Interns WHERE intern_id = ?',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ message: 'Intern not found' });
    const r = rows[0];
    const ymd = d => (d instanceof Date ? d.toISOString().slice(0, 10) : (d || null));
    r.date_of_birth = ymd(r.date_of_birth);
    r.start_date = ymd(r.start_date);
    r.end_date = ymd(r.end_date);
    res.json(r);
  } catch (err) {
    console.error('GET intern details:', err);
    res.status(500).json({ message: 'Could not load details' });
  }
});

app.put('/api/interns/details/:id', authenticateToken, async (req, res) => {
  try {
    if (!(await canAccessIntern(req, req.params.id))) return res.status(403).json({ message: 'Not allowed' });
    const body = req.body || {};
    const sets = [], vals = [], errors = {};
    for (const [field, [, max, kind]] of Object.entries(INTERN_DETAIL_FIELDS)) {
      if (!(field in body)) continue;
      let v = body[field] == null ? '' : String(body[field]).trim();
      if (v.length > max) errors[field] = 'Must be ' + max + ' characters or fewer';
      else if (v && kind === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(v)) errors[field] = 'Use the format YYYY-MM-DD';
      else if (v && kind === 'pincode' && !/^\d{6}$/.test(v)) errors[field] = 'PIN code must be 6 digits';
      else if (v && kind === 'year' && !/^(19|20)\d{2}$/.test(v)) errors[field] = 'Enter a 4-digit year';
      else if (v && kind === 'phone' && v.replace(/\D/g, '').length < 10) errors[field] = 'Phone must have at least 10 digits';
      else if (v && kind === 'url' && !/^https?:\/\/\S+$/i.test(v)) errors[field] = 'Links must start with http:// or https://';
      sets.push('`' + field + '` = ?');
      vals.push(v === '' ? null : v);
    }
    if (Object.keys(errors).length) return res.status(400).json({ message: 'Please check the highlighted fields', errors });
    if (!sets.length) return res.status(400).json({ message: 'Nothing to update' });
    vals.push(req.params.id);
    const [result] = await executeQuery('UPDATE Interns SET ' + sets.join(', ') + ' WHERE intern_id = ?', vals);
    if (!result.affectedRows) return res.status(404).json({ message: 'Intern not found' });
    res.json({ ok: true, message: 'Details saved' });
  } catch (err) {
    console.error('PUT intern details:', err);
    res.status(500).json({ message: 'Could not save details' });
  }
});

app.put("/api/interns/updateimage/:id", imageUpload.single("profileImage"), async (req, res) => {
  const internId = req.params.id;

  try {
    if (!req.file) {
      return res.status(400).json({ error: "Profile image is required" });
    }

    // Step 1: Fetch intern email
    const internData = await new Promise((resolve, reject) => {
      db.query(
        "SELECT email FROM Interns WHERE intern_id = ?",
        [internId],
        (err, rows) => {
          if (err) reject(err);
          else if (!rows || rows.length === 0) resolve(null);
          else resolve(rows[0]);
        }
      );
    });

    if (!internData) {
      return res.status(404).json({ error: "Intern not found" });
    }

    const internEmail = internData.email;
    console.log("📧 Intern Email:", internEmail);

    // Step 2: Upload new image to same Cloudinary path (auto-replace)
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: `Interns/${internId}`,
          public_id: 'profile_pic',
          resource_type: 'image',
          overwrite: true
        },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
    });

    const picUrl = result.secure_url;
    console.log('Cloudinary profile pic URL:', picUrl);

    const imageUrl = picUrl;
    console.log("✅ Profile image replaced:", imageUrl);

    // Step 3: Update only users.profile_image
    const updateResult = await new Promise((resolve, reject) => {
      db.query(
        "UPDATE users SET profile_image = ? WHERE email = ?",
        [imageUrl, internEmail],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ message: "User not found for this intern" });
    }

    res.status(200).json({
      message: "✅ Profile image updated successfully!",
      imageUrl,
    });
  } catch (error) {
    console.error("❌ Error updating profile image:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get('/api/insterdashboard-stats', async (req, res) => {
  try {
    const intern_id = req.query.intern_id;
    if (!intern_id) return res.status(400).json({ message: "intern_id is required" });

    const [[today]] = await executeQuery(
      'SELECT check_in, check_out, status, hours_worked FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
      [intern_id, getTodayIST()]);
    const [[allTime]] = await executeQuery(`SELECT ${ATT_COUNTS} FROM Attendance WHERE intern_id = ?`, [intern_id]);
    const [[month]] = await executeQuery(
      `SELECT ${ATT_COUNTS} FROM Attendance WHERE intern_id = ? AND attendance_date >= DATE_FORMAT(?, '%Y-%m-01')`,
      [intern_id, getTodayIST()]);
    const [[tasks]] = await executeQuery(
      "SELECT COUNT(*) AS total, COALESCE(SUM(status = 'Completed'), 0) AS done FROM Tasks WHERE intern_id = ?", [intern_id]);

    const all = internScores(allTime, tasks);
    const m = internScores(month, tasks);

    res.json({
      checkinout: today || {},
      attendance_summary: {
        total_present: all.attended,          // days attended (on time + late)
        total_on_time: all.present,
        total_late: all.late,
        total_absent: all.absent,
        total_leave: all.leave,
        attendance_percentage: all.attendance,
        punctuality_percentage: all.punctuality
      },
      performance_summary: {
        performance_score: m.performance,     // this month: attendance and tasks
        monthly_performance_score: m.attendance, // shown as "Attendance" on the dashboard
        monthly_attendance_percentage: m.attendance,
        monthly_punctuality_percentage: m.punctuality,
        monthly_present: m.attended,
        monthly_late: m.late,
        monthly_absent: m.absent,
        monthly_leave: m.leave,
        tasks_completed: m.doneTasks,
        tasks_total: m.totalTasks,
        task_completion_percentage: m.tasks
      }
    });
  } catch (err) {
    console.error('Dashboard stats failed:', err.code || err.message);
    res.status(500).json({ message: "DB error" });
  }
});

/* GET /api/intern/overview?intern_id=…  Everything the dashboard, attendance, leave and performance pages show as numbers.
   Nothing is made up: a number with no data behind it comes back as null and the page hides it. */
app.get('/api/intern/overview', async (req, res) => {
  try {
    const id = req.query.intern_id;
    if (!id) return res.status(400).json({ message: 'intern_id is required' });
    const today = getTodayIST();
    const monthStart = today.slice(0, 8) + '01';
    const prevStart = (() => { const d = new Date(monthStart + 'T00:00:00Z'); d.setUTCMonth(d.getUTCMonth() - 1); return d.toISOString().slice(0, 10); })();

    // Four weeks, Monday to Sunday, ending this week
    const thisMon = new Date(today + 'T00:00:00Z'); thisMon.setUTCDate(thisMon.getUTCDate() - ((thisMon.getUTCDay() + 6) % 7));
    const weeks = [3, 2, 1, 0].map(k => { const d = new Date(thisMon); d.setUTCDate(d.getUTCDate() - 7 * k); return d.toISOString().slice(0, 10); });

    const [[month]] = await executeQuery(`SELECT ${ATT_COUNTS} FROM Attendance WHERE intern_id = ? AND attendance_date >= ?`, [id, monthStart]);
    const [[prev]] = await executeQuery(`SELECT ${ATT_COUNTS}, COUNT(*) AS n FROM Attendance WHERE intern_id = ? AND attendance_date >= ? AND attendance_date < ?`, [id, prevStart, monthStart]);
    const [[all]] = await executeQuery(`SELECT ${ATT_COUNTS}, COALESCE(SUM(hours_worked), 0) AS hours FROM Attendance WHERE intern_id = ?`, [id]);
    const [[tk]] = await executeQuery("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'Completed'), 0) AS done FROM Tasks WHERE intern_id = ?", [id]);
    // A completed task is counted in the week it was last updated (when it was marked done)
    const [doneRows] = await executeQuery(
      "SELECT DATE_FORMAT(updated_at, '%Y-%m-%d') AS d FROM Tasks WHERE intern_id = ? AND status = 'Completed' AND updated_at >= ?", [id, weeks[0]]);
    const [[lv]] = await executeQuery(
      "SELECT COALESCE(SUM(number_of_working_days), 0) AS used FROM leave_requests WHERE intern_id = ? AND status = 'Approved' AND YEAR(from_date) = YEAR(?)", [id, today]);

    const m = internScores(month, tk), a = internScores(all, tk);
    const prevAttendance = Number(prev.n) ? internScores(prev, null).attendance : null;
    const weekly = weeks.map((w, k) => {
      const end = k < 3 ? weeks[k + 1] : '9999-12-31';
      const label = new Date(w + 'T00:00:00Z').toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'UTC' });
      return { week_start: w, label, done: doneRows.filter(r => r.d >= w && r.d < end).length };
    });
    const perYear = Number(process.env.ANNUAL_LEAVE_DAYS) || null;   // set by HR; null = no allowance configured

    res.json({
      month: { attendance: m.attendance, punctuality: m.punctuality, attended: m.attended, late: m.late, absent: m.absent, leave: m.leave,
               change_vs_last_month: prevAttendance === null ? null : m.attendance - prevAttendance },
      all_time: { attended: a.attended, late: a.late, punctuality: a.punctuality, hours: Math.round(Number(all.hours) * 10) / 10 },
      tasks: { total: a.totalTasks, done: a.doneTasks, completion: a.tasks },
      performance: m.performance,
      weekly,
      leave: { per_year: perYear, used_this_year: Number(lv.used), remaining: perYear === null ? null : Math.max(perYear - Number(lv.used), 0) }
    });
  } catch (err) {
    console.error('Intern overview failed:', err.code || err.message);
    res.status(500).json({ message: 'DB error' });
  }
});

/* ── Help & Support tickets ──
   Interns (and any signed-in user) raise tickets and chat with HR. HR and admins see every ticket and reply.
   A ticket is "Open" while waiting for HR, "Answered" once HR replies, "Closed" when resolved. */
const SUPPORT_CATEGORIES = ['Attendance', 'Leave', 'Reports', 'Tasks', 'Documents', 'Account', 'Technical', 'Other'];
const isStaff = (req) => HR_ROLES.includes(roleOf(req.user));
async function whoAmI(req) {
  const [[u]] = await executeQuery('SELECT id, full_name, email FROM users WHERE id = ?', [req.user.id]);
  return u || { id: req.user.id, full_name: 'User', email: '' };
}
async function ticketFor(req, id) {
  const [[t]] = await executeQuery('SELECT * FROM support_tickets WHERE id = ?', [id]);
  if (!t) return null;
  return (isStaff(req) || Number(t.user_id) === Number(req.user.id)) ? t : null;   // others' tickets look like "not found"
}

app.get('/api/support/tickets', async (req, res) => {
  try {
    const status = ['Open', 'Answered', 'Closed'].includes(req.query.status) ? req.query.status : null;
    const where = [], params = [];
    if (!isStaff(req)) { where.push('t.user_id = ?'); params.push(req.user.id); }
    if (status) { where.push('t.status = ?'); params.push(status); }
    const [rows] = await executeQuery(`
      SELECT t.id, t.subject, t.category, t.status, t.requester_name, t.requester_role, t.intern_id, t.unread_for_user,
             t.created_at, t.updated_at, UNIX_TIMESTAMP(t.created_at) AS created_ts, UNIX_TIMESTAMP(t.updated_at) AS updated_ts,
             (SELECT body FROM support_messages m WHERE m.ticket_id = t.id ORDER BY m.id DESC LIMIT 1) AS last_message
      FROM support_tickets t ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY FIELD(t.status, 'Open', 'Answered', 'Closed'), t.updated_at DESC
      LIMIT 100`, params);
    res.json({ staff: isStaff(req), tickets: rows });
  } catch (err) {
    console.error('List tickets failed:', err.code || err.message);
    res.status(500).json({ message: 'Could not load tickets' });
  }
});

app.post('/api/support/tickets', async (req, res) => {
  try {
    const category = SUPPORT_CATEGORIES.includes(req.body.category) ? req.body.category : 'Other';
    const subject = String(req.body.subject || '').trim().slice(0, 150);
    const message = String(req.body.message || '').trim().slice(0, 3000);
    if (subject.length < 3) return res.status(400).json({ message: 'Please add a short subject.' });
    if (message.length < 5) return res.status(400).json({ message: 'Please describe the problem.' });
    if (tooMany('ticket:' + req.user.id, 10, 60 * 60 * 1000)) return res.status(429).json({ message: 'Too many tickets in an hour. Please add to an existing one.' });

    const me = await whoAmI(req);
    const [r] = await executeQuery(
      'INSERT INTO support_tickets (user_id, requester_name, requester_role, intern_id, category, subject) VALUES (?, ?, ?, ?, ?, ?)',
      [me.id, me.full_name, roleOf(req.user), req.user.intern_id || null, category, subject]);
    await executeQuery('INSERT INTO support_messages (ticket_id, sender_user_id, from_staff, sender_name, body) VALUES (?, ?, 0, ?, ?)',
      [r.insertId, me.id, me.full_name, message]);

    notify('New support ticket', `${me.full_name}${req.user.intern_id ? ' (' + req.user.intern_id + ')' : ''}: ${subject}`, 'info', { role: 'hr' })
      .catch(() => {});
    sendEmail({
      to: DEFAULT_HR_EMAIL,
      subject: `Support ticket #${r.insertId}: ${subject.replace(/[\r\n]+/g, ' ')}`,
      html: `<p><strong>${esc(me.full_name)}</strong>${req.user.intern_id ? ' (' + esc(req.user.intern_id) + ')' : ''} raised a ticket.</p>
        <p><strong>Category:</strong> ${esc(category)}<br><strong>Subject:</strong> ${esc(subject)}</p>
        <p style="white-space:pre-wrap">${esc(message)}</p>
        <p>Reply from the HR portal (Help &amp; Support, bottom right).</p>`
    }).catch(() => {});
    res.json({ ok: true, id: r.insertId });
  } catch (err) {
    console.error('Create ticket failed:', err.code || err.message);
    res.status(500).json({ message: 'Could not create the ticket. Please try again.' });
  }
});

app.get('/api/support/tickets/:id/messages', async (req, res) => {
  try {
    const t = await ticketFor(req, req.params.id);
    if (!t) return res.status(404).json({ message: 'Ticket not found' });
    const [msgs] = await executeQuery(
      'SELECT id, from_staff, sender_name, body, created_at, UNIX_TIMESTAMP(created_at) AS created_ts, (sender_user_id = ?) AS mine FROM support_messages WHERE ticket_id = ? ORDER BY id',
      [req.user.id, t.id]);
    if (!isStaff(req) && t.unread_for_user) await executeQuery('UPDATE support_tickets SET unread_for_user = 0 WHERE id = ?', [t.id]);
    const [[ts]] = await executeQuery('SELECT UNIX_TIMESTAMP(created_at) AS c FROM support_tickets WHERE id = ?', [t.id]);
    res.json({ ticket: { id: t.id, subject: t.subject, category: t.category, status: t.status, requester_name: t.requester_name,
      intern_id: t.intern_id, created_at: t.created_at, created_ts: ts && ts.c }, staff: isStaff(req), messages: msgs });
  } catch (err) {
    console.error('Load ticket failed:', err.code || err.message);
    res.status(500).json({ message: 'Could not load the conversation' });
  }
});

app.post('/api/support/tickets/:id/messages', async (req, res) => {
  try {
    const t = await ticketFor(req, req.params.id);
    if (!t) return res.status(404).json({ message: 'Ticket not found' });
    const body = String(req.body.message || '').trim().slice(0, 3000);
    if (!body) return res.status(400).json({ message: 'Type a message first.' });
    if (tooMany('ticketmsg:' + req.user.id, 60, 60 * 60 * 1000)) return res.status(429).json({ message: 'Too many messages. Please wait a little.' });
    const staff = isStaff(req) && Number(t.user_id) !== Number(req.user.id);
    const me = await whoAmI(req);
    await executeQuery('INSERT INTO support_messages (ticket_id, sender_user_id, from_staff, sender_name, body) VALUES (?, ?, ?, ?, ?)',
      [t.id, me.id, staff ? 1 : 0, me.full_name, body]);
    // HR replied: "Answered" and unread for the person who asked. They replied: back to "Open" for HR.
    await executeQuery('UPDATE support_tickets SET status = ?, unread_for_user = ? WHERE id = ?', [staff ? 'Answered' : 'Open', staff ? 1 : 0, t.id]);
    if (staff) notify('HR replied to your ticket', `"${t.subject}": ${body.slice(0, 140)}`, 'info', { userId: t.user_id, role: 'intern' }).catch(() => {});
    else notify('New reply on a ticket', `${me.full_name}: "${t.subject}"`, 'info', { role: 'hr' }).catch(() => {});
    res.json({ ok: true });
  } catch (err) {
    console.error('Reply failed:', err.code || err.message);
    res.status(500).json({ message: 'Could not send. Please try again.' });
  }
});

// Close or reopen. The person who asked can close their own ticket; HR can do both.
app.put('/api/support/tickets/:id/status', async (req, res) => {
  try {
    const t = await ticketFor(req, req.params.id);
    if (!t) return res.status(404).json({ message: 'Ticket not found' });
    const status = req.body.status === 'Closed' ? 'Closed' : req.body.status === 'Open' ? 'Open' : null;
    if (!status) return res.status(400).json({ message: 'Invalid status' });
    await executeQuery('UPDATE support_tickets SET status = ?, unread_for_user = 0 WHERE id = ?', [status, t.id]);
    if (isStaff(req) && Number(t.user_id) !== Number(req.user.id) && status === 'Closed') {
      notify('Ticket resolved', `HR marked "${t.subject}" as resolved.`, 'success', { userId: t.user_id, role: 'intern' }).catch(() => {});
    }
    res.json({ ok: true, status });
  } catch (err) {
    console.error('Ticket status failed:', err.code || err.message);
    res.status(500).json({ message: 'Could not update the ticket' });
  }
});

// Get weekly attendance (hours worked per day)
app.get('/api/attendance/weekly', async (req, res) => {
  try {
    const intern_id = req.query.intern_id;
    if (!intern_id) return res.status(400).json({ message: "intern_id required" });

    const results = await new Promise((resolve, reject) => {
      db.query(
        `SELECT attendance_date, check_in, check_out
                 FROM Attendance
                 WHERE intern_id = ? 
                   AND attendance_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                 ORDER BY attendance_date ASC`,
        [intern_id],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    // Build a map of date -> hours worked
    const attendanceMap = {};
    results.forEach(row => {
      let hours = 0;
      if (row.check_in && row.check_out) {
        const [inH, inM, inS] = row.check_in.split(':').map(Number);
        const [outH, outM, outS] = row.check_out.split(':').map(Number);
        hours = (outH * 3600 + outM * 60 + outS - (inH * 3600 + inM * 60 + inS)) / 3600;
      }
      attendanceMap[new Date(row.attendance_date).toDateString()] = parseFloat(hours.toFixed(2));
    });

    // Ensure exactly 7 days in output
    const labels = [];
    const data = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dayKey = d.toDateString();
      labels.push(d.toLocaleDateString('en-US', { weekday: 'short' }));
      data.push(attendanceMap[dayKey] || 0);
    }

    res.json({ labels, data });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "DB error"});
  }
});



// Get monthly attendance percentage (Present/Absent/Leave)
app.get('/api/attendance/monthly', async (req, res) => {
  try {
    const intern_id = req.query.intern_id;
    if (!intern_id) return res.status(400).json({ message: "intern_id required" });
    const [[month]] = await executeQuery(
      `SELECT ${ATT_COUNTS} FROM Attendance WHERE intern_id = ? AND attendance_date >= DATE_FORMAT(?, '%Y-%m-01')`,
      [intern_id, getTodayIST()]);
    const m = internScores(month, null);
    res.json({
      present: m.attended,      // attended (on time + late)
      on_time: m.present,
      late: m.late,
      absent: m.absent,
      leave: m.leave,
      monthly_percentage: m.attendance,
      punctuality_percentage: m.punctuality
    });
  } catch (err) {
    console.error('Monthly attendance failed:', err.code || err.message);
    res.status(500).json({ message: "DB error" });
  }
});


// Helper to get IST date string (YYYY-MM-DD)
function getTodayIST() {
  const now = new Date();
  const offset = 5.5 * 60; // 5 hours 30 minutes in minutes
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  const ist = new Date(utc + offset * 60000);
  return ist.toISOString().slice(0, 10);
}

app.post('/api/checkout', (req, res) => {
  const { intern_id } = req.body;
  const attendance_date = getTodayIST();
  // Always the server's clock in India time (it was UTC before, and interns could send any time)
  const checkOutTime = nowTimeIST();

  if (!intern_id) {
    return res.status(400).json({ message: 'intern_id is required' });
  }

  // Check if already checked out
  db.query(
    'SELECT check_out FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
    [intern_id, attendance_date],
    (err, results) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ message: 'DB error'});
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'No attendance record found for today' });
      }

      const record = results[0];
      if (record.check_out) {
        return res.status(400).json({ message: 'Already checked out', check_out: record.check_out });
      }

      // Proceed with checkout update
      db.query(
        `UPDATE Attendance SET check_out = ?,
           hours_worked = IF(check_in IS NULL, 0, GREATEST(0, ROUND(TIME_TO_SEC(TIMEDIFF(?, check_in)) / 3600, 2)))
         WHERE intern_id = ? AND attendance_date = ?`,
        [checkOutTime, checkOutTime, intern_id, attendance_date],
        (err, result) => {
          if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'DB error'});
          }
          //2change
          // Emit real-time checkout update
          io.to('hr-dashboard').emit('attendance-update', {
            intern_id: intern_id,
            action: 'checkout',
            time: checkOutTime,
            date: attendance_date
          });

          io.to(`intern-${intern_id}`).emit('personal-attendance', {
            action: 'checkout',
            time: checkOutTime,
            date: attendance_date
          });

          res.json({ message: 'Checked out successfully', check_out: checkOutTime });
        }
      );
    }
  );
});

app.get('/api/attendance-status/:intern_id', (req, res) => {
  const intern_id = req.params.intern_id;
  const attendance_date = getTodayIST();

  db.query(
    'SELECT check_out FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
    [intern_id, attendance_date],
    (err, results) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ message: 'DB error'});
      }
      if (results.length === 0) {
        return res.status(404).json({ message: 'No attendance record found for today' });
      }
      res.json(results[0]);
    }
  );
});


// GET all tasks
app.get("/api/tasks/all", async (req, res) => {
  try {
    // Query tasks from DB
    const results = await new Promise((resolve, reject) => {
      db.query(
        `SELECT 
                    task_id AS serialNo,
                    task_title AS task,
                    task_description AS description,
                    priority,
                    progress,
                    collaborators AS collaboration,
                    DATE_FORMAT(due_date, '%Y-%m-%d') AS assignedDueDate,
                    status
                 FROM Tasks
                 WHERE intern_id = ?
                 ORDER BY task_id ASC`,
        [req.query.intern_id],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    // Ensure array
    if (!Array.isArray(results)) {
      return res.json([]);
    }

    // Format results to match frontend expectations
    const tasks = results.map((row, index) => ({
      serialNo: row.serialNo || index + 1,
      task: row.task || "",
      description: row.description || "",
      priority: row.priority || "Medium",
      progress: row.progress ?? 0, // default 0%
      collaboration: row.collaboration || "None",
      assignedDueDate: row.assignedDueDate || "", // already formatted by MySQL
      status: taskStatusForPage(row.status)
    }));

    console.log(tasks);
    res.json(tasks);

  } catch (err) {
    console.error("Error fetching tasks:", err);
    res.status(500).json({ message: "DB error"});
  }
});

//get tasks
app.get('/api/gettasks/:intern_id', (req, res) => {
  const intern_id = req.params.intern_id;
  console.log(intern_id)
  const query = `
        SELECT task_id, task_title, due_date, status, priority
        FROM Tasks
        WHERE intern_id = ?
        ORDER BY assigned_date DESC
    `;

  db.query(query, [intern_id], (err, result) => {
    if (err) {
      console.error("DB Fetch Error:", err);
      return res.status(500).json({ message: "Database error"});
    }
    console.log(result)
    // Transform to frontend format
    const tasks = result.map(task => ({
      id: task.task_id,
      title: task.task_title,
      dueDate: task.due_date,
      due_date: task.due_date,          // the dashboard reads due_date
      status: taskStatusForPage(task.status),
      priority: task.priority
    }));

    return res.json({ tasks });
  });
});

app.post('/api/addtask', (req, res) => {
  const { intern_id, task_title, task_description, priority, status, assigned_date, due_date } = req.body;

  // Ensure dates are properly formatted for MySQL
  const assignedDate = new Date(assigned_date).toISOString().split("T")[0];
  const dueDate = new Date(due_date).toISOString().split("T")[0];

  const query = `
        INSERT INTO Tasks (intern_id, task_title, task_description, priority, status, assigned_date, due_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

  const dbStatus = TASK_STATUS_DB[taskStatusForPage(status)] || 'Pending';
  db.query(query, [intern_id, String(task_title || '').slice(0, 150), task_description, priority, dbStatus, assignedDate, dueDate], (err, result) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    // A task added by HR for an intern: tell the intern
    if (HR_ROLES.includes(roleOf(req.user)) && intern_id) {
      notifyIntern(intern_id, 'New task assigned', `${String(task_title || 'A new task').slice(0, 150)}, due ${dueDate}.`, 'info');
    }
    return res.json({ message: "Task added successfully", id: result.insertId });
  });
});

//cahnge task status
// Change task status
app.put('/api/changetask/:taskId', (req, res) => {
  const taskId = req.params.taskId;
  const { status } = req.body;

  // Validate status ('in-progress' used to fail: the database calls it 'In Progress')
  const dbStatus = TASK_STATUS_DB[taskStatusForPage(status)];
  if (!dbStatus) {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  const query = `
        UPDATE Tasks
        SET status = ?, progress = CASE WHEN ? = 'Completed' THEN 100 ELSE progress END
        WHERE task_id = ?
    `;

  db.query(query, [dbStatus, dbStatus, taskId], (err, result) => {
    if (err) {
      console.error("DB Update Error:", err);
      return res.status(500).json({ message: 'Database error'});
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }

    return res.json({ message: 'Task status updated successfully' });
  });
}); // <--- Added missing closing bracket

// Fetch weekly reports for reports.html dashboard OR individual intern reports
app.get('/api/reports', async (req, res) => {
  try {
    const { intern_id, status, project } = req.query;

    // If intern_id is provided, return reports for specific intern (Intern Dashboard view)
    if (intern_id) {
      let sql = `
        SELECT id, report_title, report_type, report_description, file_path, status, submitted_at, due_date 
        FROM Reports 
        WHERE intern_id = ?
      `;
      const params = [intern_id];

      if (status) {
        sql += ` AND status = ?`;
        params.push(status);
      }

      if (project) {
        sql += ` AND report_description LIKE ?`;
        params.push(`%${project}%`);
      }

      sql += ' ORDER BY submitted_at DESC';

      db.query(sql, params, (err, rows) => {
        if (err) {
          console.error('Error fetching intern reports:', err);
          return res.status(500).json({ error: 'Failed to fetch reports' });
        }
        const reports = rows.map(r => ({
          id: r.id,
          title: r.report_title || 'Untitled Report',
          report_title: r.report_title,
          report_type: r.report_type || 'wednesday',
          description: r.report_description || '',
          report_description: r.report_description,
          file: r.file_path || '',
          file_path: r.file_path,
          status: r.status || 'Pending',
          submittedAt: r.submitted_at ? new Date(r.submitted_at).toISOString().slice(0, 10) : null,
          dueDate: r.due_date ? new Date(r.due_date).toISOString().slice(0, 10) : null,
          created_at: r.submitted_at
        }));
        res.json(reports);
      });
      return;
    }

    // ================= DATE HELPERS =================
    const formatDate = (date) => date.toLocaleDateString('en-CA');

    // Get week filter from query parameter
    const weekFilter = req.query.week || 'current';

    const today = new Date();
    let currentWeekStart = new Date(today);

    // Calculate week start based on filter
    if (weekFilter === 'prev1') {
      currentWeekStart.setDate(today.getDate() - 7);
    } else if (weekFilter === 'prev2') {
      currentWeekStart.setDate(today.getDate() - 14);
    }
    // For 'current' or any other value, use current week

    const dayOfWeek = currentWeekStart.getDay();
    const diff = currentWeekStart.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
    currentWeekStart.setDate(diff);

    const weekStartDate = formatDate(currentWeekStart);

    // ================= QUERY =================
    const sql = `
      SELECT 
        i.intern_id,
        i.name,
        i.department,

        -- Check actual Reports table for Wednesday submissions this week
        CASE 
          WHEN EXISTS (
            SELECT 1 FROM Reports r 
            WHERE r.intern_id = i.intern_id 
            AND DATE(r.submitted_at) >= ?
            AND (r.report_type = 'wednesday' OR DAYOFWEEK(r.submitted_at) IN (3, 4, 5))
          ) THEN 'Submitted'
          ELSE 'Missing'
        END AS wed,

        -- Check actual Reports table for Saturday submissions this week  
        CASE 
          WHEN EXISTS (
            SELECT 1 FROM Reports r 
            WHERE r.intern_id = i.intern_id 
            AND DATE(r.submitted_at) >= ?
            AND (r.report_type = 'saturday' OR DAYOFWEEK(r.submitted_at) IN (1, 2, 6, 7))
          ) THEN 'Submitted'
          ELSE 'Missing'
        END AS sat,

        -- Get latest submission date from Reports table
        (SELECT MAX(DATE(submitted_at)) 
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
        ) AS lastSub,

        -- Get file paths and IDs for the most recent reports
        (SELECT r.file_path 
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND (r.report_type = 'wednesday' OR DAYOFWEEK(r.submitted_at) IN (3, 4, 5))
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS wednesday_file_path,

        (SELECT r.id
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND (r.report_type = 'wednesday' OR DAYOFWEEK(r.submitted_at) IN (3, 4, 5))
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS wednesday_report_id,

        (SELECT r.file_path 
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND (r.report_type = 'saturday' OR DAYOFWEEK(r.submitted_at) IN (1, 2, 6, 7))
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS saturday_file_path,

        (SELECT r.id
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND (r.report_type = 'saturday' OR DAYOFWEEK(r.submitted_at) IN (1, 2, 6, 7))
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS saturday_report_id,

        -- Total reports THIS WEEK ONLY
        (SELECT COUNT(*) 
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
        ) AS total_reports

      FROM Interns i
      WHERE i.status = 'Active'
      ORDER BY i.name
    `;

    db.query(
      sql,
      [weekStartDate, weekStartDate, weekStartDate, weekStartDate, weekStartDate, weekStartDate, weekStartDate, weekStartDate, weekStartDate],
      (err, rows) => {
        if (err) {
          console.error('Error fetching reports:', err);
          return res.status(500).json({ error: 'Failed to fetch reports' });
        }

        const reports = rows.map(row => ({
          name: row.name,
          dept: row.department,
          wed: row.wed,
          sat: row.sat,
          lastSub: row.lastSub || '—',
          total_reports: row.total_reports,
          wednesday_file_path: row.wednesday_file_path,
          saturday_file_path: row.saturday_file_path,
          wednesday_report_id: row.wednesday_report_id,
          saturday_report_id: row.saturday_report_id
        }));

        res.json(reports);
      }
    );

  } catch (error) {
    console.error('Error in reports endpoint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/reports/upload
// Upload a new report file
app.post('/api/reports/upload', async (req, res) => {
  try {
    const {
      intern_id,
      report_title,
      report_description,
      report_type,
      due_date,
      file_path
    } = req.body;

    console.log(req.body);

    // ================= VALIDATION =================
    if (!intern_id) return res.status(400).json({ error: 'intern_id is required' });
    if (!report_title) return res.status(400).json({ error: 'report_title is required' });
    if (!file_path) return res.status(400).json({ error: 'file_path is required' });

    // ================= DATE HELPERS =================
    const formatDate = (date) => {
      return date.toLocaleDateString('en-CA'); // YYYY-MM-DD (LOCAL TIME)
    };

    const submissionDate = new Date();
    const dayOfWeek = submissionDate.getDay(); // 0=Sun, 3=Wed, 6=Sat

    // Auto-determine report_type if not passed
    let finalReportType = report_type;
    if (finalReportType !== 'wednesday' && finalReportType !== 'saturday') {
      finalReportType = (dayOfWeek === 3 || dayOfWeek === 4) ? 'wednesday' : 'saturday';
    }

    // ================= INSERT REPORT =================
    const insertSql = `
      INSERT INTO Reports 
      (intern_id, report_title, report_type, report_description, file_path, status, due_date, submitted_at)
      VALUES (?, ?, ?, ?, ?, 'Pending', ?, NOW())
    `;

    const insertResult = await executeQuery(insertSql, [
      intern_id,
      report_title,
      finalReportType,
      report_description || null,
      file_path,
      due_date || null
    ]);

    const reportId = insertResult.insertId;

    // ================= WEEK START (MONDAY) =================
    const weekStart = new Date(submissionDate);
    const day = submissionDate.getDay();
    const diff = weekStart.getDate() - day + (day === 0 ? -6 : 1);
    weekStart.setDate(diff);

    const weekStartDate = formatDate(weekStart);
    const formattedSubmissionDate = formatDate(submissionDate);

    // ================= STATUS FIELD =================
    const isWednesday = finalReportType === 'wednesday';

    const statusField = isWednesday ? 'wednesday_status' : 'saturday_status';
    const reportIdField = isWednesday ? 'wednesday_report_id' : 'saturday_report_id';

    // ================= UPSERT WEEKLY REPORT =================
    const weeklySql = `
      INSERT INTO weekly_reports 
      (intern_id, week_start_date, ${statusField}, ${reportIdField}, last_submission_date)
      VALUES (?, ?, 'Submitted', ?, ?)
      ON DUPLICATE KEY UPDATE 
        ${statusField} = 'Submitted',
        ${reportIdField} = VALUES(${reportIdField}),
        last_submission_date = VALUES(last_submission_date)
    `;

    await executeQuery(weeklySql, [
      intern_id,
      weekStartDate,
      reportId,
      formattedSubmissionDate
    ]);

    // ================= RESPONSE =================
    res.json({
      message: 'Report uploaded successfully',
      report_id: reportId,
      report_type: finalReportType,
      fileUrl: file_path,
      submitted_on: formattedSubmissionDate,
      week_start: weekStartDate
    });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to upload report' });
  }
});

// GET /api/reports/download/:id
// Download a report file by report ID
// Files are stored as web links (Cloudinary, Drive). Only redirect to http(s) links; never read the server's disk.
app.get('/api/reports/download/:id', (req, res) => {
  db.query('SELECT file_path FROM Reports WHERE id = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch report' });
    if (rows.length === 0) return res.status(404).json({ error: 'Report not found' });
    const link = String(rows[0].file_path || '');
    if (!/^https?:\/\//i.test(link)) return res.status(404).json({ error: 'File not found' });
    res.redirect(link);
  });
});

// PUT /api/reports/:id/status
// Update report status (e.g., Reviewed, Rejected)
app.put('/api/reports/:id/status', async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;
    if (!['Pending', 'Reviewed', 'Rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const sql = `UPDATE Reports SET status = ?, reviewed_at = NOW() WHERE id = ?`;
    const [result] = await executeQuery(sql, [status, id]);

    if (result.affectedRows === 0) return res.status(404).json({ error: 'Report not found' });

    const [[rep]] = await executeQuery('SELECT intern_id, report_title FROM Reports WHERE id = ?', [id]);
    if (rep && status !== 'Pending') notifyIntern(rep.intern_id,
      status === 'Reviewed' ? 'Report reviewed' : 'Report needs changes',
      `"${rep.report_title || 'Your report'}" was ${status === 'Reviewed' ? 'reviewed by HR' : 'sent back for changes'}.`, status === 'Reviewed' ? 'success' : 'warning');

    res.json({ message: 'Status updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Update the dashboard stats endpoint
app.get('/api/dashboard-stats', async (req, res) => {
  try {
    const todayIST = getTodayIST();
    const query = `
            SELECT 
                COUNT(*) as total_appointments,
                SUM(CASE WHEN DATE(appointment_date) = ? AND status = 'confirmed' THEN 1 ELSE 0 END) as appointments_today,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_confirmations,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_appointments
            FROM appointments
        `;
    const [results] = await executeQuery(query, [todayIST]);
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/submitreport', async (req, res) => {
  try {
    const { intern_id, report_title, report_description, report_type, file_path } = req.body;

    if (!intern_id || !report_title || !file_path) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const dayOfWeek = new Date().getDay();
    let finalReportType = report_type;
    if (finalReportType !== 'wednesday' && finalReportType !== 'saturday') {
      finalReportType = (dayOfWeek === 3 || dayOfWeek === 4) ? 'wednesday' : 'saturday';
    }

    const query = `
      INSERT INTO Reports (intern_id, report_title, report_type, report_description, file_path)
      VALUES (?, ?, ?, ?, ?)
    `;

    const [result] = await executeQuery(query, [intern_id, report_title, finalReportType, report_description || null, file_path]);
    res.json({ message: 'Report submitted successfully', reportId: result.insertId, report_type: finalReportType });
  } catch (err) {
    console.error("DB Insert Error:", err);
    res.status(500).json({ message: 'Database error'});
  }
});


// Add this helper function at the top of the file
function convertTo24Hour(timeStr) {
  if (!timeStr || typeof timeStr !== 'string') {
    // Return as-is or handle error
    return timeStr;
  }

  try {
    // If already in 24-hour format, return as is
    if (timeStr.match(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/)) {
      return timeStr + ':00';
    }

    // Convert 12-hour format to 24-hour
    const [time, meridiem] = timeStr.split(' ');
    const [hours, minutes] = time.split(':');
    let hour = parseInt(hours);

    if (meridiem.toLowerCase() === 'pm' && hour !== 12) {
      hour += 12;
    } else if (meridiem.toLowerCase() === 'am' && hour === 12) {
      hour = 0;
    }

    return `${hour.toString().padStart(2, '0')}:${minutes}:00`;
  } catch (error) {
    console.error('Time conversion error:', error);
    return null;
  }
}

// Modify the appointment POST endpoint
app.post('/api/appointments', (req, res) => {
  const time24 = convertTo24Hour(req.body.appointment_time);
  if (!time24) {
    res.status(400).json({
      error: 'Invalid time format',
      details: 'Time should be in format HH:MM AM/PM or HH:MM'
    });
    return;
  }

  // Get session info based on type
  const sessionInfo = SESSION_TYPES[req.body.session_type] || {
    duration: 50,
    price: 1500
  };

  const query = `
        INSERT INTO appointments 
        SET 
            patient_name = ?,
            email = ?,
            phone = ?,
            addhar = ?,
            age = ?,
            parenttype = ?,
            parentName = ?,
            guardianPhone = ?,
            address = ?,
            pincode = ?,
            state = ?,
            concerns = ?,
            appointment_date = CONVERT_TZ(?, '+00:00', '+05:30'),
            appointment_time = ?,
            session_type = ?,
            session_price = ?,
            session_duration = ?,
            status = ?,
            created_at = CONVERT_TZ(NOW(), '+00:00', '+05:30')
    `;

  const values = [
    req.body.patient_name,
    req.body.email,
    req.body.phone,
    req.body.addhar,
    req.body.age,
    req.body.parenttype,
    req.body.parentName,
    req.body.guardianPhone,
    req.body.address,
    req.body.pincode,
    req.body.state,
    req.body.concerns,
    req.body.appointment_date,
    time24,
    req.body.session_type,
    sessionInfo.price,
    sessionInfo.duration,
    req.body.status || 'pending'
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).json({
        error: 'Could not save appointment'});
      return;
    }

    res.status(201).json({
      message: 'Appointment created successfully',
      id: result.insertId,
      appointment_date: req.body.appointment_date,
      appointment_time: time24
    });
  });
});

// Helper to format date in IST (Indian Standard Time)
function formatDateIST(dateInput) {
  // Accepts either Date object or string in YYYY-MM-DD
  let d;
  if (dateInput instanceof Date) {
    d = dateInput;
  } else {
    // Parse as local date (not UTC)
    // This ensures no timezone shift
    const [year, month, day] = dateInput.split('-');
    d = new Date(Number(year), Number(month) - 1, Number(day));
  }
  // Convert to IST
  const utc = d.getTime() + (d.getTimezoneOffset() * 60000);
  const istOffset = 5.5 * 60 * 60000;
  const istDate = new Date(utc + istOffset);
  // Format as YYYY-MM-DD
  return istDate.getFullYear() + '-' +
    String(istDate.getMonth() + 1).padStart(2, '0') + '-' +
    String(istDate.getDate()).padStart(2, '0');
}

// Add this helper function at the top
function getCurrentISTDate() {
  const now = new Date();
  const istOffset = 5.5 * 60 * 60000; // IST offset in milliseconds
  const istDate = new Date(now.getTime() + istOffset);
  return istDate.toISOString().split('T')[0];
}


//api to get the id and role
app.get("/api/profile", authenticateToken, async (req, res) => {
  console.log('🔍 Profile endpoint called!');
  console.log('🔍 User from token:', req.user);
  console.log('🔍 User ID:', req.user?.id);
  console.log('🔍 User role:', req.user?.role);

  try {
    // Query by user ID from the token
    if (!req.user?.id) {
      console.log('🔍 No user ID found in token');
      return res.status(400).json({ message: "Invalid token: missing user ID" });
    }

    const query = `
      SELECT u.id, u.role, u.full_name as name, u.email, u.profile_image, i.department, i.status 
      FROM users u
      LEFT JOIN Interns i ON u.email = i.email
      WHERE u.id = ?
    `;

    console.log('🔍 Querying by user ID:', req.user.id);
    const [results] = await executeQuery(query, [req.user.id]);

    console.log('🔍 Query results:', results);

    if (results.length === 0) {
      console.log('🔍 No user found');
      return res.status(404).json({ message: "User not found" });
    }

    const user = results[0];

    // Add intern_id if we can find it from Interns table
    if (user.email) {
      const internQuery = `SELECT intern_id FROM Interns WHERE email = ?`;
      const [internResults] = await executeQuery(internQuery, [user.email]);
      if (internResults.length > 0) {
        user.intern_id = internResults[0].intern_id;
      }
    }

    console.log('🔍 Returning user data:', user);
    res.json(user);
  } catch (error) {
    console.error('❌ Error in profile endpoint:', error);
    res.status(500).json({ message: "Server error" });
  }
});

//api to get the id and role
app.get("/api/getalldoc", (req, res) => {
  db.query("SELECT id,full_name FROM doctor_details", [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    if (results.length === 0) return res.status(404).json({ message: "User not found" });

    res.json(results[0]);
  });
});

//api to get the particular doctor details
app.get("/api/getdoc/:id", (req, res) => {
  db.query("SELECT id,full_name FROM doctor_details where id=?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    if (results.length === 0) return res.status(404).json({ message: "User not found" });

    res.json(results[0]);
  });
});

//api to get the dashboard_ui
app.get("/api/dashboard_ui/:id", (req, res) => {
  db.query("SELECT * FROM doctor_ui where doctor_id=?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    if (results.length === 0) return res.status(404).json({ message: "User not found" });

    res.json(results[0]);
  });
});

//api to update the dashboard_ui
app.put("/api/dashboard_ui/:id", (req, res) => {
  const doctorId = req.params.id;
  const NUMERIC = ['patients_count', 'appointments_today', 'pending_confirmations', 'reports_to_finalize', 'prescriptions', 'follow_ups_needed', 'unread_messages'];
  const fields = {};
  for (const k of NUMERIC) if (k in req.body && Number.isInteger(Number(req.body[k]))) fields[k] = Number(req.body[k]);
  if (typeof req.body.mood_trend === 'string') fields.mood_trend = req.body.mood_trend.slice(0, 20);
  if (Object.keys(fields).length === 0) {
    return res.status(400).json({ message: "No fields provided to update" });
  }

  db.query("UPDATE doctor_ui SET ? WHERE doctor_id = ?", [fields, doctorId], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error"});

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Doctor not found" });
    }

    res.json({ message: "Update successful" });
  });
});

//attendence

// Helper: format 24h time to 12h AM/PM format
function formatTimeTo12Hour(timeStr) {
  if (!timeStr) return '--:--';
  const [hourStr, minute] = timeStr.split(':');
  let hour = parseInt(hourStr, 10);
  const ampm = hour >= 12 ? 'PM' : 'AM';
  hour = hour % 12 || 12;
  return `${hour}:${minute} ${ampm}`;
}

// API: Get attendance data for an intern for a given year and month
app.get('/api/attendance', async (req, res) => {
  try {
    const { intern_id, year, month } = req.query;
    if (!intern_id || !year || !month) {
      return res.status(400).json({ error: 'intern_id, year and month query params are required' });
    }
    console.log(month)
    console.log(year)
    const startDate = `${year}-${month.padStart(2, '0')}-01`;
    const daysInMonth = new Date(year, parseInt(month, 10), 0).getDate();
    const endDate = `${year}-${month.padStart(2, '0')}-${String(daysInMonth).padStart(2, '0')}`;

    // Proper promise wrapper
    const rows = await new Promise((resolve, reject) => {
      db.query(
        `SELECT attendance_date, status, check_in, check_out
           FROM Attendance
           WHERE intern_id = ? AND attendance_date BETWEEN ? AND ?`,
        [intern_id, startDate, endDate],
        (err, results) => {
          if (err) reject(err);
          else resolve(results);
        }
      );
    });

    const attendanceByDay = {};
    rows.forEach(row => {
      const day = new Date(row.attendance_date).getDate();
      attendanceByDay[day] = {
        status: row.status,
        checkIn: formatTimeTo12Hour(row.check_in),
        checkOut: formatTimeTo12Hour(row.check_out),
      };
    });

    res.json({ attendanceByDay, year: parseInt(year, 10), month: parseInt(month, 10) });
  } catch (error) {
    console.error('Error fetching attendance:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});


// API: Check-in or Check-out for today for an intern
app.post('/api/attendance/checkinout', async (req, res) => {
  try {
    const { intern_id } = req.body;
    if (!intern_id) {
      return res.status(400).json({ error: 'intern_id is required' });
    }

    const now = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000;
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
    const istNow = new Date(utc + istOffset);

    const todayStr = istNow.toISOString().slice(0, 10);
    const nowTime = istNow.toTimeString().slice(0, 8);

    // Check if attendance record exists for today
    const [rows] = await executeQuery(
      'SELECT * FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
      [intern_id, todayStr]
    );

    if (!rows || rows.length === 0) {
      // First check-in: fetch intern details for email notifications
      const [internRows] = await executeQuery(
        'SELECT intern_id, name, email FROM Interns WHERE intern_id = ?',
        [intern_id]
      );
      const intern = (internRows && internRows[0]) ? internRows[0] : null;
      const internName = intern ? intern.name : '';
      const internEmail = intern ? intern.email : '';

      const checkInResult = await processInternCheckIn({
        internId: intern_id,
        internName,
        internEmail,
        date: todayStr,
        time: nowTime
      });

      return res.json({ action: 'checkin', checkIn: nowTime, checkOut: null, status: checkInResult.status });
    } else {
      const attendance = rows[0];

      if (!attendance.check_out) {
        // Check-out: update record with check_out = now
        await executeQuery(
          `UPDATE Attendance SET check_out = ?,
             hours_worked = IF(check_in IS NULL, 0, GREATEST(0, ROUND(TIME_TO_SEC(TIMEDIFF(?, check_in)) / 3600, 2)))
           WHERE id = ?`,
          [nowTime, nowTime, attendance.id]
        );
        return res.json({ action: 'checkout', checkIn: attendance.check_in, checkOut: nowTime });
      } else {
        // Already checked out today
        return res.status(400).json({ error: 'Already checked out for today' });
      }
    }
  } catch (error) {
    console.error('Error in check-in/out:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});

app.get('/api/attendance/insights', async (req, res) => {
  try {
    // Get current month and year
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth() + 1; // 1-based month

    const startDate = `${year}-${String(month).padStart(2, '0')}-01`;
    const daysInMonth = new Date(year, month, 0).getDate();
    const endDate = `${year}-${String(month).padStart(2, '0')}-${String(daysInMonth).padStart(2, '0')}`;

    // Query with manual Promise wrapper
    const results = await new Promise((resolve, reject) => {
      db.query(
        `SELECT i.name as intern_name, i.intern_id, 
              ROUND(SUM(a.status = 'Present') / ? * 100, 2) as attendance_percentage
           FROM Interns i
           LEFT JOIN Attendance a 
             ON i.intern_id = a.intern_id 
             AND a.attendance_date BETWEEN ? AND ?
           GROUP BY i.intern_id
           ORDER BY attendance_percentage DESC`,
        [daysInMonth, startDate, endDate],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (results.length === 0) {
      return res.json({ highest: null, lowest: null });
    }

    const highest = results[0];
    const lowest = results[results.length - 1];

    res.json({
      highest: { name: highest.intern_name, percentage: highest.attendance_percentage },
      lowest: { name: lowest.intern_name, percentage: lowest.attendance_percentage },
    });
  } catch (error) {
    console.error('Error fetching attendance insights:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});


function calculatePerformanceScore(completed, total) {
  if (total === 0) return 0;
  return Math.round((completed / total) * 100);
}

// API to get intern performance data
app.get('/api/intern/performance', async (req, res) => {
  try {
    const internId = req.query.intern_id;
    if (!internId) return res.status(400).json({ error: 'intern_id is required' });

    // 1. Tasks stats
    const taskStats = await new Promise((resolve, reject) => {
      db.query(
        `SELECT 
              COUNT(*) AS total_tasks,
              SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks,
              AVG(TIMESTAMPDIFF(MINUTE, assigned_date, due_date)) AS avg_completion_minutes
           FROM Tasks
           WHERE intern_id = ?`,
        [internId],
        (err, results) => (err ? reject(err) : resolve(results))
      );
    });

    const totalTasks = taskStats[0]?.total_tasks || 0;
    const completedTasks = taskStats[0]?.completed_tasks || 0;
    const avgCompletionMinutes = taskStats[0]?.avg_completion_minutes || 0;
    const avgCompletionTime = (avgCompletionMinutes / 60).toFixed(1); // in hours

    // Performance score
    const score = calculatePerformanceScore(completedTasks, totalTasks);

    // 2. Chart data: weekly completed tasks for last 4 weeks
    const chartRows = await new Promise((resolve, reject) => {
      db.query(
        `SELECT WEEK(assigned_date) AS week_number, 
                  SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks
           FROM Tasks
           WHERE intern_id = ? AND assigned_date >= DATE_SUB(CURDATE(), INTERVAL 4 WEEK)
           GROUP BY week_number
           ORDER BY week_number`,
        [internId],
        (err, results) => (err ? reject(err) : resolve(results))
      );
    });

    // Default 4-week array
    const chartData = [0, 0, 0, 0];
    chartRows.forEach((row, index) => {
      if (index >= 0 && index < 4) {
        chartData[index] = row.completed_tasks;
      }
    });

    // 3. Feedback: use reports as feedback
    const feedbackRows = await new Promise((resolve, reject) => {
      db.query(
        `SELECT report_title AS project, report_description AS comments, submitted_at AS created_at
           FROM Reports
           WHERE intern_id = ?
           ORDER BY submitted_at DESC
           LIMIT 10`,
        [internId],
        (err, results) => (err ? reject(err) : resolve(results))
      );
    });

    // Add default rating + reviewer
    const feedback = feedbackRows.map(row => ({
      reviewer: 'Lead Mentor',
      project: row.project || 'N/A',
      rating: 4,
      comments: row.comments || '',
    }));

    res.json({
      score,
      tasks: `${completedTasks}/${totalTasks}`,
      completionTime: `${avgCompletionTime} hrs`,
      chartData,
      feedback,
    });
  } catch (error) {
    console.error('Error fetching performance:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});
app.get('/api/intern/performance/insights', async (req, res) => {
  try {
    const rows = await new Promise((resolve, reject) => {
      db.query(
        `SELECT i.intern_id, i.name,
              IFNULL(SUM(t.status = 'Completed'), 0) AS completed_tasks,
              COUNT(t.task_id) AS total_tasks,
              CASE WHEN COUNT(t.task_id) = 0 
                   THEN 0 
                   ELSE ROUND(SUM(t.status = 'Completed') / COUNT(t.task_id) * 100, 2) 
              END AS completion_rate
           FROM Interns i
           LEFT JOIN Tasks t ON i.intern_id = t.intern_id
           GROUP BY i.intern_id
           ORDER BY completion_rate DESC`,
        (err, results) => (err ? reject(err) : resolve(results))
      );
    });

    if (!rows || rows.length === 0) {
      return res.json({ topPerformer: null, needsSupport: null });
    }

    const topPerformer = rows[0];
    const needsSupport = rows[rows.length - 1];

    res.json({
      topPerformer: {
        name: topPerformer.name,
        completionRate: topPerformer.completion_rate,
      },
      needsSupport: {
        name: needsSupport.name,
        completionRate: needsSupport.completion_rate,
      }
    });
  } catch (error) {
    console.error('Error fetching performance insights:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});



// Create a leave request
app.post('/api/leave-requests', async (req, res) => {
  try {
    const { intern_id, leave_type, from_date, to_date, number_of_working_days, reason, reporting_lead, handover_note } = req.body;
    if (!intern_id || !from_date || !to_date || !number_of_working_days || !reason) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const typeVal = leave_type || 'Casual';

    // Insert leave request
    await new Promise((resolve, reject) => {
      db.query(
        `INSERT INTO leave_requests (intern_id, leave_type, from_date, to_date, number_of_working_days, reason, reporting_lead, handover_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [intern_id, typeVal, from_date, to_date, number_of_working_days, reason, reporting_lead || null, handover_note || null],
        (err, results) => {
          if (err) reject(err);
          else resolve(results);
        }
      );
    });

    // Fetch intern details for HR email notification
    let internDetails = { intern_id, name: 'Intern', email: '', phone: '', department: 'N/A' };
    try {
      const internRows = await new Promise((resolve, reject) => {
        db.query(
          `SELECT intern_id, name, email, phone, department, internrole FROM Interns WHERE intern_id = ?`,
          [intern_id],
          (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
          }
        );
      });
      if (internRows && internRows.length > 0) {
        internDetails = { ...internDetails, ...internRows[0] };
      } else {
        const userRows = await new Promise((resolve, reject) => {
          db.query(
            `SELECT full_name as name, email, phone, role as department FROM users WHERE id = ? OR username = ?`,
            [intern_id, intern_id],
            (err, rows) => {
              if (err) resolve([]);
              else resolve(rows);
            }
          );
        });
        if (userRows && userRows.length > 0) {
          internDetails = { ...internDetails, ...userRows[0] };
        }
      }
    } catch (fetchErr) {
      console.warn('Could not fetch intern details for HR email:', fetchErr.message);
    }

    // Send email notification to HR
    const hrSubject = `New Leave Application: ${String(internDetails.name || intern_id).replace(/[\r\n]+/g, ' ')} (${String(typeVal).replace(/[\r\n]+/g, ' ')})`;
    // Escaped copies for the email HTML
    internDetails = Object.fromEntries(Object.entries(internDetails).map(([k, v]) => [k, esc(v)]));
    const e_ = { intern_id: esc(intern_id), typeVal: esc(typeVal), from_date: esc(from_date), to_date: esc(to_date), days: esc(number_of_working_days),
      reason: esc(reason), reporting_lead: esc(reporting_lead), handover_note: esc(handover_note) };
    const hrHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: Arial, Helvetica, sans-serif; font-size: 15px; line-height: 1.6; color: #222222; margin: 0; padding: 20px; background-color: #ffffff;">
  <div style="max-width: 650px; margin: 0; padding: 0;">
    
    <p>Dear <strong>HR Team</strong>,</p>
    
    <p>A new leave application has been submitted by <strong>${internDetails.name || 'Intern'}</strong> (${e_.intern_id}).</p>
    
    <p><strong>Leave Application Details:</strong></p>
    <ul style="margin: 10px 0 16px 0; padding-left: 20px;">
      <li><strong>Intern Name:</strong> ${internDetails.name || 'N/A'} (${e_.intern_id})</li>
      <li><strong>Department/Role:</strong> ${internDetails.department || internDetails.internrole || 'N/A'}</li>
      <li><strong>Intern Email:</strong> ${internDetails.email || 'N/A'}</li>
      ${internDetails.phone ? `<li><strong>Phone:</strong> ${internDetails.phone}</li>` : ''}
      <li><strong>Leave Type:</strong> ${e_.typeVal}</li>
      <li><strong>Duration / Dates:</strong> ${e_.from_date} to ${e_.to_date} (${e_.days} day(s))</li>
      <li><strong>Reason:</strong> ${e_.reason}</li>
      ${reporting_lead ? `<li><strong>Reporting Lead:</strong> ${e_.reporting_lead}</li>` : ''}
      ${handover_note ? `<li><strong>Handover Note:</strong> ${e_.handover_note}</li>` : ''}
    </ul>

    <p>Please log in to the HR Dashboard to review and respond to this request.</p>
    
    <br />
    <p style="margin-bottom: 4px;">Best regards,</p>
    <p style="margin-top: 0; margin-bottom: 4px;"><strong>InnerWhispers Leave Management System</strong></p>
    <p style="margin-top: 0; color: #555555; font-size: 13px;">
      InnerWhispers Wellness LLP<br />
      Website: <a href="https://innerwhispers.in/" style="color: #0056b3;">https://innerwhispers.in/</a>
    </p>

  </div>
</body>
</html>
    `;

    sendEmail({ to: DEFAULT_HR_EMAIL, subject: hrSubject, html: hrHtml });
    notify('New leave request', `${String(internDetails.name || intern_id).replace(/&[a-z#0-9]+;/gi, '')} asked for ${number_of_working_days} day(s) from ${from_date} to ${to_date}.`, 'info', { role: 'hr' })
      .catch(err => console.warn('Notification not saved:', err.code || err.message));

    res.json({ message: 'Leave request submitted successfully' });
  } catch (error) {
    console.error('Error creating leave request:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});

// Get leave requests for an intern
app.get('/api/leave-requests/:intern_id?', async (req, res) => {
  try {
    const internId = req.params.intern_id || req.query.intern_id;
    if (!internId) {
      return res.status(400).json({ error: 'intern_id is required' });
    }

    const rows = await new Promise((resolve, reject) => {
      db.query(
        `SELECT id, leave_type, from_date, to_date, number_of_working_days, reason, status, remarks, reporting_lead, handover_note, requested_at 
           FROM leave_requests 
           WHERE intern_id = ? 
           ORDER BY requested_at DESC`,
        [internId],
        (err, results) => {
          if (err) reject(err);
          else resolve(results);
        }
      );
    });

    res.json(rows);
  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});

// Update leave request status (approve/reject)
app.put('/api/leave-requests/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, remarks } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be Approved or Rejected' });
    }

    const remarksVal = remarks ? remarks.trim() : null;

    const result = await new Promise((resolve, reject) => {
      db.query(
        `UPDATE leave_requests SET status = ?, remarks = ? WHERE id = ?`,
        [status, remarksVal, id],
        (err, results) => {
          if (err) reject(err);
          else resolve(results);
        }
      );
    });

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }

    // In-app notification for the intern
    const [[lr]] = await executeQuery("SELECT intern_id, DATE_FORMAT(from_date, '%d %b') AS f, DATE_FORMAT(to_date, '%d %b') AS t FROM leave_requests WHERE id = ?", [id]);
    if (lr) notifyIntern(lr.intern_id, `Leave ${status.toLowerCase()}`,
      `Your leave from ${lr.f} to ${lr.t} was ${status.toLowerCase()}.` + (remarksVal ? ` HR: ${remarksVal}` : ''), status === 'Approved' ? 'success' : 'warning');

    // Fetch leave request details along with intern profile to notify intern via email
    try {
      const leaveDetails = await new Promise((resolve, reject) => {
        db.query(
          `SELECT lr.*, i.name as intern_name, i.email as intern_email, i.department 
             FROM leave_requests lr
             LEFT JOIN Interns i ON lr.intern_id = i.intern_id
             WHERE lr.id = ?`,
          [id],
          (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
          }
        );
      });

      if (leaveDetails && leaveDetails.length > 0) {
        const leave = leaveDetails[0];
        let internEmail = leave.intern_email;
        let internName = leave.intern_name || 'Intern';

        if (!internEmail) {
          const uRows = await new Promise((resolve, reject) => {
            db.query(
              `SELECT email, full_name FROM users WHERE id = ? OR username = ?`,
              [leave.intern_id, leave.intern_id],
              (err, rows) => {
                if (err) resolve([]);
                else resolve(rows);
              }
            );
          });
          if (uRows && uRows.length > 0) {
            internEmail = uRows[0].email;
            internName = uRows[0].full_name || internName;
          }
        }

        if (internEmail) {
          const isApproved = status === 'Approved';
          const badgeBg = isApproved ? '#dcfce7' : '#fee2e2';
          const badgeColor = isApproved ? '#15803d' : '#b91c1c';

          const subject = `Leave Request ${status}: ${leave.leave_type || 'Leave'} (${leave.from_date} to ${leave.to_date})`;
          const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family: Arial, Helvetica, sans-serif; font-size: 15px; line-height: 1.6; color: #222222; margin: 0; padding: 20px; background-color: #ffffff;">
  <div style="max-width: 650px; margin: 0; padding: 0;">
    
    <p>Dear <strong>${esc(internName)}</strong>,</p>
    
    <p>Your leave request has been reviewed by the HR team and marked as <strong>${status.toUpperCase()}</strong>.</p>
    
    <p><strong>Leave Application Details:</strong></p>
    <ul style="margin: 10px 0 16px 0; padding-left: 20px;">
      <li><strong>Leave Type:</strong> ${esc(leave.leave_type || 'Casual Leave')}</li>
      <li><strong>Duration / Dates:</strong> ${leave.from_date} to ${leave.to_date} (${esc(leave.number_of_working_days)} day(s))</li>
      <li><strong>Reason:</strong> ${esc(leave.reason || '—')}</li>
      <li><strong>Status:</strong> ${status}</li>
      ${remarksVal ? `<li><strong>HR Remarks:</strong> ${esc(remarksVal)}</li>` : ''}
    </ul>

    <p>If you have any questions regarding this decision, please feel free to reply to this email or contact the HR team at <a href="mailto:${DEFAULT_HR_EMAIL}" style="color: #0056b3;">${DEFAULT_HR_EMAIL}</a>.</p>
    
    <br />
    <p style="margin-bottom: 4px;">Best regards,</p>
    <p style="margin-top: 0; margin-bottom: 4px;"><strong>Human Resources Department</strong></p>
    <p style="margin-top: 0; color: #555555; font-size: 13px;">
      InnerWhispers Wellness LLP<br />
      Email: <a href="mailto:${DEFAULT_HR_EMAIL}" style="color: #0056b3;">${DEFAULT_HR_EMAIL}</a><br />
      Website: <a href="https://innerwhispers.in/" style="color: #0056b3;">https://innerwhispers.in/</a>
    </p>

  </div>
</body>
</html>
          `;

          sendEmail({ to: internEmail, subject, html });
        } else {
          console.warn(`⚠️ No email address found for intern_id ${leave.intern_id}, decision email not sent.`);
        }
      }
    } catch (mailErr) {
      console.error('Error fetching details for decision email:', mailErr.message);
    }

    res.json({ message: `Leave request ${status.toLowerCase()} successfully` });
  } catch (error) {
    console.error('Error updating leave request:', error);
    res.status(500).json({ error: 'Internal Server Error'});
  }
});

// ------------------- GET submitted documents (uploaded by intern) -------------------
app.get('/api/documents/submitted', (req, res) => {
  const internId = req.query.intern_id;
  if (!internId) return res.status(400).json({ error: 'intern_id is required' });

  const sql = `SELECT id, doc_title, upload_date, status, file_path
                 FROM Documents
                 WHERE intern_id = ? AND uploaded_by = 'Intern'
                 ORDER BY upload_date DESC`;

  db.query(sql, [internId], (err, rows) => {
    if (err) {
      console.error('Failed to fetch submitted documents:', err);
      return res.status(500).json({ error: 'Failed to fetch submitted documents' });
    }
    res.json(rows);
  });
});
app.get('/api/documents', (req, res) => {
  const internId = req.query.intern_id;
  if (!internId) return res.status(400).json({ error: 'intern_id query parameter is required' });

  let sql = `SELECT id, doc_title, upload_date, status, file_path 
               FROM Documents WHERE intern_id = ?`;
  const params = [internId];

  if (req.query.status) {
    sql += ' AND status = ?';
    params.push(req.query.status);
  }
  if (req.query.type) {
    sql += ' AND doc_title LIKE ?';
    params.push(`%${req.query.type}%`);
  }

  sql += ' ORDER BY upload_date DESC';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Error fetching documents:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const documents = rows.map(doc => ({
      id: doc.id,
      name: doc.doc_title,
      dateUploaded: doc.upload_date.toString().slice(0, 10),
      status: doc.status,
      filename: doc.file_path
    }));

    res.json(documents);
  });
});



// ------------------- GET ALL DOCUMENTS (for documents.html page) -------------------
app.get('/api/documents/all', (req, res) => {
  const sql = `
      SELECT d.id, d.intern_id, d.doc_title, d.doc_description, d.file_path, 
             d.file_size, d.category, d.uploaded_by, d.status, d.upload_date,
             i.name as intern_name, i.department as intern_department
      FROM Documents d
      LEFT JOIN Interns i ON d.intern_id = i.intern_id
      ORDER BY d.upload_date DESC
    `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error('Error fetching all documents:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const documents = rows.map(doc => ({
      id: doc.id,
      name: doc.intern_name || 'Unknown',
      type: doc.uploaded_by === 'Intern' ? 'Intern' : 'Employee',
      category: doc.category,
      uploadedOn: doc.upload_date ? doc.upload_date.toString().slice(0, 10) : null,
      status: doc.status,
      filePath: doc.file_path
    }));

    // Calculate statistics
    const stats = {
      total: documents.length,
      employee: documents.filter(d => d.type === 'Employee').length,
      intern: documents.filter(d => d.type === 'Intern').length,
      pending: documents.filter(d => d.status === 'Pending').length
    };

    // Get pending documents (missing files)
    const pendingDocs = documents
      .filter(d => d.status === 'Pending' || d.status === 'Missing')
      .map(d => ({
        name: d.name,
        required: d.category,
        type: d.type
      }));

    res.json({
      documents,
      pendingDocs,
      stats
    });
  });
});

// ------------------- GET issued documents (uploaded by others) -------------------
app.get('/api/documents/issued', (req, res) => {
  const internId = req.query.intern_id;
  if (!internId) return res.status(400).json({ error: 'intern_id is required' });

  const sql = `SELECT id, doc_title, upload_date, status, file_path
                 FROM Documents
                 WHERE intern_id = ? AND uploaded_by != 'Intern'
                 ORDER BY upload_date DESC`;

  db.query(sql, [internId], (err, rows) => {
    if (err) {
      console.error('Failed to fetch issued documents:', err);
      return res.status(500).json({ error: 'Failed to fetch issued documents' });
    }
    res.json(rows);
  });
});

// ------------------- UPLOAD document (file or link) -------------------
app.post('/api/documents/upload', async (req, res) => {
  try {
    const { intern_id, customFileName, fileUrl } = req.body;

    // Validation
    if (!intern_id) {
      return res.status(400).json({ error: "intern_id is required" });
    }

    if (!fileUrl || fileUrl.trim() === "") {
      return res.status(400).json({ error: "No file URL provided" });
    }

    // Determine filename
    const filename = customFileName?.trim() || fileUrl.split('/').pop() || "Document";

    // Insert into database
    const sql = `
      INSERT INTO Documents 
      (intern_id, doc_title, upload_date, status, file_path, uploaded_by) 
      VALUES (?, ?, NOW(), 'Pending', ?, 'Intern')
    `;

    db.query(sql, [intern_id, filename, fileUrl], (err, result) => {
      if (err) {
        console.error("Failed to save document:", err);
        return res.status(500).json({ error: "Failed to upload document" });
      }
      res.json({ message: "✅ Document uploaded successfully", filePath: fileUrl });
    });

  } catch (err) {
    console.error("Server error uploading document:", err);
    return res.status(500).json({ error: "Server error" });
  }
});



// ------------------- UPDATE DOCUMENT STATUS -------------------
app.put('/api/documents/:id/status', (req, res) => {
  const docId = req.params.id;
  const { status } = req.body;

  if (!status || !['Reviewed', 'Rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Must be Reviewed or Rejected' });
  }

  const sql = `UPDATE Documents SET status = ?, updated_at = NOW() WHERE id = ?`;

  db.query(sql, [status, docId], (err, result) => {
    if (err) {
      console.error('Error updating document status:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    executeQuery('SELECT intern_id, doc_title FROM Documents WHERE id = ?', [docId]).then(([[d]]) => {
      if (d && d.intern_id) notifyIntern(d.intern_id, status === 'Reviewed' ? 'Document accepted' : 'Document rejected',
        `"${d.doc_title}" was ${status === 'Reviewed' ? 'accepted' : 'rejected'} by HR.`, status === 'Reviewed' ? 'success' : 'warning');
    }).catch(() => {});

    res.json({
      message: `Document status updated to ${status} successfully`,
      docId,
      newStatus: status
    });
  });
});


// ------------------- DOWNLOAD document by ID -------------------
app.get('/api/documents/download/:id', (req, res) => {
  const docId = req.params.id;

  const sql = `SELECT doc_title, file_path FROM Documents WHERE id = ?`;
  db.query(sql, [docId], (err, rows) => {
    if (err) {
      console.error('Failed to fetch document:', err);
      return res.status(500).json({ error: 'Failed to download document' });
    }
    if (rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const link = String(rows[0].file_path || '');
    if (!/^https?:\/\//i.test(link)) return res.status(404).json({ error: 'File not found' });
    res.redirect(link);
  });
});



// Modify the appointment POST endpoint
app.post('/api/appointments', (req, res) => {
  const time24 = convertTo24Hour(req.body.appointment_time);
  if (!time24) {
    res.status(400).json({
      error: 'Invalid time format',
      details: 'Time should be in format HH:MM AM/PM or HH:MM'
    });
    return;
  }

  // Get session info based on type
  const sessionInfo = SESSION_TYPES[req.body.session_type] || {
    duration: 50,
    price: 1500
  };

  const query = `
        INSERT INTO appointments 
        SET 
            patient_name = ?,
            email = ?,
            phone = ?,
            addhar = ?,
            age = ?,
            parenttype = ?,
            parentName = ?,
            guardianPhone = ?,
            address = ?,
            pincode = ?,
            state = ?,
            concerns = ?,
            appointment_date = CONVERT_TZ(?, '+00:00', '+05:30'),
            appointment_time = ?,
            session_type = ?,
            session_price = ?,
            session_duration = ?,
            status = ?,
            created_at = CONVERT_TZ(NOW(), '+00:00', '+05:30')
    `;

  const values = [
    req.body.patient_name,
    req.body.email,
    req.body.phone,
    req.body.addhar,
    req.body.age,
    req.body.parenttype,
    req.body.parentName,
    req.body.guardianPhone,
    req.body.address,
    req.body.pincode,
    req.body.state,
    req.body.concerns,
    req.body.appointment_date,
    time24,
    req.body.session_type,
    sessionInfo.price,
    sessionInfo.duration,
    req.body.status || 'pending'
  ];

  const r = db.query(query, values, (err, result) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).json({
        error: 'Could not save appointment'});
      return;
    }

    res.status(201).json({
      message: 'Appointment created successfully',
      id: result.insertId,
      appointment_date: req.body.appointment_date, // Send back the original date
      appointment_time: time24,
      r
    });
  });
});

// Helper to format date in IST (Indian Standard Time)
function formatDateIST(dateInput) {
  // Accepts either Date object or string in YYYY-MM-DD
  let d;
  if (dateInput instanceof Date) {
    d = dateInput;
  } else {
    // Parse as local date (not UTC)
    // This ensures no timezone shift
    const [year, month, day] = dateInput.split('-');
    d = new Date(Number(year), Number(month) - 1, Number(day));
  }
  // Convert to IST
  const utc = d.getTime() + (d.getTimezoneOffset() * 60000);
  const istOffset = 5.5 * 60 * 60000;
  const istDate = new Date(utc + istOffset);
  // Format as YYYY-MM-DD
  return istDate.getFullYear() + '-' +
    String(istDate.getMonth() + 1).padStart(2, '0') + '-' +
    String(istDate.getDate()).padStart(2, '0');
}

// Modify the appointments GET endpoint to return dates in IST
app.get('/api/appointments/:id', (req, res) => {
  const { id } = req.params
  const query = `
        SELECT 
            *,
            DATE_FORMAT(CONVERT_TZ(appointment_date, '+00:00', '+05:30'), '%Y-%m-%d') as appointment_date
        FROM appointments 
        where doctor_id=?
        ORDER BY appointment_date, appointment_time
    `;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.json(results);
  });
});

// Update appointment status endpoint
app.put('/api/appointments/:doc_id/:id/status', (req, res) => {
  const { doc_id, id } = req.params;
  const { status } = req.body;
  db.query(
    'UPDATE appointments SET status = ? WHERE doctor_id = ? AND id = ?',
    [status, doc_id, id],

    (err) => {
      if (err) {
        res.status(500).json({ error: 'Internal Server Error' });
        return;
      }
      res.json({ message: 'Status updated successfully' });
    }
  );
});


// Add this endpoint after the existing endpoints
app.put('/api/appointments/:doc_id/:id/reschedule', (req, res) => {
  const { doc_id, id } = req.params;
  let { appointment_date, appointment_time } = req.body;
  // Log the raw body for debugging
  console.log('RAW BODY:', req.body);

  if (!appointment_date || !appointment_time) {
    return res.status(400).json({ error: 'Date and time required' });
  }
  // Accept only YYYY-MM-DD format
  if (typeof appointment_date === 'string') {
    // If it contains T, extract only the date part
    if (appointment_date.includes('T')) {
      appointment_date = appointment_date.split('T')[0];
    }
    // If it is not in YYYY-MM-DD format, reject
    if (!/^\d{4}-\d{2}-\d{2}$/.test(appointment_date)) {
      return res.status(400).json({ error: 'Invalid date format, must be YYYY-MM-DD' });
    }
  } else {
    return res.status(400).json({ error: 'Invalid date format, must be string' });
  }
  // Prevent any timezone conversion: do NOT use new Date(appointment_date)
  // Log for debugging
  console.log('Reschedule request:', { id, appointment_date, appointment_time });

  // Convert time to 24-hour format with seconds
  const time24 = convertTo24Hour(appointment_time);
  if (!time24) {
    return res.status(400).json({ error: 'Invalid time format' });
  }
  db.query(
    'UPDATE appointments SET appointment_date = ?, appointment_time = ? WHERE doctor_id=? and id = ?',
    [appointment_date, time24, doc_id, id],
    (err) => {
      if (err) {
        res.status(500).json({ error: 'Internal Server Error' });
        return;
      }
      res.json({ message: 'Appointment rescheduled successfully' });
    }
  );
});

// Add better error handling for database connection
// Remove direct event listeners; pool manages connections internally

// Remove the duplicate db.connect at the bottom since it's already handled in the main connection

// unify single listener above

// New API endpoints for prescriptions
app.get('/api/patients', (req, res) => {
  const query = `
        SELECT DISTINCT patient_name 
        FROM appointments 
        WHERE status = 'confirmed' 
        ORDER BY patient_name
    `;

  db.query(query, (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.json(results);
  });
});

app.post('/api/prescriptions', (req, res) => {
  const {
    patient_name,
    medication_name,
    medication_type,
    medication_dosage,
    medication_supply,
    special_instructions,
    notes
  } = req.body;

  const query = `
        INSERT INTO prescriptions 
        (patient_name, prescription_date, medication_name, medication_type, 
         medication_dosage, medication_supply, special_instructions, notes)
        VALUES (?, CURDATE(), ?, ?, ?, ?, ?, ?)
    `;

  db.query(query, [
    patient_name,
    medication_name,
    medication_type,
    medication_dosage,
    medication_supply,
    special_instructions,
    notes
  ], (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.status(201).json({
      id: result.insertId,
      message: 'Prescription created successfully'
    });
  });
});

app.get('/api/prescriptions', (req, res) => {
  const query = `
        SELECT * FROM prescriptions 
        ORDER BY prescription_date DESC, created_at DESC
    `;

  db.query(query, (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.json(results);
  });
});

// Add new endpoint to get single prescription
app.get('/api/prescriptions/:id', (req, res) => {
  const { id } = req.params;

  const query = `
        SELECT * FROM prescriptions 
        WHERE id = ?
    `;

  db.query(query, [id], (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

    if (results.length === 0) {
      res.status(404).json({ error: 'Prescription not found' });
      return;
    }

    res.json(results[0]);
  });
});

// Add new search endpoint
app.get('/api/prescriptions/search', (req, res) => {
  const { term } = req.query;

  const query = `
        SELECT * FROM prescriptions 
        WHERE LOWER(patient_name) LIKE ? 
        OR DATE_FORMAT(prescription_date, '%b %d, %Y') LIKE ?
        ORDER BY prescription_date DESC, created_at DESC
    `;

  const searchTerm = `%${term.toLowerCase()}%`;

  db.query(query, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.json(results);
  });
});

// --- Transactions ---
app.get('/api/transactions', (req, res) => {
  const { type, search } = req.query;

  let sql = 'SELECT * FROM transactions WHERE 1=1';
  const params = [];

  if (type && ['income', 'expense'].includes(type)) {
    sql += ' AND type = ?';
    params.push(type);
  }

  if (search) {
    sql += ' AND description LIKE ?';
    params.push(`%${search}%`);
  }

  sql += ' ORDER BY id DESC';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Failed to fetch transactions:', err);
      return res.status(500).json({ error: 'Failed to fetch transactions' });
    }
    res.json(rows);
  });
});

app.get('/api/filtertransactions', (req, res) => {
  const { fromDate, toDate, category } = req.query;

  let query = `SELECT * FROM transactions WHERE type='expense'`;
  const params = [];

  if (fromDate) {
    query += ` AND date >= ?`;
    params.push(fromDate);
  }

  if (toDate) {
    query += ` AND date <= ?`;
    params.push(toDate);
  }

  if (category && category !== 'All') {
    query += ` AND category = ?`;
    params.push(category);
  }

  query += ` ORDER BY date DESC`;

  db.query(query, params, (err, rows) => {
    if (err) {
      console.error('Error fetching filtered transactions:', err);
      return res.status(500).json({ error: 'Database error while filtering transactions' });
    }
    console.log(rows)
    res.json(rows);
  });
});


app.get('/api/summary', (req, res) => {
  const incomeQuery = 'SELECT SUM(amount) AS totalIncome FROM transactions WHERE type="income"';
  const expenseQuery = 'SELECT SUM(amount) AS totalExpenses FROM transactions WHERE type="expense"';

  db.query(incomeQuery, (incomeErr, incomeRows) => {
    if (incomeErr) {
      console.error('Failed to fetch income summary:', incomeErr);
      return res.status(500).json({ error: 'Failed to fetch income summary' });
    }

    db.query(expenseQuery, (expenseErr, expenseRows) => {
      if (expenseErr) {
        console.error('Failed to fetch expense summary:', expenseErr);
        return res.status(500).json({ error: 'Failed to fetch expense summary' });
      }

      const totalIncome = incomeRows[0].totalIncome || 0;
      const totalExpenses = expenseRows[0].totalExpenses || 0;
      const netProfit = totalIncome - totalExpenses;
      const budgetUtilization = Math.min(Math.round((totalExpenses / 100000) * 100), 100);

      res.json({
        totalIncome,
        totalExpenses,
        netProfit,
        budgetUtilization
      });
    });
  });
});

app.get('/api/expenseSummary', (req, res) => {
  const { category } = req.query; // e.g., ?category=HR
  const categoryFilter = category && category !== 'All' ? 'AND category = ?' : '';
  const catParams = categoryFilter ? [String(category)] : [];

  const expenseSummaryQuery = `
    SELECT 
      SUM(approval_status='Approved') AS approved,
      SUM(CASE WHEN approval_status='Pending' THEN amount ELSE 0 END) AS pending,
      SUM(CASE WHEN approval_status='Rejected' THEN amount ELSE 0 END) AS rejected,
      SUM(amount) AS totalExpenses
    FROM transactions
    WHERE type='expense' ${categoryFilter}
  `;

  const monthlyQuery = `
    SELECT DATE_FORMAT(date, '%b') AS month, SUM(amount) AS total
    FROM transactions
    WHERE type='expense' ${categoryFilter}
    GROUP BY MONTH(date)
    ORDER BY MONTH(date)
  `;

  const categoryQuery = `
    SELECT category, SUM(amount) AS total
    FROM transactions
    WHERE type='expense'
    GROUP BY category
  `;

  db.query(expenseSummaryQuery, catParams, (err, expenseRows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error fetching expense summary' });
    }

    const expenseData = expenseRows[0];
    console.log(expenseData)
    db.query(monthlyQuery, catParams, (err2, monthlyRows) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ error: 'Error fetching monthly expenses' });
      }

      db.query(categoryQuery, (err3, categoryRows) => {
        if (err3) {
          console.error(err3);
          return res.status(500).json({ error: 'Error fetching category breakdown' });
        }

        const months = monthlyRows.map(r => r.month);
        const monthlyExpenses = monthlyRows.map(r => r.total);
        const categoryBreakdown = {};
        categoryRows.forEach(r => (categoryBreakdown[r.category] = r.total));

        res.json({
          totalExpenses: expenseData.totalExpenses || 0,
          approved: expenseData.approved || 0,
          pending: expenseData.pending || 0,
          rejected: expenseData.rejected || 0,
          months,
          monthlyExpenses,
          categoryBreakdown
        });
      });
    });
  });
});




app.post('/api/budgets', (req, res) => {
  console.log("body", req.body);
  const { name, allocated, duration, categories } = req.body;
  const sql = 'INSERT INTO budgets (name, total_amount, duration) VALUES (?, ?, ?)';
  db.query(sql, [name, allocated, duration], (err, result) => {
    if (err) {
      console.error('Failed to create budget:', err);
      return res.status(500).json({ error: 'Failed to create budget' });
    }
    const budgetId = result.insertId;
    const catSql = 'INSERT INTO budget_categories (budget_id, name, amount) VALUES ?';
    const catValues = categories.map(cat => [budgetId, cat.name, cat.amount]);
    db.query(catSql, [catValues], (catErr, catResult) => {
      if (catErr) {
        console.error('Failed to create budget categories:', catErr);
        return res.status(500).json({ error: 'Failed to create budget categories' });
      }
      res.json({ id: budgetId });
    });
  });
});

// --- Budgets ---
app.get('/api/budgets', (req, res) => {
  const sql = 'SELECT * FROM budgets ORDER BY id DESC';

  db.query(sql, (err, budgets) => {
    if (err) {
      console.error('Failed to fetch budgets:', err);
      return res.status(500).json({ error: 'Failed to fetch budgets' });
    }

    if (budgets.length === 0) {
      return res.json([]);
    }

    let pending = budgets.length;

    budgets.forEach((budget, index) => {
      const catSql = 'SELECT name, amount FROM budget_categories WHERE budget_id = ?';

      db.query(catSql, [budget.id], (catErr, categories) => {
        if (catErr) {
          console.error('Failed to fetch budget categories:', catErr);
          budgets[index].categories = [];
        } else {
          budgets[index].categories = categories;
        }

        pending--;
        if (pending === 0) {
          // All queries done, send response
          res.json(budgets);
        }
      });
    });
  });
});


// --- Payments ---
app.get('/api/payments', (req, res) => {
  const { search = '', status } = req.query;

  let sql = 'SELECT * FROM payments WHERE 1=1';
  const params = [];

  if (status && ['Succeeded', 'Pending', 'Failed'].includes(status)) {
    sql += ' AND status = ?';
    params.push(status);
  }

  if (search) {
    sql += ' AND (payment_id LIKE ? OR client_name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  sql += ' ORDER BY received_date DESC, id DESC';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Failed to fetch payments:', err);
      return res.status(500).json({ error: 'Failed to fetch payments' });
    }
    res.json(rows);
  });
});


// --- Invoices ---
app.get('/api/invoices', (req, res) => {
  const { search = '', status } = req.query;

  let sql = 'SELECT * FROM invoices WHERE 1=1';
  const params = [];

  if (status && ['Paid', 'Pending', 'Overdue'].includes(status)) {
    sql += ' AND status = ?';
    params.push(status);
  }

  if (search) {
    sql += ' AND (invoice_number LIKE ? OR client_name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }

  sql += ' ORDER BY due_date DESC, id DESC';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Failed to fetch invoices:', err);
      return res.status(500).json({ error: 'Failed to fetch invoices' });
    }
    res.json(rows);
  });
});

app.get('/api/receipts', (req, res) => {
  const { search = '' } = req.query;

  let sql = 'SELECT * FROM receipts WHERE 1=1';
  const params = [];

  if (search) {
    sql += ' AND (receipt_number LIKE ? OR client_name LIKE ? OR invoice_number LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  sql += ' ORDER BY issue_date DESC';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Failed to fetch receipts:', err);
      return res.status(500).json({ error: 'Failed to fetch receipts' });
    }
    res.json(rows);
  });
});

app.get('/api/irsummary', (req, res) => {
  const { search = '' } = req.query;

  // Totals query
  const totalsQuery = `
    SELECT 
      (SELECT IFNULL(SUM(amount), 0) FROM invoices) AS totalInvoiced,
      (SELECT IFNULL(SUM(amount), 0) FROM receipts) AS receiptsIssued,
      (SELECT IFNULL(SUM(amount), 0) FROM invoices) - (SELECT IFNULL(SUM(amount), 0) FROM receipts) AS outstanding
  `;

  db.query(totalsQuery, (totalsErr, totalsRows) => {
    if (totalsErr) {
      console.error('Failed to fetch totals:', totalsErr);
      return res.status(500).json({ error: 'Failed to fetch totals' });
    }

    // Receipts query
    let receiptsQuery = `
      SELECT 
        receipt_number, 
        client_name, 
        invoice_number, 
        amount, 
        DATE_FORMAT(created_at, "%Y-%m-%d") AS issueDate 
      FROM receipts 
      WHERE 1=1
    `;
    const receiptsParams = [];

    if (search) {
      receiptsQuery += ' AND (receipt_number LIKE ? OR client_name LIKE ? OR invoice_number LIKE ?)';
      receiptsParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    receiptsQuery += ' ORDER BY issueDate DESC LIMIT 100';

    db.query(receiptsQuery, receiptsParams, (receiptsErr, receiptsRows) => {
      if (receiptsErr) {
        console.error('Failed to fetch receipts:', receiptsErr);
        return res.status(500).json({ error: 'Failed to fetch receipts' });
      }

      // Invoices query
      let invoicesQuery = `
        SELECT 
          invoice_number, 
          client_name, 
          amount,
          DATE_FORMAT(created_at, '%Y-%m-%d') AS issueDate,
          DATE_FORMAT(due_date, '%Y-%m-%d') AS dueDate
        FROM invoices
        WHERE 1=1
      `;
      const invoicesParams = [];

      if (search) {
        invoicesQuery += ' AND (invoice_number LIKE ? OR client_name LIKE ?)';
        invoicesParams.push(`%${search}%`, `%${search}%`);
      }

      invoicesQuery += ' ORDER BY issueDate DESC LIMIT 100';

      db.query(invoicesQuery, invoicesParams, (invoicesErr, invoicesRows) => {
        if (invoicesErr) {
          console.error('Failed to fetch invoices:', invoicesErr);
          return res.status(500).json({ error: 'Failed to fetch invoices' });
        }

        // Send combined response
        res.json({
          totals: totalsRows[0],
          receipts: receiptsRows,
          invoices: invoicesRows
        });
      });
    });
  });
});

app.get('/api/income-trend', (req, res) => {
  const query = `
    SELECT DATE_FORMAT(issue_date, '%Y-%m') AS month, SUM(amount) AS amount
    FROM invoices
    WHERE issue_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
    GROUP BY month
    ORDER BY month
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch income trend' });
    res.json(results);
  });
});

// GET Settings
app.get('/api/settings', (req, res) => {
  const sql = 'SELECT * FROM settings LIMIT 1';
  db.query(sql, (err, rows) => {
    if (err) {
      console.error('Failed to fetch settings:', err);
      return res.status(500).json({ error: 'Failed to fetch settings' });
    }

    if (rows.length === 0) {
      return res.json({});
    }

    res.json(rows[0]);
  });
});

// PUT Settings (Update or Insert)
app.put('/api/settings', (req, res) => {
  const {
    company_name,
    support_email,
    timezone,
    currency,
    pay_terms,
    tax_rate,
    invoice_prefix,
    auto_send,
  } = req.body;

  // First check if record exists
  const checkSql = 'SELECT * FROM settings LIMIT 1';
  db.query(checkSql, (err, rows) => {
    if (err) {
      console.error('Error checking settings:', err);
      return res.status(500).json({ error: 'Failed to update settings' });
    }

    if (rows.length === 0) {
      // Insert new record
      const insertSql = `
                INSERT INTO settings 
                (company_name, support_email, timezone, currency, pay_terms, tax_rate, invoice_prefix, auto_send)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;
      const params = [company_name, support_email, timezone, currency, pay_terms, tax_rate, invoice_prefix, auto_send];
      db.query(insertSql, params, (err2) => {
        if (err2) {
          console.error('Failed to insert settings:', err2);
          return res.status(500).json({ error: 'Failed to insert settings' });
        }
        res.json({ message: 'Settings saved successfully' });
      });
    } else {
      // Update existing record
      const updateSql = `
                UPDATE settings SET 
                company_name = ?, 
                support_email = ?, 
                timezone = ?, 
                currency = ?, 
                pay_terms = ?, 
                tax_rate = ?, 
                invoice_prefix = ?, 
                auto_send = ?
                WHERE id = ?
            `;
      const params = [company_name, support_email, timezone, currency, pay_terms, tax_rate, invoice_prefix, auto_send, rows[0].id];
      db.query(updateSql, params, (err3) => {
        if (err3) {
          console.error('Failed to update settings:', err3);
          return res.status(500).json({ error: 'Failed to update settings' });
        }
        res.json({ message: 'Settings updated successfully' });
      });
    }
  });
});



/* ------------------------------
   Final error handler (must stay after every route)
------------------------------- */
app.use((err, req, res, next) => {
  if (err && err.message && err.message.includes('Only images and PDF')) {
    return res.status(400).json({ error: err.message, message: err.message });
  }
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'The file is larger than 5 MB.', message: 'The file is larger than 5 MB.' });
  }
  console.error('Unhandled error:', err && (err.code || err.message));
  res.status(500).json({ error: 'Internal Server Error', message: 'Something went wrong. Please try again.' });
});

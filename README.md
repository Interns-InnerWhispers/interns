# InnerWhispers Portal Backend (HR, interns, doctors)

The API behind the HR portal (`/portal/hr/`) and the intern portal (`/portal/interns/`) on innerwhispers.in: sign-in, attendance, tasks, reports, documents, leave, notifications, HR finance pages, and the doctor/appointment records.

| | |
|---|---|
| **Live URL** | `https://interns-x9e4.onrender.com` |
| **Runs on** | Render (Node.js) |
| **Database** | MySQL on Hostinger |
| **Files** | Cloudinary (profile photos); documents and reports are stored as web links |
| **Live updates** | Socket.IO |

> This code used to live inside `public_html/portal/interns/`, which made it downloadable from the website. It now lives here and must **never** be uploaded to Hostinger.

---

## Access model

Every `/api` route is listed in the `ACCESS` table in `server.js` with who may call it. **Anything not listed is refused (404).** One gate (`accessGate`) runs before all routes.

```mermaid
flowchart TD
  R["Request to /api/..."] --> M{"Listed in ACCESS?"}
  M -- No --> N404["404 Not found"]
  M -- Yes --> P{"Public route?<br/>login, forgot password, register"}
  P -- Yes --> OK["Route runs"]
  P -- No --> T{"Valid token?"}
  T -- No --> N401["401 Please sign in again"]
  T -- Yes --> W{"Who may call it"}
  W -- "Any signed-in user" --> OK
  W -- "HR / admin" --> H{"Role hr or admin?"}
  W -- "Doctors / admin" --> D{"Clinical role or admin?"}
  W -- "Self" --> S{"Role?"}
  H -- Yes --> OK
  H -- No --> N403["403 Not allowed"]
  D -- Yes --> OK
  D -- No --> N403
  S -- "hr / admin" --> OK
  S -- "intern" --> I{"Only their own intern_id?<br/>URL, ?intern_id, body,<br/>and owned task / report / document"}
  S -- "other" --> N403
  I -- Yes --> OK
  I -- No --> N403
```

| Who | Routes (examples) |
|---|---|
| **Public** | `POST /api/login`, `POST /api/forgotpass/request`, `POST /api/forgotpass/reset`, `POST /api/register` |
| **Any signed-in user** | `/api/profile`, notifications, dream reflection |
| **Self** (intern: own records only; HR: everyone) | attendance, check-in/out, tasks, reports, performance, leave requests, documents, own profile details and photo |
| **HR / admin** | HR dashboard, intern list, attendance records and edits, leave approval, report and document review, posting notifications, all finance pages, settings |
| **Help & Support** (any signed-in user; own tickets only, HR sees all) | `GET/POST /api/support/tickets`, `GET/POST /api/support/tickets/:id/messages`, `PUT /api/support/tickets/:id/status` (Open / Closed) |
| **Doctors / admin** | appointments (incl. Aadhaar and addresses), patients, prescriptions, doctor dashboard |

Roles come from `users.role` (case and spaces ignored). Clinical roles: `psychiatry`, `psychology`, `therapy`, `counseling`, `guidance`, `doctor`.

**Adding a route:** add the route, then add a line to `ACCESS`. Until you do, it returns 404. For intern routes with an intern ID in the URL, set `{ own: n }` (the regex group); for records looked up by their own ID, set `{ check: ['Table', 'id_column'] }`.

---

## Sign-in, sign-up and password reset

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant P as Portal page
  participant A as Backend
  participant DB as MySQL
  participant M as Email

  Note over U,A: Sign in
  U->>P: Email + password
  P->>A: POST /api/login
  A->>A: 10 tries / 15 min per network and per account
  A->>DB: User, bcrypt check, account active?
  A-->>P: Token (4 hours)
  Note over P: portal-auth.js adds the token to every request

  Note over U,A: Forgot password
  U->>P: Email
  P->>A: POST /api/forgotpass/request
  A->>DB: Store hash of 6-digit code (10 min)
  A->>M: Email the code (same reply whether or not the account exists)
  U->>P: Code + new password (8+ characters)
  P->>A: POST /api/forgotpass/reset
  A->>DB: Check code (5 tries), set new bcrypt hash

  Note over U,A: Sign up
  U->>P: Details, photo, department
  P->>A: POST /api/register
  alt Intern
    A->>A: Invite code must match INTERN_INVITE_CODE
  else HR, doctor, other roles
    A->>A: Request must come from a signed-in HR or admin
  else Admin
    A->>A: Request must come from a signed-in admin
  end
  A->>DB: Create user (and intern record)
```

---

## Security fixes in this version

| Was | Now |
|---|---|
| `/api/forgotpass` set anyone's password with just an email | Emailed 6-digit code, 10-minute expiry, 5 tries, rate-limited; old route returns 410 |
| Anyone could register as HR or admin | Interns need the invite code; other roles need an HR/admin login; admins need an admin |
| `/users` returned every user with password hashes | Removed |
| `/api/reports/download-file?path=` read any file on the server (including `.env`) | Removed; downloads only redirect to stored `http(s)` links |
| Patient appointments, Aadhaar, prescriptions open to anyone | Doctors and admin only |
| Finance, settings, documents, leave approval, tasks open to anyone | HR/admin, or the intern's own records |
| Interns could read or change other interns' data by changing an ID | Intern ID forced from the token; tasks, reports, documents checked for ownership |
| SQL injection in `/api/expenseSummary?category=` | Parameterised |
| Unlimited password guessing | 10 per 15 minutes per network and per account |
| CORS `*` | Allow-list (`ALLOWED_ORIGINS`) |
| Anyone could join the HR live-update room | Socket.IO requires a token; HR room for HR/admin; interns only their own room |
| Raw database errors sent to browsers | Generic messages; details only in logs |
| Email certificates not checked | Checked |
| Names, reasons and notes injected into email HTML | Escaped |
| Any field writable on the doctor dashboard (`SET ?`) | Only the known counters |
| Gemini endpoint open to anyone (costs money) | Signed-in users, 20 per hour |
| A notification for one intern was shown to every intern | Personal notifications (with a user) are seen only by that user |
| Posting a notification always failed (helper out of scope) | `notify()` / `notifyIntern()` available to every route |
| Interns could see other interns' attendance ranking (`/api/attendance/insights`) | HR only; interns get their own numbers from `/api/intern/overview` |
| "Chat with HR" on the attendance page sent messages nowhere | Help & Support tickets, saved and answered by HR |
| Any file type as a profile photo | JPG, PNG, WebP or GIF, 5 MB max |
| Weak or missing `SECRET_KEY` accepted | Server refuses to start unless it is 32+ characters |
| Demo `/upload` routes, debug route, duplicate `/health`, second `server.listen` | Removed |

**Known limits:** tokens are kept in the browser's `localStorage`, so a script injected into a portal page could read them; keep third-party scripts off portal pages. Rate limits are in memory (reset on restart, per instance). The doctor portal pages don't call this backend yet. The calendar service (`calander-q361.onrender.com`) is separate and wasn't reviewed.

---

## Intern data and dashboard numbers

```mermaid
erDiagram
  users ||--o| Interns : "same email"
  Interns ||--o{ Attendance : "intern_id"
  Interns ||--o{ Tasks : "intern_id"
  Interns ||--o{ Reports : "intern_id"
  Interns ||--o{ Documents : "intern_id"
  Interns ||--o{ leave_requests : "intern_id"
  Interns ||--o{ weekly_reports : "intern_id"
  users {
    int id PK
    varchar email UK
    varchar password_hash "bcrypt"
    varchar role "intern, hr, admin, clinical roles"
    enum status "active, inactive, suspended"
  }
  Interns {
    varchar intern_id UK "10 chars, e.g. IW2025AB01"
    varchar name "100"
    varchar internrole "60"
    varchar email UK "255"
    varchar phone "20"
    date start_date
    date end_date
    enum status "Active, Inactive, Completed"
  }
  Attendance {
    varchar intern_id FK
    date attendance_date "unique per intern"
    enum status "Present, Late, Absent, Leave"
    time check_in "India time"
    time check_out "India time"
    decimal hours_worked "set at check-out"
  }
  Tasks {
    int task_id PK
    varchar task_title "150"
    enum status "Pending, In Progress, Completed, Overdue, Urgent"
    date due_date
  }
  Reports {
    int id PK
    varchar report_title "150"
    enum report_type "wednesday, saturday"
    varchar file_path "web link"
  }
```

**Automatic upgrades** (`upgradeInternSchema`, on every start, never deletes data): widens columns that were shorter than the forms allow (intern role "Full Stack Development" didn't fit; report titles over 50 characters failed), adds indexes for the dashboards' most common lists, and fills in `hours_worked` for past days.

**How the numbers are worked out** (`internScores`, used by the intern dashboard and the HR intern list):

| Number | Formula |
|---|---|
| Days attended | Present + Late |
| Attendance % | attended ÷ (attended + absent). Leave is excused and not counted against it. |
| Punctuality % | on time ÷ attended |
| Task completion % | completed tasks ÷ all tasks |
| Performance | average of attendance % (this month) and task completion %; attendance % alone if there are no tasks |

Previously absences *raised* the score, late days counted as nothing, the HR list showed 0% attendance and "Missing" reports for everyone, check-out times were saved in UTC (so hours were wrong), "In progress" couldn't be saved on a task, and finished tasks never showed as completed.

---

## Dashboard numbers: `GET /api/intern/overview`

One call returns every number the intern pages show (interns get only their own; HR can pass any `intern_id`). A number with no data behind it is `null`, and the page hides it rather than inventing one.

| Field | Meaning |
|---|---|
| `month.attendance`, `month.punctuality`, `month.attended`, `month.late`, `month.absent`, `month.leave` | This calendar month (India time) |
| `month.change_vs_last_month` | Attendance % change vs last month; `null` if last month has no records |
| `all_time.attended`, `all_time.punctuality`, `all_time.hours` | Since the internship started; hours come from check-out times |
| `tasks.total`, `tasks.done`, `tasks.completion` | All tasks |
| `weekly[]` | The last 4 weeks (Monday start): `label` and tasks marked done that week |
| `performance` | This month: average of attendance % and task completion % |
| `leave.per_year`, `leave.used_this_year`, `leave.remaining` | `per_year` from `ANNUAL_LEAVE_DAYS`; `null` when HR hasn't set an allowance |

---

## Notifications

```mermaid
flowchart LR
  A["HR approves / rejects leave"] --> N["notifyIntern()"]
  B["HR reviews / rejects a report"] --> N
  C["HR accepts / rejects a document"] --> N
  D["HR assigns a task"] --> N
  E["HR replies to a ticket"] --> N
  F["Intern requests leave"] --> H["notify(role: hr)"]
  G["New ticket / intern reply"] --> H
  N --> T[("Notifications<br/>target_user_id = the intern")]
  H --> R[("Notifications<br/>target_role = hr")]
  T --> Bell["Bell on the intern's pages"]
  R --> HBell["Bell on HR pages"]
```

- A notification with `target_user_id` is **personal**; without one it goes to everyone with `target_role` (`hr`, `intern` or `all`).
- `GET /api/notifications`, `GET /api/notifications/unread-count`, `PUT /api/notifications/read-all`: the bell loads the latest 15 every minute and marks them read when opened.
- Live push: each signed-in Socket.IO connection joins `user-<id>`; HR also joins `hr-dashboard`.
- `notifyIntern()` never throws, so a failed notice never fails the action (leave approval etc.).
- Known limit: role-wide notifications have one shared read flag.

---

## Help & Support tickets

The chat button (bottom right of every portal page, `public_html/portal/support.js`) is backed by two tables, created automatically on start:

| Table | Columns |
|---|---|
| `support_tickets` | `id`, `user_id`, `requester_name`, `requester_role`, `intern_id`, `category`, `subject`, `status` (`Open` / `Answered` / `Closed`), `unread_for_user`, timestamps |
| `support_messages` | `id`, `ticket_id`, `sender_user_id`, `from_staff`, `sender_name`, `body`, `created_at` |

```mermaid
sequenceDiagram
  autonumber
  actor I as Intern
  participant W as Chat widget
  participant A as Backend
  actor H as HR
  I->>W: Raise a ticket (category, subject, message)
  W->>A: POST /api/support/tickets
  A->>A: Save ticket (Open) + first message
  A-->>H: Bell notification + email to HR_EMAIL
  H->>W: Opens Support inbox, replies
  W->>A: POST /api/support/tickets/:id/messages
  A->>A: Status Answered, unread for the intern
  A-->>I: Bell notification + red badge on the chat button
  I->>W: Replies (status back to Open) or "Mark as resolved"
  W->>A: PUT /api/support/tickets/:id/status {Closed}
```

| Route | Who |
|---|---|
| `GET /api/support/tickets?status=` | Own tickets; HR and admins see all (Open first) |
| `POST /api/support/tickets` | Any signed-in user; 10 per hour |
| `GET /api/support/tickets/:id/messages` | Owner or HR; others get 404 |
| `POST /api/support/tickets/:id/messages` | Owner or HR; 60 messages per hour |
| `PUT /api/support/tickets/:id/status` | Owner or HR: `Closed` or `Open` |

Categories: Attendance, Leave, Reports, Tasks, Documents, Account, Technical, Other. No attachments yet (people paste a link).

---

## Configuration

Set in **Render → Environment** (see `.env.example`):

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | **Yes** | 32+ random characters; signs logins. Changing it signs everyone out. |
| `INTERN_INVITE_CODE` | **Yes, for intern sign-up** | Code HR gives new interns. Without it, public intern sign-up is closed. |
| `ALLOWED_ORIGINS` | No | Default `https://innerwhispers.in,https://www.innerwhispers.in` |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | Yes | Hostinger MySQL |
| `CLOUDINARY_CLOUDNAME`, `CLOUDINARY_API`, `CLOUDINARY_APISEC` | Yes | Profile photos |
| `BREVO_API_KEY` or `SMTP_*`, `SMTP_FROM`, `HR_EMAIL` | Yes | Emails (attendance, leave, reset codes) |
| `ANNUAL_LEAVE_DAYS` | No | Leave days per intern per year. Empty = the Leave page shows days taken, with no made-up balance |
| `GEMINI_API` | No | Dream reflection |

---

## Testing

```bash
npm install
npm test
```

`test.js` starts the real server on a fake database and checks that: removed routes stay gone; the old password reset is refused; patients' records are doctors-only; nobody can self-register as HR/admin; the invite code and password length are enforced; interns can't read or write other interns' data or HR pages; the expense category is passed as a value (no SQL injection); unknown routes and forged tokens are refused; login is rate-limited; CORS refuses other sites; the overview returns real numbers (and no leave balance without `ANNUAL_LEAVE_DAYS`); the team ranking is HR-only; personal notifications stay personal; support tickets can only be read by their owner and HR, and HR replies move them to Answered.

---

## Deployment

1. **Rotate every secret first** (the old code exposed `.env`): Hostinger database password, Brevo key, Cloudinary API secret, `SECRET_KEY`, Gemini key.
2. Set `SECRET_KEY` (32+ characters) and `INTERN_INVITE_CODE` in Render.
3. Push this folder to the repository Render deploys from; run `npm test` first.
4. Upload the updated portal pages to Hostinger: every file in `public_html/portal/hr/` and `public_html/portal/interns/`, plus `public_html/portal/portal-auth.js` and `public_html/.htaccess`.
5. **Delete** `portal/interns/server.js`, `package.json` and `package-lock.json` from Hostinger's `public_html`.
6. Check: `https://innerwhispers.in/portal/interns/server.js` returns 403 or 404; sign in as an intern and as HR; try "Forgot password".

---

## Project structure

```text
.
├── server.js       All routes, the ACCESS table and gate, Socket.IO, emails
├── test.js         Security self-check (npm test)
├── package.json
├── .env.example    Every setting, no real values
└── .gitignore
```

© InnerWhispers Wellness LLP. All rights reserved. Proprietary and confidential.

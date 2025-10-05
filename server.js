// Load environment variables
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mysql = require('mysql2'); 
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3006;
/* ------------------------------
   🔐 Security & Middleware
------------------------------- */
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ CORS for Hostinger + your domains
app.use(cors({
    origin: function (origin, callback) {
        const allowIf = (o) => {
            if (!o) return true; // Postman, curl, server-to-server
            try {
                const url = new URL(o);
                const host = url.hostname.toLowerCase();
                return (
                    host === 'localhost' ||
                    host === '127.0.0.1' ||
                    host.endsWith('.innerwhispers.com') ||
                    host === 'innerwhispers.com' ||
                    host === 'www.innerwhispers.com'
                );
            } catch {
                return false;
            }
        };
        if (allowIf(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    optionsSuccessStatus: 204
}));

app.options('*', cors());
app.set('trust proxy', 1); // trust proxy (important if behind nginx)

/* ------------------------------
   📂 File Uploads (Multer)
------------------------------- */
// Ensure upload folder exists
const uploadDir = process.env.NODE_ENV === 'production'
    ? '/home/u841735361/domains/innerwhispers.in/public_html/uploads'
    : path.join(__dirname, "uploads");

const uploadMembersDir = process.env.NODE_ENV === 'production'
    ? '/home/u841735361/domains/innerwhispers.in/public_html/members'
    : path.join(__dirname, "members");

// Ensure both directories exist
[uploadDir, uploadMembersDir].forEach(dir => {
    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
        }
    } catch (e) {
        console.error('❌ Failed to create directory:', dir, e);
    }
});

// Storage config
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    },
});

// File filter (images/pdf only, check mimetype)
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only images and PDF allowed!'));
};

const upload = multer({ storage, fileFilter });

/* ------------------------------
   🗄️ Database Setup
------------------------------- */
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_NAME', 'DB_PASSWORD'];
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
  } catch (err) {
    console.error('❌ DB Connection Error:', err.message);
  }
})();


// ✅ DB Initializer
async function initializeDatabase() {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Database initialized");
    } catch (err) {
        console.error("❌ DB Init Error:", err.message);
    }
}

/* ------------------------------
   🌐 Routes
------------------------------- */
app.get('/', (req, res) => res.send('🚀 API is running on Hostinger'));

app.get('/health', async (req, res) => {
    if (!db) return res.status(500).send('❌ DB not initialized');
    try {
        await db.query('SELECT 1');
        res.send('✅ Healthy');
    } catch {
        res.status(500).send('❌ DB Down');
    }
});

// Example file upload route
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ success: true, file: req.file.filename });
});

/* ------------------------------
   🛠️ Error Handling
------------------------------- */
app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err.message.includes('Only images and PDF')) {
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Something went wrong!' });
});

/* ------------------------------
   🚀 Start Server
------------------------------- */



function executeQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
}

app.get('/health', async (req, res) => {
    try {
        await dbp().query('SELECT 1');
        res.send('✅ Healthy');
    } catch {
        res.status(500).send('❌ DB Down');
    }
});

// Upload example
app.post('/upload', upload.single('file'), (req, res) => {
    res.json({
        message: '✅ File uploaded successfully',
        file: req.file
    });
});

// Example DB query
app.get('/users', async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM users");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ------------------------------
   ⚠️ Error Handling
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

const server = app.listen(PORT, '0.0.0.0', () => {
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
    db.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\`` , (err) => {
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
    end_date DATE NOT NULL DEFAULT (CURRENT_DATE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

    db.query(createInternTable, (err) => {
        if (err) {
            console.error('Error creating prescriptions table:', err);
        }
    });

    //attendence table
    const createAttendenceTable = `
        CREATE TABLE IF NOT EXISTS ${Q('Attendance')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    attendance_date DATE NOT NULL,
    status ENUM('Present', 'Absent', 'Leave') DEFAULT 'Absent',
    check_in TIME NULL,
    check_out TIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


    `;

    db.query(createAttendenceTable, (err) => {
        if (err) {
            console.error('Error creating prescriptions table:', err);
        }
    });

    //attendence table
    const createReportsTable = `
    CREATE TABLE IF NOT EXISTS ${Q('Reports')} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    intern_id VARCHAR(10) NOT NULL,
    report_title VARCHAR(50),
    report_description TEXT,
    file_path VARCHAR(255),
    status ENUM('Pending', 'Reviewed', 'Rejected') DEFAULT 'Pending',
    due_date DATE,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP NULL,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

    db.query(createReportsTable, (err) => {
        if (err) {
            console.error('Error creating prescriptions table:', err);
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
    uploaded_by ENUM('Intern','HR', 'Lead'),
    status ENUM('Pending', 'Reviewed', 'Rejected') DEFAULT 'Pending',
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,                
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


 `;

    db.query(createDocumentsTable, (err) => {
        if (err) {
            console.error('Error creating prescriptions table:', err);
        }
    });
    // Ensure missing columns exist (safety for older schema)
    db.query("ALTER TABLE documents ADD COLUMN IF NOT EXISTS status ENUM('Pending','Reviewed','Rejected') DEFAULT 'Pending'", () => {});
    db.query("ALTER TABLE documents ADD COLUMN IF NOT EXISTS uploaded_by ENUM('Intern','HR','Lead') DEFAULT 'Intern'", () => {});
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
  CONSTRAINT leave_requests_ibfk_1 FOREIGN KEY (intern_id) REFERENCES interns (intern_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

 `;

    db.query(createLeaveTable, (err) => {
        if (err) {
            console.error('Error creating prescriptions table:', err);
        }
    });
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

// Lightweight token encode/decode without secret
function encodeToken(payload) {
    try {
        return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    } catch (e) {
        return null;
    }
}

function decodeToken(token) {
    try {
        const json = Buffer.from(token, 'base64').toString('utf8');
        return JSON.parse(json);
    } catch (e) {
        return null;
    }
}

//function to get the doctor id
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    const user = decodeToken(token);
    if (!user) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
}
//login
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const users = await executeQuery("SELECT * FROM users WHERE email = ?", [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ message: "Invalid email" });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password_hash);
        
        if (!match) {
            return res.status(401).json({ message: "Invalid password" });
        }

        if (user.role === "Intern") {
            const internResults = await executeQuery(
                "SELECT intern_id, name FROM interns WHERE email = ?", 
                [email]
            );

            if (internResults.length === 0) {
                return res.status(401).json({ message: "Intern not found" });
            }

            await executeQuery(
                `INSERT INTO Attendance (intern_id, attendance_date, status, check_in) 
                 VALUES (?, CURDATE(), 'Present', CURTIME())`,
                [internResults[0].intern_id]
            );

            const token = encodeToken({ 
                id: user.id, 
                name: user.full_name, 
                role: user.role, 
                intern_id: internResults[0].intern_id 
            });
            return res.json({ token });
        }

        const token = encodeToken({ id: user.id, role: user.role });
        return res.json({ token });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

app.post('/api/forgotpass', (req, res) => {
    const { email, npass } = req.body;

    if (!email || !npass) {
        return res.status(400).json({ error: "Email and new password are required" });
    }

    const query = `SELECT id FROM users WHERE email=?`;
    db.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: "No user with that email" });
        }

        // ✅ Hash the password AFTER confirming the email exists
        const hashed_pass = bcrypt.hashSync(npass, 10);

        const sql = `UPDATE users SET password_hash = ? WHERE email = ?`;
        db.query(sql, [hashed_pass, email], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });

            if (result.affectedRows === 0) {
                return res.status(404).json({ ok: false, message: "No user with that email" });
            }

            return res.json({ ok: true, message: "Password updated successfully" });
        });
    });
});

//for register
app.post("/api/register", upload.single("profileImage"), async (req, res) => {
    try {
        const { username, email, password, fullname, ph, department, internRole, internid } = req.body;
        if (!username || !email || !password || !fullname) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const hashed_pass = await bcrypt.hash(password, 10);

        let picpath = null;
        if (req.file) {
            // Ensure members dir and move file
            const extension = path.extname(req.file.originalname) || '.png';
            picpath = `members/${username}${extension}`;
            const newPath = path.join(
                process.env.NODE_ENV === 'production' ? uploadMembersDir : path.join(__dirname, 'members'),
                `${username}${extension}`
            );
            try {
                if (!fs.existsSync(path.dirname(newPath))) {
                    fs.mkdirSync(path.dirname(newPath), { recursive: true, mode: 0o755 });
                }
                await fs.promises.rename(req.file.path, newPath);
            } catch (e) {
                console.error('Failed to move profile image:', e);
                // Do not fail registration if image move fails
                picpath = null;
            }
        }

        // Insert user and catch duplicate errors explicitly
        try {
            await executeQuery(
                `INSERT INTO ${process.env.DB_NAME ? `\`${process.env.DB_NAME}\`.` : ''}users (username, email, password_hash, full_name, phone, role, profile_image) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [username, email, hashed_pass, fullname, ph || null, department || 'patient', picpath]
            );
        } catch (e) {
            if (e && e.code === 'ER_DUP_ENTRY') {
                return res.status(409).json({ error: 'User already exists (email or username)' });
            }
            console.error('User insert failed:', e);
            return res.status(500).json({ error: 'Failed to save user' });
        }

        if ((department || '').toLowerCase() === "intern") {
            try {
            await executeQuery(
                `INSERT INTO ${process.env.DB_NAME ? `\`${process.env.DB_NAME}\`.` : ''}interns(intern_id, name, internrole, email, phone) VALUES (?, ?, ?, ?, ?)`,
                    [internid, fullname, internRole || null, email, ph || null]
                );
            } catch (e) {
                console.error('Intern insert failed:', e);
                // Don't hard fail user registration on intern row failure
            }
        }

        res.json({ ok: true, message: "Registration successful" });
    } catch (err) {
        console.error('Registration error:', { body: req.body, error: err });
        res.status(500).json({ error: "Server error", details: err.message });
    }
});

//interndashboard

app.get('/api/insterdashboard-stats', async (req, res) => {
    try {
        const intern_id = req.query.intern_id; // use query param
        if (!intern_id) return res.status(400).json({ message: "intern_id is required" });

        const today = new Date().toISOString().split('T')[0];

        // 1. Check-in/out today
        const checkinout = await new Promise((resolve, reject) => {
            db.query(
                `SELECT check_in, check_out 
                 FROM Attendance 
                 WHERE intern_id = ? AND attendance_date = ?`,
                [intern_id, today],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results[0] || null); // return first row or null
                }
            );
        });

        // 2. Attendance summary
        const attdata = await new Promise((resolve, reject) => {
            db.query(
                `SELECT 
                    SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS total_present,
                    SUM(CASE WHEN status='Absent' THEN 1 ELSE 0 END) AS total_absent,
                    SUM(CASE WHEN status='Leave' THEN 1 ELSE 0 END) AS total_leave
                 FROM Attendance
                 WHERE intern_id = ?`,
                [intern_id],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results[0] || null);
                }
            );
        });

        // 3. Performance score
        const perresults = await new Promise((resolve, reject) => {
            db.query(
                `SELECT 
                    ((SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) * 1) +
                     (SUM(CASE WHEN status='Leave' THEN 1 ELSE 0 END) * 0.5) +
                     (SUM(Case when status='Absent' Then 1 Else 0 End)*0.5))
                     / COUNT(*) * 100 AS performance_score,

                    ((SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) * 1) +
                    (SUM(CASE WHEN status='Leave' THEN 1 ELSE 0 END) * 0.5)+
                    (SUM(Case when status='Absent' Then 1 Else 0 End)*0.6)) 
                    / COUNT(*) * 100 AS monthly_performance_score
                    

                 FROM Attendance
                 WHERE intern_id = ? 
                    AND MONTH(attendance_date) = MONTH(CURDATE())
                    AND YEAR(attendance_date) = YEAR(CURDATE())`,
                [intern_id],
                (err, results) => {
                    if (err) reject(err);
                    else resolve(results[0] || {
                        monthly_attendance_percentage: 0,
                        monthly_performance_score: 0,
                        monthly_present: 0,
                        monthly_absent: 0,
                        monthly_leave: 0
                    });
                }
            );
        });

        res.json({
            checkinout,
            attendance_summary: attdata,
            performance_summary: perresults
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "DB error", error: err });
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
        res.status(500).json({ message: "DB error", error: err });
    }
});



// Get monthly attendance percentage (Present/Absent/Leave)
app.get('/api/attendance/monthly', async (req, res) => {
    try {
        const intern_id = req.query.intern_id;
        if (!intern_id) return res.status(400).json({ message: "intern_id required" });

        const results = await new Promise((resolve, reject) => {
            db.query(
                `SELECT 
                    COALESCE(SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END), 0) AS present,
                    COALESCE(SUM(CASE WHEN status='Absent' THEN 1 ELSE 0 END), 0) AS absent,
                    COALESCE(SUM(CASE WHEN status='Leave' THEN 1 ELSE 0 END), 0) AS leave_days,
                    COUNT(*) AS total
                 FROM Attendance
                 WHERE intern_id = ?
                   AND MONTH(attendance_date) = MONTH(CURDATE())
                   AND YEAR(attendance_date) = YEAR(CURDATE())`,
                [intern_id],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows[0]);
                }
            );
        });

        const monthlyPercentage = results.total > 0
            ? ((results.present + 0.5 * results.leave_days) / results.total) * 100
            : 0;

        res.json({
            present: results.present,
            absent: results.absent,
            leave: results.leave_days,
            monthly_percentage: parseFloat(monthlyPercentage.toFixed(2))
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "DB error", error: err });
    }
});


//intern chekout
app.post('/api/checkout', (req, res) => {
    const { intern_id, check_out } = req.body;
    db.query('UPDATE Attendance SET check_out = ? WHERE intern_id = ? AND attendance_date = ?', [check_out, intern_id, getTodayIST()], (err, results) => {
        if (err) res.status(500).json({ message: "DB error", error: err });
        else res.json({ message: "Checked out successfully" });
        console.log(results);
    });
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
            status: row.status || "pending"
        }));

        console.log(tasks);
        res.json(tasks);

    } catch (err) {
        console.error("Error fetching tasks:", err);
        res.status(500).json({ message: "DB error", error: err });
    }
});

//get tasks
app.get('/api/gettasks/:intern_id', (req, res) => {
    const intern_id = req.params.intern_id;
    console.log(intern_id)
    const query = `
        SELECT task_id, task_title, due_date, status, priority
        FROM tasks
        WHERE intern_id = ?
        ORDER BY assigned_date DESC
    `;

    db.query(query, [intern_id], (err, result) => {
        if (err) {
            console.error("DB Fetch Error:", err);
            return res.status(500).json({ message: "Database error", error: err });
        }
        console.log(result)
        // Transform to frontend format
        const tasks = result.map(task => ({
            id: task.task_id,
            title: task.task_title,
            dueDate: task.due_date,
            status: task.status,
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
        INSERT INTO tasks (intern_id, task_title, task_description, priority, status, assigned_date, due_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(query, [intern_id, task_title, task_description, priority, status, assignedDate, dueDate], (err, result) => {
        if (err) {
            console.error("DB Error:", err);
            return res.status(500).json({ message: err });
        }
        console.log("DB Insert Result:", result);
        return res.json({ message: "Task added successfully", result });
    });
});

//cahnge task status
// Change task status
app.put('/api/changetask/:taskId', (req, res) => {
    const taskId = req.params.taskId;
    const { status } = req.body; 

    // Validate status
    const validStatuses = ['pending', 'in-progress', 'completed'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status value' });
    }

    const query = `
        UPDATE tasks
        SET status = ?
        WHERE task_id = ?
    `;

    db.query(query, [status, taskId], (err, result) => {
        if (err) {
            console.error("DB Update Error:", err);
            return res.status(500).json({ message: 'Database error', error: err });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }

        return res.json({ message: 'Task status updated successfully' });
    });
});

// GET /api/reports?intern_id=&project=&status=
// Fetch reports for an intern with optional filters
app.get('/api/reports', (req, res) => {
    const { intern_id, project, status } = req.query;
    if (!intern_id) return res.status(400).json({ error: 'intern_id is required' });

    let sql = `
      SELECT id, report_title, report_description, file_path, status, submitted_at, due_date 
      FROM reports 
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
        console.error(err);
        return res.status(500).json({ error: 'Failed to fetch reports' });
      }
      const reports = rows.map(r => ({
        id: r.id,
        title: r.report_title,
        description: r.report_description,
        file: r.file_path,
        status: r.status,
        submittedAt: r.submitted_at ? new Date(r.submitted_at).toISOString().slice(0, 10) : null,
        dueDate: r.due_date ? new Date(r.due_date).toISOString().slice(0, 10) : null,
      }));
      res.json(reports);
    });
  });
  
  // POST /api/reports/upload
  // Upload a new report file
app.post('/api/reports/upload', upload.single('file'), (req, res) => {
    const { intern_id, report_title, report_description, due_date } = req.body;
    if (!intern_id || !report_title) return res.status(400).json({ error: 'intern_id and report_title are required' });
    if (!req.file) return res.status(400).json({ error: 'Report file is required' });

    const filePath = 'uploads/' + req.file.filename;
    const sql = `
      INSERT INTO reports (intern_id, report_title, report_description, file_path, status, due_date, submitted_at)
      VALUES (?, ?, ?, ?, 'Pending', ?, NOW())
    `;
    db.query(sql, [intern_id, report_title, report_description || null, filePath, due_date || null], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to upload report' });
      }
      res.json({ message: 'Report uploaded successfully' });
    });
  });
  
  // GET /api/reports/download/:id
  // Download a report file by report ID
app.get('/api/reports/download/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT report_title, file_path FROM reports WHERE id = ?', [id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch report' });
      if (rows.length === 0) return res.status(404).json({ error: 'Report not found' });
      const { file_path, report_title } = rows[0];
      const fullPath = path.join(__dirname, file_path);
      if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'File not found' });
      res.download(fullPath, report_title);
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
  
      const sql = `UPDATE reports SET status = ?, reviewed_at = NOW() WHERE id = ?`;
  const [result] = await dbp().query(sql, [status, id]);
  
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Report not found' });
  
      res.json({ message: 'Status updated successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to update status' });
    }
  });
  


// Update the dashboard stats endpoint
app.get('/api/dashboard-stats', (req, res) => {
    const todayIST = getTodayIST();
    const query = `
        SELECT 
            COUNT(*) as total_appointments,
            SUM(CASE WHEN DATE(appointment_date) = ? AND status = 'confirmed' THEN 1 ELSE 0 END) as appointments_today,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_confirmations,
            SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_appointments
        FROM appointments
    `;
    db.query(query, [todayIST], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results[0]);
    });
});

//submit report
app.post('/api/submitreport', upload.single('reportFile'), (req, res) => {
    const { intern_id, report_description,report_title } = req.body;

    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const filePath = req.file.path;

    const query = `
        INSERT INTO reports (intern_id, report_title,report_description, file_path)
        VALUES (?, ?, ?,?)
    `;

    db.query(query, [intern_id, report_title,report_description, filePath], (err, result) => {
        if (err) {
            console.error("DB Insert Error:", err);
            return res.status(500).json({ message: 'Database error', error: err });
        }

        return res.json({ message: 'Report submitted successfully', reportId: result.insertId });
    });
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

// Add this helper function at the top
function getCurrentISTDate() {
    const now = new Date();
    const istOffset = 5.5 * 60 * 60000; // IST offset in milliseconds
    const istDate = new Date(now.getTime() + istOffset);
    return istDate.toISOString().split('T')[0];
}

//api to get the id and role
app.get("/api/profile", authenticateToken, (req, res) => {
    db.query("SELECT id, role,username,full_name,profile_image FROM users WHERE id = ?", [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ message: "DB error" });
        if (results.length === 0) return res.status(404).json({ message: "User not found" });

        if (results[0].role == "Intern") {
            results[0].intern_id = req.user.intern_id;
        }
        console.log(results[0]);
        res.json(results[0]);
    });
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
    const fields = req.body;
    if (Object.keys(fields).length === 0) {
        return res.status(400).json({ message: "No fields provided to update" });
    }

    db.query("UPDATE doctor_ui SET ? WHERE doctor_id = ?", [fields, doctorId], (err, results) => {
        if (err) return res.status(500).json({ message: "DB error", error: err });

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
           FROM attendance
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
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  });
  
  
  // API: Check-in or Check-out for today for an intern
  app.post('/api/attendance/checkinout', async (req, res) => {
    try {
      const { intern_id } = req.body;
      if (!intern_id) {
        return res.status(400).json({ error: 'intern_id is required' });
      }
  
      const today = new Date();
      const todayStr = today.toISOString().slice(0, 10);
      const nowTime = today.toTimeString().slice(0, 8);
  
      // Check if attendance record exists for today
      const rows = await new Promise((resolve, reject) => {
        db.query(
          'SELECT * FROM attendance WHERE intern_id = ? AND attendance_date = ?',
          [intern_id, todayStr],
          (err, results) => {
            if (err) reject(err);
            else resolve(results);
          }
        );
      });
  
      if (rows.length === 0) {
        // First check-in: insert record with check_in = now
        await new Promise((resolve, reject) => {
          db.query(
            'INSERT INTO attendance (intern_id, attendance_date, status, check_in) VALUES (?, ?, ?, ?)',
            [intern_id, todayStr, 'Present', nowTime],
            (err, results) => {
              if (err) reject(err);
              else resolve(results);
            }
          );
        });
        return res.json({ action: 'checkin', checkIn: nowTime, checkOut: null });
      } else {
        const attendance = rows[0];
  
        if (!attendance.check_out) {
          // Check-out: update record with check_out = now
          await new Promise((resolve, reject) => {
            db.query(
              'UPDATE attendance SET check_out = ? WHERE id = ?',
              [nowTime, attendance.id],
              (err, results) => {
                if (err) reject(err);
                else resolve(results);
              }
            );
          });
          return res.json({ action: 'checkout', checkIn: attendance.check_in, checkOut: nowTime });
        } else {
          // Already checked out today
          return res.status(400).json({ error: 'Already checked out for today' });
        }
      }
    } catch (error) {
      console.error('Error in check-in/out:', error);
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
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
           FROM interns i
           LEFT JOIN attendance a 
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
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
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
           FROM tasks
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
           FROM tasks
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
           FROM reports
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
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
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
           FROM interns i
           LEFT JOIN tasks t ON i.intern_id = t.intern_id
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
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  });
  
  
  
// Create a leave request
app.post('/api/leave-requests', async (req, res) => {
    try {
      const { intern_id, from_date, to_date, number_of_working_days, reason } = req.body;
      if (!intern_id || !from_date || !to_date || !number_of_working_days || !reason) {
        return res.status(400).json({ error: 'All fields are required' });
      }
  
      // Insert leave request
      await new Promise((resolve, reject) => {
        db.query(
          `INSERT INTO leave_requests (intern_id, from_date, to_date, number_of_working_days, reason) VALUES (?, ?, ?, ?, ?)`,
          [intern_id, from_date, to_date, number_of_working_days, reason],
          (err, results) => {
            if (err) reject(err);
            else resolve(results);
          }
        );
      });
  
      res.json({ message: 'Leave request submitted successfully' });
    } catch (error) {
      console.error('Error creating leave request:', error);
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  });
  
  // Get leave requests for an intern
  app.get('/api/leave-requests/:intern_id', async (req, res) => {
    try {
      const internId = req.params.intern_id;
      if (!internId) {
        return res.status(400).json({ error: 'intern_id is required' });
      }
  
      const rows = await new Promise((resolve, reject) => {
        db.query(
          `SELECT id, from_date, to_date, number_of_working_days, reason, status, requested_at 
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
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  });
  app.get('/api/documents', (req, res) => {
    const internId = req.query.intern_id;
    if (!internId) return res.status(400).json({ error: 'intern_id query parameter is required' });
  
    let sql = `SELECT id, doc_title, upload_date, status, file_path 
               FROM documents WHERE intern_id = ?`;
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
  
  // ------------------- GET submitted documents (uploaded by intern) -------------------
  app.get('/api/documents/submitted', (req, res) => {
    const internId = req.query.intern_id;
    if (!internId) return res.status(400).json({ error: 'intern_id is required' });
  
    const sql = `SELECT id, doc_title, upload_date, status, file_path
                 FROM documents
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
  
  // ------------------- GET issued documents (uploaded by others) -------------------
  app.get('/api/documents/issued', (req, res) => {
    const internId = req.query.intern_id;
    if (!internId) return res.status(400).json({ error: 'intern_id is required' });
  
    const sql = `SELECT id, doc_title, upload_date, status, file_path
                 FROM documents
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
  app.post('/api/documents/upload', upload.single("file"), (req, res) => {
    console.log("BODY:", req.body);
    console.log("FILE:", req.file);
  
    const { intern_id, customFileName, fileLink } = req.body;
    if (!intern_id) return res.status(400).json({ error: "intern_id is required" });
  
    let filename = null;
    let filePath = null;
  
    if (req.file) {
      filename = customFileName?.trim() || req.file.originalname;
      filePath = req.file.path;
    } else if (fileLink && fileLink.trim() !== "") {
      filePath = fileLink.trim();
      filename = customFileName?.trim() || "Link";
    } else {
      return res.status(400).json({ error: "No file or link provided" });
    }
  
    const sql = `INSERT INTO documents 
                 (intern_id, doc_title, upload_date, status, file_path, uploaded_by) 
                 VALUES (?, ?, NOW(), 'Pending', ?, 'Intern')`;
  
    db.query(sql, [intern_id, filename, filePath], (err, result) => {
      if (err) {
        console.error("Failed to save document:", err);
        return res.status(500).json({ error: "Failed to upload document" });
      }
      res.json({ message: "✅ Document uploaded successfully" });
    });
  });
  
  
  // ------------------- DOWNLOAD document by ID -------------------
  app.get('/api/documents/download/:id', (req, res) => {
    const docId = req.params.id;
  
    const sql = `SELECT doc_title, file_path FROM documents WHERE id = ?`;
    db.query(sql, [docId], (err, rows) => {
      if (err) {
        console.error('Failed to fetch document:', err);
        return res.status(500).json({ error: 'Failed to download document' });
      }
      if (rows.length === 0) return res.status(404).json({ error: 'Document not found' });
  
      const doc = rows[0];
      if (doc.file_path.startsWith('http')) return res.redirect(doc.file_path);
  
      const fullPath = path.join(__dirname, doc.file_path);
      if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'File not found on server' });
  
      res.download(fullPath, doc.doc_title);
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
                error: 'Could not save appointment',
                details: err.message
            });
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
            res.status(500).json({ error: err.message });
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
                res.status(500).json({ error: err.message });
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
                res.status(500).json({ error: err.message });
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
            res.status(500).json({ error: err.message });
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
            res.status(500).json({ error: err.message });
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
            res.status(500).json({ error: err.message });
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
            res.status(500).json({ error: err.message });
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
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

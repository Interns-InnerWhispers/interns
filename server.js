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
const bcrypt=require('bcrypt');
const app = express();
const streamifier = require('streamifier');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const JWT_SECRET =process.env.SECRET_KEY;
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUDNAME,
    api_key: process.env.CLOUDINARY_API,
    api_secret: process.env.CLOUDINARY_APISEC
});
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
  origin: "*",
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  optionsSuccessStatus: 204
}));


app.options('*', cors());
app.set('trust proxy', 1); 



const upload = multer({ storage: multer.memoryStorage() });

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
                COUNT(CASE WHEN status = 'Present' THEN 1 END) * 100.0 / COUNT(*) as attendance_rate
            FROM Attendance 
            WHERE attendance_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 6 DAY) AND CURDATE()
            GROUP BY DAYNAME(attendance_date), attendance_date
            ORDER BY attendance_date
        `);
        
        const [lastWeekData] = await executeQuery(`
            SELECT 
                DAYNAME(attendance_date) as day_name,
                COUNT(CASE WHEN status = 'Present' THEN 1 END) * 100.0 / COUNT(*) as attendance_rate
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
            ApprovedLeaves:ApprovedLeaves[0].count,
            RejectedLeaves:RejectedLeaves[0].count,
            onLeave:onLeave[0].count,
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
            intern_id:row.intern_id,
            department:row.department,
            name: row.name,
            type: row.leave_type,
            startDate:row.fromDate,
            endDate:row.toDate,
            dates: row.fromDate === row.toDate ? 
                    row.fromDate : 
                    `${row.fromDate}–${row.toDate}`,
            reason:row.reason,
            days:row.days,
            status: row.status
        }));
        console.log("leave request",leaveRequests)
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
    const result = new Array(7).fill(0); // Default to 0% for all days
    
    data.forEach(row => {
        const dayIndex = daysOfWeek.indexOf(row.day_name);
        if (dayIndex !== -1) {
            result[dayIndex] = Math.round(parseFloat(row.attendance_rate) || 0);
        }
    });
    
    // If no data for weekends, set to 0
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

app.get('/health', async (req, res) => {
    try {
        const [result] = await executeQuery('SELECT 1');
        if (result[0]['1'] === 1) {
            res.send('');
        } else {
            res.status(500).send('');
        }
    } catch {
        res.status(500).send('');
    }
});

// Upload example
app.post('/upload', upload.single('file'), (req, res) => {
    res.json({
        message: '',
        message: '✅ File uploaded successfully',
        file: req.file
    });
});

// Example DB query
app.get('/users', async (req, res) => {
    try {
        const [rows] = await executeQuery("SELECT * FROM users");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);
  
  // Join HR dashboard room
  socket.on('join-hr-dashboard', () => {
    socket.join('hr-dashboard');
    console.log('👤 User joined HR dashboard room');
  });
  
  // Join intern room for personal updates
  socket.on('join-intern-room', (internId) => {
    socket.join(`intern-${internId}`);
    console.log(`👨‍💻 Intern ${internId} joined their room`);
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
    try {
        await db.query(`
            ALTER TABLE Interns
            ADD COLUMN department VARCHAR(50),
            ADD COLUMN HR_id INT,
            ADD COLUMN Team_id INT,
            ADD COLUMN attendance_percentage DECIMAL(5,2) DEFAULT 0.00,
            ADD COLUMN profile_image VARCHAR(255),
            ADD COLUMN status ENUM('Active', 'Inactive', 'Completed') DEFAULT 'Active',
            ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        `);

        console.log("✅ Interns table updated successfully");
    } catch (err) {
        console.error("❌ Update Error:", err.message);
    }
}
updateInternsTable();
    // Add foreign key constraints for Interns table
    db.query("ALTER TABLE Interns ADD CONSTRAINT fk_intern_hr FOREIGN KEY (HR_id) REFERENCES Interns(id)", () => {});
    db.query("ALTER TABLE Interns ADD CONSTRAINT fk_intern_team FOREIGN KEY (Team_id) REFERENCES Teams(id)", () => {});

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
            console.error('Error creating prescriptions table:', err);
        }
    });
async function UpdateAttendanceTable() {
    const queries = [
        `ALTER TABLE Attendance ADD COLUMN hours_worked DECIMAL(4,2) DEFAULT 0.00`,
        `ALTER TABLE Attendance ADD COLUMN note TEXT`,
        `ALTER TABLE Attendance MODIFY COLUMN status ENUM('Present','Absent','Leave','Late') DEFAULT 'Absent`
    ];

    for (let q of queries) {
        try {
            await db.query(q);
        } catch (e) {}
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
        `ALTER TABLE Reports ADD COLUMN report_type VARCHAR(50) DEFAULT 'weekly'`,
        `ALTER TABLE Reports ADD COLUMN submission_date DATE`,
        `ALTER TABLE Reports ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
        `ALTER TABLE Reports ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`,
        `ALTER TABLE Reports MODIFY COLUMN status ENUM('Pending','Reviewed','Rejected','Submitted') DEFAULT 'Submitted'`
    ];

    for (let q of queries) {
        try {
            await db.query(q);
        } catch (e) {}
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
    last_submission_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (intern_id) REFERENCES Interns(intern_id),
    UNIQUE KEY unique_intern_week (intern_id, week_start_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    `;

    db.query(createWeeklyReportsTable, (err) => {
        if (err) {
            console.error('Error creating weekly reports table:', err);
        } else {
            console.log('✅ Weekly reports table created successfully');
            
            // After table creation, populate it with all existing interns
            const currentWeekStart = new Date();
            const dayOfWeek = currentWeekStart.getDay();
            const diff = currentWeekStart.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
            currentWeekStart.setDate(diff);
            const weekStartDate = currentWeekStart.toISOString().split('T')[0];
            const sql = `
      ALTER TABLE weekly_reports 
      ADD COLUMN wednesday_report_id INT NULL,
      ADD COLUMN saturday_report_id INT NULL,
      ADD CONSTRAINT fk_wednesday_report 
        FOREIGN KEY (wednesday_report_id) REFERENCES Reports(id) ON DELETE SET NULL,
      ADD CONSTRAINT fk_saturday_report 
        FOREIGN KEY (saturday_report_id) REFERENCES Reports(id) ON DELETE SET NULL;
    `;

  db.query(sql , (err, result) => {
                if (err) {
                    console.error('Error adding columns to weekly reports table:', err);
                } else {
                    console.log('✅ Columns and foreign keys added successfully');
                }
            });

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
                    console.log(`✅ Weekly reports table populated with ${result.affectedRows} interns`);
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
            console.error('Error creating prescriptions table:', err);
        }
    });
    // Ensure missing columns exist (safety for older schema)
    db.query("ALTER TABLE Documents ADD COLUMN IF NOT EXISTS status ENUM('Pending','Reviewed','Rejected') DEFAULT 'Pending'", () => {});
    db.query("ALTER TABLE Documents ADD COLUMN IF NOT EXISTS uploaded_by ENUM('Intern','HR','Lead') DEFAULT 'Intern'", () => {});

    async function UpdateDocumentsTable() {
    const queries = [
        `ALTER TABLE Documents ADD COLUMN file_size INT`,
        `ALTER TABLE Documents ADD COLUMN category VARCHAR(50) DEFAULT 'General'`,
        `ALTER TABLE Documents ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`,
        `ALTER TABLE Documents ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`,
        `ALTER TABLE Documents MODIFY COLUMN uploaded_by ENUM('Intern','HR','Lead') DEFAULT 'Intern'`
    ];

    for (let q of queries) {
        try {
            await db.query(q);
        } catch (e) {}
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
    
    // Add leave_type column if it doesn't exist
    db.query("ALTER TABLE leave_requests ADD COLUMN IF NOT EXISTS leave_type ENUM('Sick', 'Casual', 'Annual', 'Maternity', 'Paternity') DEFAULT 'Casual'", (err) => {
        if (err) {
            console.error('Error adding leave_type column:', err);
        } else {
            console.log('✅ leave_type column added to leave_requests table');
        }
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
  const { text, emotions } = req.body;
  console.log(req.body)

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
        const [interns] = await executeQuery(`
            SELECT 
               *
            FROM Interns 
            ORDER BY created_at DESC
        `);
        
        // Transform data to match frontend expectations
        const transformedInterns = interns.map(intern => ({
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
            attendance: intern.attendance_percentage || 0,
            wed: 'Missing', 
            sat: 'Missing',
            university: intern.university || 'N/A',
            performance_score: intern.performance_score || 0,
            hr_id: intern.HR_id || 'N/A',
            team_id: intern.Team_id || 'N/A',
            profile_image: intern.profile_image || null,
            createdAt: intern.created_at,
            updatedAt: intern.updated_at
        }));
        
        res.json({ interns: transformedInterns });
    } catch (error) {
        console.error('Error fetching interns:', error);
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
            whereClause += ' AND (target_user_id = ? OR target_role = "all" OR target_role = ?)';
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
                   created_at as createdAt
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
        const { notify, description, type, targetUserId, targetRole } = req.body;
        
        if (!notify || !description) {
            return res.status(400).json({ error: 'notify and description are required' });
        }
        
        const notificationId = await createNotification(notify, description, type, targetUserId, targetRole);
        
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
            whereClause += ' AND (target_user_id = ? OR target_role = "all" OR target_role = ?)';
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
            whereClause += ' AND (target_user_id = ? OR target_role = "all" OR target_role = ?)';
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
        const { email, password } = req.body;
        console.log(email," ", password)
        const [users] = await executeQuery("SELECT * FROM users WHERE email = ?", [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ message: "Invalid email" });
        }

        const user = users[0];
        
        // Check if password_hash exists
        if (!user.password_hash) {
            console.error('User found but no password_hash:', user);
            return res.status(401).json({ message: "Invalid credentials" });
        }
        
        const match = await bcrypt.compare(password, user.password_hash);
        
        if (!match) {
            return res.status(401).json({ message: "Invalid password" });
        }
        console.log("user role",user.role)
        // If Intern — handle attendance
        if (user.role.toLowerCase() === "intern") {
            const internResults = await executeQuery(
                "SELECT intern_id, name FROM Interns WHERE email = ?", 
                [email]
            ); 

            if (internResults.length === 0) {
                return res.status(401).json({ message: "Intern not found" });
            }

            const internId = internResults[0][0].intern_id;
            console.log(internResults)
            console.log(internId)

            // Get current IST date & time
            const now = new Date();
            const istNow = new Date(now.getTime() + (5.5 * 60 * 60 * 1000)); // Convert UTC → IST
            const date = istNow.toISOString().slice(0, 10); // YYYY-MM-DD
            const time = istNow.toTimeString().slice(0, 8); // HH:MM:SS

            // ✅ Check if attendance already exists for today
            const existingAttendance = await executeQuery(
                `SELECT * FROM Attendance WHERE intern_id = ? AND attendance_date = ?`,
                [internId, date]
            );

            if (existingAttendance.length === 0) {
                // Insert only if not present already
                await executeQuery(
                    `INSERT INTO Attendance (intern_id, attendance_date, status, check_in)
                     VALUES (?, ?, 'Present', ?)`,
                    [internId, date, time]
                );
                //1
                // Emit real-time attendance update
                io.to('hr-dashboard').emit('attendance-update', {
                    intern_id: internId,
                    action: 'check-in',
                    time: time,
                    date: date
                });
                
                io.to(`intern-${internId}`).emit('personal-attendance', {
                    action: 'check-in',
                    time: time,
                    date: date
                });
            }

            // Create token
            const token = encodeToken({ 
                id: user.id, 
                name: user.full_name, 
                role: user.role, 
                intern_id: internId 
            });

            return res.json({ token });
        }

        // For non-intern users
        const token = encodeToken({ id: user.id, role: user.role });
        return res.json({ token });

    } catch (err) {
        console.error("Login error:", err);
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
        
        const hashed_pass = bcrypt.hashSync(password, 10);

        if (!req.file) {
            return res.status(400).json({ error: "Profile image is required" });
        }

        // Upload to Cloudinary
        const uploadResult = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder: `Interns/${internid}`,
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
        console.error(err);
        res.status(500).json({ error: "Server error", details: err.message });
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

app.put("/api/interns/updateimage/:id", upload.single("profileImage"), async (req, res) => {
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


// Helper to get IST date string (YYYY-MM-DD)
function getTodayIST() {
  const now = new Date();
  const offset = 5.5 * 60; // 5 hours 30 minutes in minutes
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  const ist = new Date(utc + offset * 60000);
  return ist.toISOString().slice(0, 10);
}

app.post('/api/checkout', (req, res) => {
  const { intern_id, check_out } = req.body;
  const attendance_date = getTodayIST();
  const checkOutTime = check_out || new Date().toISOString().slice(11, 19);

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
        return res.status(500).json({ message: 'DB error', error: err.message });
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
        'UPDATE Attendance SET check_out = ? WHERE intern_id = ? AND attendance_date = ?',
        [checkOutTime, intern_id, attendance_date],
        (err, result) => {
          if (err) {
            console.error('DB error:', err);
            return res.status(500).json({ message: 'DB error', error: err.message });
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
        return res.status(500).json({ message: 'DB error', error: err.message });
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
        FROM Tasks
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
        INSERT INTO Tasks (intern_id, task_title, task_description, priority, status, assigned_date, due_date)
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
        UPDATE Tasks
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
}); // <--- Added missing closing bracket

// Fetch weekly reports for reports.html dashboard
app.get('/api/reports', async (req, res) => {
  try {
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
            AND DAYOFWEEK(r.submitted_at) = 4
          ) THEN 'Submitted'
          ELSE 'Missing'
        END AS wed,

        -- Check actual Reports table for Saturday submissions this week  
        CASE 
          WHEN EXISTS (
            SELECT 1 FROM Reports r 
            WHERE r.intern_id = i.intern_id 
            AND DATE(r.submitted_at) >= ?
            AND DAYOFWEEK(r.submitted_at) = 7
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
         AND DAYOFWEEK(r.submitted_at) = 4
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS wednesday_file_path,

        (SELECT r.id
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND DAYOFWEEK(r.submitted_at) = 4
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS wednesday_report_id,

        (SELECT r.file_path 
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND DAYOFWEEK(r.submitted_at) = 7
         ORDER BY r.submitted_at DESC 
         LIMIT 1
        ) AS saturday_file_path,

        (SELECT r.id
         FROM Reports r 
         WHERE r.intern_id = i.intern_id 
         AND DATE(r.submitted_at) >= ?
         AND DAYOFWEEK(r.submitted_at) = 7
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
      due_date,
      file_path
    } = req.body;

    console.log(req.body);

    // ================= VALIDATION =================
    if (!intern_id) return res.status(400).json({ error: 'intern_id is required' });
    if (!report_title) return res.status(400).json({ error: 'report_title is required' });
    if (!file_path) return res.status(400).json({ error: 'file_path is required' });
    if (!due_date) return res.status(400).json({ error: 'due_date is required' });

    // ================= DATE HELPERS =================
    const formatDate = (date) => {
      return date.toLocaleDateString('en-CA'); // YYYY-MM-DD (LOCAL TIME)
    };

    const submissionDate = new Date();
    const dayOfWeek = submissionDate.getDay(); // 0=Sun, 3=Wed, 6=Sat

    // ================= ALLOW ONLY WED & SAT =================
    if (dayOfWeek !== 3 && dayOfWeek !== 6) {
      return res.status(400).json({
        error: 'Reports can only be submitted on Wednesday or Saturday'
      });
    }

    // ================= INSERT REPORT =================
    const insertSql = `
      INSERT INTO Reports 
      (intern_id, report_title, report_description, file_path, status, due_date, submitted_at)
      VALUES (?, ?, ?, ?, 'Pending', ?, NOW())
    `;

    const insertResult = await executeQuery(insertSql, [
      intern_id,
      report_title,
      report_description || null,
      file_path,
      due_date
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
    const isWednesday = dayOfWeek === 3;

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
app.get('/api/reports/download/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT report_title, file_path FROM Reports WHERE id = ?', [id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch report' });
      if (rows.length === 0) return res.status(404).json({ error: 'Report not found' });
      const { file_path, report_title } = rows[0];
      const fullPath = path.join(__dirname, file_path);
      if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'File not found' });
      res.download(fullPath, report_title);
    });
  });

  // GET /api/reports/download-file
  // Download a report file by file path
app.get('/api/reports/download-file', (req, res) => {
    const filePath = req.query.path;
    if (!filePath) {
      return res.status(400).json({ error: 'File path is required' });
    }
    
    const fullPath = path.join(__dirname, filePath);
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Get filename from path
    const fileName = filePath.split('/').pop() || 'report';
    res.download(fullPath, fileName);
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
  
      res.json({ message: 'Status updated successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to update status' });
    }
  });

// Debug endpoint to check Reports table data
app.get('/api/debug/reports', (req, res) => {
  const sql = `
    SELECT 
      id,
      intern_id,
      report_title,
      DATE(submitted_at) as submitted_date,
      DAYOFWEEK(submitted_at) as day_of_week,
      DAYNAME(submitted_at) as day_name,
      file_path,
      status
    FROM Reports 
    ORDER BY submitted_at DESC 
    LIMIT 10
  `;
  
  db.query(sql, (err, rows) => {
    if (err) {
      console.error('Debug query error:', err);
      return res.status(500).json({ error: 'Debug query failed' });
    }
    
    console.log('=== DEBUG: Reports Table Data ===');
    console.log('Number of recent reports:', rows.length);
    console.log('Sample reports:', rows);
    
    res.json({
      message: 'Debug data from Reports table',
      count: rows.length,
      data: rows
    });
  });
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
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/submitreport', async (req, res) => {
  try {
    const { intern_id, report_title, report_description, file_path } = req.body;

    if (!intern_id || !report_title || !file_path) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const query = `
      INSERT INTO Reports (intern_id, report_title, report_description, file_path)
      VALUES (?, ?, ?, ?)
    `;

    const [result] = await executeQuery(query, [intern_id, report_title, report_description, file_path]);
    res.json({ message: 'Report submitted successfully', reportId: result.insertId });
  } catch (err) {
    console.error("DB Insert Error:", err);
    res.status(500).json({ message: 'Database error', error: err });
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
            error: 'Could not save appointment',
            details: err.message
        });
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
          'SELECT * FROM Attendance WHERE intern_id = ? AND attendance_date = ?',
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
            'INSERT INTO Attendance (intern_id, attendance_date, status, check_in) VALUES (?, ?, ?, ?)',
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
              'UPDATE Attendance SET check_out = ? WHERE id = ?',
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
  
  // Update leave request status (approve/reject)
  app.put('/api/leave-requests/:id/status', async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      
      if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be Approved or Rejected' });
      }
  
      const result = await new Promise((resolve, reject) => {
        db.query(
          `UPDATE leave_requests SET status = ? WHERE id = ?`,
          [status, id],
          (err, results) => {
            if (err) reject(err);
            else resolve(results);
          }
        );
      });
  
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Leave request not found' });
      }
  
      res.json({ message: `Leave request ${status.toLowerCase()} successfully` });
    } catch (error) {
      console.error('Error updating leave request:', error);
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
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
  const categoryFilter = category && category !== 'All' ? `AND category='${category}'` : '';

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

  db.query(expenseSummaryQuery, (err, expenseRows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error fetching expense summary' });
    }

    const expenseData = expenseRows[0];
    console.log(expenseData)
    db.query(monthlyQuery, (err2, monthlyRows) => {
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

// Start the server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

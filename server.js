
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcryptjs");
const path = require("path");

const User = require("./models/User");
const Attendance = require("./models/Attendance");
const Leave = require("./models/Leave");
const Notification = require("./models/Notification");
const { requireLogin, requireAdmin } = require("./middleware/auth");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  name: "student.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: "sessions"
  }),
    cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

function safeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    registerNo: user.registerNo,
    department: user.department
  };
}

function validDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value || "") &&
    !Number.isNaN(Date.parse(value));
}

function sendError(res, error) {
  console.error(error);
  res.status(500).json({ message: "Server error. Please try again." });
}

// Create the initial administrator
async function createAdmin() {
  const email = process.env.ADMIN_EMAIL.toLowerCase();
  let admin = await User.findOne({ email });

  if (!admin) {
    const password = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await User.create({
      name: process.env.ADMIN_NAME,
      email,
      password,
      role: "admin"
    });
    console.log("Initial administrator created.");
  } else if (admin.role !== "admin") {
    throw new Error("ADMIN_EMAIL belongs to a non-admin account.");
  }
}

// Register a student
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, registerNo, department } = req.body;

    if (!name || !email || !password || password.length < 8) {
      return res.status(400).json({
        message: "Enter your name, email and a password of at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (normalizedEmail === process.env.ADMIN_EMAIL.toLowerCase()) {
      return res.status(400).json({ message: "This email is reserved." });
    }

    const hashed = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashed,
      registerNo: registerNo || "",
      department: department || "",
      role: "student"
    });

    req.session.userId = user._id.toString();
    req.session.role = user.role;

    res.status(201).json({ message: "Registration successful.", user: safeUser(user) });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ message: "Email already registered." });
    }
    sendError(res, error);
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(req.body.password || "", user.password))) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    req.session.regenerate((error) => {
      if (error) return sendError(res, error);

      req.session.userId = user._id.toString();
      req.session.role = user.role;

      req.session.save((saveError) => {
        if (saveError) return sendError(res, saveError);
        res.json({
          message: "Login successful.",
          user: safeUser(user)
        });
      });
    });
  } catch (error) {
    sendError(res, error);
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) return sendError(res, error);
    res.clearCookie("student.sid");
    res.json({ message: "Logged out successfully." });
  });
});

// Current logged-in user
app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(401).json({ message: "Please log in again." });
    res.json({ user: safeUser(user) });
  } catch (error) {
    sendError(res, error);
  }
});

// Student dashboard
app.get("/api/dashboard", requireLogin, async (req, res) => {
  try {
    if (req.session.role === "admin") {
      const [students, pendingLeaves, attendanceCount] = await Promise.all([
        User.countDocuments({ role: "student" }),
        Leave.countDocuments({ status: "Pending" }),
        Attendance.countDocuments()
      ]);

      return res.json({ students, pendingLeaves, attendanceCount });
    }

    const id = req.session.userId;
    const [records, leaves, notifications] = await Promise.all([
      Attendance.find({ student: id }).sort({ date: -1 }).limit(100),
      Leave.find({ student: id }).sort({ createdAt: -1 }),
      Notification.find({ user: id }).sort({ createdAt: -1 }).limit(30)
    ]);

    const total = records.length;
    const present = records.filter(r => r.status === "Present").length;

    res.json({
      total,
      present,
      absent: total - present,
      percentage: total ? Math.round(present / total * 100) : 0,
      records,
      leaves,
      notifications
    });
  } catch (error) {
    sendError(res, error);
  }
});

// Submit a leave request
app.post("/api/leaves", requireLogin, async (req, res) => {
  try {
    if (req.session.role !== "student") {
      return res.status(403).json({ message: "Only students can request leave." });
    }

    const { fromDate, toDate, reason } = req.body;

    if (!validDate(fromDate) || !validDate(toDate) ||
        fromDate > toDate || !reason || !reason.trim()) {
      return res.status(400).json({ message: "Enter valid dates and a reason." });
    }

    const leave = await Leave.create({
      student: req.session.userId,
      fromDate,
      toDate,
      reason: reason.trim()
    });

    res.status(201).json({ message: "Leave request submitted.", leave });
  } catch (error) {
    sendError(res, error);
  }
});

// Student notifications
app.get("/api/notifications", requireLogin, async (req, res) => {
  try {
    const notifications = await Notification.find({
      user: req.session.userId
    }).sort({ createdAt: -1 }).limit(50);

    res.json(notifications);
  } catch (error) {
    sendError(res, error);
  }
});

// Admin: list students
app.get("/api/admin/students", requireLogin, requireAdmin, async (req, res) => {
  try {
    const students = await User.find({ role: "student" })
      .select("-password").sort({ name: 1 });
    res.json(students);
  } catch (error) {
    sendError(res, error);
  }
});

// Admin: mark attendance
app.post("/api/admin/attendance", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { studentId, date, subject, status } = req.body;

    if (!mongoose.isValidObjectId(studentId) || !validDate(date) ||
        !subject || !["Present", "Absent"].includes(status)) {
      return res.status(400).json({ message: "Invalid attendance details." });
    }

    const student = await User.findOne({ _id: studentId, role: "student" });
    if (!student) return res.status(404).json({ message: "Student not found." });

    const record = await Attendance.findOneAndUpdate(
      { student: studentId, date, subject: subject.trim() },
      { status, markedBy: req.session.userId },
      { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
    );

    res.json({ message: "Attendance saved.", record });
  } catch (error) {
    sendError(res, error);
  }
});

// Admin: view leave requests
app.get("/api/admin/leaves", requireLogin, requireAdmin, async (req, res) => {
  try {
    const leaves = await Leave.find()
      .populate("student", "name email registerNo department")
      .sort({ createdAt: -1 });
    res.json(leaves);
  } catch (error) {
    sendError(res, error);
  }
});

// Admin: approve or reject a leave request
app.patch("/api/admin/leaves/:id", requireLogin, requireAdmin, async (req, res) => {
  try {
    const { status, reviewNote } = req.body;

    if (!["Approved", "Rejected"].includes(status)) {
      return res.status(400).json({ message: "Choose Approved or Rejected." });
    }

    const leave = await Leave.findById(req.params.id);
    if (!leave) return res.status(404).json({ message: "Leave request not found." });

    if (leave.status !== "Pending") {
      return res.status(400).json({ message: "This request has already been reviewed." });
    }

    leave.status = status;
    leave.reviewedBy = req.session.userId;
    leave.reviewNote = (reviewNote || "").trim();
    await leave.save();

    await Notification.create({
      user: leave.student,
      message: `Your leave from ${leave.fromDate} to ${leave.toDate} was ${status.toLowerCase()}.`
    });

    res.json({ message: `Leave ${status.toLowerCase()}.`, leave });
  } catch (error) {
    sendError(res, error);
  }
});

// Admin: attendance and leave report
app.get("/api/admin/reports", requireLogin, requireAdmin, async (req, res) => {
  try {
    const [students, records, pending, approved, rejected] = await Promise.all([
      User.countDocuments({ role: "student" }),
      Attendance.countDocuments(),
      Leave.countDocuments({ status: "Pending" }),
      Leave.countDocuments({ status: "Approved" }),
      Leave.countDocuments({ status: "Rejected" })
    ]);

    res.json({ students, attendanceRecords: records, pending, approved, rejected });
  } catch (error) {
    sendError(res, error);
  }
});

// Frontend fallback
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

async function start() {
  if (!process.env.MONGODB_URI || !process.env.SESSION_SECRET ||
      !process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    throw new Error("Please configure MONGODB_URI, SESSION_SECRET and admin credentials.");
  }

  await mongoose.connect(process.env.MONGODB_URI);
  await createAdmin();

  const port = process.env.PORT || 3000;
  app.listen(port, "0.0.0.0", () => {
    console.log(`Website running on port ${port}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});

require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// ================= CONFIG =================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URLS = process.env.FRONTEND_URLS.split(",");

// Enable CORS
app.use(cors({
  origin: FRONTEND_URLS,
  credentials: true
}));
app.use(bodyParser.json());

// ================= MYSQL CONNECTION =================
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) console.error("❌ MySQL connection error:", err);
  else console.log("✅ MySQL Connected...");
});

// ================= REGISTER =================
app.post("/api/register", async (req, res) => {
  const { full_name, email, username, password, role } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (full_name, email, username, password, role) VALUES (?, ?, ?, ?, ?)",
      [full_name, email, username, hashedPassword, role || "user"],
      (err, result) => {
        if (err) {
          console.error("DB Error:", err);
          return res.status(500).json({ success: false, message: "Database error" });
        }
        res.json({ success: true, message: "User registered successfully" });
      }
    );
  } catch (err) {
    console.error("Server Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= LOGIN =================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!results.length) return res.status(401).json({ error: "Invalid credentials" });

    const user = results[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ success: true, token });
  });
});

// ================= AUTH MIDDLEWARE =================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ================= GET USER PROFILE =================
app.get("/api/users/me", authenticateToken, (req, res) => {
  db.query(
    "SELECT id, full_name, username, email, role FROM users WHERE id = ?",
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (!results.length) return res.status(404).json({ error: "User not found" });
      res.json(results[0]);
    }
  );
});

// ================= START SERVER =================
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

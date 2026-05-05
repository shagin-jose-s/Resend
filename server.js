const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { Resend } = require("resend");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

/* ===== DATABASE ===== */
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

db.query("SELECT 1")
  .then(() => console.log("✅ PostgreSQL Connected"))
  .catch(err => console.error("❌ DB Error:", err));

/* ===== RESEND SETUP ===== */
const resend = new Resend(process.env.RESEND_API_KEY);

/* ===== OTP ===== */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
  try {
    let { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();
    username = username.toLowerCase().trim();

    /* CHECK USER */
    const existing = await db.query(
      "SELECT id FROM users WHERE email=$1 OR username=$2",
      [email, username]
    );

    if (existing.rows.length > 0) {
      return res.json({ success: false, message: "User already exists" });
    }

    /* HASH PASSWORD */
    const hashedPassword = await bcrypt.hash(password, 10);

    /* INSERT USER */
    const result = await db.query(
      `INSERT INTO users (email, username, password_hash, is_verified, role)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [email, username, hashedPassword, false, "intern"]
    );

    const userId = result.rows[0].id;

    /* GENERATE OTP */
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await db.query(
      "INSERT INTO otps (user_id, otp, expires_at) VALUES ($1,$2,$3)",
      [userId, otp, expiresAt]
    );

    /* SEND EMAIL USING RESEND */
    let emailSent = true;

    try {
      await resend.emails.send({
        from: process.env.EMAIL_FROM, // IMPORTANT
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP is ${otp}. It expires in 5 minutes.`,
      });

      console.log("📧 Email sent via Resend");
    } catch (err) {
      console.error("❌ RESEND ERROR:", err.message);
      emailSent = false;
    }

    res.json({
      success: true,
      message: emailSent
        ? "Signup successful! OTP sent."
        : "Signup successful! OTP generated (email failed)"
    });

  } catch (err) {
    console.error("🔥 SIGNUP ERROR:", err.message);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

/* ================= VERIFY OTP ================= */
app.post("/verifyotp", async (req, res) => {
  try {
    let { email, otp } = req.body;

    if (!email || !otp) {
      return res.json({ success: false, message: "Missing fields" });
    }

    email = email.toLowerCase().trim();

    const userRes = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const userId = userRes.rows[0].id;

    const otpRes = await db.query(
      "SELECT * FROM otps WHERE user_id=$1 AND otp=$2 AND expires_at > NOW()",
      [userId, otp]
    );

    if (otpRes.rows.length === 0) {
      return res.json({ success: false, message: "OTP invalid or expired" });
    }

    await db.query("UPDATE users SET is_verified=TRUE WHERE id=$1", [userId]);
    await db.query("DELETE FROM otps WHERE user_id=$1", [userId]);

    res.json({ success: true, message: "Account verified!" });

  } catch (err) {
    console.error("❌ VERIFY ERROR:", err.message);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    if (!username || !password) {
      return res.json({ success: false, message: "Missing fields" });
    }

    username = username.toLowerCase();

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1 OR username=$2",
      [username, username]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const user = result.rows[0];

    if (!user.is_verified) {
      return res.json({ success: false, message: "User not verified yet" });
    }

    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (err) {
    console.error("❌ LOGIN ERROR:", err.message);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

/* ===== TEST ===== */
app.get("/", (req, res) => {
  res.send("Server is working ✅");
});

/* ===== SERVER ===== */
const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
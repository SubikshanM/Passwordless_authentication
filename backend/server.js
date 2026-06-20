const path = require("path");
// Load environment variables from the parent directory's .env file
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const express = require("express");
const { Pool } = require("@neondatabase/serverless");
const ws = require("ws");
const crypto = require("crypto");

const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 8080;

// Load RSA asymmetric keys from env variables (Base64)
const publicKeyPem = process.env.TOTP_PUBLIC_KEY
  ? Buffer.from(process.env.TOTP_PUBLIC_KEY, "base64").toString("utf8")
  : "";
const privateKeyPem = process.env.TOTP_PRIVATE_KEY
  ? Buffer.from(process.env.TOTP_PRIVATE_KEY, "base64").toString("utf8")
  : "";

// Asymmetric Encryption Helper
function encryptAsymmetric(plainText) {
  if (!publicKeyPem) return plainText;
  const buffer = Buffer.from(plainText, "utf8");
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    buffer
  );
  return encrypted.toString("base64");
}

// Asymmetric Decryption Helper
function decryptAsymmetric(cipherTextBase64) {
  if (!privateKeyPem) return cipherTextBase64;
  try {
    const buffer = Buffer.from(cipherTextBase64, "base64");
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      buffer
    );
    return decrypted.toString("utf8");
  } catch (err) {
    console.error("RSA decryption error:", err);
    return cipherTextBase64;
  }
}

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Serve static frontend files from the parent directory (root folder)
app.use(express.static(path.join(__dirname, "..")));

// Redirect root to login page
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// NeonDB PostgreSQL connection
let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false, // Required for NeonDB connection over SSL
    },
  });
  console.log("NeonDB pool initialized successfully.");

  // Auto-run schema migrations to ensure lockout columns exist
  pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_totp_attempts INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_locked_until TIMESTAMP WITH TIME ZONE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_passkey_attempts INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS passkey_locked_until TIMESTAMP WITH TIME ZONE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT FALSE;
  `).then(() => {
    console.log("Database schema auto-migrations verified successfully.");
  }).catch(err => {
    console.error("Database migration warning (non-fatal):", err);
  });
} else {
  console.warn("WARNING: DATABASE_URL is not set in the .env file! Database queries will fail.");
}

// Mock database store with persistent local JSON fallback
const fs = require("fs");
const MOCK_DB_FILE = path.join(__dirname, "mock_db.json");

let dbUsers = new Map();
let dbOtps = [];

function loadMockDb() {
  try {
    if (fs.existsSync(MOCK_DB_FILE)) {
      const data = JSON.parse(fs.readFileSync(MOCK_DB_FILE, "utf8"));
      dbUsers = new Map(Object.entries(data.users || {}));
      dbOtps = data.otps || [];
      console.log(`Loaded ${dbUsers.size} users and ${dbOtps.length} OTPs from local mock DB.`);
    }
  } catch (err) {
    console.error("Error loading mock database file:", err);
  }
}

function saveMockDb() {
  try {
    const data = {
      users: Object.fromEntries(dbUsers),
      otps: dbOtps
    };
    fs.writeFileSync(MOCK_DB_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Error saving mock database file:", err);
  }
}

// Initial load
loadMockDb();

// Helper: Query Database (with transparent in-memory mock fallback)
async function query(text, params) {
  if (pool) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      console.warn("NeonDB query failed, falling back to mock database:", err.message || err);
    }
  }

  // Mimic PostgreSQL behavior using in-memory mock collections
  const textClean = text.trim().replace(/\s+/g, " ");

  if (textClean.startsWith("INSERT INTO otps")) {
    const newOtp = {
      id: dbOtps.length + 1,
      email: params[0],
      otp_code: params[1],
      expires_at: params[2],
      is_used: false,
      created_at: new Date()
    };
    dbOtps.push(newOtp);
    saveMockDb();
    return { rows: [newOtp] };
  }

  if (textClean.startsWith("SELECT * FROM otps")) {
    const email = params[0];
    const otpCode = params[1];
    const now = new Date();
    // Filter matching, active, unexpired OTPs
    const matching = dbOtps
      .filter(o => o.email === email && o.otp_code === otpCode && !o.is_used && o.expires_at > now)
      .sort((a, b) => b.created_at - a.created_at);
    return { rows: matching.length > 0 ? [matching[0]] : [] };
  }

  if (textClean.startsWith("UPDATE otps")) {
    const id = params[0];
    const record = dbOtps.find(o => o.id === id);
    if (record) {
      record.is_used = true;
      saveMockDb();
    }
    return { rows: [] };
  }

  if (textClean.startsWith("SELECT id FROM users")) {
    const email = params[0];
    const username = params[1];
    const match = Array.from(dbUsers.values()).find(u => u.email === email || u.username === username);
    return { rows: match ? [{ id: match.id }] : [] };
  }

  if (textClean.startsWith("INSERT INTO users")) {
    const newUser = {
      id: dbUsers.size + 1,
      username: params[0],
      email: params[1],
      phone: params[2],
      totp_secret: params[3],
      backup_passkey: params[4],
      is_verified: true,
      phone_verified: false,
      failed_totp_attempts: 0,
      totp_locked_until: null,
      failed_passkey_attempts: 0,
      passkey_locked_until: null,
      created_at: new Date()
    };
    dbUsers.set(newUser.email, newUser);
    saveMockDb();
    return { rows: [newUser] };
  }

  if (textClean.startsWith("SELECT * FROM users") || textClean.includes("FROM users WHERE email = $1")) {
    const email = params[0];
    const match = dbUsers.get(email);
    return { rows: match ? [match] : [] };
  }

  if (textClean.startsWith("UPDATE users")) {
    const email = params[params.length - 1];
    const user = dbUsers.get(email);
    if (user) {
      if (textClean.includes("failed_totp_attempts = $1") || textClean.includes("failed_totp_attempts = 0")) {
        const attempts = textClean.includes("failed_totp_attempts = 0") ? 0 : params[0];
        const lockedUntil = textClean.includes("totp_locked_until = NULL") ? null : (attempts === 0 ? null : params[1]);
        user.failed_totp_attempts = attempts;
        user.totp_locked_until = lockedUntil;
      }
      if (textClean.includes("failed_passkey_attempts = $1") || textClean.includes("failed_passkey_attempts = 0")) {
        let attemptsVal = 0;
        let lockedVal = null;
        if (textClean.includes("failed_passkey_attempts = 0")) {
          attemptsVal = 0;
          lockedVal = null;
        } else {
          attemptsVal = params[0];
          lockedVal = params[1];
        }
        user.failed_passkey_attempts = attemptsVal;
        user.passkey_locked_until = lockedVal;
      }
      if (textClean.includes("phone = $1")) {
        user.phone = params[0];
      }
      if (textClean.includes("totp_secret = $1")) {
        user.totp_secret = params[0];
      }
      saveMockDb();
    }
    return { rowCount: user ? 1 : 0 };
  }

  throw new Error(`Unsupported mock query: ${text}`);
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// In-memory rate limiting and progressive lockout storage for email OTP verification
const otpLockouts = new Map();

function getOtpLockout(email) {
  if (!otpLockouts.has(email)) {
    otpLockouts.set(email, {
      failedAttempts: 0,
      lockedUntil: null,
      lastOtpSent: 0
    });
  }
  const data = otpLockouts.get(email);
  if (data.lockedUntil && new Date(data.lockedUntil) < new Date()) {
    data.failedAttempts = 0;
    data.lockedUntil = null;
  }
  return data;
}

/**
 * 1. POST /api/auth/send-otp
 * Generates a 6-digit OTP, stores it in the database, and sends it to the email via Brevo.
 */
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email address is required." });
  }

  const lockout = getOtpLockout(email);

  // Check if email is currently locked out
  if (lockout.lockedUntil && new Date(lockout.lockedUntil) > new Date()) {
    return res.status(429).json({
      success: false,
      message: "Too many verification failures. OTP requests are temporarily locked.",
      lockedUntil: lockout.lockedUntil
    });
  }

  // Rate limit: 1 OTP request per 60 seconds
  const now = Date.now();
  if (now - lockout.lastOtpSent < 60 * 1000) {
    const secondsLeft = Math.ceil((60 * 1000 - (now - lockout.lastOtpSent)) / 1000);
    return res.status(429).json({
      success: false,
      message: `Please wait ${secondsLeft} seconds before requesting a new verification code.`
    });
  }

  lockout.lastOtpSent = now;

  try {
    // Generate a 6-digit random code
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiration

    // Store the OTP in NeonDB
    await query(
      "INSERT INTO otps (email, otp_code, expires_at) VALUES ($1, $2, $3)",
      [email, otpCode, expiresAt]
    );

    console.log(`[OTP] Generated code ${otpCode} for ${email}`);

    // Send the email using Brevo SMTP API
    if (process.env.BREVO_API_KEY) {
      const senderEmail = process.env.BREVO_SENDER_EMAIL || "no-reply@cybershield.security";
      console.log(`[Brevo] Sending email to: ${email} from: ${senderEmail}`);
      const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "accept": "application/json",
          "api-key": process.env.BREVO_API_KEY,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sender: { name: "CyberShield Auth", email: senderEmail },
          to: [{ email: email }],
          subject: "Your CyberShield Verification OTP",
          htmlContent: `
            <div style="font-family: Arial, sans-serif; background-color: #04060c; color: #ffffff; padding: 25px; border-radius: 12px; border: 1px solid #00d2ff; max-width: 500px; margin: 0 auto;">
              <h2 style="color: #00d2ff; text-align: center; margin-bottom: 20px; font-weight: bold; letter-spacing: 1px;">CyberShield Security Portal</h2>
              <p style="text-align: center; font-size: 1.1rem; color: #ccd6f6;">To complete your registration setup, please verify your email using this code:</p>
              <div style="background-color: #0c101b; padding: 15px; border-radius: 8px; text-align: center; font-size: 2.5rem; font-weight: bold; letter-spacing: 6px; color: #00d2ff; margin: 25px 0; border: 1px dashed rgba(0, 210, 255, 0.3);">
                ${otpCode}
              </div>
              <p style="text-align: center; font-size: 0.85rem; color: #8892b0; margin-top: 25px;">This OTP will expire in 5 minutes. If you did not request this verification, please secure your account credentials.</p>
            </div>
          `,
        }),
      });

      const responseBody = await brevoRes.text();
      console.log(`[Brevo] Response Status: ${brevoRes.status}, Body: ${responseBody}`);

      if (!brevoRes.ok) {
        console.error("Brevo API error:", responseBody);
        throw new Error("Failed to send verification email via Brevo.");
      }
    } else {
      console.warn("WARNING: BREVO_API_KEY is not defined. OTP is logged to server console only:", otpCode);
    }

    res.json({
      success: true,
      message: "OTP sent successfully.",
      devOtp: process.env.BREVO_API_KEY ? undefined : otpCode,
    });
  } catch (err) {
    console.error("Error in /api/auth/send-otp:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to process OTP request." });
  }
});

/**
 * 2. POST /api/auth/verify-otp
 * Verifies the submitted OTP code.
 */
app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otpCode } = req.body;
  if (!email || !otpCode) {
    return res.status(400).json({ success: false, message: "Email and OTP code are required." });
  }

  const lockout = getOtpLockout(email);

  // Check if locked out
  if (lockout.lockedUntil && new Date(lockout.lockedUntil) > new Date()) {
    return res.status(429).json({
      success: false,
      message: "Too many failed attempts. Verification locked.",
      lockedUntil: lockout.lockedUntil
    });
  }

  try {
    const result = await query(
      "SELECT * FROM otps WHERE email = $1 AND otp_code = $2 AND is_used = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1",
      [email, otpCode]
    );

    if (result.rows.length === 0) {
      // Increment failed attempts
      lockout.failedAttempts += 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (lockout.failedAttempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (lockout.failedAttempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
        lockout.lockedUntil = lockedUntil;
      }

      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP.",
        failedAttempts: lockout.failedAttempts,
        lockedUntil: lockedUntil
      });
    }

    const otpRecord = result.rows[0];

    // Mark as used
    await query("UPDATE otps SET is_used = true WHERE id = $1", [otpRecord.id]);

    // Reset lockout upon successful verification
    lockout.failedAttempts = 0;
    lockout.lockedUntil = null;

    res.json({ success: true, message: "OTP verified successfully." });
  } catch (err) {
    console.error("Error in /api/auth/verify-otp:", err);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

/**
 * 3. POST /api/auth/register
 * Completes registration by saving username, email, phone, and TOTP secret in NeonDB.
 */
app.post("/api/auth/register", async (req, res) => {
  const { username, email, phone, totpSecret, backupPasskey } = req.body;
  if (!username || !email || !phone || !totpSecret || !backupPasskey) {
    return res.status(400).json({ success: false, message: "All registration fields (including backup passkey) are required." });
  }

  try {
    // Check if user already exists
    const checkUser = await query(
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ success: false, message: "Username or email is already registered." });
    }

    // Encrypt the TOTP secret key and backup passkey using asymmetric RSA encryption
    const encryptedTotpSecret = encryptAsymmetric(totpSecret);
    const encryptedBackupPasskey = encryptAsymmetric(backupPasskey);

    // Save user details
    await query(
      "INSERT INTO users (username, email, phone, totp_secret, backup_passkey, is_verified) VALUES ($1, $2, $3, $4, $5, true)",
      [username, email, phone, encryptedTotpSecret, encryptedBackupPasskey]
    );

    res.json({ success: true, message: "User registered successfully." });
  } catch (err) {
    console.error("Error in /api/auth/register:", err);
    res.status(500).json({ success: false, message: "Failed to register user." });
  }
});

/**
 * Helper to verify TOTP code on server-side
 */
function verifyTOTPNode(secretBase32, enteredCode) {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const base32 = secretBase32.replace(/=+$/, "").toUpperCase();
  const len = base32.length;
  const keyBytes = Buffer.alloc(Math.floor((len * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < len; i++) {
    const val = base32chars.indexOf(base32[i]);
    if (val === -1) throw new Error("Invalid base32 character: " + base32[i]);
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      keyBytes[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  const steps = [0, -1, 1]; // Allow clock drift
  for (const stepOffset of steps) {
    const epoch = Math.floor(Date.now() / 1000) + (stepOffset * 30);
    const counter = Math.floor(epoch / 30);
    const counterBytes = Buffer.alloc(8);
    let temp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = temp & 0xff;
      temp = Math.floor(temp / 256);
    }

    const hmac = crypto.createHmac("sha1", keyBytes).update(counterBytes).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = (binary % 1000000).toString().padStart(6, "0");
    if (otp === enteredCode) {
      return true;
    }
  }
  return false;
}

/**
 * 4. POST /api/auth/login-step1
 * Handles reCAPTCHA verification and checks if email is registered.
 */
app.post("/api/auth/login-step1", async (req, res) => {
  const { email, recaptchaToken } = req.body;
  if (!email || !recaptchaToken) {
    return res.status(400).json({ success: false, message: "Email and reCAPTCHA verification are required." });
  }

  try {
    // Verify Google reCAPTCHA v2 token
    if (process.env.RECAPTCHA_SECRET_KEY) {
      const recaptchaRes = await fetch("https://www.google.com/recaptcha/api/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`,
      });
      const recaptchaData = await recaptchaRes.json();
      if (!recaptchaData.success) {
        return res.status(400).json({ success: false, message: "reCAPTCHA verification failed." });
      }
    }

    // Check if user is registered in NeonDB
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "Email is not registered. Please sign up." });
    }

    const user = result.rows[0];

    // Check progressive TOTP lockout
    if (user.totp_locked_until) {
      const lockedUntil = new Date(user.totp_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Too many failed attempts. Authenticator locked.",
          lockedUntil: user.totp_locked_until
        });
      } else {
        // Reset expired lockout
        await query(
          "UPDATE users SET failed_totp_attempts = 0, totp_locked_until = NULL WHERE email = $1",
          [email]
        );
        user.failed_totp_attempts = 0;
        user.totp_locked_until = null;
      }
    }

    res.json({
      success: true,
      message: "Credentials verified.",
      totpSecret: decryptAsymmetric(user.totp_secret),
      passkeyLockedUntil: user.passkey_locked_until
    });
  } catch (err) {
    console.error("Error in /api/auth/login-step1:", err);
    res.status(500).json({ success: false, message: "Internal server error during credential lookup." });
  }
});

/**
 * 4.5. POST /api/auth/verify-totp
 * Verifies submitted TOTP code on server-side and manages progressive lockout.
 */
app.post("/api/auth/verify-totp", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ success: false, message: "Email and code are required." });
  }

  try {
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const user = result.rows[0];

    // Check progressive TOTP lockout
    if (user.totp_locked_until) {
      const lockedUntil = new Date(user.totp_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Authenticator locked. Try again later.",
          lockedUntil: user.totp_locked_until
        });
      }
    }

    const decryptedSecret = decryptAsymmetric(user.totp_secret);
    const isValid = verifyTOTPNode(decryptedSecret, code);

    if (isValid) {
      // Clear lockout on success
      await query(
        "UPDATE users SET failed_totp_attempts = 0, totp_locked_until = NULL WHERE email = $1",
        [email]
      );
      return res.json({ success: true, message: "TOTP verified successfully." });
    } else {
      // Increment failure count
      const attempts = (user.failed_totp_attempts || 0) + 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (attempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (attempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
      }

      await query(
        "UPDATE users SET failed_totp_attempts = $1, totp_locked_until = $2 WHERE email = $3",
        [attempts, lockedUntil, email]
      );

      return res.status(401).json({
        success: false,
        message: "Invalid TOTP code.",
        failedAttempts: attempts,
        lockedUntil: lockedUntil
      });
    }
  } catch (err) {
    console.error("Error in /api/auth/verify-totp:", err);
    res.status(500).json({ success: false, message: "Server error during verification." });
  }
});

/**
 * 5. POST /api/user/profile
 * Retrieves username, email, phone, and created_at details for the active session.
 */
app.post("/api/user/profile", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required." });
  }

  try {
    const result = await query("SELECT username, email, phone, created_at FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const ipRaw = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const clientIp = ipRaw === '::1' || ipRaw === '::ffff:127.0.0.1' ? '127.0.0.1' : ipRaw.replace(/^.*:/, '');

    res.json({
      success: true,
      user: result.rows[0],
      ip: clientIp
    });
  } catch (err) {
    console.error("Error in /api/user/profile:", err);
    res.status(500).json({ success: false, message: "Failed to load user profile." });
  }
});


/**
 * 6. POST /api/auth/request-magic-link
 * Verifies the backup passkey and emails a signed stateless Magic Link.
 */
app.post("/api/auth/request-magic-link", async (req, res) => {
  const { email, passkey } = req.body;
  if (!email || !passkey) {
    return res.status(400).json({ success: false, message: "Email and backup passkey are required." });
  }

  try {
    // Retrieve user by email
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "Email address not registered." });
    }

    const user = result.rows[0];

    // Check passkey lockout status
    if (user.passkey_locked_until) {
      const lockedUntil = new Date(user.passkey_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Too many failed attempts. Recovery locked.",
          lockedUntil: user.passkey_locked_until
        });
      } else {
        // Reset expired lockout
        await query(
          "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
          [email]
        );
        user.failed_passkey_attempts = 0;
        user.passkey_locked_until = null;
      }
    }
    
    // Decrypt the stored backup passkey and verify match
    const decryptedBackupPasskey = decryptAsymmetric(user.backup_passkey);
    if (decryptedBackupPasskey !== passkey) {
      const attempts = (user.failed_passkey_attempts || 0) + 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (attempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (attempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
      }

      await query(
        "UPDATE users SET failed_passkey_attempts = $1, passkey_locked_until = $2 WHERE email = $3",
        [attempts, lockedUntil, email]
      );

      return res.status(401).json({
        success: false,
        message: "Invalid backup passkey credentials.",
        failedAttempts: attempts,
        lockedUntil: lockedUntil
      });
    }

    // Reset passkey attempts on success
    await query(
      "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
      [email]
    );

    // Generate signed magic token (valid for 15 minutes)
    const expiresAt = Date.now() + 15 * 60 * 1000;
    const tokenPayload = `${email}:${expiresAt}`;
    const secret = process.env.RECAPTCHA_SECRET_KEY || "cybershieldDefaultSecret";
    const signature = crypto.createHmac("sha256", secret).update(tokenPayload).digest("hex");
    const token = Buffer.from(`${tokenPayload}:${signature}`).toString("base64");

    const magicLink = `http://localhost:8080/magic-login.html?token=${encodeURIComponent(token)}`;
    console.log(`[MAGIC LINK] Generated for ${email}: ${magicLink}`);

    // Send the email using Brevo SMTP API
    if (process.env.BREVO_API_KEY) {
      const senderEmail = process.env.BREVO_SENDER_EMAIL || "no-reply@cybershield.security";
      const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "accept": "application/json",
          "api-key": process.env.BREVO_API_KEY,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          sender: { name: "CyberShield Security", email: senderEmail },
          to: [{ email: email }],
          subject: "Your CyberShield Magic Recovery Link",
          htmlContent: `
            <div style="font-family: Arial, sans-serif; background-color: #04060c; color: #ffffff; padding: 25px; border-radius: 12px; border: 1px solid #00d2ff; max-width: 500px; margin: 0 auto;">
              <h2 style="color: #00d2ff; text-align: center; margin-bottom: 20px; font-weight: bold; letter-spacing: 1px;">CyberShield Recovery Center</h2>
              <p style="font-size: 1rem; color: #ccd6f6; line-height: 1.5;">We received a request to bypass your authenticator using your secure backup passkey. Click the secure button below to login to your dashboard:</p>
              
              <div style="text-align: center; margin: 30px 0;">
                <a href="${magicLink}" style="background-color: #00d2ff; color: #04060c; padding: 14px 28px; border-radius: 8px; font-weight: bold; text-decoration: none; font-size: 1rem; display: inline-block; letter-spacing: 0.5px; box-shadow: 0 4px 15px rgba(0, 210, 255, 0.4);">
                  Authenticate Securely
                </a>
              </div>
              
              <p style="font-size: 0.85rem; color: #8892b0; line-height: 1.4; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 15px;">This magic link will expire in 15 minutes. Note that you will be required to re-verify your passkey upon landing to maintain secure access.</p>
            </div>
          `,
        }),
      });

      if (!brevoRes.ok) {
        const errText = await brevoRes.text();
        console.error("Brevo API error:", errText);
        throw new Error("Failed to send magic link email.");
      }
    }

    res.json({
      success: true,
      message: "Magic recovery link sent to your registered email address.",
      devMagicLink: process.env.BREVO_API_KEY ? undefined : magicLink
    });
  } catch (err) {
    console.error("Error in /api/auth/request-magic-link:", err);
    res.status(500).json({ success: false, message: "Internal server error generating magic link." });
  }
});


/**
 * 7. POST /api/auth/magic-login
 * Decodes the token, verifies the signature, and matches the passkey once more.
 */
app.post("/api/auth/magic-login", async (req, res) => {
  const { token, passkey } = req.body;
  if (!token || !passkey) {
    return res.status(400).json({ success: false, message: "Token and verification passkey are required." });
  }

  try {
    // Decode token
    const decoded = Buffer.from(token, "base64").toString("utf-8");
    const parts = decoded.split(":");
    if (parts.length < 3) {
      return res.status(400).json({ success: false, message: "Invalid token structure." });
    }

    const email = parts[0];
    const expiresAt = parseInt(parts[1], 10);
    const signature = parts.slice(2).join(":");

    // Verify token expiration
    if (expiresAt < Date.now()) {
      return res.status(400).json({ success: false, message: "Magic link has expired." });
    }

    // Verify signature
    const secret = process.env.RECAPTCHA_SECRET_KEY || "cybershieldDefaultSecret";
    const expectedSignature = crypto.createHmac("sha256", secret).update(`${email}:${expiresAt}`).digest("hex");
    if (signature !== expectedSignature) {
      return res.status(400).json({ success: false, message: "Token signature verification failed." });
    }

    // Verify user exists and verify passkey
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User record associated with this token not found." });
    }

    const user = result.rows[0];

    // Check passkey lockout status
    if (user.passkey_locked_until) {
      const lockedUntil = new Date(user.passkey_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Too many failed attempts. Recovery locked.",
          lockedUntil: user.passkey_locked_until
        });
      } else {
        // Reset expired lockout
        await query(
          "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
          [email]
        );
        user.failed_passkey_attempts = 0;
        user.passkey_locked_until = null;
      }
    }

    const decryptedBackupPasskey = decryptAsymmetric(user.backup_passkey);
    if (decryptedBackupPasskey !== passkey) {
      const attempts = (user.failed_passkey_attempts || 0) + 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (attempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (attempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
      }

      await query(
        "UPDATE users SET failed_passkey_attempts = $1, passkey_locked_until = $2 WHERE email = $3",
        [attempts, lockedUntil, email]
      );

      return res.status(401).json({
        success: false,
        message: "Invalid passkey. Access Denied.",
        failedAttempts: attempts,
        lockedUntil: lockedUntil
      });
    }

    // Reset passkey attempts on success
    await query(
      "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
      [email]
    );

    res.json({
      success: true,
      message: "Verification successful.",
      email: user.email
    });
  } catch (err) {
    console.error("Error in /api/auth/magic-login:", err);
    res.status(500).json({ success: false, message: "Server error during magic link login." });
  }
});

/**
 * 8. POST /api/user/update-phone
 * Updates the user's phone number.
 */
app.post("/api/user/update-phone", async (req, res) => {
  const { email, newPhone } = req.body;
  if (!email || !newPhone) {
    return res.status(400).json({ success: false, message: "Email and new phone number are required." });
  }

  try {
    const checkUser = await query("SELECT id FROM users WHERE email = $1", [email]);
    if (checkUser.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    await query("UPDATE users SET phone = $1 WHERE email = $2", [newPhone, email]);

    res.json({
      success: true,
      message: "Phone number updated successfully."
    });
  } catch (err) {
    console.error("Error in /api/user/update-phone:", err);
    res.status(500).json({ success: false, message: "Failed to update phone number." });
  }
});

/**
 * 9. POST /api/user/get-totp-secret
 * Decrypts and returns the existing TOTP secret key after checking backup passkey.
 */
app.post("/api/user/get-totp-secret", async (req, res) => {
  const { email, passkey } = req.body;
  if (!email || !passkey) {
    return res.status(400).json({ success: false, message: "Email and backup passkey are required." });
  }

  try {
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const user = result.rows[0];

    // Check passkey lockout status
    if (user.passkey_locked_until) {
      const lockedUntil = new Date(user.passkey_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Too many failed attempts. Access locked.",
          lockedUntil: user.passkey_locked_until
        });
      } else {
        // Reset expired lockout
        await query(
          "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
          [email]
        );
        user.failed_passkey_attempts = 0;
        user.passkey_locked_until = null;
      }
    }

    // Decrypt and verify passkey
    const decryptedBackupPasskey = decryptAsymmetric(user.backup_passkey);
    if (decryptedBackupPasskey !== passkey) {
      const attempts = (user.failed_passkey_attempts || 0) + 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (attempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (attempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
      }

      await query(
        "UPDATE users SET failed_passkey_attempts = $1, passkey_locked_until = $2 WHERE email = $3",
        [attempts, lockedUntil, email]
      );

      return res.status(401).json({
        success: false,
        message: "Invalid backup passkey credentials.",
        failedAttempts: attempts,
        lockedUntil: lockedUntil
      });
    }

    // Reset attempts on success
    await query(
      "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
      [email]
    );

    const decryptedSecret = decryptAsymmetric(user.totp_secret);
    res.json({
      success: true,
      secret: decryptedSecret
    });
  } catch (err) {
    console.error("Error in /api/user/get-totp-secret:", err);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

/**
 * 10. POST /api/user/update-totp-secret
 * Validates new TOTP and saves the encrypted secret.
 */
app.post("/api/user/update-totp-secret", async (req, res) => {
  const { email, passkey, newSecret, totpCode } = req.body;
  if (!email || !passkey || !newSecret || !totpCode) {
    return res.status(400).json({ success: false, message: "All fields are required." });
  }

  try {
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const user = result.rows[0];

    // Check passkey lockout status
    if (user.passkey_locked_until) {
      const lockedUntil = new Date(user.passkey_locked_until);
      if (lockedUntil > new Date()) {
        return res.status(429).json({
          success: false,
          message: "Too many failed attempts. Access locked.",
          lockedUntil: user.passkey_locked_until
        });
      } else {
        // Reset expired lockout
        await query(
          "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
          [email]
        );
        user.failed_passkey_attempts = 0;
        user.passkey_locked_until = null;
      }
    }

    // Decrypt and verify passkey
    const decryptedBackupPasskey = decryptAsymmetric(user.backup_passkey);
    if (decryptedBackupPasskey !== passkey) {
      const attempts = (user.failed_passkey_attempts || 0) + 1;
      let lockedUntil = null;
      let durationMs = 0;

      if (attempts >= 5) {
        durationMs = 60 * 60 * 1000; // 1 hour
      } else if (attempts >= 3) {
        durationMs = 5 * 60 * 1000; // 5 minutes
      }

      if (durationMs > 0) {
        lockedUntil = new Date(Date.now() + durationMs);
      }

      await query(
        "UPDATE users SET failed_passkey_attempts = $1, passkey_locked_until = $2 WHERE email = $3",
        [attempts, lockedUntil, email]
      );

      return res.status(401).json({
        success: false,
        message: "Invalid backup passkey credentials.",
        failedAttempts: attempts,
        lockedUntil: lockedUntil
      });
    }

    // Verify TOTP code against new secret
    const isValid = verifyTOTPNode(newSecret, totpCode);
    if (!isValid) {
      return res.status(400).json({ success: false, message: "Invalid TOTP verification code." });
    }

    // Reset passkey attempts on success
    await query(
      "UPDATE users SET failed_passkey_attempts = 0, passkey_locked_until = NULL WHERE email = $1",
      [email]
    );

    // Encrypt the new secret
    const encryptedSecret = encryptAsymmetric(newSecret);

    // Update in database
    await query("UPDATE users SET totp_secret = $1 WHERE email = $2", [encryptedSecret, email]);

    res.json({
      success: true,
      message: "Authenticator key rotated successfully."
    });
  } catch (err) {
    console.error("Error in /api/user/update-totp-secret:", err);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`CyberShield Authentication Portal Server Running`);
  console.log(`Server Address: http://localhost:${PORT}`);
  console.log(`===================================================`);
});

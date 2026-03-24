require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const axios = require("axios");
const { unserialize } = require("php-unserialize");
const dayjs = require("dayjs");




const {
  PORT = 3001,
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASS,
  DB_NAME,
  JWT_SECRET,
  COOKIE_NAME = "access_token",
  NODE_ENV,
  RECAPTCHA_SECRET_KEY
} = process.env;

const REFRESH_COOKIE = "refresh_token";
const app = express();
app.use(express.json());
app.use(cookieParser());

/**
 * ✅ Regex-based CORS whitelist
 */
const allowedOrigins = [
  /^http:\/\/localhost:\d+$/,                    // allow any localhost port
  /^https:\/\/(www\.)?simplyparkandfly\.co\.uk$/, // allow main + www
  /^https:\/\/stg\.simplyparkandfly\.co\.uk$/,    // allow staging
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true); // allow Postman/curl
      const isAllowed = allowedOrigins.some((pattern) => pattern.test(origin));
      if (isAllowed) {
        callback(null, true);
      } else {
        console.warn("❌ Blocked by CORS:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
      "Origin",
    ],
    exposedHeaders: ["Set-Cookie"],
  })
);

// ✅ Ensure preflight OPTIONS requests are handled
app.options("*", cors());

/**
 * ✅ MySQL pool
 */
const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  connectionLimit: 10,
});

/**
 * ✅ JWT helpers
 */
function signAccess(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" }); // short-lived
}

function signRefresh(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" }); // longer-lived
}

/**
 * ✅ Cookie domain helper
 */
function getCookieDomain() {
  if (NODE_ENV !== "production") return undefined; // dev → default
  return ".simplyparkandfly.co.uk"; // works across all subdomains
}

/**
 * ✅ reCAPTCHA verification
 */
async function verifyRecaptcha(token, expectedAction) {
  try {
    const response = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret: RECAPTCHA_SECRET_KEY,
        response: token,
      })
    );

    const data = response.data;
    console.log(`🔍 reCAPTCHA result for ${expectedAction}:`, data);

    if (!data.success) {
      return { ok: false, reason: "recaptcha-failed" };
    }
    if (expectedAction && data.action !== expectedAction) {
      return { ok: false, reason: "wrong-action" };
    }
    if (data.score < 0.5) {
      return { ok: false, reason: "low-score", score: data.score };
    }

    return { ok: true, score: data.score };
  } catch (err) {
    console.error("❌ reCAPTCHA verification error:", err);
    return { ok: false, reason: "verification-error" };
  }
}

/**
 * ✅ Routes
 */
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/", (req, res) => {
  res.json({ status: "Auth API running", time: new Date().toISOString() });
});






/**
 * ✅ Search endpoint (basic version)
 * GET /search?token=xxxx
 */
app.get("/search", async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ message: "Token required" });
  }

  try {
    // 1. Lookup checkout record
    const [checkoutRows] = await pool.query(
      "SELECT * FROM checkout WHERE token = ? ORDER BY id DESC LIMIT 1",
      [token]
    );
    if (checkoutRows.length === 0) {
      return res.status(404).json({ message: "Checkout not found" });
    }
    const checkout = checkoutRows[0];

    // 2. Parse param (PHP serialized → JSON)
    let param;
    try {
      param = unserialize(checkout.param);
    } catch (e) {
      console.error("❌ Failed to unserialize param:", e);
      return res.status(500).json({ message: "Failed to parse checkout params" });
    }

    // 3. Lookup airport
    const [airportRows] = await pool.query(
      "SELECT * FROM airport WHERE airport_code = ? LIMIT 1",
      [param.airport]
    );
    const airport = airportRows[0] || null;

    // 4. Get tags
    const [tagRows] = await pool.query(
      "SELECT id, title, order_by FROM rate_tag"
    );
    const tags = tagRows.reduce((acc, tag) => {
      acc[tag.id] = { title: tag.title, order_by: tag.order_by };
      return acc;
    }, {});

    // 5. Example rates query (simplified)
    const [rates] = await pool.query(
      "SELECT * FROM view_rate_grid WHERE airport_id = ? AND rate_date = ?",
      [airport?.id || 0, param.dropoff_date]
    );

    // 6. Example parking types
    const [parkingTypes] = await pool.query(
      "SELECT * FROM parking_type WHERE pt_status = 1"
    );

    // 7. Calculate date difference
    const diff = dayjs(param.pickup_date).diff(
      dayjs(param.dropoff_date),
      "day"
    ) + 1;

    // 8. Response
    res.json({
      checkoutId: checkout.id,
      param,
      airport,
      tags,
      diff,
      rates,
      parkingTypes,
      external: {}, // placeholder for external API integrations later
    });
  } catch (err) {
    console.error("❌ Search error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});







/**
 * ✅ Search endpoint (authenticated version, using predefined token)
 * POST /search  
 * Body: { dropoff_date, pickup_date, dropoff_time, pickup_time, airport, coupon_code? }
 */
app.post("/search", async (req, res) => {
  try {
    // // 1. Verify user is authenticated via access token cookie
    // const accessToken = req.cookies[COOKIE_NAME];
    // if (!accessToken) {
    //   return res.status(401).json({ message: "Unauthenticated" });
    // }
    // let decoded;
    // try {
    //   decoded = jwt.verify(accessToken, JWT_SECRET);
    // } catch (err) {
    //   return res.status(401).json({ message: "Invalid or expired access token" });
    // }

    // 2. Validate request body (token not required from frontend)
    const {
      dropoff_date,
      pickup_date,
      dropoff_time,
      pickup_time,
      airport,
      coupon_code = ""
    } = req.body || {};

    if (
      !dropoff_date ||
      !pickup_date ||
      !dropoff_time ||
      !pickup_time ||
      !airport
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // 3. Use predefined token in environment config
    const predefinedToken = process.env.SPF_TOKEN;
    if (!predefinedToken) {
      console.error("⚠️ Missing PREDEFINED_CHECKOUT_TOKEN in env");
      return res
        .status(500)
        .json({ message: "Server configuration error" });
    }

    // 4. Forward request to external availability API
    const apiUrl =
      "https://stgbackend.simplyparkandfly.co.uk/search/availability";
    const forwardBody = {
      dropoff_date,
      pickup_date,
      dropoff_time,
      pickup_time,
      airport,
      coupon_code,
      token: predefinedToken
    };

    const externalRes = await axios.post(apiUrl, forwardBody, {
      timeout: 20000
    });
    const externalData = externalRes.data;

    // 5. Validate external response JSON
    if (!externalData || typeof externalData !== "object") {
      console.warn(
        "⚠️ External API did not return JSON object",
        externalData
      );
      return res
        .status(502)
        .json({ message: "Invalid response from upstream service" });
    }
    if (externalData.status !== true || externalData.code !== 200) {
      console.warn("⚠️ External API returned error", externalData);
      return res.status(502).json({
        message: "Upstream service returned error",
        details: externalData
      });
    }

    // 6. Send clean data back to frontend
    return res.json({
      ok: true,
      data: externalData.data
    });
  } catch (err) {
    console.error("❌ /search error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});





















/**
 * ✅ Check if user exists (by email) with reCAPTCHA v3
 */
app.post("/check-user", async (req, res) => {
  const { email, recaptchaToken } = req.body || {};
  if (!email || !recaptchaToken) {
    return res.status(400).json({ message: "Email and recaptchaToken required" });
  }

  // ✅ Verify with action = "check_user"
  const check = await verifyRecaptcha(recaptchaToken, "check_user");
  if (!check.ok) {
    console.warn("⚠️ reCAPTCHA failed on /check-user:", check);
    return res.status(403).json({
      message: "Suspicious activity detected",
      reason: check.reason,
      score: check.score || null,
    });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id FROM spf0_user WHERE email = ? LIMIT 1",
      [email]
    );
    res.json({ exists: rows.length > 0, recaptchaScore: check.score });
  } catch (err) {
    console.error("❌ Check-user error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


/**
 * ✅ Login with reCAPTCHA v3 verification
 */
app.post("/login", async (req, res) => {
  const { email, password, recaptchaToken } = req.body || {};
  if (!email || !password || !recaptchaToken) {
    return res.status(400).json({ message: "Email, password, and recaptchaToken required" });
  }

  // Verify with action = "login"
  const check = await verifyRecaptcha(recaptchaToken, "login");
  if (!check.ok) {
    console.warn("⚠️ reCAPTCHA failed on /login:", check);
    return res.status(403).json({
      message: "Suspicious activity detected",
      reason: check.reason,
      score: check.score || null,
    });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, first_name, last_name, email, password FROM spf0_user WHERE email = ? LIMIT 1",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];
    const hash = (user.password || "").replace(/^\$2y\$/, "$2a$");
    const ok = await bcrypt.compare(password, hash);

    if (!ok) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const name = `${user.first_name || ""} ${user.last_name || ""}`.trim();
    const accessToken = signAccess({ id: user.id, email: user.email, name });
    const refreshToken = signRefresh({ id: user.id });

    // Access token cookie (short-lived)
    res.cookie(COOKIE_NAME, accessToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "lax",
      domain: getCookieDomain(),
      path: "/",
      maxAge: 1000 * 60 * 15, // 15m
    });

    // Refresh token cookie (long-lived)
    res.cookie(REFRESH_COOKIE, refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "lax",
      domain: getCookieDomain(),
      path: "/",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    });

    res.json({ name, email: user.email, recaptchaScore: check.score });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * ✅ Refresh
 */
app.post("/refresh", (req, res) => {
  const token = req.cookies[REFRESH_COOKIE];
  if (!token) return res.status(401).json({ message: "No refresh token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const newAccess = signAccess({ id: payload.id });

    res.cookie(COOKIE_NAME, newAccess, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "lax",
      domain: getCookieDomain(),
      path: "/",
      maxAge: 1000 * 60 * 15, // 15m
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("❌ Refresh error:", err);
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

/**
 * ✅ Current user (guest-safe)
 */
app.get("/me", async (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.json(null);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [rows] = await pool.query(
      "SELECT id, first_name, last_name, email FROM spf0_user WHERE id = ? LIMIT 1",
      [decoded.id]
    );
    if (!rows[0]) return res.json(null);

    const u = rows[0];
    res.json({
      id: u.id,
      email: u.email,
      name: `${u.first_name || ""} ${u.last_name || ""}`.trim(),
    });
  } catch {
    return res.json(null);
  }
});

/**
 * ✅ Logout
 */
app.post("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "lax",
    domain: getCookieDomain(),
    path: "/",
  });

  res.clearCookie(REFRESH_COOKIE, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "lax",
    domain: getCookieDomain(),
    path: "/",
  });

  res.status(204).end();
});

/**
 * ✅ Start server
 */
app.listen(PORT, () => console.log(`Auth API listening on port ${PORT}`));

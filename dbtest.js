require("dotenv").config();
const mysql = require("mysql2/promise");

async function testDb() {
  try {
    const conn = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
    });
    const [rows] = await conn.query("SHOW TABLES");
    console.log("✅ Connected! Tables:", rows.map(r => Object.values(r)[0]));
    await conn.end();
  } catch (err) {
    console.error("❌ DB connection failed:", err.message);
    process.exit(1);
  }
}

testDb();

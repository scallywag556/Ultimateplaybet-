const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "ultimateplaybet-simulation-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname)));

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const testHash = crypto.scryptSync(password, salt, 64).toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(testHash, "hex")
  );
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'player',
      approved BOOLEAN DEFAULT FALSE,
      active BOOLEAN DEFAULT TRUE,
      balance NUMERIC(12,2) DEFAULT 0,
      starting_balance NUMERIC(12,2) DEFAULT 0,
      wager_limit NUMERIC(12,2) DEFAULT 500,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      sport VARCHAR(100),
      selection TEXT NOT NULL,
      odds VARCHAR(50),
      amount NUMERIC(12,2) NOT NULL,
      potential_payout NUMERIC(12,2),
      status VARCHAR(30) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Database tables ready.");
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required" });
  }
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required" });
  }

  const result = await pool.query(
    "SELECT role FROM users WHERE id = $1",
    [req.session.userId]
  );

  if (!result.rows[0] || result.rows[0].role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  next();
}

app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password || password.length < 6) {
      return res.status(400).json({
        error: "Username and password of at least 6 characters required"
      });
    }

    const count = await pool.query("SELECT COUNT(*) FROM users");
    const firstUser = Number(count.rows[0].count) === 0;

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users
       (username, password_hash, role, approved, active, balance, starting_balance)
       VALUES ($1,$2,$3,$4,TRUE,$5,$5)
       RETURNING id, username, role, approved, balance`,
      [
        username.trim(),
        passwordHash,
        firstUser ? "admin" : "player",
        firstUser,
        firstUser ? 1000 : 0
      ]
    );

    res.json({
      success: true,
      firstAdmin: firstUser,
      user: result.rows[0]
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({ error: "Username already exists" });
    }

    console.error(error);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    const user = result.rows[0];

    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    if (!user.active) {
      return res.status(403).json({ error: "Account suspended" });
    }

    if (!user.approved) {
      return res.status(403).json({ error: "Account awaiting admin approval" });
    }

    req.session.userId = user.id;

    await pool.query(
      "INSERT INTO activity_logs (user_id, action) VALUES ($1,$2)",
      [user.id, "login"]
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        balance: user.balance,
        wagerLimit: user.wager_limit
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/me", requireLogin, async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, role, approved, active,
            balance, starting_balance, wager_limit
     FROM users
     WHERE id = $1`,
    [req.session.userId]
  );

  res.json(result.rows[0]);
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT id, username, role, approved, active,
           balance, starting_balance, wager_limit, created_at
    FROM users
    ORDER BY created_at DESC
  `);

  res.json(result.rows);
});

app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const { approved, active, balance, wagerLimit } = req.body;
  const userId = req.params.id;

  if (balance !== undefined && (balance < 0 || balance > 1000)) {
    return res.status(400).json({
      error: "Simulated balance must be between $0 and $1,000"
    });
  }

  const result = await pool.query(
    `UPDATE users
     SET approved = COALESCE($1, approved),
         active = COALESCE($2, active),
         balance = COALESCE($3, balance),
         wager_limit = COALESCE($4, wager_limit)
     WHERE id = $5
     RETURNING id, username, approved, active, balance, wager_limit`,
    [approved, active, balance, wagerLimit, userId]
  );

  res.json(result.rows[0]);
});

app.post("/api/bets", requireLogin, async (req, res) => {
  try {
    const { sport, selection, odds, amount, potentialPayout } = req.body;

    const wager = Number(amount);

    if (!selection || !Number.isFinite(wager) || wager <= 0) {
      return res.status(400).json({ error: "Invalid simulated wager" });
    }

    const userResult = await pool.query(
      "SELECT balance, wager_limit, active FROM users WHERE id = $1",
      [req.session.userId]
    );

    const user = userResult.rows[0];

    if (!user.active) {
      return res.status(403).json({ error: "Account suspended" });
    }

    if (wager > Number(user.wager_limit)) {
      return res.status(400).json({ error: "Wager exceeds account limit" });
    }

    if (wager > Number(user.balance)) {
      return res.status(400).json({ error: "Insufficient simulated balance" });
    }

    await pool.query("BEGIN");

    await pool.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [wager, req.session.userId]
    );

    const betResult = await pool.query(
      `INSERT INTO bets
       (user_id, sport, selection, odds, amount, potential_payout)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [
        req.session.userId,
        sport || "",
        selection,
        odds || "",
        wager,
        Number(potentialPayout) || 0
      ]
    );

    await pool.query(
      `INSERT INTO activity_logs (user_id, action, details)
       VALUES ($1,$2,$3)`,
      [
        req.session.userId,
        "simulated_wager",
        `${selection} - $${wager}`
      ]
    );

    await pool.query("COMMIT");

    res.json({
      success: true,
      bet: betResult.rows[0]
    });
  } catch (error) {
    await pool.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Could not place simulated wager" });
  }
});

app.get("/api/bets", requireLogin, async (req, res) => {
  const result = await pool.query(
    `SELECT *
     FROM bets
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [req.session.userId]
  );

  res.json(result.rows);
});

app.get("/api/admin/activity", requireAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT activity_logs.*, users.username
    FROM activity_logs
    LEFT JOIN users ON users.id = activity_logs.user_id
    ORDER BY activity_logs.created_at DESC
    LIMIT 500
  `);

  res.json(result.rows);
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`UltimatePlayBet running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database startup error:", error);
    process.exit(1);
  });

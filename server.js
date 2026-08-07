const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

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
    secret:
      process.env.SESSION_SECRET ||
      "ultimateplaybet-simulation-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.app.use(express.static(path.join(__dirname, "public")));

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(":");

    const testHash = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    const storedBuffer = Buffer.from(hash, "hex");
    const testBuffer = Buffer.from(testHash, "hex");

    if (storedBuffer.length !== testBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(storedBuffer, testBuffer);
  } catch {
    return false;
  }
}

async function initializeDatabase() {
  await pool.query(
    "CREATE TABLE IF NOT EXISTS users (" +
      "id SERIAL PRIMARY KEY," +
      "username VARCHAR(50) UNIQUE NOT NULL," +
      "password_hash TEXT NOT NULL," +
      "role VARCHAR(20) NOT NULL DEFAULT 'player'," +
      "approved BOOLEAN NOT NULL DEFAULT FALSE," +
      "active BOOLEAN NOT NULL DEFAULT TRUE," +
      "balance NUMERIC(12,2) NOT NULL DEFAULT 0," +
      "starting_balance NUMERIC(12,2) NOT NULL DEFAULT 0," +
      "wager_limit NUMERIC(12,2) NOT NULL DEFAULT 500," +
      "created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP" +
    ")"
  );

  await pool.query(
    "CREATE TABLE IF NOT EXISTS bets (" +
      "id SERIAL PRIMARY KEY," +
      "user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE," +
      "sport VARCHAR(100)," +
      "selection TEXT NOT NULL," +
      "odds VARCHAR(50)," +
      "amount NUMERIC(12,2) NOT NULL," +
      "potential_payout NUMERIC(12,2) NOT NULL DEFAULT 0," +
      "status VARCHAR(30) NOT NULL DEFAULT 'pending'," +
      "created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP" +
    ")"
  );

  await pool.query(
    "CREATE TABLE IF NOT EXISTS activity_logs (" +
      "id SERIAL PRIMARY KEY," +
      "user_id INTEGER REFERENCES users(id) ON DELETE SET NULL," +
      "action TEXT NOT NULL," +
      "details TEXT," +
      "created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP" +
    ")"
  );

  console.log("Database tables ready.");
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required" });
  }

  next();
}

async function requireAdmin(req, res, next) {
  try {
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
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Admin check failed" });
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      success: true,
      database: "connected",
      mode: "simulation"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      database: "disconnected"
    });
  }
});

app.post("/api/signup", async (req, res) => {
  try {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    if (username.length < 3) {
      return res.status(400).json({
        error: "Username must be at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    const countResult = await pool.query(
      "SELECT COUNT(*)::int AS total FROM users"
    );

    const firstUser = countResult.rows[0].total === 0;

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users
       (
         username,
         password_hash,
         role,
         approved,
         active,
         balance,
         starting_balance
       )
       VALUES ($1, $2, $3, $4, TRUE, $5, $5)
       RETURNING
         id,
         username,
         role,
         approved,
         active,
         balance,
         starting_balance,
         wager_limit`,
      [
        username,
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
      return res.status(400).json({
        error: "Username already exists"
      });
    }

    console.error(error);

    res.status(500).json({
      error: "Signup failed"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    const user = result.rows[0];

    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    if (!user.active) {
      return res.status(403).json({
        error: "Account suspended"
      });
    }

    if (!user.approved) {
      return res.status(403).json({
        error: "Account awaiting admin approval"
      });
    }

    req.session.userId = user.id;

    await pool.query(
      "INSERT INTO activity_logs (user_id, action) VALUES ($1, $2)",
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

    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         id,
         username,
         role,
         approved,
         active,
         balance,
         starting_balance,
         wager_limit
       FROM users
       WHERE id = $1`,
      [req.session.userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load account"
    });
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         id,
         username,
         role,
         approved,
         active,
         balance,
         starting_balance,
         wager_limit,
         created_at
       FROM users
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load users"
    });
  }
});

app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId)) {
      return res.status(400).json({
        error: "Invalid user ID"
      });
    }

    const updates = [];
    const values = [];

    if (typeof req.body.approved === "boolean") {
      values.push(req.body.approved);
      updates.push(`approved = $${values.length}`);
    }

    if (typeof req.body.active === "boolean") {
      values.push(req.body.active);
      updates.push(`active = $${values.length}`);
    }

    if (req.body.balance !== undefined) {
      const balance = Number(req.body.balance);

      if (!Number.isFinite(balance) || balance < 0 || balance > 1000) {
        return res.status(400).json({
          error: "Simulated balance must be between $0 and $1,000"
        });
      }

      values.push(balance);
      updates.push(`balance = $${values.length}`);
    }

    if (req.body.wagerLimit !== undefined) {
      const wagerLimit = Number(req.body.wagerLimit);

      if (!Number.isFinite(wagerLimit) || wagerLimit < 0) {
        return res.status(400).json({
          error: "Invalid wager limit"
        });
      }

      values.push(wagerLimit);
      updates.push(`wager_limit = $${values.length}`);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: "No valid changes supplied"
      });
    }

    values.push(userId);

    const result = await pool.query(
      `UPDATE users
       SET ${updates.join(", ")}
       WHERE id = $${values.length}
       RETURNING
         id,
         username,
         role,
         approved,
         active,
         balance,
         wager_limit`,
      values
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not update user"
    });
  }
});

app.post("/api/bets", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const selection =
      typeof req.body.selection === "string"
        ? req.body.selection.trim()
        : "";

    const sport =
      typeof req.body.sport === "string"
        ? req.body.sport.trim()
        : "";

    const odds =
      typeof req.body.odds === "string"
        ? req.body.odds.trim()
        : "";

    const wager = Number(req.body.amount);
    const potentialPayout = Number(req.body.potentialPayout) || 0;

    if (!selection || !Number.isFinite(wager) || wager <= 0) {
      return res.status(400).json({
        error: "Invalid simulated wager"
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      `SELECT balance, wager_limit, active
       FROM users
       WHERE id = $1
       FOR UPDATE`,
      [req.session.userId]
    );

    const user = userResult.rows[0];

    if (!user) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "User not found"
      });
    }

    if (!user.active) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        error: "Account suspended"
      });
    }

    if (wager > Number(user.wager_limit)) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Wager exceeds account limit"
      });
    }

    if (wager > Number(user.balance)) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient simulated balance"
      });
    }

    await client.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [wager, req.session.userId]
    );

    const betResult = await client.query(
      `INSERT INTO bets
       (
         user_id,
         sport,
         selection,
         odds,
         amount,
         potential_payout
       )
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        req.session.userId,
        sport,
        selection,
        odds,
        wager,
        potentialPayout
      ]
    );

    await client.query(
      `INSERT INTO activity_logs
       (user_id, action, details)
       VALUES ($1, $2, $3)`,
      [
        req.session.userId,
        "simulated_wager",
        `${selection} - $${wager}`
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      bet: betResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Could not place simulated wager"
    });
  } finally {
    client.release();
  }
});

app.get("/api/bets", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT *
       FROM bets
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.session.userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load simulated wagers"
    });
  }
});

app.get("/api/admin/activity", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         activity_logs.*,
         users.username
       FROM activity_logs
       LEFT JOIN users
         ON users.id = activity_logs.user_id
       ORDER BY activity_logs.created_at DESC
       LIMIT 500`
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load activity"
    });
  }
});

app.get("*", (req, res) => {res.sendFile(path.join(__dirname, "public", "index.html"));
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

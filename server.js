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
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
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
      "change-this-session-secret-before-production",
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

app.use(express.static(path.join(__dirname, "public")));

/* --------------------------------
   PASSWORD HELPERS
--------------------------------- */

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

/* --------------------------------
   DATABASE SETUP
--------------------------------- */

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'player',
      approved BOOLEAN NOT NULL DEFAULT FALSE,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      starting_balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      wager_limit NUMERIC(12,2) NOT NULL DEFAULT 1000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sport VARCHAR(100),
      selection TEXT NOT NULL,
      odds VARCHAR(50),
      amount NUMERIC(12,2) NOT NULL,
      potential_payout NUMERIC(12,2) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      result_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      settled_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(100) NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS balance_history (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      balance_after NUMERIC(12,2) NOT NULL,
      type VARCHAR(50) NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

/* --------------------------------
   AUTH MIDDLEWARE
--------------------------------- */

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const result = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows[0] || result.rows[0].role !== "admin") {
      return res.status(403).json({
        error: "Admin access required"
      });
    }

    next();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Admin check failed"
    });
  }
}

/* --------------------------------
   HEALTH
--------------------------------- */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      database: "connected",
      mode: "simulation"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      database: "disconnected"
    });
  }
});

/* --------------------------------
   SIGNUP
--------------------------------- */

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

    const role = firstUser ? "admin" : "player";
    const approved = firstUser;
    const startingBalance = firstUser ? 1000 : 0;

    const result = await pool.query(
      `
      INSERT INTO users
      (
        username,
        password_hash,
        role,
        approved,
        active,
        balance,
        starting_balance,
        wager_limit
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4,
        TRUE,
        $5,
        $5,
        1000
      )
      RETURNING
        id,
        username,
        role,
        approved,
        active,
        balance,
        starting_balance,
        wager_limit,
        created_at
      `,
      [
        username,
        passwordHash,
        role,
        approved,
        startingBalance
      ]
    );

    const user = result.rows[0];

    await pool.query(
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [
        user.id,
        "account_created",
        firstUser
          ? "Administrator account created"
          : "Player account created"
      ]
    );

    res.json({
      success: true,
      firstAdmin: firstUser,
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({
        error: "Username already exists"
      });
    }

    console.error("Signup error:", error);

    res.status(500).json({
      error: "Signup failed"
    });
  }
});

/* --------------------------------
   LOGIN
--------------------------------- */

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
      `
      SELECT *
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
      `,
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
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [user.id, "login", "User logged in"]
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        approved: user.approved,
        active: user.active,
        balance: user.balance,
        starting_balance: user.starting_balance,
        wager_limit: user.wager_limit
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* --------------------------------
   LOGOUT
--------------------------------- */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

/* --------------------------------
   CURRENT USER
--------------------------------- */

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
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
      WHERE id = $1
      `,
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

/* --------------------------------
   PLAYER BETS
--------------------------------- */

app.get("/api/bets", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM bets
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [req.session.userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load bets"
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
    const potentialPayout = Number(req.body.potentialPayout);

    if (
      !selection ||
      !Number.isFinite(wager) ||
      wager <= 0 ||
      !Number.isFinite(potentialPayout) ||
      potentialPayout <= 0
    ) {
      return res.status(400).json({
        error: "Invalid wager"
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      `
      SELECT
        balance,
        wager_limit,
        active,
        approved
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
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

    if (!user.approved) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        error: "Account awaiting approval"
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
        error: "Insufficient balance"
      });
    }

    const updatedUser = await client.query(
      `
      UPDATE users
      SET balance = balance - $1
      WHERE id = $2
      RETURNING balance
      `,
      [wager, req.session.userId]
    );

    const betResult = await client.query(
      `
      INSERT INTO bets
      (
        user_id,
        sport,
        selection,
        odds,
        amount,
        potential_payout
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
      `,
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
      `
      INSERT INTO balance_history
      (
        user_id,
        amount,
        balance_after,
        type,
        note
      )
      VALUES ($1, $2, $3, $4, $5)
      `,
      [
        req.session.userId,
        -wager,
        updatedUser.rows[0].balance,
        "wager",
        selection
      ]
    );

    await client.query(
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [
        req.session.userId,
        "wager_placed",
        `${selection} - $${wager.toFixed(2)}`
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      bet: betResult.rows[0],
      balance: updatedUser.rows[0].balance
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Could not place wager"
    });
  } finally {
    client.release();
  }
});

/* --------------------------------
   BALANCE HISTORY
--------------------------------- */

app.get("/api/balance-history", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM balance_history
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 250
      `,
      [req.session.userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load balance history"
    });
  }
});

/* --------------------------------
   ADMIN USERS
--------------------------------- */

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
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
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load users"
    });
  }
});

/* --------------------------------
   ADMIN CREATE PLAYER
--------------------------------- */

app.post("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    const startingBalance = Number(req.body.startingBalance ?? 0);
    const wagerLimit = Number(req.body.wagerLimit ?? 1000);

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

    if (
      !Number.isFinite(startingBalance) ||
      !Number.isFinite(wagerLimit) ||
      wagerLimit < 0
    ) {
      return res.status(400).json({
        error: "Invalid balance or wager limit"
      });
    }

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `
      INSERT INTO users
      (
        username,
        password_hash,
        role,
        approved,
        active,
        balance,
        starting_balance,
        wager_limit
      )
      VALUES
      (
        $1,
        $2,
        'player',
        TRUE,
        TRUE,
        $3,
        $3,
        $4
      )
      RETURNING
        id,
        username,
        role,
        approved,
        active,
        balance,
        starting_balance,
        wager_limit,
        created_at
      `,
      [
        username,
        passwordHash,
        startingBalance,
        wagerLimit
      ]
    );

    await pool.query(
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [
        req.session.userId,
        "admin_created_player",
        `Created player ${username}`
      ]
    );

    res.json({
      success: true,
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
      error: "Could not create player"
    });
  }
});

/* --------------------------------
   ADMIN UPDATE PLAYER
--------------------------------- */

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

    function addUpdate(column, value) {
      values.push(value);
      updates.push(`${column} = $${values.length}`);
    }

    if (typeof req.body.approved === "boolean") {
      addUpdate("approved", req.body.approved);
    }

    if (typeof req.body.active === "boolean") {
      addUpdate("active", req.body.active);
    }

    if (req.body.balance !== undefined) {
      const balance = Number(req.body.balance);

      if (!Number.isFinite(balance)) {
        return res.status(400).json({
          error: "Invalid balance"
        });
      }

      addUpdate("balance", balance);
    }

    if (req.body.startingBalance !== undefined) {
      const startingBalance = Number(req.body.startingBalance);

      if (!Number.isFinite(startingBalance)) {
        return res.status(400).json({
          error: "Invalid starting balance"
        });
      }

      addUpdate("starting_balance", startingBalance);
    }

    if (req.body.wagerLimit !== undefined) {
      const wagerLimit = Number(req.body.wagerLimit);

      if (!Number.isFinite(wagerLimit) || wagerLimit < 0) {
        return res.status(400).json({
          error: "Invalid wager limit"
        });
      }

      addUpdate("wager_limit", wagerLimit);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        error: "No valid changes supplied"
      });
    }

    values.push(userId);

    const result = await pool.query(
      `
      UPDATE users
      SET ${updates.join(", ")}
      WHERE id = $${values.length}
      RETURNING
        id,
        username,
        role,
        approved,
        active,
        balance,
        starting_balance,
        wager_limit,
        created_at
      `,
      values
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    await pool.query(
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [
        req.session.userId,
        "admin_updated_player",
        `Updated player ${result.rows[0].username}`
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not update user"
    });
  }
});

/* --------------------------------
   ADMIN BETS
--------------------------------- */

app.get("/api/admin/bets", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        bets.*,
        users.username
      FROM bets
      JOIN users
        ON users.id = bets.user_id
      ORDER BY bets.created_at DESC
      LIMIT 500
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load bets"
    });
  }
});

/* --------------------------------
   ADMIN SETTLE BET
--------------------------------- */

app.patch("/api/admin/bets/:id", requireAdmin, async (req, res) => {
  const client = await pool.connect();

  try {
    const betId = Number(req.params.id);
    const status = String(req.body.status || "").toLowerCase();

    if (!["won", "lost", "void"].includes(status)) {
      return res.status(400).json({
        error: "Invalid bet result"
      });
    }

    await client.query("BEGIN");

    const betResult = await client.query(
      `
      SELECT *
      FROM bets
      WHERE id = $1
      FOR UPDATE
      `,
      [betId]
    );

    const bet = betResult.rows[0];

    if (!bet) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Bet not found"
      });
    }

    if (bet.status !== "pending") {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Bet is already settled"
      });
    }

    let credit = 0;

    if (status === "won") {
      credit = Number(bet.potential_payout);
    }

    if (status === "void") {
      credit = Number(bet.amount);
    }

    let balanceAfter = null;

    if (credit > 0) {
      const updateUser = await client.query(
        `
        UPDATE users
        SET balance = balance + $1
        WHERE id = $2
        RETURNING balance
        `,
        [credit, bet.user_id]
      );

      balanceAfter = updateUser.rows[0].balance;

      await client.query(
        `
        INSERT INTO balance_history
        (
          user_id,
          amount,
          balance_after,
          type,
          note
        )
        VALUES ($1, $2, $3, $4, $5)
        `,
        [
          bet.user_id,
          credit,
          balanceAfter,
          status === "won" ? "win" : "void",
          bet.selection
        ]
      );
    }

    const updatedBet = await client.query(
      `
      UPDATE bets
      SET
        status = $1,
        result_note = $2,
        settled_at = NOW()
      WHERE id = $3
      RETURNING *
      `,
      [
        status,
        req.body.note || null,
        betId
      ]
    );

    await client.query(
      `
      INSERT INTO activity_logs
      (user_id, action, details)
      VALUES ($1, $2, $3)
      `,
      [
        req.session.userId,
        "admin_settled_bet",
        `Bet ${betId} marked ${status}`
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      bet: updatedBet.rows[0],
      balanceAfter
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Could not settle bet"
    });
  } finally {
    client.release();
  }
});

/* --------------------------------
   ADMIN ACTIVITY
--------------------------------- */

app.get("/api/admin/activity", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        activity_logs.*,
        users.username
      FROM activity_logs
      LEFT JOIN users
        ON users.id = activity_logs.user_id
      ORDER BY activity_logs.created_at DESC
      LIMIT 500
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load activity"
    });
  }
});

/* --------------------------------
   FALLBACK
--------------------------------- */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* --------------------------------
   START SERVER
--------------------------------- */

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `UltimatePlayBet running on port ${PORT}`
      );
    });
  })
  .catch((error) => {
    console.error("Database startup error:", error);
    process.exit(1);
  });

const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Security
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
  })
);

// Read form and JSON data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || "ultimateplaybet-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// Serve website files from /public
app.use(express.static(path.join(__dirname, "public")));

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    app: "UltimatePlayBet",
  });
});

// Basic API status
app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    name: "UltimatePlayBet",
    mode: "simulation",
    cashValue: false,
  });
});

// Send main website
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`UltimatePlayBet running on port ${PORT}`);
});

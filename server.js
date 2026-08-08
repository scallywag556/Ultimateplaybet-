const express = require("express");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const ODDS_API_KEY = process.env.ODDS_API_KEY;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Sports supported by UltimatePlayBet
const SPORTS = {
  nba: "basketball_nba",
  mlb: "baseball_mlb",
  nfl: "americanfootball_nfl",
  nhl: "icehockey_nhl",
  ncaaf: "americanfootball_ncaaf",
  ncaab: "basketball_ncaab"
};

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    oddsApiConfigured: Boolean(ODDS_API_KEY)
  });
});

// Get real/current sportsbook odds
app.get("/api/odds/:sport", async (req, res) => {
  try {
    const sport = SPORTS[req.params.sport];

    if (!sport) {
      return res.status(400).json({
        error: "That sport is not supported."
      });
    }

    if (!ODDS_API_KEY) {
      return res.status(500).json({
        error: "ODDS_API_KEY is not configured."
      });
    }

    const params = new URLSearchParams({
      apiKey: ODDS_API_KEY,
      regions: "us",
      markets: "h2h,spreads,totals",
      oddsFormat: "american",
      dateFormat: "iso"
    });

    const url =
      `https://api.the-odds-api.com/v4/sports/${sport}/odds/?${params}`;

    const response = await fetch(url);

    if (!response.ok) {
      const errorText = await response.text();

      console.error(
        "Odds API error:",
        response.status,
        errorText
      );

      return res.status(response.status).json({
        error: "Unable to load current odds."
      });
    }

    const games = await response.json();

    res.json({
      sport: req.params.sport,
      updatedAt: new Date().toISOString(),
      requestsRemaining:
        response.headers.get("x-requests-remaining"),
      games
    });

  } catch (error) {
    console.error("Odds route error:", error);

    res.status(500).json({
      error: "Unable to load sportsbook odds."
    });
  }
});

// Get real scores/status
app.get("/api/scores/:sport", async (req, res) => {
  try {
    const sport = SPORTS[req.params.sport];

    if (!sport) {
      return res.status(400).json({
        error: "That sport is not supported."
      });
    }

    if (!ODDS_API_KEY) {
      return res.status(500).json({
        error: "ODDS_API_KEY is not configured."
      });
    }

    const params = new URLSearchParams({
      apiKey: ODDS_API_KEY,
      daysFrom: "3",
      dateFormat: "iso"
    });

    const url =
      `https://api.the-odds-api.com/v4/sports/${sport}/scores/?${params}`;

    const response = await fetch(url);

    if (!response.ok) {
      const errorText = await response.text();

      console.error(
        "Scores API error:",
        response.status,
        errorText
      );

      return res.status(response.status).json({
        error: "Unable to load scores."
      });
    }

    const scores = await response.json();

    res.json({
      sport: req.params.sport,
      updatedAt: new Date().toISOString(),
      scores
    });

  } catch (error) {
    console.error("Scores route error:", error);

    res.status(500).json({
      error: "Unable to load scores."
    });
  }
});

// Serve UltimatePlayBet frontend
app.get(/.*/, (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`UltimatePlayBet running on port ${PORT}`);
  console.log(
    `Odds API configured: ${Boolean(ODDS_API_KEY)}`
  );
});

import "dotenv/config";
import mongoose from "mongoose";
import { connectDatabase } from "./config/db.js";
import app from "./app.js";
import { Session } from "./models/index.js";
import { captureDailyRiskSnapshot } from "./services/riskAnalysis.js";

const port = Number(process.env.PORT) || (process.env.NODE_ENV === "production" ? 5000 : 3001);
connectDatabase().catch(() => {
  console.error("[db] Connection could not be established. Check Atlas network access, credentials, and MONGODB_URI.");
});
app.listen(port, "0.0.0.0", () => {
  console.info(`[api] ZeroTrust API listening on ${port}`);
});

setInterval(async () => {
  if (mongoose.connection.readyState !== 1) return;
  try {
    await Session.updateMany({
      status: "ACTIVE",
      $or: [{ expiresAt: { $lte: new Date() } }, { lastActivity: { $lt: new Date(Date.now() - 30 * 60 * 1000) } }],
    }, { $set: { status: "EXPIRED" } });
  } catch {
    console.error("[sessions] Could not expire stale sessions.");
  }
}, 60_000).unref();

let lastRiskSnapshotDay = "";
let riskSnapshotRunning = false;
setInterval(async () => {
  if (mongoose.connection.readyState !== 1 || riskSnapshotRunning) return;
  const day = new Date().toISOString().slice(0, 10);
  if (day === lastRiskSnapshotDay) return;
  riskSnapshotRunning = true;
  try {
    await captureDailyRiskSnapshot();
    lastRiskSnapshotDay = day;
  } catch {
    console.error("[risk-history] Could not capture the daily score snapshot.");
  } finally {
    riskSnapshotRunning = false;
  }
}, 60_000).unref();

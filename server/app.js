import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { requireDatabase } from "./middleware/auth.js";
import authRoutes from "./routes/auth.js";
import managementRoutes from "./routes/management.js";
import resourceRoutes from "./routes/resources.js";
import dashboardRoutes from "./routes/dashboard.js";

const app = express();
const clientBuild = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist/client");
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  frameguard: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'", "https://replit.com", "https://*.replit.dev"],
    },
  },
}));
app.use(express.json({ limit: "64kb" }));
app.use(cookieParser());

app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const fetchSite = req.get("sec-fetch-site");
  if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) {
    return res.status(403).json({ error: "Cross-site requests are not allowed.", code: "CSRF_BLOCKED" });
  }
  const cookieToken = req.cookies?.zt_csrf;
  const headerToken = req.get("x-csrf-token");
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: "Request verification failed. Refresh the page and try again.", code: "CSRF_BLOCKED" });
  }
  next();
});

app.get("/api/health", (_req, res) => {
  res.status(200).json({
    service: "zerotrust-api",
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    databaseConfigured: Boolean(process.env.MONGODB_URI),
  });
});
app.use("/api/auth", (req, res, next) => {
  if (req.path === "/csrf") return next();
  return requireDatabase(req, res, next);
}, authRoutes);
app.use("/api", requireDatabase, managementRoutes);
app.use("/api", requireDatabase, resourceRoutes);
app.use("/api", requireDatabase, dashboardRoutes);
app.use("/api", (_req, res) => res.status(404).json({ error: "API endpoint not found." }));

if (process.env.NODE_ENV === "production") {
  app.use(express.static(clientBuild, { index: false }));
  app.get(/.*/, (_req, res) => res.sendFile(path.join(clientBuild, "index.html")));
}

app.use((error, _req, res, _next) => {
  if (error?.name === "ZodError") {
    return res.status(400).json({ error: "Check the submitted fields.", code: "VALIDATION_ERROR", details: error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })) });
  }
  if (error?.code === 11000) return res.status(409).json({ error: "That record already exists." });
  if (error?.name === "CastError") return res.status(400).json({ error: "Invalid record identifier." });
  if (error?.name === "ValidationError") return res.status(400).json({ error: "The record could not be saved.", details: Object.values(error.errors).map((item) => item.message) });
  console.error("[api] Request failed:", error?.name || "unknown error");
  res.status(500).json({ error: "The request could not be completed. Try again." });
});

export default app;

import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { AuditLog, Device, Resource, Session, User } from "../models/index.js";
import { requireAuth } from "../middleware/auth.js";
import { writeAudit } from "../lib/audit.js";
import { AiInvalidResponseError, AiProviderUnavailableError, generateRiskAnalysis } from "../services/aiRiskAnalysis.js";
import {
  classifyRiskEvent, getRiskHistory, getRiskSnapshot, RISK_EVIDENCE_EVENT_TYPES,
} from "../services/riskAnalysis.js";
import { literalSearch } from "../lib/pagination.js";

const router = Router();
const DAY = 24 * 60 * 60 * 1000;
const riskAnalysisLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many AI risk analyses. Try again in 15 minutes.", code: "RATE_LIMITED" },
});

export function canViewRiskAnalysis(user) {
  return user?.role === "ADMIN" && user?.isBootstrapAdmin === true;
}

async function requireBootstrapAdministrator(req, res, next) {
  if (canViewRiskAnalysis(req.user)) return next();
  await writeAudit(req, {
    eventType: "RISK_ANALYSIS_ACCESS_DENIED",
    description: "A non-bootstrap account attempted to access the super-admin risk analysis.",
    status: "CRITICAL",
    user: req.user,
  });
  return res.status(403).json({ error: "Only the bootstrap administrator can view risk analysis.", code: "FORBIDDEN" });
}

function dayKey(date) {
  return new Date(date).toISOString().slice(0, 10);
}

function labelsForRange(days) {
  return Array.from({ length: days }, (_, index) => {
    const date = new Date();
    date.setUTCHours(0, 0, 0, 0);
    date.setUTCDate(date.getUTCDate() - (days - 1 - index));
    return {
      date,
      key: dayKey(date),
      label: days === 7
        ? date.toLocaleDateString("en", { weekday: "short", timeZone: "UTC" })
        : date.toLocaleDateString("en", { month: "short", day: "numeric", timeZone: "UTC" }),
    };
  });
}

router.get("/dashboard/risk-analysis", requireAuth, requireBootstrapAdministrator, async (_req, res, next) => {
  try {
    res.json({ snapshot: await getRiskSnapshot() });
  } catch (error) { next(error); }
});

router.get("/dashboard/risk-analysis/history", requireAuth, requireBootstrapAdministrator, async (req, res, next) => {
  try {
    const days = req.query.days === "90" ? 90 : 30;
    const accountId = req.query.accountId == null ? null : String(req.query.accountId);
    if (accountId && !/^[a-f\d]{24}$/i.test(accountId)) {
      return res.status(400).json({ error: "Choose a valid account.", code: "INVALID_ACCOUNT_ID" });
    }
    const history = await getRiskHistory({ days, accountId });
    res.json({ days, history });
  } catch (error) { next(error); }
});

router.get("/dashboard/risk-analysis/accounts", requireAuth, requireBootstrapAdministrator, async (req, res, next) => {
  try {
    const input = z.object({ q: z.string().trim().max(80).optional() }).parse(req.query);
    const filter = input.q ? {
      $or: [{ name: literalSearch(input.q) }, { email: literalSearch(input.q) }],
    } : {};
    const accounts = await User.find(filter).select("_id name role status")
      .sort({ name: 1, _id: 1 }).limit(50).lean();
    res.json({ accounts: accounts.map(({ _id, name, role, status }) => ({
      id: String(_id), name, role, status,
    })) });
  } catch (error) { next(error); }
});

router.get("/dashboard/risk-analysis/evidence", requireAuth, requireBootstrapAdministrator, async (req, res, next) => {
  try {
    const input = z.object({
      accountId: z.string().regex(/^[a-f\d]{24}$/i).optional(),
      days: z.enum(["7", "30", "90"]).optional(),
    }).parse(req.query);
    const now = new Date();
    const since = new Date(now.getTime() - Number(input.days || "7") * DAY);
    const events = await AuditLog.find({
      ...(input.accountId ? { userId: input.accountId } : {}),
      createdAt: { $gte: since, $lt: now },
      $or: [{ eventType: { $in: RISK_EVIDENCE_EVENT_TYPES } }, { status: "CRITICAL" }],
    }).sort({ createdAt: -1, _id: -1 })
      .select("userName eventType status description createdAt")
      .limit(100).lean();
    res.json({
      events: events.filter((event) => classifyRiskEvent(event.eventType, event.status))
        .slice(0, 30)
        .map(({ userName, eventType, status, description, createdAt }) => ({
          userName, eventType, status, description, createdAt,
        })),
    });
  } catch (error) { next(error); }
});

router.post("/dashboard/risk-analysis", requireAuth, requireBootstrapAdministrator, riskAnalysisLimit, async (req, res, next) => {
  let snapshot;
  try {
    snapshot = await getRiskSnapshot();
    if (snapshot.organization.score === null) {
      return res.status(409).json({ error: "No active accounts are available to analyze.", code: "RISK_DATA_UNAVAILABLE" });
    }
    const analysis = await generateRiskAnalysis(snapshot);
    await writeAudit(req, {
      eventType: "RISK_ANALYSIS_GENERATED",
      description: "Bootstrap administrator generated an AI risk analysis.",
      status: "SUCCESS",
      user: req.user,
      metadata: {
        organizationScore: snapshot.organization.score,
        windowDays: snapshot.windowDays,
        accountCount: snapshot.organization.activeAccountCount,
      },
    });
    res.json({ snapshot, analysis });
  } catch (error) {
    await writeAudit(req, {
      eventType: "RISK_ANALYSIS_FAILED",
      description: "Bootstrap administrator requested an AI risk analysis but no report was produced.",
      status: "WARNING",
      user: req.user,
      metadata: snapshot ? { organizationScore: snapshot.organization.score, windowDays: snapshot.windowDays } : {},
    }).catch(() => {});
    if (error instanceof AiProviderUnavailableError) {
      return res.status(503).json({
        error: "AI analysis is not enabled for this app. The deterministic risk score is still available.",
        code: "AI_NOT_CONFIGURED",
      });
    }
    if (error instanceof AiInvalidResponseError) {
      return res.status(502).json({ error: "The AI provider returned an invalid analysis. Try again.", code: "AI_INVALID_RESPONSE" });
    }
    if (error?.status === 401 || error?.status === 403) {
      return res.status(503).json({ error: "The managed AI provider is not available to this app.", code: "AI_NOT_CONFIGURED" });
    }
    if (error?.status === 429 || error?.status >= 500 || error?.name === "APIConnectionError" || error?.name === "APIConnectionTimeoutError") {
      return res.status(503).json({ error: "AI analysis could not be generated right now. The risk score is still available.", code: "AI_UNAVAILABLE" });
    }
    next(error);
  }
});

router.get("/dashboard/summary", requireAuth, async (req, res, next) => {
  try {
    const user = req.user;
    if (user.role === "ADMIN") {
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const [totalUsers, activeUsers, activeSessions, pendingDevices, failedLoginAttempts, criticalEvents, roleCounts, recentActivity] = await Promise.all([
        User.countDocuments(),
        User.countDocuments({ status: "ACTIVE" }),
        Session.countDocuments({ status: "ACTIVE", expiresAt: { $gt: new Date() } }),
        Device.countDocuments({ status: "PENDING" }),
        AuditLog.countDocuments({ eventType: { $in: ["LOGIN_FAILED", "MFA_FAILED"] }, createdAt: { $gte: since } }),
        AuditLog.countDocuments({ status: "CRITICAL", createdAt: { $gte: since } }),
        User.aggregate([{ $match: { status: "ACTIVE" } }, { $group: { _id: "$role", count: { $sum: 1 } } }]),
        AuditLog.find().sort({ createdAt: -1 }).limit(8).lean(),
      ]);
      return res.json({
        role: "ADMIN",
        metrics: { totalUsers, activeUsers, activeSessions, pendingDevices, failedLoginAttempts, criticalEvents },
        roleDistribution: roleCounts.map(({ _id, count }) => ({ role: _id, count })),
        recentActivity: recentActivity.map((item) => ({ ...item, id: item._id })),
      });
    }
    if (user.role === "MANAGER") {
      const departmentId = user.departmentId?._id || user.departmentId;
      const team = departmentId ? await User.find({ departmentId }).select("_id").lean() : [];
      const teamIds = team.map((item) => item._id);
      const resourceScope = departmentId
        ? { $or: [{ departmentId }, { departmentId: null }] }
        : { departmentId: null };
      const [employees, resources, events, activeSessions] = await Promise.all([
        departmentId ? User.countDocuments({ departmentId, role: "EMPLOYEE", status: "ACTIVE" }) : 0,
        Resource.countDocuments({ active: true, allowedRoles: "MANAGER", ...resourceScope }),
        AuditLog.find({ userId: { $in: teamIds } }).sort({ createdAt: -1 }).limit(8).lean(),
        Session.countDocuments({ userId: user._id, status: "ACTIVE", expiresAt: { $gt: new Date() } }),
      ]);
      return res.json({
        role: "MANAGER",
        metrics: { employees, resources, activeSessions },
        departmentName: user.departmentId?.name || "Unassigned",
        recentActivity: events.map((item) => ({ ...item, id: item._id })),
        security: { mfaEnabled: user.mfaEnabled, accountStatus: user.status },
      });
    }
    const [resources, activeSessions, recentActivity] = await Promise.all([
      Resource.countDocuments({ active: true, allowedRoles: "EMPLOYEE", $or: [{ departmentId: user.departmentId?._id || user.departmentId }, { departmentId: null }] }),
      Session.countDocuments({ userId: user._id, status: "ACTIVE", expiresAt: { $gt: new Date() } }),
      AuditLog.find({ userId: user._id }).sort({ createdAt: -1 }).limit(8).lean(),
    ]);
    return res.json({
      role: "EMPLOYEE",
      metrics: { resources, activeSessions },
      security: { mfaEnabled: user.mfaEnabled, accountStatus: user.status },
      lastLoginAt: user.lastLoginAt,
      recentActivity: recentActivity.map((item) => ({ ...item, id: item._id })),
    });
  } catch (error) { next(error); }
});

router.get("/dashboard/activity", requireAuth, async (req, res, next) => {
  try {
    const range = ["7d", "30d", "90d"].includes(req.query.range) ? req.query.range : "7d";
    const days = Number(range.slice(0, -1));
    const labels = labelsForRange(days);
    const nextDay = new Date(labels.at(-1).date.getTime() + DAY);
    let userFilter = {};
    if (req.user.role === "EMPLOYEE") {
      userFilter = { userId: req.user._id };
    } else if (req.user.role === "MANAGER") {
      const departmentId = req.user.departmentId?._id || req.user.departmentId;
      const team = departmentId
        ? await User.find({ departmentId, role: "EMPLOYEE", status: "ACTIVE" }).select("_id").lean()
        : [];
      userFilter = { userId: { $in: team.map(({ _id }) => _id) } };
    }
    const groupedEvents = await AuditLog.aggregate([
      { $match: { ...userFilter, createdAt: { $gte: labels[0].date, $lt: nextDay } } },
      { $group: {
        _id: {
          day: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt", timezone: "UTC" } },
          eventType: "$eventType",
          status: "$status",
        },
        count: { $sum: 1 },
      } },
    ]);
    const byDay = new Map(labels.map((item) => [item.key, { date: item.label, logins: 0, alerts: 0, denied: 0 }]));
    for (const event of groupedEvents) {
      const row = byDay.get(event._id.day);
      if (!row) continue;
      if (event._id.eventType === "LOGIN_SUCCESS") row.logins += event.count;
      if (event._id.status === "CRITICAL") row.alerts += event.count;
      if (event._id.eventType.includes("DENIED") || event._id.eventType.includes("MISMATCH") || event._id.eventType === "UNAUTHORIZED_ACCESS" || event._id.eventType === "UNAUTHORIZED_RESOURCE_ACCESS") row.denied += event.count;
    }
    res.json({ range, activity: [...byDay.values()] });
  } catch (error) { next(error); }
});

export default router;

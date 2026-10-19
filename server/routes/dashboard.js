import { Router } from "express";
import { AuditLog, Device, Resource, Session, User } from "../models/index.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();
const DAY = 24 * 60 * 60 * 1000;

function dayKey(date) {
  return new Date(date).toISOString().slice(0, 10);
}

function labelsForLastWeek() {
  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date();
    date.setUTCHours(0, 0, 0, 0);
    date.setUTCDate(date.getUTCDate() - (6 - index));
    return { date, key: dayKey(date), label: date.toLocaleDateString("en", { weekday: "short", timeZone: "UTC" }) };
  });
}

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
    const since = new Date(Date.now() - days * DAY);
    const labels = labelsForLastWeek();
    const userFilter = req.user.role === "ADMIN" ? {} : { userId: req.user._id };
    const events = await AuditLog.find({ ...userFilter, createdAt: { $gte: since } })
      .sort({ createdAt: 1 }).limit(3000).select("eventType status createdAt").lean();
    const byDay = new Map(labels.map((item) => [item.key, { date: item.label, logins: 0, alerts: 0, denied: 0 }]));
    for (const event of events) {
      const row = byDay.get(dayKey(event.createdAt));
      if (!row) continue;
      if (event.eventType === "LOGIN_SUCCESS") row.logins += 1;
      if (event.status === "CRITICAL") row.alerts += 1;
      if (event.eventType.includes("DENIED") || event.eventType.includes("MISMATCH") || event.eventType === "UNAUTHORIZED_ACCESS" || event.eventType === "UNAUTHORIZED_RESOURCE_ACCESS") row.denied += 1;
    }
    res.json({ range, activity: [...byDay.values()] });
  } catch (error) { next(error); }
});

export default router;

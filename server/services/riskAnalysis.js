import { AuditLog, Device, User } from "../models/index.js";

export const RISK_WINDOW_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

const failedEventTypes = new Set(["LOGIN_FAILED", "MFA_FAILED"]);
const deniedEventTypes = new Set([
  "PORTAL_ROLE_MISMATCH",
  "UNAUTHORIZED_PORTAL_ACCESS",
  "UNAUTHORIZED_ACCESS",
  "UNAUTHORIZED_RESOURCE_ACCESS",
  "UNAUTHORIZED_USER_ACCESS",
  "LOGIN_BLOCKED",
  "UNAUTHENTICATED_ACCESS",
  "INACTIVE_SESSION_ACCESS",
  "INACTIVE_ACCOUNT_ACCESS",
  "MFA_REQUIRED_ACCESS",
  "UNAPPROVED_DEVICE_ACCESS",
]);

export function riskLevel(score) {
  if (score === null || score === undefined) return "NO_DATA";
  if (score < 25) return "LOW";
  if (score < 50) return "MODERATE";
  if (score < 75) return "HIGH";
  return "CRITICAL";
}

function clampScore(points) {
  return Math.min(100, Math.max(0, Math.round(points)));
}

function countFor(map, userId) {
  return map.get(String(userId)) || { failed: 0, denied: 0, critical: 0 };
}

function addEvents(target, eventRows, byUser = false) {
  for (const row of eventRows) {
    const { eventType, status } = row._id;
    const bucket = failedEventTypes.has(eventType)
      ? "failed"
      : deniedEventTypes.has(eventType)
        ? "denied"
        : status === "CRITICAL"
          ? "critical"
          : null;
    if (!bucket) continue;
    const key = byUser ? String(row._id.userId || "") : "organization";
    if (!key) continue;
    const counts = target.get(key) || { failed: 0, denied: 0, critical: 0 };
    counts[bucket] += row.count;
    target.set(key, counts);
  }
}

function factor(key, label, points, detail) {
  return { key, label, points, detail };
}

export function calculateAccountRisk(user, activity = {}, stalePendingDevices = 0) {
  const isMfaDisabled = user.mfaEnabled !== true;
  const privilegePoints = user.role === "ADMIN" ? 15 : user.role === "MANAGER" ? 8 : 0;
  const factors = [
    factor("mfa", "MFA posture", isMfaDisabled ? 30 : 0, isMfaDisabled ? "MFA is not enabled." : "MFA is enabled."),
    factor("privilege", "Privilege level", privilegePoints, `${user.role} account privilege weighting.`),
    factor("failedAuth", "Failed sign-ins / MFA", Math.min(20, (activity.failed || 0) * 5), `${activity.failed || 0} failed authentication event(s) in 7 days.`),
    factor("deniedAccess", "Denied access attempts", Math.min(30, (activity.denied || 0) * 10), `${activity.denied || 0} denied or mismatched access event(s) in 7 days.`),
    factor("criticalEvents", "Other critical events", Math.min(25, (activity.critical || 0) * 10), `${activity.critical || 0} other critical event(s) in 7 days.`),
    factor("staleDevices", "Unresolved device approvals", stalePendingDevices > 0 ? 10 : 0, `${stalePendingDevices} pending device approval(s) older than 24 hours.`),
  ];
  const score = clampScore(factors.reduce((sum, item) => sum + item.points, 0));
  return { score, level: riskLevel(score), factors };
}

export function calculateOrganizationRisk({ activeUsers = [], activity = {}, stalePendingDevices = 0 }) {
  if (activeUsers.length === 0) {
    return {
      score: null,
      level: riskLevel(null),
      mfaCoveragePercent: null,
      factors: [],
    };
  }
  const mfaEnabled = activeUsers.filter((user) => user.mfaEnabled === true).length;
  const mfaCoveragePercent = Math.round((mfaEnabled / activeUsers.length) * 100);
  const factors = [
    factor("mfaCoverage", "MFA coverage gap", Math.round(30 * (1 - mfaEnabled / activeUsers.length)), `${mfaEnabled} of ${activeUsers.length} active identities have MFA enabled (${mfaCoveragePercent}%).`),
    factor("deniedAccess", "Denied access attempts", Math.min(25, (activity.denied || 0) * 8), `${activity.denied || 0} denied or mismatched access event(s) in 7 days; capped at 25 points.`),
    factor("criticalEvents", "Critical security events", Math.min(25, (activity.critical || 0) * 10), `${activity.critical || 0} other critical event(s) in 7 days; capped at 25 points.`),
    factor("failedAuth", "Failed sign-ins / MFA", Math.min(10, (activity.failed || 0) * 2), `${activity.failed || 0} failed authentication event(s) in 7 days; capped at 10 points.`),
    factor("staleDevices", "Unresolved device approvals", Math.min(10, stalePendingDevices * 5), `${stalePendingDevices} pending device approval(s) older than 24 hours; capped at 10 points.`),
  ];
  const score = clampScore(factors.reduce((sum, item) => sum + item.points, 0));
  return { score, level: riskLevel(score), mfaCoveragePercent, factors };
}

function trend(current = {}, previous = {}) {
  return ["failed", "denied", "critical"].map((key) => ({
    key,
    label: key === "failed" ? "Failed authentication" : key === "denied" ? "Denied access" : "Other critical events",
    current: current[key] || 0,
    previous: previous[key] || 0,
    change: (current[key] || 0) - (previous[key] || 0),
  }));
}

export async function getRiskSnapshot(now = new Date()) {
  const currentStart = new Date(now.getTime() - RISK_WINDOW_DAYS * DAY_MS);
  const previousStart = new Date(currentStart.getTime() - RISK_WINDOW_DAYS * DAY_MS);
  const staleDeviceBefore = new Date(now.getTime() - DAY_MS);
  const activeUsers = await User.find({ status: "ACTIVE" })
    .select("_id name role mfaEnabled")
    .lean();
  const activeUserIds = activeUsers.map((user) => user._id);

  const [currentGlobalEvents, previousGlobalEvents, accountEventRows, staleDeviceRows] = await Promise.all([
    AuditLog.aggregate([
      { $match: { createdAt: { $gte: currentStart, $lt: now } } },
      { $group: { _id: { eventType: "$eventType", status: "$status" }, count: { $sum: 1 } } },
    ]),
    AuditLog.aggregate([
      { $match: { createdAt: { $gte: previousStart, $lt: currentStart } } },
      { $group: { _id: { eventType: "$eventType", status: "$status" }, count: { $sum: 1 } } },
    ]),
    activeUserIds.length
      ? AuditLog.aggregate([
        { $match: { userId: { $in: activeUserIds }, createdAt: { $gte: currentStart, $lt: now } } },
        { $group: { _id: { userId: "$userId", eventType: "$eventType", status: "$status" }, count: { $sum: 1 } } },
      ])
      : Promise.resolve([]),
    Device.aggregate([
      { $match: { status: "PENDING", createdAt: { $lte: staleDeviceBefore } } },
      { $group: { _id: "$userId", count: { $sum: 1 } } },
    ]),
  ]);

  const currentCounts = new Map();
  const previousCounts = new Map();
  const accountCounts = new Map();
  addEvents(currentCounts, currentGlobalEvents);
  addEvents(previousCounts, previousGlobalEvents);
  addEvents(accountCounts, accountEventRows, true);
  const staleByUser = new Map(staleDeviceRows.map((row) => [String(row._id), row.count]));
  const globalActivity = currentCounts.get("organization") || { failed: 0, denied: 0, critical: 0 };
  const previousActivity = previousCounts.get("organization") || { failed: 0, denied: 0, critical: 0 };
  const organization = calculateOrganizationRisk({
    activeUsers,
    activity: globalActivity,
    stalePendingDevices: staleDeviceRows.reduce((sum, row) => sum + row.count, 0),
  });
  const accounts = activeUsers.map((user) => ({
    id: String(user._id),
    name: user.name,
    role: user.role,
    mfaEnabled: user.mfaEnabled === true,
    ...calculateAccountRisk(user, countFor(accountCounts, user._id), staleByUser.get(String(user._id)) || 0),
  })).sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return {
    generatedAt: now.toISOString(),
    windowDays: RISK_WINDOW_DAYS,
    windowStart: currentStart.toISOString(),
    windowEnd: now.toISOString(),
    organization: {
      ...organization,
      activeAccountCount: activeUsers.length,
      highRiskAccountCount: accounts.filter((account) => account.score >= 50).length,
      trends: trend(globalActivity, previousActivity),
    },
    accounts: accounts.slice(0, 10),
  };
}

export function buildRedactedRiskInput(snapshot) {
  const refs = new Map();
  const accounts = snapshot.accounts.map((account, index) => {
    const accountRef = `acct-${index + 1}`;
    refs.set(accountRef, { id: account.id, name: account.name, role: account.role });
    return {
      accountRef,
      role: account.role,
      mfaEnabled: account.mfaEnabled,
      riskScore: account.score,
      riskLevel: account.level,
      factors: account.factors.filter((item) => item.points > 0).map(({ key, points, detail }) => ({ key, points, detail })),
    };
  });
  return {
    refs,
    data: {
      windowDays: snapshot.windowDays,
      organization: {
        score: snapshot.organization.score,
        level: snapshot.organization.level,
        activeAccountCount: snapshot.organization.activeAccountCount,
        mfaCoveragePercent: snapshot.organization.mfaCoveragePercent,
        highRiskAccountCount: snapshot.organization.highRiskAccountCount,
        factors: snapshot.organization.factors.map(({ key, points, detail }) => ({ key, points, detail })),
        trends: snapshot.organization.trends,
      },
      accounts,
    },
  };
}

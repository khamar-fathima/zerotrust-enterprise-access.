import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { Department, Device, AuditLog, PreAuth, Role, Session, User } from "../models/index.js";
import { writeAudit } from "../lib/audit.js";
import { cookieOptions, hashToken, requestContext } from "../lib/security.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import {
  auditQuery, deviceQuery, literalSearch, pageMetadata, paginate, sessionQuery, usersQuery,
} from "../lib/pagination.js";

const router = Router();
const objectIdText = /^[a-f\d]{24}$/i;
const safeUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  status: user.status,
  departmentId: user.departmentId?._id || user.departmentId || null,
  departmentName: user.departmentId?.name || "",
  mfaEnabled: user.mfaEnabled,
  createdAt: user.createdAt,
  lastLoginAt: user.lastLoginAt,
});

function cleanText(value, max = 120) {
  return String(value || "").trim().slice(0, max);
}

router.get("/users", requireAuth, async (req, res, next) => {
  try {
    if (!["ADMIN", "MANAGER"].includes(req.user.role)) {
      return res.status(403).json({ error: "You cannot view other users.", code: "FORBIDDEN" });
    }
    const input = usersQuery.parse(req.query);
    const isManager = req.user.role === "MANAGER";
    const departmentId = req.user.departmentId?._id || req.user.departmentId;
    if (isManager && !departmentId) {
      return res.json({ users: [], total: 0, page: 1, limit: input.limit, totalPages: 0 });
    }
    const filters = {};
    if (input.status) filters.status = input.status;
    if (input.role) filters.role = input.role;
    if (input.departmentId) filters.departmentId = input.departmentId;
    if (input.q) {
      const search = literalSearch(input.q);
      const departments = await Department.find({
        name: search, ...(isManager ? { _id: departmentId } : {}),
      }).select("_id").lean();
      filters.$or = ["name", "email", "role", "status"].map((field) => ({ [field]: search }));
      filters.$or.push({ departmentId: { $in: departments.map((item) => item._id) } });
    }
    // Client filters may narrow this scope, never overwrite it.
    const scopedFilters = isManager ? { $and: [
      { departmentId, role: "EMPLOYEE", status: "ACTIVE" }, filters,
    ] } : filters;
    const pagination = await paginate(User, scopedFilters, input);
    const users = await User.find(scopedFilters)
      .select("name email role status departmentId mfaEnabled createdAt lastLoginAt")
      .populate("departmentId", "name")
      .sort(isManager ? { name: 1, _id: 1 } : { createdAt: -1, _id: -1 })
      .skip(pagination.skip).limit(pagination.limit).lean();
    return res.json({ users: users.map(safeUser), ...pageMetadata(pagination) });
  } catch (error) { next(error); }
});

router.get("/users/:id", requireAuth, async (req, res, next) => {
  try {
    const target = await User.findById(req.params.id).populate("departmentId", "name");
    if (!target) return res.status(404).json({ error: "User not found." });
    const ownRecord = target._id.equals(req.user._id);
    const sameDepartment = req.user.departmentId && target.departmentId &&
      String(req.user.departmentId._id || req.user.departmentId) === String(target.departmentId._id || target.departmentId);
    const allowed = req.user.role === "ADMIN" || ownRecord || (req.user.role === "MANAGER" && sameDepartment && target.role === "EMPLOYEE");
    if (!allowed) {
      await writeAudit(req, { eventType: "UNAUTHORIZED_USER_ACCESS", description: "A user attempted to retrieve a private identity outside their scope.", status: "CRITICAL", user: req.user, metadata: { targetUserId: target._id.toString() } });
      return res.status(403).json({ error: "You cannot view this user's private information.", code: "FORBIDDEN" });
    }
    res.json({ user: safeUser(target) });
  } catch (error) { next(error); }
});

router.post("/users", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    if (typeof req.body?.departmentId === "string" && !objectIdText.test(req.body.departmentId)) {
      return res.status(400).json({ error: "Choose a valid department.", code: "INVALID_DEPARTMENT_ID" });
    }
    const input = z.object({
      name: z.string().trim().min(2).max(100),
      email: z.string().email().max(254),
      role: z.enum(["MANAGER", "EMPLOYEE"]),
      departmentId: z.string().regex(objectIdText, "Choose a valid department."),
      temporaryPassword: z.string().min(12).max(128).regex(/[a-z]/).regex(/[A-Z]/).regex(/\d/),
    }).parse(req.body);
    const email = input.email.toLowerCase();
    if (await User.exists({ email })) return res.status(409).json({ error: "An account with that email already exists." });
    if (!(await Department.exists({ _id: input.departmentId }))) return res.status(400).json({ error: "Choose a valid department." });
    const user = await User.create({
      name: input.name,
      email,
      role: input.role,
      departmentId: input.departmentId,
      status: "ACTIVE",
      passwordHash: await bcrypt.hash(input.temporaryPassword, 12),
      forcePasswordChange: true,
    });
    await writeAudit(req, {
      eventType: "USER_CREATED",
      description: `Administrator created a ${input.role.toLowerCase()} account.`,
      user: req.user,
      metadata: { targetUserId: user._id.toString(), targetRole: user.role },
    });
    res.status(201).json({ user: safeUser(user), message: "Account created. The user must change the temporary password and enroll MFA." });
  } catch (error) { next(error); }
});

router.patch("/users/:id", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    if (typeof req.body?.departmentId === "string" && req.body.departmentId !== "" && !objectIdText.test(req.body.departmentId)) {
      return res.status(400).json({ error: "Choose a valid department.", code: "INVALID_DEPARTMENT_ID" });
    }
    const input = z.object({
      name: z.string().trim().min(2).max(100).optional(),
      role: z.enum(["ADMIN", "MANAGER", "EMPLOYEE"]).optional(),
      status: z.enum(["ACTIVE", "DISABLED"]).optional(),
      departmentId: z.union([z.string().regex(objectIdText, "Choose a valid department."), z.literal("")]).nullable().optional(),
    }).refine((value) => Object.keys(value).length > 0).parse(req.body);
    const target = await User.findById(req.params.id).populate("departmentId", "name");
    if (!target) return res.status(404).json({ error: "User not found." });
    if (target._id.equals(req.user._id) && (input.role && input.role !== "ADMIN" || input.status === "DISABLED")) {
      const activeAdmins = await User.countDocuments({ role: "ADMIN", status: "ACTIVE" });
      if (activeAdmins <= 1) return res.status(409).json({ error: "You cannot remove the only active administrator." });
    }
    if (input.departmentId && !(await Department.exists({ _id: input.departmentId }))) {
      return res.status(400).json({ error: "Choose a valid department." });
    }
    const beforeRole = target.role;
    const beforeStatus = target.status;
    const previousDepartment = target.departmentId;
    const oldDepartmentId = previousDepartment
      ? String(previousDepartment._id || previousDepartment)
      : null;
    const requestedDepartmentId = input.departmentId ? String(input.departmentId) : null;
    const departmentChanged = Object.hasOwn(input, "departmentId") && requestedDepartmentId !== oldDepartmentId;
    let newDepartment = null;
    if (departmentChanged && requestedDepartmentId) {
      newDepartment = await Department.findById(requestedDepartmentId).select("name").lean();
      if (!newDepartment) return res.status(400).json({ error: "Choose a valid department." });
    }
    const oldDepartmentName = previousDepartment?.name || null;
    const newDepartmentName = newDepartment?.name || null;
    Object.assign(target, input);
    await target.save();
    if (input.role || input.status === "DISABLED") {
      await Session.updateMany({ userId: target._id, status: "ACTIVE" }, {
        $set: { status: "REVOKED", revokedAt: new Date(), revokeReason: "Account role or status changed" },
      });
    }
    if (input.status === "DISABLED") {
      await PreAuth.deleteMany({ userId: target._id });
    }
    const eventType = input.role && input.role !== beforeRole ? "ROLE_MODIFIED" : input.status && input.status !== beforeStatus ? "ACCOUNT_STATUS_CHANGED" : "USER_UPDATED";
    await writeAudit(req, {
      eventType,
      description: [
        input.role && input.role !== beforeRole
          ? `Administrator changed a user's role from ${beforeRole} to ${input.role}.`
          : null,
        input.status && input.status !== beforeStatus
          ? `Administrator changed a user's status to ${input.status}.`
          : null,
        departmentChanged
          ? `Department changed from ${oldDepartmentName || "Unassigned"} to ${newDepartmentName || "Unassigned"}.`
          : null,
      ].filter(Boolean).join(" ") || "Administrator updated a user profile.",
      user: req.user,
      status: input.status === "DISABLED" ? "WARNING" : "SUCCESS",
      metadata: {
        targetUserId: target._id.toString(),
        role: target.role,
        status: target.status,
        ...(departmentChanged ? {
          oldDepartmentId,
          oldDepartmentName,
          newDepartmentId: newDepartment?._id?.toString() || null,
          newDepartmentName,
        } : {}),
      },
    });
    res.json({ user: safeUser(target) });
  } catch (error) { next(error); }
});

router.post("/users/:id/review", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    const { decision } = z.object({ decision: z.enum(["APPROVE", "REJECT"]) }).parse(req.body);
    const user = await User.findById(req.params.id);
    if (!user || user.status !== "PENDING" || user.role !== "EMPLOYEE") {
      return res.status(404).json({ error: "Pending employee request not found." });
    }
    user.status = decision === "APPROVE" ? "ACTIVE" : "REJECTED";
    await user.save();
    await writeAudit(req, {
      eventType: decision === "APPROVE" ? "REGISTRATION_APPROVED" : "REGISTRATION_REJECTED",
      description: `Administrator ${decision.toLowerCase()}d an employee registration request.`,
      user: req.user,
      status: decision === "REJECT" ? "WARNING" : "SUCCESS",
      metadata: { targetUserId: user._id.toString() },
    });
    res.json({ user: safeUser(user), message: `Registration ${decision.toLowerCase()}d.` });
  } catch (error) { next(error); }
});

router.get("/roles", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    const roles = await Role.find().sort({ key: 1 }).lean();
    res.json({ roles });
  } catch (error) { next(error); }
});

router.get("/departments", requireAuth, async (req, res, next) => {
  try {
    const departments = req.user.role === "ADMIN"
      ? await Department.find().sort({ name: 1 }).lean()
      : await Department.find({ _id: req.user.departmentId?._id || req.user.departmentId }).sort({ name: 1 }).lean();
    res.json({ departments });
  } catch (error) { next(error); }
});

router.get("/devices", requireAuth, async (req, res, next) => {
  try {
    const input = deviceQuery.parse(req.query);
    const filters = {};
    if (req.user.role !== "ADMIN") filters.userId = req.user._id;
    else if (input.userId) filters.userId = input.userId;
    if (input.status) filters.status = input.status;
    if (input.q) {
      const search = literalSearch(input.q);
      const owners = await User.find({ $or: [{ name: search }, { email: search }] }).select("_id").limit(500).lean();
      filters.$or = [
        { name: search }, { browser: search }, { operatingSystem: search },
        { userId: { $in: owners.map(({ _id }) => _id) } },
      ];
    }
    const pagination = await paginate(Device, filters, input);
    const devices = await Device.find(filters).populate("userId", "name email role departmentId")
      .sort({ createdAt: -1, _id: -1 }).skip(pagination.skip).limit(pagination.limit);
    res.json({
      devices: devices.map((device) => ({
        id: device._id,
        userId: device.userId?._id,
        userName: device.userId?.name || "",
        userEmail: device.userId?.email || "",
        role: device.userId?.role || "",
        name: device.name,
        browser: device.browser,
        operatingSystem: device.operatingSystem,
        status: device.status,
        createdAt: device.createdAt,
        lastActivity: device.lastActivity,
        ipAddress: req.user.role === "ADMIN" ? device.ipAddress : undefined,
        current: device._id.equals(req.device._id),
      })),
      ...pageMetadata(pagination),
    });
  } catch (error) { next(error); }
});

router.patch("/devices/:id", requireAuth, async (req, res, next) => {
  try {
    const { status } = z.object({ status: z.enum(["APPROVED", "REVOKED"]) }).parse(req.body);
    const device = await Device.findById(req.params.id);
    if (!device) return res.status(404).json({ error: "Device not found." });
    if (req.user.role !== "ADMIN" && (!device.userId.equals(req.user._id) || status !== "REVOKED")) {
      await writeAudit(req, { eventType: "UNAUTHORIZED_ACCESS", description: "A user attempted to manage a device outside their permissions.", status: "CRITICAL", user: req.user, metadata: { deviceId: device._id.toString() } });
      return res.status(403).json({ error: "Only administrators can approve devices. You may revoke your own devices.", code: "FORBIDDEN" });
    }
    device.status = status;
    device.approvedAt = status === "APPROVED" ? new Date() : null;
    device.approvedBy = status === "APPROVED" ? req.user._id : null;
    await device.save();
    if (status === "REVOKED") {
      await Session.updateMany({ deviceId: device._id, status: "ACTIVE" }, {
        $set: { status: "REVOKED", revokedAt: new Date(), revokeReason: "Device revoked by administrator" },
      });
    }
    const targetUser = await User.findById(device.userId);
    await writeAudit(req, {
      eventType: status === "APPROVED" ? "DEVICE_APPROVED" : "DEVICE_REVOKED",
      description: `${req.user.role === "ADMIN" ? "Administrator" : "User"} ${status === "APPROVED" ? "approved" : "revoked"} a registered device.`,
      user: req.user,
      status: status === "REVOKED" ? "WARNING" : "SUCCESS",
      metadata: { targetUserId: targetUser?._id.toString(), deviceId: device._id.toString(), deviceName: device.name },
    });
    res.json({ device: { id: device._id, status: device.status, name: device.name } });
  } catch (error) { next(error); }
});

router.get("/sessions", requireAuth, async (req, res, next) => {
  try {
    const input = sessionQuery.parse(req.query);
    const filters = {};
    if (req.user.role !== "ADMIN") filters.userId = req.user._id;
    else if (input.userId) filters.userId = input.userId;
    if (input.status) filters.status = input.status;
    if (input.q) {
      const search = literalSearch(input.q);
      const [owners, devices] = await Promise.all([
        User.find({ $or: [{ name: search }, { email: search }] }).select("_id").limit(500).lean(),
        Device.find({ $or: [{ name: search }, { browser: search }, { operatingSystem: search }] }).select("_id").limit(500).lean(),
      ]);
      filters.$or = [
        { browser: search },
        ...(req.user.role === "ADMIN" ? [{ ipAddress: search }] : []),
        { deviceId: { $in: devices.map(({ _id }) => _id) } },
        { userId: { $in: owners.map(({ _id }) => _id) } },
      ];
    }
    const pagination = await paginate(Session, filters, input);
    const sessions = await Session.find(filters)
      .populate("userId", "name email role")
      .populate("deviceId", "name status")
      .sort({ lastActivity: -1, _id: -1 }).skip(pagination.skip).limit(pagination.limit);
    res.json({
      sessions: sessions.map((session) => ({
        id: session._id,
        userId: session.userId?._id,
        userName: session.userId?.name || "",
        userEmail: session.userId?.email || "",
        role: session.userId?.role || session.roleAtIssue,
        ipAddress: req.user.role === "ADMIN" ? session.ipAddress : "",
        browser: session.browser,
        deviceName: session.deviceId?.name || "Unknown device",
        deviceStatus: session.deviceId?.status || "REVOKED",
        status: session.status,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        current: session._id.equals(req.session._id),
      })),
      ...pageMetadata(pagination),
    });
  } catch (error) { next(error); }
});

router.delete("/sessions/:id", requireAuth, async (req, res, next) => {
  try {
    const session = await Session.findById(req.params.id);
    if (!session) return res.status(404).json({ error: "Session not found." });
    const isAdmin = req.user.role === "ADMIN";
    if (!isAdmin && !session.userId.equals(req.user._id)) return res.status(403).json({ error: "You can only revoke your own sessions.", code: "FORBIDDEN" });
    if (session.status !== "ACTIVE") return res.status(409).json({ error: "This session is already inactive." });
    session.status = "REVOKED";
    session.revokedAt = new Date();
    session.revokeReason = isAdmin ? "Terminated by administrator" : "Signed out by user";
    await session.save();
    await writeAudit(req, {
      eventType: "SESSION_TERMINATED",
      description: isAdmin ? "Administrator terminated an active session." : "User terminated one of their active sessions.",
      user: req.user,
      status: "WARNING",
      metadata: { targetSessionId: session._id.toString(), targetUserId: session.userId.toString() },
    });
    if (session._id.equals(req.session._id)) res.clearCookie("zt_session", cookieOptions());
    res.json({ message: "Session revoked." });
  } catch (error) { next(error); }
});

router.post("/sessions/revoke-all", requireAuth, async (req, res, next) => {
  try {
    const userId = req.body.userId || req.user._id.toString();
    if (req.user.role !== "ADMIN" && userId !== req.user._id.toString()) {
      await writeAudit(req, { eventType: "UNAUTHORIZED_ACCESS", description: "A user attempted to revoke another user's sessions.", status: "CRITICAL", user: req.user });
      return res.status(403).json({ error: "You can only revoke your own sessions.", code: "FORBIDDEN" });
    }
    await Session.updateMany({ userId, status: "ACTIVE" }, { $set: { status: "REVOKED", revokedAt: new Date(), revokeReason: "All sessions revoked" } });
    await writeAudit(req, { eventType: "SESSIONS_TERMINATED", description: "All active sessions for a user were revoked.", status: "WARNING", user: req.user, metadata: { targetUserId: userId } });
    if (userId === req.user._id.toString()) res.clearCookie("zt_session", cookieOptions());
    res.json({ message: "All sessions revoked." });
  } catch (error) { next(error); }
});

router.get("/audit-logs", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    const input = auditQuery.parse(req.query);
    const filters = {};
    if (input.status) filters.status = input.status;
    if (input.eventType) filters.eventType = input.eventType;
    if (input.userId) filters.userId = input.userId;
    if (input.from || input.to) {
      filters.createdAt = {};
      if (input.from) filters.createdAt.$gte = new Date(input.from);
      if (input.to) filters.createdAt.$lte = new Date(input.to);
    }
    if (input.q) {
      const search = literalSearch(input.q);
      filters.$or = ["description", "eventType", "userName", "ipAddress", "status"].map((field) => ({ [field]: search }));
    }
    const pagination = await paginate(AuditLog, filters, input);
    const logs = await AuditLog.find(filters).sort({ createdAt: -1, _id: -1 })
      .skip(pagination.skip).limit(pagination.limit).lean();
    res.json({ logs: logs.map((log) => ({ ...log, id: log._id })), ...pageMetadata(pagination) });
  } catch (error) { next(error); }
});

router.get("/profile", requireAuth, async (req, res) => {
  res.json({ user: safeUser(req.user) });
});

router.patch("/profile", requireAuth, async (req, res, next) => {
  try {
    const input = z.object({ name: z.string().trim().min(2).max(100) }).parse(req.body);
    const user = await User.findById(req.user._id);
    user.name = input.name;
    await user.save();
    await writeAudit(req, { eventType: "PROFILE_UPDATED", description: "User updated their profile.", user });
    res.json({ user: safeUser(user) });
  } catch (error) { next(error); }
});

router.get("/profile/login-history", requireAuth, async (req, res, next) => {
  try {
    const logs = await AuditLog.find({ userId: req.user._id, eventType: { $in: ["LOGIN_SUCCESS", "LOGIN_FAILED", "PORTAL_ROLE_MISMATCH", "MFA_FAILED"] } })
      .sort({ createdAt: -1 }).limit(50).lean();
    res.json({ logs: logs.map((log) => ({ ...log, id: log._id })) });
  } catch (error) { next(error); }
});

export default router;

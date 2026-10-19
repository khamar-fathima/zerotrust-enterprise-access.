import jwt from "jsonwebtoken";
import { User, Session, Device } from "../models/index.js";
import { cookieOptions, hashToken } from "../lib/security.js";
import { writeAudit } from "../lib/audit.js";

export async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.zt_session;
    if (!token) {
      await writeAudit(req, { eventType: "UNAUTHENTICATED_ACCESS", description: "Protected access was denied because no authenticated session was supplied.", status: "WARNING", metadata: { path: req.originalUrl } });
      return res.status(401).json({ error: "Sign in to continue.", code: "AUTH_REQUIRED" });
    }
    const claims = jwt.verify(token, process.env.SESSION_SECRET, { algorithms: ["HS256"] });
    const session = await Session.findById(claims.sid);
    if (!session || session.userId.toString() !== claims.sub || session.status !== "ACTIVE") {
      await writeAudit(req, { eventType: "INACTIVE_SESSION_ACCESS", description: "Protected access was denied because the session is inactive.", status: "WARNING", metadata: { path: req.originalUrl } });
      return res.status(401).json({ error: "This session is no longer active.", code: "SESSION_REVOKED" });
    }
    if (session.expiresAt <= new Date() || Date.now() - session.lastActivity.getTime() > 30 * 60 * 1000) {
      session.status = "EXPIRED";
      await session.save();
      res.clearCookie("zt_session", cookieOptions());
      return res.status(401).json({ error: "Your session expired. Sign in again.", code: "SESSION_EXPIRED" });
    }
    const user = await User.findById(session.userId).populate("departmentId", "name");
    if (!user || user.status !== "ACTIVE") {
      await writeAudit(req, { eventType: "INACTIVE_ACCOUNT_ACCESS", description: "Protected access was denied because the account is inactive.", status: "WARNING", user });
      return res.status(403).json({ error: "This account is not active.", code: "ACCOUNT_INACTIVE" });
    }
    if (!user.mfaEnabled) {
      await writeAudit(req, { eventType: "MFA_REQUIRED_ACCESS", description: "Protected access was denied because MFA verification is required.", status: "WARNING", user });
      return res.status(403).json({ error: "MFA enrollment is required before using protected services.", code: "MFA_REQUIRED" });
    }
    const device = await Device.findById(session.deviceId).select("+credentialHash");
    const currentDeviceCredential = req.cookies?.zt_device;
    const deviceCredentialMatches = currentDeviceCredential && device?.credentialHash === hashToken(currentDeviceCredential);
    if (!device || !deviceCredentialMatches || device.status !== "APPROVED" || device.userId.toString() !== user._id.toString()) {
      session.status = "REVOKED";
      session.revokeReason = "Device verification is no longer valid";
      session.revokedAt = new Date();
      await session.save();
      await writeAudit(req, { eventType: "UNAPPROVED_DEVICE_ACCESS", description: "Protected access was denied because the device is no longer approved.", status: "CRITICAL", user });
      return res.status(403).json({ error: "This device is not approved.", code: "DEVICE_NOT_APPROVED" });
    }
    // Re-check role and account state from MongoDB on each request.
    session.roleAtIssue = user.role;
    session.lastActivity = new Date();
    device.lastActivity = session.lastActivity;
    await Promise.all([session.save(), device.save()]);
    req.user = user;
    req.session = session;
    req.device = device;
    const passwordChangeAllowed = ["/api/auth/me", "/api/auth/change-password", "/api/auth/logout", "/api/profile"];
    if (user.forcePasswordChange && !passwordChangeAllowed.includes(req.path) && !passwordChangeAllowed.includes(req.originalUrl.split("?")[0])) {
      return res.status(403).json({ error: "Change your temporary password before continuing.", code: "PASSWORD_CHANGE_REQUIRED" });
    }
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Your session is invalid or expired.", code: "AUTH_REQUIRED" });
    }
    next(error);
  }
}

export function requireRole(...roles) {
  return async (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      await writeAudit(req, {
        eventType: "UNAUTHORIZED_ACCESS",
        description: `Denied ${req.user?.role || "unknown"} access to a role-restricted endpoint.`,
        status: "CRITICAL",
        user: req.user,
        metadata: { path: req.originalUrl, method: req.method, requiredRoles: roles },
      });
      return res.status(403).json({ error: "You do not have permission to access this area.", code: "FORBIDDEN" });
    }
    next();
  };
}

export async function requireDatabase(req, res, next) {
  const mongoose = await import("mongoose");
  if (mongoose.default.connection.readyState !== 1) {
    return res.status(503).json({ error: "MongoDB is not connected. Configure MONGODB_URI to enable this feature.", code: "DATABASE_UNAVAILABLE" });
  }
  next();
}

export function clearAuthCookies(res) {
  res.clearCookie("zt_session", cookieOptions());
  res.clearCookie("zt_preauth", cookieOptions());
}

export function currentDeviceQuery(req) {
  const credential = req.cookies?.zt_device;
  return credential ? Device.findOne({ credentialHash: hashToken(credential) }).select("+credentialHash") : null;
}

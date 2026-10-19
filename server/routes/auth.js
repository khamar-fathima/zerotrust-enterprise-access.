import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { Department, Device, PreAuth, Session, User } from "../models/index.js";
import { writeAudit, auditFailure } from "../lib/audit.js";
import {
  cookieOptions,
  decryptSecret,
  encryptSecret,
  hashToken,
  newTotpSecret,
  randomToken,
  requestContext,
  totpUri,
  verifyTotp,
} from "../lib/security.js";
import { clearAuthCookies, requireAuth } from "../middleware/auth.js";

const router = Router();
const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many sign-in attempts. Try again in 15 minutes.", code: "RATE_LIMITED" },
});
const challengeLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many verification attempts. Start again in a few minutes.", code: "RATE_LIMITED" },
});
const portalSchema = z.enum(["admin", "manager", "employee"]);
const loginSchema = z.object({
  portal: portalSchema,
  email: z.string().email().max(254),
  password: z.string().min(1).max(200),
});
const passwordSchema = z.string().min(12).max(128).regex(/[a-z]/).regex(/[A-Z]/).regex(/\d/);
const cookieAge = 12 * 60 * 60 * 1000;

function safeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    isBootstrapAdmin: user.isBootstrapAdmin === true,
    status: user.status,
    departmentId: user.departmentId?._id || user.departmentId || null,
    departmentName: user.departmentId?.name || "",
    mfaEnabled: user.mfaEnabled,
    forcePasswordChange: user.forcePasswordChange,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
  };
}

async function findPreAuth(req) {
  const token = req.cookies?.zt_preauth;
  if (!token) return null;
  return PreAuth.findOne({ challengeHash: hashToken(token), expiresAt: { $gt: new Date() } });
}

async function setPreAuth(res, user, portal) {
  const token = randomToken();
  await PreAuth.create({
    challengeHash: hashToken(token),
    userId: user._id,
    portal,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  });
  res.cookie("zt_preauth", token, cookieOptions(5 * 60 * 1000));
}

async function issueSession(req, res, user, device, challenge) {
  const now = new Date();
  const consumed = await PreAuth.findOneAndDelete({
    _id: challenge._id,
    userId: user._id,
    portal: user.role,
    mfaVerified: true,
    expiresAt: { $gt: now },
  });
  if (!consumed) {
    res.status(401);
    return { error: "This sign-in challenge has expired or was already used.", code: "PREAUTH_EXPIRED" };
  }
  const expiresAt = new Date(now.getTime() + cookieAge);
  const context = requestContext(req);
  const session = await Session.create({
    userId: user._id,
    deviceId: device._id,
    roleAtIssue: user.role,
    ipAddress: context.ipAddress,
    browser: context.browser,
    lastActivity: now,
    expiresAt,
  });
  const token = jwt.sign({ sub: user._id.toString(), sid: session._id.toString() }, process.env.SESSION_SECRET, {
    algorithm: "HS256",
    expiresIn: "12h",
  });
  res.cookie("zt_session", token, cookieOptions(cookieAge));
  res.clearCookie("zt_preauth", cookieOptions());
  await Promise.all([
    User.updateOne({ _id: user._id }, { $set: { lastLoginAt: now } }),
    writeAudit(req, { eventType: "LOGIN_SUCCESS", description: "User completed password, MFA, and device verification.", user, status: "SUCCESS" }),
  ]);
  return { authenticated: true, user: safeUser(user) };
}

async function finishVerification(req, res, preAuth, user, recoveryCodes = undefined) {
  if (!user || user.status !== "ACTIVE" || user.role !== preAuth.portal) {
    await writeAudit(req, { eventType: "AUTHORIZATION_CHANGED", description: "Sign-in was denied because account authorization changed during verification.", status: "WARNING", user });
    res.status(403);
    return { error: "Your account authorization changed. Start sign-in again.", code: "AUTHORIZATION_CHANGED" };
  }
  let deviceToken = req.cookies?.zt_device;
  let device = deviceToken ? await Device.findOne({ credentialHash: hashToken(deviceToken) }).select("+credentialHash") : null;
  if (device && device.userId.toString() !== user._id.toString()) device = null;

  if (device?.status === "APPROVED") {
    preAuth.mfaVerified = true;
    await preAuth.save();
    const result = await issueSession(req, res, user, device, preAuth);
    return { ...result, ...(recoveryCodes ? { recoveryCodes } : {}) };
  }

  if (device?.status === "PENDING") {
    preAuth.mfaVerified = true;
    preAuth.deviceId = device._id;
    await preAuth.save();
    return { deviceApprovalRequired: true, deviceStatus: device.status, ...(recoveryCodes ? { recoveryCodes } : {}) };
  }

  const rawCredential = randomToken(40);
  const context = requestContext(req);
  const isFirstBootstrapDevice = user.role === "ADMIN" && user.isBootstrapAdmin && !user.bootstrapDeviceUsed;
  const anyApprovedAdminDevice = isFirstBootstrapDevice
    ? await Device.exists({ userId: user._id, status: "APPROVED" })
    : true;
  const autoApprove = isFirstBootstrapDevice && !anyApprovedAdminDevice;
  device = await Device.create({
    userId: user._id,
    name: context.deviceName,
    browser: context.browser,
    operatingSystem: context.operatingSystem,
    credentialHash: hashToken(rawCredential),
    status: autoApprove ? "APPROVED" : "PENDING",
    ipAddress: context.ipAddress,
    lastActivity: new Date(),
    approvedAt: autoApprove ? new Date() : null,
    approvedBy: autoApprove ? user._id : null,
  });
  res.cookie("zt_device", rawCredential, cookieOptions(365 * 24 * 60 * 60 * 1000));
  preAuth.mfaVerified = true;
  preAuth.deviceId = device._id;
  await preAuth.save();

  if (autoApprove) {
    user.bootstrapDeviceUsed = true;
    await user.save();
    await writeAudit(req, {
      eventType: "BOOTSTRAP_DEVICE_APPROVED",
      description: "The first administrator device was approved during one-time account bootstrap.",
      status: "WARNING",
      user,
      metadata: { deviceId: device._id.toString() },
    });
    const result = await issueSession(req, res, user, device, preAuth);
    return { ...result, ...(recoveryCodes ? { recoveryCodes } : {}) };
  }

  await writeAudit(req, {
    eventType: "DEVICE_REGISTERED",
    description: "A new device was registered and is awaiting administrator approval.",
    status: "WARNING",
    user,
    metadata: { deviceId: device._id.toString(), deviceName: device.name },
  });
  return { deviceApprovalRequired: true, deviceStatus: "PENDING", ...(recoveryCodes ? { recoveryCodes } : {}) };
}

router.get("/csrf", (req, res) => {
  const token = randomToken(24);
  res.cookie("zt_csrf", token, {
    httpOnly: false,
    secure: process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
  res.json({ csrfToken: token });
});

router.get("/departments", async (_req, res, next) => {
  try {
    const departments = await Department.find().select("_id name").sort({ name: 1 }).lean();
    res.json({ departments });
  } catch (error) { next(error); }
});

router.post("/register", async (req, res, next) => {
  try {
    const schema = z.object({
      name: z.string().trim().min(2).max(100),
      email: z.string().email().max(254),
      password: passwordSchema,
      departmentId: z.string().optional().default(""),
    });
    const input = schema.parse(req.body);
    const email = input.email.toLowerCase();
    if (await User.exists({ email })) return res.status(409).json({ error: "An account with that email already exists." });
    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = await User.create({
      name: input.name,
      email,
      passwordHash,
      role: "EMPLOYEE",
      status: "PENDING",
      departmentId: input.departmentId || null,
    });
    await writeAudit(req, {
      eventType: "REGISTRATION_REQUESTED",
      description: "A new employee account requested access and is awaiting approval.",
      status: "WARNING",
      user,
    });
    res.status(201).json({ message: "Request submitted. An administrator must approve the account before sign-in." });
  } catch (error) { next(error); }
});

router.post("/login", loginLimit, async (req, res, next) => {
  try {
    const input = loginSchema.parse(req.body);
    const user = await User.findOne({ email: input.email.toLowerCase() }).populate("departmentId", "name");
    const portalRole = input.portal.toUpperCase();
    if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) {
      auditFailure(req, {
        eventType: "LOGIN_FAILED",
        description: "A sign-in attempt failed because the credentials were invalid.",
        status: "WARNING",
        user,
        metadata: { portal: portalRole },
      });
      return res.status(401).json({ error: "Invalid credentials or access denied for this portal.", code: "INVALID_CREDENTIALS" });
    }
    if (user.role !== portalRole) {
      await writeAudit(req, {
        eventType: "PORTAL_ROLE_MISMATCH",
        description: `${user.role} user attempted to sign in through the ${portalRole} portal. Access was denied.`,
        status: "CRITICAL",
        user,
        metadata: { attemptedPortal: portalRole, actualRole: user.role },
      });
      return res.status(403).json({ error: "This account is not authorized for that portal.", code: "PORTAL_ROLE_MISMATCH" });
    }
    if (user.status !== "ACTIVE") {
      auditFailure(req, {
        eventType: "LOGIN_BLOCKED",
        description: `Sign-in was blocked because the account is ${user.status.toLowerCase()}.`,
        status: "WARNING",
        user,
        metadata: { portal: portalRole },
      });
      return res.status(403).json({ error: "This account is not active. Contact your administrator.", code: "ACCOUNT_INACTIVE" });
    }
    await PreAuth.deleteMany({ userId: user._id });
    await setPreAuth(res, user, portalRole);
    res.json({ mfaEnabled: user.mfaEnabled, requiresMfaSetup: !user.mfaEnabled, requiresMfa: user.mfaEnabled });
  } catch (error) { next(error); }
});

router.post("/mfa/setup", challengeLimit, async (req, res, next) => {
  try {
    const challenge = await findPreAuth(req);
    if (!challenge) return res.status(401).json({ error: "Sign-in challenge expired. Start again.", code: "PREAUTH_EXPIRED" });
    const user = await User.findById(challenge.userId);
    if (!user || user.status !== "ACTIVE") return res.status(403).json({ error: "Account is not active." });
    if (user.mfaEnabled) return res.status(409).json({ error: "MFA is already enabled for this account." });
    const secret = newTotpSecret();
    challenge.mfaSecretEncrypted = encryptSecret(secret);
    await challenge.save();
    res.json({
      qrCodeDataUrl: await QRCode.toDataURL(totpUri(secret, user.email), { width: 240, margin: 2 }),
      manualEntryKey: secret,
    });
  } catch (error) { next(error); }
});

router.post("/mfa/confirm", challengeLimit, async (req, res, next) => {
  try {
    const { code } = z.object({ code: z.string().regex(/^\d{6}$/) }).parse(req.body);
    const challenge = await findPreAuth(req);
    if (!challenge?.mfaSecretEncrypted) return res.status(401).json({ error: "MFA setup expired. Start again.", code: "PREAUTH_EXPIRED" });
    const user = await User.findById(challenge.userId).populate("departmentId", "name");
    if (!user || user.status !== "ACTIVE" || user.role !== challenge.portal) return res.status(403).json({ error: "Account authorization changed. Start sign-in again." });
    const secret = decryptSecret(challenge.mfaSecretEncrypted);
    if (!verifyTotp(secret, code)) {
      await writeAudit(req, { eventType: "MFA_FAILED", description: "An invalid code was submitted during MFA enrollment.", status: "WARNING", user });
      return res.status(401).json({ error: "That code is not valid. Try the current code from your authenticator.", code: "INVALID_MFA" });
    }
    const recoveryCodes = Array.from({ length: 8 }, () => randomToken(8).toUpperCase());
    user.mfaSecretEncrypted = encryptSecret(secret);
    user.mfaEnabled = true;
    user.recoveryCodeHashes = await Promise.all(recoveryCodes.map((item) => bcrypt.hash(item, 10)));
    await user.save();
    await writeAudit(req, { eventType: "MFA_ENABLED", description: "The user enrolled in authenticator-based MFA.", user });
    const outcome = await finishVerification(req, res, challenge, user, recoveryCodes);
    res.json({ ...outcome, recoveryCodes });
  } catch (error) { next(error); }
});

router.post("/mfa/verify", challengeLimit, async (req, res, next) => {
  try {
    const { code } = z.object({ code: z.string().min(6).max(64) }).parse(req.body);
    const challenge = await findPreAuth(req);
    if (!challenge) return res.status(401).json({ error: "Sign-in challenge expired. Start again.", code: "PREAUTH_EXPIRED" });
    const user = await User.findById(challenge.userId).populate("departmentId", "name");
    if (!user?.mfaEnabled || !user.mfaSecretEncrypted) return res.status(403).json({ error: "MFA is not configured.", code: "MFA_REQUIRED" });

    let valid = false;
    if (/^\d{6}$/.test(code)) {
      valid = verifyTotp(decryptSecret(user.mfaSecretEncrypted), code);
    } else {
      const matches = [];
      for (let index = 0; index < user.recoveryCodeHashes.length; index += 1) {
        if (await bcrypt.compare(code.toUpperCase(), user.recoveryCodeHashes[index])) matches.push(index);
      }
      if (matches.length) {
        const usedHash = user.recoveryCodeHashes[matches[0]];
        const removed = await User.updateOne({ _id: user._id, recoveryCodeHashes: usedHash }, { $pull: { recoveryCodeHashes: usedHash } });
        valid = removed.modifiedCount === 1;
      }
    }
    if (!valid) {
      await writeAudit(req, { eventType: "MFA_FAILED", description: "An invalid authenticator or recovery code was submitted.", status: "WARNING", user });
      return res.status(401).json({ error: "That verification code is not valid.", code: "INVALID_MFA" });
    }
    const outcome = await finishVerification(req, res, challenge, user);
    res.json(outcome);
  } catch (error) { next(error); }
});

router.get("/device-status", async (req, res, next) => {
  try {
    const challenge = await findPreAuth(req);
    if (!challenge?.mfaVerified || !challenge.deviceId) {
      return res.status(404).json({ error: "No device is awaiting approval.", code: "NO_PENDING_DEVICE" });
    }
    const device = await Device.findById(challenge.deviceId).select("status name");
    if (!device) return res.status(404).json({ error: "Device request was not found." });
    res.json({ status: device.status, deviceName: device.name });
  } catch (error) { next(error); }
});

router.post("/device/complete", async (req, res, next) => {
  try {
    const challenge = await findPreAuth(req);
    if (!challenge?.mfaVerified || !challenge.deviceId) return res.status(401).json({ error: "Device verification challenge expired.", code: "PREAUTH_EXPIRED" });
    const device = await Device.findOne({ _id: challenge.deviceId, userId: challenge.userId, status: "APPROVED" });
    if (!device) return res.status(403).json({ error: "This device has not been approved.", code: "DEVICE_PENDING" });
    const user = await User.findById(challenge.userId).populate("departmentId", "name");
    if (!user || user.status !== "ACTIVE" || user.role !== challenge.portal || !user.mfaEnabled) return res.status(403).json({ error: "Account authorization changed. Start sign-in again." });
    res.json(await issueSession(req, res, user, device, challenge));
  } catch (error) { next(error); }
});

router.post("/mfa/disable", requireAuth, challengeLimit, async (req, res, next) => {
  try {
    const { password, code } = z.object({ password: z.string().min(1).max(200), code: z.string().regex(/^\d{6}$/) }).parse(req.body);
    const user = await User.findById(req.user._id);
    if (!(await bcrypt.compare(password, user.passwordHash)) || !verifyTotp(decryptSecret(user.mfaSecretEncrypted), code)) {
      await writeAudit(req, { eventType: "MFA_DISABLE_FAILED", description: "MFA disabling was denied because reauthentication failed.", status: "WARNING", user });
      return res.status(401).json({ error: "Password or authenticator code is incorrect." });
    }
    user.mfaEnabled = false;
    user.mfaSecretEncrypted = "";
    user.recoveryCodeHashes = [];
    await user.save();
    await Session.updateMany({ userId: user._id, status: "ACTIVE" }, { $set: { status: "REVOKED", revokedAt: new Date(), revokeReason: "MFA was disabled" } });
    await writeAudit(req, { eventType: "MFA_DISABLED", description: "The user disabled MFA after reauthentication. New enrollment is required at next sign-in.", status: "WARNING", user });
    res.clearCookie("zt_session", cookieOptions());
    res.json({ message: "MFA disabled and sessions revoked. Enroll MFA again at the next sign-in." });
  } catch (error) { next(error); }
});

router.get("/me", requireAuth, (req, res) => res.json({
  user: safeUser(req.user),
  device: { id: req.device._id, name: req.device.name, status: req.device.status },
  session: { id: req.session._id, expiresAt: req.session.expiresAt },
}));

router.get("/portal/:portal", requireAuth, async (req, res, next) => {
  try {
    const portal = portalSchema.parse(req.params.portal).toUpperCase();
    if (req.user.role !== portal) {
      await writeAudit(req, {
        eventType: "UNAUTHORIZED_PORTAL_ACCESS",
        description: `${req.user.role} user attempted to open the ${portal} protected console. Access was denied.`,
        status: "CRITICAL",
        user: req.user,
        metadata: { attemptedPortal: portal, actualRole: req.user.role },
      });
      return res.status(403).json({ error: "Your account does not have access to this portal.", code: "FORBIDDEN" });
    }
    res.json({ authorized: true });
  } catch (error) { next(error); }
});

router.post("/change-password", requireAuth, async (req, res, next) => {
  try {
    const input = z.object({ currentPassword: z.string().min(1).max(200), newPassword: passwordSchema }).parse(req.body);
    const user = await User.findById(req.user._id);
    if (!(await bcrypt.compare(input.currentPassword, user.passwordHash))) {
      await writeAudit(req, { eventType: "PASSWORD_CHANGE_FAILED", description: "A password change failed because the current password was incorrect.", status: "WARNING", user });
      return res.status(401).json({ error: "Current password is incorrect." });
    }
    user.passwordHash = await bcrypt.hash(input.newPassword, 12);
    user.forcePasswordChange = false;
    await user.save();
    await writeAudit(req, { eventType: "PASSWORD_CHANGED", description: "The user changed their account password.", user });
    res.json({ message: "Password updated." });
  } catch (error) { next(error); }
});

router.post("/logout", async (req, res, next) => {
  try {
    const token = req.cookies?.zt_session;
    if (token) {
      try {
        const claims = jwt.verify(token, process.env.SESSION_SECRET, { algorithms: ["HS256"] });
        const session = await Session.findById(claims.sid);
        if (session?.status === "ACTIVE") {
          session.status = "REVOKED";
          session.revokedAt = new Date();
          session.revokeReason = "User signed out";
          await session.save();
          const user = await User.findById(session.userId);
          await writeAudit(req, { eventType: "SESSION_TERMINATED", description: "User signed out and revoked this session.", user });
        }
      } catch {}
    }
    clearAuthCookies(res);
    res.clearCookie("zt_csrf", { path: "/" });
    res.json({ message: "Signed out." });
  } catch (error) { next(error); }
});

export default router;

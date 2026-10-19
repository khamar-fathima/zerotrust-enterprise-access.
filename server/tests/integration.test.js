import "dotenv/config";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import { AuditLog, Department, Device, Resource, Session, User } from "../models/index.js";
import { encryptSecret, generateTotp, hashToken, newTotpSecret, randomToken } from "../lib/security.js";

const uri = process.env.MONGODB_URI;

test("MongoDB-backed security acceptance scenarios", { skip: !uri, timeout: 120_000 }, async (t) => {
  process.env.NODE_ENV = "test";
  process.env.COOKIE_SECURE = "false";
  if (!process.env.SESSION_SECRET) process.env.SESSION_SECRET = crypto.randomBytes(40).toString("base64url");
  const { default: app } = await import("../app.js");
  const databaseName = `zerotrust_test_${Date.now()}_${randomToken(4).replace(/[^a-zA-Z0-9]/g, "")}`;
  await mongoose.connect(uri, { dbName: databaseName, serverSelectionTimeoutMS: 10_000 });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const password = `Test-${randomToken(20)}-9aA`;
  const secret = newTotpSecret();
  const department = await Department.create({ name: "Test engineering" });
  const makeUser = (role, extra = {}) => User.create({
    name: `${role} fixture`,
    email: `${role.toLowerCase()}-${randomToken(6).toLowerCase()}@example.test`,
    role,
    status: "ACTIVE",
    departmentId: department._id,
    passwordHash: bcrypt.hashSync(password, 4),
    mfaEnabled: true,
    mfaSecretEncrypted: encryptSecret(secret),
    ...extra,
  });
  const admin = await makeUser("ADMIN", { isBootstrapAdmin: true });
  const employee = await makeUser("EMPLOYEE");
  const manager = await makeUser("MANAGER");
  const restricted = await Resource.create({ name: "Admin-only test record", content: "Private test fixture", classification: "RESTRICTED", allowedRoles: ["ADMIN"] });

  function client(initialCookies = {}) {
    const cookies = new Map(Object.entries(initialCookies));
    return {
      async request(method, route, body) {
        const headers = { "Content-Type": "application/json" };
        if (cookies.size) headers.Cookie = [...cookies].map(([key, value]) => `${key}=${value}`).join("; ");
        if (!["GET", "HEAD"].includes(method) && cookies.has("zt_csrf")) headers["X-CSRF-Token"] = decodeURIComponent(cookies.get("zt_csrf"));
        const response = await fetch(`${origin}/api${route}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
        for (const cookie of response.headers.getSetCookie()) {
          const [pair] = cookie.split(";");
          const [name, ...values] = pair.split("=");
          const value = values.join("=");
          if (value) cookies.set(name, value);
          else cookies.delete(name);
        }
        return { status: response.status, body: await response.json() };
      },
    };
  }

  async function knownClient(user) {
    const raw = randomToken(40);
    await Device.create({ userId: user._id, credentialHash: hashToken(raw), name: "Test browser", browser: "Test", operatingSystem: "Test", status: "APPROVED" });
    return client({ zt_device: raw });
  }

  async function signIn(sessionClient, user, portal = user.role.toLowerCase()) {
    await sessionClient.request("GET", "/auth/csrf");
    const login = await sessionClient.request("POST", "/auth/login", { portal, email: user.email, password });
    if (login.status !== 200) return login;
    return sessionClient.request("POST", "/auth/mfa/verify", { code: generateTotp(secret) });
  }

  const adminClient = client();
  const employeeClient = await knownClient(employee);
  const managerClient = await knownClient(manager);
  const pendingClient = client();

  try {
    const adminLogin = await signIn(adminClient, admin);
    assert.equal(adminLogin.status, 200);
    assert.equal(adminLogin.body.authenticated, true);

    await t.test("1. Employee logs in through the employee portal with password, MFA, and approved device", async () => {
      const response = await signIn(employeeClient, employee);
      assert.equal(response.status, 200);
      assert.equal(response.body.authenticated, true);
      assert.equal((await employeeClient.request("GET", "/auth/me")).body.user.role, "EMPLOYEE");
    });

    await t.test("2. Employee administrator-portal attempt is denied and persisted in the audit log", async () => {
      const response = await employeeClient.request("POST", "/auth/login", { portal: "admin", email: employee.email, password });
      assert.equal(response.status, 403);
      assert.equal(response.body.code, "PORTAL_ROLE_MISMATCH");
      const event = await AuditLog.findOne({ userId: employee._id, eventType: "PORTAL_ROLE_MISMATCH" });
      assert.ok(event);
      const audit = await adminClient.request("GET", "/audit-logs?eventType=PORTAL_ROLE_MISMATCH");
      assert.equal(audit.status, 200);
      assert.ok(audit.body.logs.some((row) => row.eventType === "PORTAL_ROLE_MISMATCH"));
    });

    await t.test("3. Manager cannot access an administrator API", async () => {
      assert.equal((await signIn(managerClient, manager)).body.authenticated, true);
      assert.equal((await managerClient.request("GET", "/roles")).status, 403);
    });

    await t.test("4. Invalid MFA code cannot complete authentication", async () => {
      const badClient = client();
      await badClient.request("GET", "/auth/csrf");
      await badClient.request("POST", "/auth/login", { portal: "employee", email: employee.email, password });
      const response = await badClient.request("POST", "/auth/mfa/verify", { code: "invalid-recovery-code" });
      assert.equal(response.status, 401);
      assert.equal((await badClient.request("GET", "/profile")).status, 401);
    });

    await t.test("5. New unapproved device cannot access protected resources", async () => {
      const response = await signIn(pendingClient, employee);
      assert.equal(response.body.deviceApprovalRequired, true);
      assert.equal((await pendingClient.request("GET", "/profile")).status, 401);
    });

    await t.test("6. Administrator approval allows the pending browser to finish authentication", async () => {
      const pending = await Device.findOne({ userId: employee._id, status: "PENDING" });
      assert.ok(pending);
      assert.equal((await adminClient.request("PATCH", `/devices/${pending._id}`, { status: "APPROVED" })).status, 200);
      const response = await pendingClient.request("POST", "/auth/device/complete");
      assert.equal(response.body.authenticated, true);
      assert.equal((await pendingClient.request("GET", "/profile")).status, 200);
    });

    await t.test("7. Revoked session immediately loses protected access", async () => {
      const active = await Session.findOne({ userId: employee._id, status: "ACTIVE" }).sort({ createdAt: 1 });
      assert.equal((await adminClient.request("DELETE", `/sessions/${active._id}`)).status, 200);
      assert.equal((await employeeClient.request("GET", "/profile")).status, 401);
    });

    await t.test("8. Unauthorized direct resource access creates an audit record", async () => {
      assert.equal((await pendingClient.request("GET", `/resources/${restricted._id}/content`)).status, 403);
      assert.ok(await AuditLog.exists({ userId: employee._id, eventType: "UNAUTHORIZED_RESOURCE_ACCESS" }));
    });

    await t.test("9. Role change immediately invalidates existing authorization", async () => {
      assert.equal((await adminClient.request("PATCH", `/users/${manager._id}`, { role: "EMPLOYEE" })).status, 200);
      assert.equal((await User.findById(manager._id)).role, "EMPLOYEE");
      assert.equal((await managerClient.request("GET", "/users")).status, 401);
    });

    await t.test("10. Employee cannot retrieve another user's private record", async () => {
      const response = await pendingClient.request("GET", `/users/${admin._id}`);
      assert.equal(response.status, 403);
      assert.equal(response.body.user, undefined);
      assert.equal((await pendingClient.request("GET", "/auth/portal/admin")).status, 403);
      assert.ok(await AuditLog.exists({ userId: employee._id, eventType: "UNAUTHORIZED_PORTAL_ACCESS" }));
    });

    await t.test("Cookie-authenticated writes require a CSRF token", async () => {
      const response = await client().request("POST", "/auth/login", { portal: "admin", email: admin.email, password });
      assert.equal(response.status, 403);
      assert.equal(response.body.code, "CSRF_BLOCKED");
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    // Only this run's uniquely named, test-owned database is removed.
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  }
});

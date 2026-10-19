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
  assert.ok(Buffer.byteLength(databaseName) <= 38, "Atlas test database names must not exceed 38 bytes.");
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

    await t.test("Managers cannot cross department boundaries", async (t) => {
      // All fixtures remain inside this run's disposable database. Setup failures
      // here are also covered by the parent suite's finally cleanup.
      const operations = await Department.create({ name: "Test operations" });
      const operationsManager = await makeUser("MANAGER", { departmentId: operations._id });
      const operationsEmployees = await Promise.all([
        makeUser("EMPLOYEE", { departmentId: operations._id, name: "Operations employee one" }),
        makeUser("EMPLOYEE", { departmentId: operations._id, name: "Operations employee two" }),
      ]);
      await Promise.all([
        makeUser("EMPLOYEE", { name: "Disabled engineering employee", status: "DISABLED" }),
        makeUser("EMPLOYEE", { departmentId: operations._id, status: "PENDING" }),
      ]);
      const operationsClient = await knownClient(operationsManager);
      const login = await signIn(operationsClient, operationsManager);
      assert.equal(login.status, 200);
      assert.equal(login.body.authenticated, true);

      const [engineeringResource, operationsResource, operationsManagerResource, sharedResource] = await Promise.all([
        Resource.create({ name: "Engineering handbook", content: "Engineering-only fixture content", departmentId: department._id, allowedRoles: ["MANAGER", "EMPLOYEE"] }),
        Resource.create({ name: "Operations handbook", content: "Operations-only fixture content", departmentId: operations._id, allowedRoles: ["MANAGER", "EMPLOYEE"] }),
        Resource.create({ name: "Operations manager handbook", content: "Operations manager fixture content", departmentId: operations._id, allowedRoles: ["MANAGER"] }),
        Resource.create({ name: "Shared manager handbook", content: "Shared fixture content", departmentId: null, allowedRoles: ["MANAGER"] }),
      ]);
      await Promise.all([
        Resource.create({ name: "Inactive engineering handbook", content: "Inactive fixture content", departmentId: department._id, active: false, allowedRoles: ["MANAGER"] }),
        Resource.create({ name: "Employee-only engineering handbook", content: "Employee-only fixture content", departmentId: department._id, allowedRoles: ["EMPLOYEE"] }),
      ]);

      const scopes = [
        {
          client: managerClient, manager, department, employees: [employee],
          resources: [engineeringResource, sharedResource], localResource: engineeringResource,
          foreignManager: operationsManager, foreignEmployees: operationsEmployees,
          foreignResources: [operationsResource, operationsManagerResource],
        },
        {
          client: operationsClient, manager: operationsManager, department: operations,
          employees: operationsEmployees, resources: [operationsResource, operationsManagerResource, sharedResource],
          localResource: operationsResource, foreignManager: manager, foreignEmployees: [employee],
          foreignResources: [engineeringResource],
        },
      ];
      const ids = (rows) => rows.map((row) => String(row.id || row._id)).sort();
      const deniedEvents = [];
      const assertSafeUser = (user) => {
        for (const field of ["passwordHash", "mfaSecretEncrypted", "recoveryCodeHashes"]) {
          assert.equal(Object.hasOwn(user, field), false, `${field} must never be returned`);
        }
      };
      async function expectDenied(scope, route, eventType, targetKey, target, privateValue) {
        const filter = {
          userId: scope.manager._id, eventType,
          [`metadata.${targetKey}`]: String(target._id),
        };
        const before = await AuditLog.countDocuments(filter);
        const response = await scope.client.request("GET", route);
        assert.equal(response.status, 403, route);
        assert.equal(response.body.code, "FORBIDDEN");
        for (const field of ["user", "resource", "content"]) assert.equal(response.body[field], undefined);
        assert.equal(JSON.stringify(response.body).includes(privateValue), false);
        assert.equal(await AuditLog.countDocuments(filter), before + 1, "each denied request must be audited");
        const event = await AuditLog.findOne(filter).sort({ createdAt: -1, _id: -1 }).lean();
        assert.equal(event.role, "MANAGER");
        assert.equal(event.status, "CRITICAL");
        deniedEvents.push(event);
      }

      await t.test("both managers see only their active employees and their own department", async () => {
        for (const scope of scopes) {
          const response = await scope.client.request("GET", "/users");
          assert.equal(response.status, 200);
          assert.deepEqual(ids(response.body.users), ids(scope.employees));
          assert.equal(response.body.total, scope.employees.length);
          for (const user of response.body.users) {
            assert.equal(user.departmentId, String(scope.department._id));
            assert.equal(user.role, "EMPLOYEE");
            assert.equal(user.status, "ACTIVE");
            assertSafeUser(user);
          }
          const departments = await scope.client.request("GET", "/departments");
          assert.equal(departments.status, 200);
          assert.deepEqual(ids(departments.body.departments), [String(scope.department._id)]);

          // Caller-supplied department/role/status/search values may narrow
          // results, but must never widen the authenticated manager's scope.
          const tampered = await scope.client.request("GET",
            `/users?departmentId=${scope.foreignManager.departmentId}&role=ADMIN&status=PENDING&q=${encodeURIComponent(scope.foreignEmployees[0].email)}`);
          assert.equal(tampered.status, 200);
          for (const user of tampered.body.users) {
            assert.equal(user.departmentId, String(scope.department._id));
            assert.equal(user.role, "EMPLOYEE");
            assert.equal(user.status, "ACTIVE");
          }
          assert.ok(tampered.body.total <= scope.employees.length);
        }
      });

      await t.test("own identity requests succeed but foreign employees and managers are denied and audited", async () => {
        for (const scope of scopes) {
          for (const target of [scope.manager, ...scope.employees]) {
            const response = await scope.client.request("GET", `/users/${target._id}`);
            assert.equal(response.status, 200);
            assert.equal(response.body.user.id, String(target._id));
            assertSafeUser(response.body.user);
          }
          for (const target of [scope.foreignManager, ...scope.foreignEmployees]) {
            await expectDenied(scope, `/users/${target._id}?departmentId=${scope.department._id}`,
              "UNAUTHORIZED_USER_ACCESS", "targetUserId", target, target.email);
          }
        }
        // Sharing a department does not let a manager retrieve an administrator.
        await expectDenied(scopes[0], `/users/${admin._id}`, "UNAUTHORIZED_USER_ACCESS", "targetUserId", admin, admin.email);
      });

      await t.test("resource lists and content enforce both role and department without blocking shared resources", async () => {
        for (const scope of scopes) {
          const response = await scope.client.request("GET", "/resources");
          assert.equal(response.status, 200);
          assert.deepEqual(ids(response.body.resources), ids(scope.resources));
          for (const resource of response.body.resources) assert.equal(Object.hasOwn(resource, "content"), false);
          const tampered = await scope.client.request("GET", `/resources?departmentId=${scope.foreignManager.departmentId}`);
          assert.equal(tampered.status, 200);
          assert.deepEqual(ids(tampered.body.resources), ids(scope.resources));
          for (const target of scope.resources) {
            const content = await scope.client.request("GET", `/resources/${target._id}/content`);
            assert.equal(content.status, 200);
            assert.equal(content.body.resource.id, String(target._id));
            assert.equal(content.body.resource.content, target.content);
          }
          for (const target of scope.foreignResources) {
            await expectDenied(scope, `/resources/${target._id}/content`,
              "UNAUTHORIZED_RESOURCE_ACCESS", "resourceId", target, target.content);
          }
        }
      });

      await t.test("dashboard counts and recent activity stay scoped in both departments", async () => {
        // Future-dated by one second so both markers stay in the eight newest
        // events regardless of authentication/audit traffic earlier in the suite.
        const markers = await AuditLog.create(scopes.map((scope) => ({
          userId: scope.employees[0]._id, userName: scope.employees[0].name, role: "EMPLOYEE",
          eventType: "TEST_DEPARTMENT_ACTIVITY", description: `${scope.department.name} test activity`,
          createdAt: new Date(Date.now() + 1000),
        })));
        const engineeringTeam = [admin, manager, employee];
        const operationsTeam = [operationsManager, ...operationsEmployees];
        for (const [index, scope] of scopes.entries()) {
          const response = await scope.client.request("GET", "/dashboard/summary");
          assert.equal(response.status, 200);
          assert.equal(response.body.role, "MANAGER");
          assert.equal(response.body.departmentName, scope.department.name);
          assert.deepEqual(response.body.metrics, {
            employees: scope.employees.length, resources: scope.resources.length, activeSessions: 1,
          });
          assert.equal(response.body.roleDistribution, undefined);
          assert.ok(response.body.recentActivity.some((event) => String(event.id) === String(markers[index]._id)));
          const teamIds = ids(index === 0 ? engineeringTeam : operationsTeam);
          for (const event of response.body.recentActivity) {
            assert.ok(teamIds.includes(String(event.userId)), "foreign actors must not appear in department activity");
          }
        }
      });

      await t.test("foreign department events do not change either manager's activity chart", async () => {
        for (const scope of scopes) {
          const before = await scope.client.request("GET", "/dashboard/activity?range=7d");
          assert.equal(before.status, 200);
          assert.equal(before.body.activity.length, 7);
          await AuditLog.create([
            { userId: scope.foreignManager._id, eventType: "LOGIN_SUCCESS", description: "Foreign department test login" },
            { userId: scope.foreignEmployees[0]._id, eventType: "UNAUTHORIZED_RESOURCE_ACCESS", status: "CRITICAL", description: "Foreign department test denial" },
          ]);
          const after = await scope.client.request("GET", "/dashboard/activity?range=7d");
          assert.equal(after.status, 200);
          assert.deepEqual(after.body, before.body);
        }
      });

      await t.test("administrators retain global visibility and can retrieve every denied-access audit record", async () => {
        const users = await adminClient.request("GET", "/users");
        assert.equal(users.status, 200);
        const visible = ids(users.body.users);
        for (const scope of scopes) {
          for (const user of [scope.manager, ...scope.employees]) assert.ok(visible.includes(String(user._id)));
          const resource = await adminClient.request("GET", `/resources/${scope.localResource._id}/content`);
          assert.equal(resource.status, 200);
          assert.equal(resource.body.resource.content, scope.localResource.content);
        }
        for (const eventType of ["UNAUTHORIZED_USER_ACCESS", "UNAUTHORIZED_RESOURCE_ACCESS"]) {
          const response = await adminClient.request("GET", `/audit-logs?eventType=${eventType}`);
          assert.equal(response.status, 200);
          for (const expected of deniedEvents.filter((event) => event.eventType === eventType)) {
            const actual = response.body.logs.find((event) => String(event.id) === String(expected._id));
            assert.ok(actual, "denied requests must be visible through the administrator audit API");
            assert.equal(String(actual.userId), String(expected.userId));
            assert.equal(actual.status, "CRITICAL");
            assert.deepEqual(actual.metadata, expected.metadata);
          }
        }
      });
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
    try {
      await mongoose.connection.dropDatabase();
    } finally {
      await mongoose.disconnect();
    }
  }
});

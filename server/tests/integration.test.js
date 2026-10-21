import "dotenv/config";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import { AuditLog, Department, Device, PreAuth, Resource, RiskHistory, Session, User } from "../models/index.js";
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
  let managerForAdminPromotion;
  let managerSessionForAdminPromotion;
  let forwardedForAdminPromotion;
  const restricted = await Resource.create({ name: "Admin-only test record", content: "Private test fixture", classification: "RESTRICTED", allowedRoles: ["ADMIN"] });

  function client(initialCookies = {}, requestHeaders = {}) {
    const cookies = new Map(Object.entries(initialCookies));
    return {
      clone() {
        return client(Object.fromEntries(cookies), requestHeaders);
      },
      async request(method, route, body) {
        const headers = { "Content-Type": "application/json", ...requestHeaders };
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

  async function knownClient(user, forwardedFor) {
    const raw = randomToken(40);
    await Device.create({ userId: user._id, credentialHash: hashToken(raw), name: "Test browser", browser: "Test", operatingSystem: "Test", status: "APPROVED" });
    return client(
      { zt_device: raw },
      forwardedFor ? { "X-Forwarded-For": forwardedFor } : {},
    );
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

    await t.test("Risk scores are visible only to the bootstrap administrator", async () => {
      assert.equal((await adminClient.request("GET", "/auth/me")).body.user.isBootstrapAdmin, true);
      const risk = await adminClient.request("GET", "/dashboard/risk-analysis");
      assert.equal(risk.status, 200);
      assert.equal(risk.body.snapshot.windowDays, 7);
      assert.equal(typeof risk.body.snapshot.organization.score, "number");
      assert.ok(risk.body.snapshot.accounts.some((account) => String(account.id) === String(employee._id)));
      assert.equal(JSON.stringify(risk.body).includes(employee.email), false);
      const history = await adminClient.request("GET", `/dashboard/risk-analysis/history?days=30&accountId=${employee._id}`);
      assert.equal(history.status, 200);
      assert.ok(history.body.history.some((row) => typeof row.account?.score === "number"));
      assert.equal(JSON.stringify(history.body).includes(employee.email), false);
      const evidence = await adminClient.request("GET", `/dashboard/risk-analysis/evidence?accountId=${employee._id}`);
      assert.equal(evidence.status, 200);
      assert.ok(evidence.body.events.some((event) => event.eventType === "PORTAL_ROLE_MISMATCH"));

      const ordinaryAdmin = await makeUser("ADMIN");
      const ordinaryAdminClient = await knownClient(ordinaryAdmin, "198.51.100.42");
      try {
        assert.equal((await signIn(ordinaryAdminClient, ordinaryAdmin)).body.authenticated, true);
        assert.equal((await ordinaryAdminClient.request("GET", "/auth/me")).body.user.isBootstrapAdmin, false);
        await adminClient.request("GET", "/dashboard/risk-analysis");
        const ordinaryAdminHistory = await adminClient.request("GET", `/dashboard/risk-analysis/history?accountId=${ordinaryAdmin._id}`);
        assert.ok(ordinaryAdminHistory.body.history.some((row) => typeof row.account?.score === "number"));
        for (const unauthorizedClient of [ordinaryAdminClient, managerClient, employeeClient]) {
          for (const method of ["GET", "POST"]) {
            const denied = await unauthorizedClient.request(method, "/dashboard/risk-analysis");
            assert.equal(denied.status, 403);
            assert.equal(denied.body.code, "FORBIDDEN");
          }
          const deniedHistory = await unauthorizedClient.request("GET", "/dashboard/risk-analysis/history");
          assert.equal(deniedHistory.status, 403);
          assert.equal(deniedHistory.body.code, "FORBIDDEN");
          for (const route of ["/dashboard/risk-analysis/accounts", "/dashboard/risk-analysis/evidence"]) {
            const denied = await unauthorizedClient.request("GET", route);
            assert.equal(denied.status, 403);
          }
        }
        assert.ok(await AuditLog.exists({ eventType: "RISK_ANALYSIS_ACCESS_DENIED", userId: ordinaryAdmin._id }));
        assert.equal(await AuditLog.countDocuments({ eventType: "RISK_ANALYSIS_GENERATED" }), 0);
      } finally {
        await Promise.all([
          Session.deleteMany({ userId: ordinaryAdmin._id }),
          Device.deleteMany({ userId: ordinaryAdmin._id }),
          User.deleteOne({ _id: ordinaryAdmin._id }),
          AuditLog.deleteMany({ $or: [{ userId: ordinaryAdmin._id }, { eventType: "RISK_ANALYSIS_ACCESS_DENIED" }] }),
        ]);
        assert.equal(await RiskHistory.exists({ "accounts.userId": ordinaryAdmin._id }), null);
      }
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
      const unassignedManager = await makeUser("MANAGER", {
        departmentId: null, name: "Unassigned manager",
      });
      const unassignedEmployees = await Promise.all([
        makeUser("EMPLOYEE", { departmentId: null, name: "Unassigned employee one" }),
        makeUser("EMPLOYEE", { departmentId: null, name: "Unassigned employee two" }),
      ]);
      const unassignedClient = await knownClient(unassignedManager);
      const unassignedLogin = await signIn(unassignedClient, unassignedManager);
      assert.equal(unassignedLogin.status, 200);
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

      await t.test("an unassigned manager cannot enumerate unassigned or assigned staff", async () => {
        const listing = await unassignedClient.request("GET", "/users");
        assert.equal(listing.status, 200);
        assert.deepEqual(listing.body.users, []);
        assert.equal(listing.body.total, 0);

        const ownIdentity = await unassignedClient.request("GET", `/users/${unassignedManager._id}`);
        assert.equal(ownIdentity.status, 200);
        assert.equal(ownIdentity.body.user.id, String(unassignedManager._id));
        assertSafeUser(ownIdentity.body.user);
        for (const target of [...unassignedEmployees, manager, operationsManager]) {
          await expectDenied(unassignedClient, `/users/${target._id}`,
            "UNAUTHORIZED_USER_ACCESS", "targetUserId", target, target.email);
        }

        const departments = await unassignedClient.request("GET", "/departments");
        assert.equal(departments.status, 200);
        assert.deepEqual(departments.body.departments, []);
      });

      await t.test("administrators retain global visibility of unassigned identities", async () => {
        const listing = await adminClient.request("GET", "/users");
        assert.equal(listing.status, 200);
        const visibleIds = ids(listing.body.users);
        for (const target of [unassignedManager, ...unassignedEmployees]) {
          assert.ok(visibleIds.includes(String(target._id)));
          const identity = await adminClient.request("GET", `/users/${target._id}`);
          assert.equal(identity.status, 200);
          assert.equal(identity.body.user.id, String(target._id));
        }
        const departments = await adminClient.request("GET", "/departments");
        assert.equal(departments.status, 200);
        assert.ok(ids(departments.body.departments).includes(String(department._id)));
        assert.ok(ids(departments.body.departments).includes(String(operations._id)));
      });

      await t.test("an unassigned manager sees only role-authorized shared resources", async () => {
        const listing = await unassignedClient.request("GET", "/resources");
        assert.equal(listing.status, 200);
        assert.deepEqual(ids(listing.body.resources), [String(sharedResource._id)]);
        assert.equal(Object.hasOwn(listing.body.resources[0], "content"), false);
        const sharedContent = await unassignedClient.request("GET", `/resources/${sharedResource._id}/content`);
        assert.equal(sharedContent.status, 200);
        assert.equal(sharedContent.body.resource.content, sharedResource.content);
        for (const target of [engineeringResource, operationsResource, operationsManagerResource]) {
          await expectDenied(unassignedClient, `/resources/${target._id}/content`,
            "UNAUTHORIZED_RESOURCE_ACCESS", "resourceId", target, target.content);
        }
      });

      await t.test("unassigned managers get fail-closed people counts and no team activity", async () => {
        const markerTime = new Date(Date.now() + 2000);
        const markers = await AuditLog.create([
          ...unassignedEmployees.map((person) => ({
            userId: person._id, userName: person.name, role: "EMPLOYEE",
            eventType: "TEST_UNASSIGNED_ACTIVITY", description: person.name, createdAt: markerTime,
          })),
          {
            userId: employee._id, userName: employee.name, role: "EMPLOYEE",
            eventType: "TEST_ASSIGNED_ACTIVITY", description: "Engineering assigned activity", createdAt: markerTime,
          },
          {
            userId: operationsEmployees[0]._id, userName: operationsEmployees[0].name, role: "EMPLOYEE",
            eventType: "TEST_ASSIGNED_ACTIVITY", description: "Operations assigned activity", createdAt: markerTime,
          },
        ]);
        const response = await unassignedClient.request("GET", "/dashboard/summary");
        assert.equal(response.status, 200);
        assert.equal(response.body.role, "MANAGER");
        assert.equal(response.body.departmentName, "Unassigned");
        assert.deepEqual(response.body.metrics, {
          employees: 0, resources: 1, activeSessions: 1,
        });
        assert.deepEqual(response.body.recentActivity, []);
        assert.equal(response.body.recentActivity.some((event) => markers.some(
          (marker) => String(marker._id) === String(event.id),
        )), false);

        // The two assigned-department controls retain their own counts and activity.
        for (const [control, expectedEmployeeCount, marker] of [
          [scopes[0], scopes[0].employees.length, markers[2]],
          [scopes[1], scopes[1].employees.length, markers[3]],
        ]) {
          const controlSummary = await control.client.request("GET", "/dashboard/summary");
          assert.equal(controlSummary.status, 200);
          assert.equal(controlSummary.body.metrics.employees, expectedEmployeeCount);
          assert.ok(controlSummary.body.recentActivity.some(
            (event) => String(event.id) === String(marker._id),
          ));
          for (const event of controlSummary.body.recentActivity) {
            assert.equal(unassignedEmployees.some((person) => String(person._id) === String(event.userId)), false);
          }
        }
      });

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
          const todayLabel = before.body.activity.at(-1).date;
          const todayLogins = before.body.activity.at(-1).logins;
          await AuditLog.create({
            userId: scope.employees[0]._id,
            userName: scope.employees[0].name,
            role: "EMPLOYEE",
            eventType: "LOGIN_SUCCESS",
            description: "Department-scoped trend fixture",
          });
          const withTeamActivity = await scope.client.request("GET", "/dashboard/activity?range=7d");
          assert.equal(withTeamActivity.status, 200);
          const todayRow = withTeamActivity.body.activity.find((row) => row.date === todayLabel);
          assert.equal(todayRow.logins, todayLogins + 1, "manager trends include active employees from their department");
          await AuditLog.create([
            { userId: scope.foreignManager._id, eventType: "LOGIN_SUCCESS", description: "Foreign department test login" },
            { userId: scope.foreignEmployees[0]._id, eventType: "UNAUTHORIZED_RESOURCE_ACCESS", status: "CRITICAL", description: "Foreign department test denial" },
          ]);
          const after = await scope.client.request("GET", "/dashboard/activity?range=7d");
          assert.equal(after.status, 200);
          assert.deepEqual(after.body, withTeamActivity.body);
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

    await t.test("department transfers immediately update active manager and employee scopes", async (t) => {
      const [formerDepartment, newDepartment] = await Promise.all([
        Department.create({ name: "Transfer source department" }),
        Department.create({ name: "Transfer destination department" }),
      ]);
      t.after(async () => {
        await User.updateOne({ _id: manager._id }, { $set: { departmentId: department._id } });
      });
      const [transferredManager, sourceManager, transferredEmployee, sourceEmployee, destinationEmployee] = await Promise.all([
        makeUser("MANAGER", { departmentId: formerDepartment._id, name: "Transferred manager" }),
        makeUser("MANAGER", { departmentId: formerDepartment._id, name: "Source manager" }),
        makeUser("EMPLOYEE", { departmentId: formerDepartment._id, name: "Transferred employee" }),
        makeUser("EMPLOYEE", { departmentId: formerDepartment._id, name: "Remaining source employee" }),
        makeUser("EMPLOYEE", { departmentId: newDepartment._id, name: "Destination employee" }),
      ]);
      const destinationManagerUpdate = await adminClient.request("PATCH", `/users/${manager._id}`, {
        departmentId: String(newDepartment._id),
      });
      assert.equal(destinationManagerUpdate.status, 200);
      const destinationManager = await User.findById(manager._id);
      const [transferredManagerClient, sourceManagerClient, transferredEmployeeClient] = await Promise.all([
        knownClient(transferredManager),
        knownClient(sourceManager),
        knownClient(transferredEmployee),
      ]);
      const destinationManagerClient = managerClient;
      for (const [sessionClient, user] of [
        [transferredManagerClient, transferredManager],
        [sourceManagerClient, sourceManager],
        [transferredEmployeeClient, transferredEmployee],
      ]) {
        const login = await signIn(sessionClient, user);
        assert.equal(login.status, 200);
        assert.equal(login.body.authenticated, true);
      }

      const [sourceManagerResource, destinationManagerResource, sharedManagerResource,
        sourceEmployeeResource, destinationEmployeeResource, sharedEmployeeResource] = await Promise.all([
        Resource.create({ name: "Transfer source manager guide", content: "Source manager-only content", departmentId: formerDepartment._id, allowedRoles: ["MANAGER"] }),
        Resource.create({ name: "Transfer destination manager guide", content: "Destination manager-only content", departmentId: newDepartment._id, allowedRoles: ["MANAGER"] }),
        Resource.create({ name: "Transfer shared manager guide", content: "Shared manager-only content", departmentId: null, allowedRoles: ["MANAGER"] }),
        Resource.create({ name: "Transfer source employee guide", content: "Source employee-only content", departmentId: formerDepartment._id, allowedRoles: ["EMPLOYEE"] }),
        Resource.create({ name: "Transfer destination employee guide", content: "Destination employee-only content", departmentId: newDepartment._id, allowedRoles: ["EMPLOYEE"] }),
        Resource.create({ name: "Transfer shared employee guide", content: "Shared employee-only content", departmentId: null, allowedRoles: ["EMPLOYEE"] }),
      ]);
      const ids = (rows) => rows.map((row) => String(row.id || row._id)).sort();
      const sharedManagerResources = await Resource.find({
        departmentId: null, active: true, allowedRoles: "MANAGER",
      }).select("_id").lean();
      const sharedEmployeeResources = await Resource.find({
        departmentId: null, active: true, allowedRoles: "EMPLOYEE",
      }).lean();
      const assertManagerSummary = async (sessionClient, expectedDepartment, employees) => {
        const summary = await sessionClient.request("GET", "/dashboard/summary");
        assert.equal(summary.status, 200);
        assert.equal(summary.body.departmentName, expectedDepartment.name);
        assert.deepEqual(summary.body.metrics, {
          employees, resources: sharedManagerResources.length + 1, activeSessions: 1,
        });
      };
      const assertEmployeeResources = async (sessionClient, expectedResources, deniedResources) => {
        const list = await sessionClient.request("GET", "/resources");
        assert.equal(list.status, 200);
        assert.deepEqual(ids(list.body.resources), ids(expectedResources));
        for (const resource of deniedResources) {
          assert.equal((await sessionClient.request("GET", `/resources/${resource._id}/content`)).status, 403);
        }
        for (const resource of expectedResources) {
          const content = await sessionClient.request("GET", `/resources/${resource._id}/content`);
          assert.equal(content.status, 200);
          assert.equal(content.body.resource.content, resource.content);
        }
      };
      const [formerDepartmentActivity, newDepartmentActivity] = await AuditLog.create([
        {
          userId: sourceEmployee._id, userName: sourceEmployee.name, role: "EMPLOYEE",
          eventType: "TEST_TRANSFER_ACTIVITY", description: "Activity in the transfer source department",
          createdAt: new Date(Date.now() + 60_000),
        },
        {
          userId: destinationEmployee._id, userName: destinationEmployee.name, role: "EMPLOYEE",
          eventType: "TEST_TRANSFER_ACTIVITY", description: "Activity in the transfer destination department",
          createdAt: new Date(Date.now() + 60_000),
        },
      ]);
      const transferredManagerSession = await Session.findOne({ userId: transferredManager._id, status: "ACTIVE" });
      const transferredEmployeeSession = await Session.findOne({ userId: transferredEmployee._id, status: "ACTIVE" });
      assert.ok(transferredManagerSession);
      assert.ok(transferredEmployeeSession);

      await t.test("manager transfer moves active session scope and dashboard totals", async () => {
        const before = await transferredManagerClient.request("GET", "/users");
        assert.equal(before.status, 200);
        assert.deepEqual(ids(before.body.users), ids([transferredEmployee, sourceEmployee]));
        await assertManagerSummary(transferredManagerClient, formerDepartment, 2);

        const update = await adminClient.request("PATCH", `/users/${transferredManager._id}`, {
          departmentId: String(newDepartment._id),
        });
        assert.equal(update.status, 200);
        assert.equal(String(update.body.user.departmentId), String(newDepartment._id));
        assert.equal((await Session.findById(transferredManagerSession._id)).status, "ACTIVE");

        const identity = await transferredManagerClient.request("GET", "/auth/me");
        assert.equal(identity.status, 200);
        assert.equal(identity.body.user.departmentName, newDepartment.name);
        const employees = await transferredManagerClient.request("GET", "/users");
        assert.equal(employees.status, 200);
        assert.deepEqual(ids(employees.body.users), ids([destinationEmployee]));
        assert.equal((await sourceManagerClient.request("GET", `/users/${transferredManager._id}`)).status, 403);
        assert.deepEqual(ids((await sourceManagerClient.request("GET", "/departments")).body.departments), [String(formerDepartment._id)]);
        assert.deepEqual(ids((await transferredManagerClient.request("GET", "/departments")).body.departments), [String(newDepartment._id)]);
        const movedManagerSummary = await transferredManagerClient.request("GET", "/dashboard/summary");
        assert.equal(movedManagerSummary.status, 200);
        assert.equal(movedManagerSummary.body.departmentName, newDepartment.name);
        assert.deepEqual(movedManagerSummary.body.metrics, {
          employees: 1, resources: sharedManagerResources.length + 1, activeSessions: 1,
        });
        assert.ok(movedManagerSummary.body.recentActivity.some((event) => String(event.id) === String(newDepartmentActivity._id)));
        assert.equal(movedManagerSummary.body.recentActivity.some((event) => String(event.id) === String(formerDepartmentActivity._id)), false);
        const sourceManagerSummary = await sourceManagerClient.request("GET", "/dashboard/summary");
        assert.equal(sourceManagerSummary.body.departmentName, formerDepartment.name);
        assert.deepEqual(sourceManagerSummary.body.metrics, {
          employees: 2, resources: sharedManagerResources.length + 1, activeSessions: 1,
        });
        assert.ok(sourceManagerSummary.body.recentActivity.some((event) => String(event.id) === String(formerDepartmentActivity._id)));
        assert.equal(sourceManagerSummary.body.recentActivity.some((event) => String(event.id) === String(newDepartmentActivity._id)), false);

        const resources = await transferredManagerClient.request("GET", "/resources");
        assert.equal(resources.status, 200);
        assert.deepEqual(ids(resources.body.resources), ids([
          destinationManagerResource, ...sharedManagerResources,
        ]));
        assert.equal((await transferredManagerClient.request("GET", `/resources/${sourceManagerResource._id}/content`)).status, 403);
        assert.equal((await transferredManagerClient.request("GET", `/resources/${destinationEmployeeResource._id}/content`)).status, 403);
        assert.equal((await transferredManagerClient.request("GET", `/resources/${sharedEmployeeResource._id}/content`)).status, 403);
        for (const resource of [destinationManagerResource, sharedManagerResource]) {
          assert.equal((await transferredManagerClient.request("GET", `/resources/${resource._id}/content`)).status, 200);
        }
      });

      await t.test("employee transfer updates live identity, resource access, manager listings, and aggregates", async () => {
        const update = await adminClient.request("PATCH", `/users/${transferredEmployee._id}`, {
          departmentId: String(newDepartment._id),
        });
        assert.equal(update.status, 200);
        assert.equal(String(update.body.user.departmentId), String(newDepartment._id));
        assert.equal((await Session.findById(transferredEmployeeSession._id)).status, "ACTIVE");

        const identity = await transferredEmployeeClient.request("GET", "/auth/me");
        assert.equal(identity.status, 200);
        assert.equal(identity.body.user.departmentName, newDepartment.name);
        assert.deepEqual(ids((await transferredEmployeeClient.request("GET", "/departments")).body.departments), [String(newDepartment._id)]);
        await assertEmployeeResources(transferredEmployeeClient,
          [destinationEmployeeResource, ...sharedEmployeeResources],
          [sourceEmployeeResource, sharedManagerResource]);
        const summary = await transferredEmployeeClient.request("GET", "/dashboard/summary");
        assert.equal(summary.status, 200);
        assert.deepEqual(summary.body.metrics, {
          resources: sharedEmployeeResources.length + 1, activeSessions: 1,
        });

        for (const managerClient of [transferredManagerClient, destinationManagerClient]) {
          const listing = await managerClient.request("GET", "/users");
          assert.equal(listing.status, 200);
          assert.ok(ids(listing.body.users).includes(String(transferredEmployee._id)));
        }
        const sourceListing = await sourceManagerClient.request("GET", "/users");
        assert.equal(sourceListing.status, 200);
        assert.deepEqual(ids(sourceListing.body.users), ids([sourceEmployee]));
        assert.equal((await sourceManagerClient.request("GET", `/users/${transferredEmployee._id}`)).status, 403);
        assert.equal((await transferredManagerClient.request("GET", `/users/${transferredEmployee._id}`)).status, 200);
        await assertManagerSummary(sourceManagerClient, formerDepartment, 1);
        await assertManagerSummary(transferredManagerClient, newDepartment, 2);
        await assertManagerSummary(destinationManagerClient, newDepartment, 2);
      });

      await t.test("a combined role and department update revokes the old session and applies destination manager access", async () => {
        const combinedTransferUser = await makeUser("EMPLOYEE", {
          departmentId: formerDepartment._id,
          name: "Combined transfer employee",
        });
        forwardedForAdminPromotion = "198.51.100.18";
        const combinedTransferClient = await knownClient(combinedTransferUser, forwardedForAdminPromotion);
        const initialLogin = await signIn(combinedTransferClient, combinedTransferUser);
        assert.equal(initialLogin.status, 200);
        assert.equal(initialLogin.body.authenticated, true);
        const oldSession = await Session.findOne({
          userId: combinedTransferUser._id, status: "ACTIVE",
        }).sort({ createdAt: -1 });
        assert.ok(oldSession, "the employee must have an active session before the combined update");

        const update = await adminClient.request("PATCH", `/users/${combinedTransferUser._id}`, {
          role: "MANAGER",
          departmentId: String(newDepartment._id),
        });
        assert.equal(update.status, 200);
        assert.equal(update.body.user.role, "MANAGER");
        assert.equal(String(update.body.user.departmentId), String(newDepartment._id));

        const revokedSession = await Session.findById(oldSession._id);
        assert.equal(revokedSession.status, "REVOKED");
        assert.equal(revokedSession.revokeReason, "Account role or status changed");
        const oldSessionIdentity = await combinedTransferClient.request("GET", "/auth/me");
        assert.equal(oldSessionIdentity.status, 401);
        assert.equal(oldSessionIdentity.body.code, "SESSION_REVOKED");
        const oldSessionRoles = await combinedTransferClient.request("GET", "/roles");
        assert.equal(oldSessionRoles.status, 401);
        assert.equal(oldSessionRoles.body.code, "SESSION_REVOKED");

        const newManagerClient = await knownClient(combinedTransferUser, forwardedForAdminPromotion);
        const newLogin = await signIn(newManagerClient, combinedTransferUser, "manager");
        assert.equal(newLogin.status, 200);
        assert.equal(newLogin.body.authenticated, true);
        managerForAdminPromotion = combinedTransferUser;
        managerSessionForAdminPromotion = newManagerClient;
        const newSession = await Session.findOne({
          userId: combinedTransferUser._id, status: "ACTIVE",
        }).sort({ createdAt: -1 });
        assert.ok(newSession);
        assert.notEqual(String(newSession._id), String(oldSession._id));

        const identity = await newManagerClient.request("GET", "/auth/me");
        assert.equal(identity.status, 200);
        assert.equal(identity.body.user.role, "MANAGER");
        assert.equal(identity.body.user.departmentName, newDepartment.name);
        const ownIdentity = await newManagerClient.request("GET", `/users/${combinedTransferUser._id}`);
        assert.equal(ownIdentity.status, 200);
        assert.equal(ownIdentity.body.user.role, "MANAGER");
        assert.equal(String(ownIdentity.body.user.departmentId), String(newDepartment._id));

        const visibleEmployees = await newManagerClient.request("GET", "/users");
        assert.equal(visibleEmployees.status, 200);
        assert.deepEqual(ids(visibleEmployees.body.users), ids([transferredEmployee, destinationEmployee]));
        assert.equal((await newManagerClient.request("GET", `/users/${destinationEmployee._id}`)).status, 200);
        assert.equal((await newManagerClient.request("GET", `/users/${sourceEmployee._id}`)).status, 403);
        assert.equal((await sourceManagerClient.request("GET", `/users/${combinedTransferUser._id}`)).status, 403);

        const managerResources = await newManagerClient.request("GET", "/resources");
        assert.equal(managerResources.status, 200);
        assert.deepEqual(ids(managerResources.body.resources), ids([
          destinationManagerResource, ...sharedManagerResources,
        ]));
        assert.equal((await newManagerClient.request(
          "GET", `/resources/${destinationManagerResource._id}/content`,
        )).status, 200);
        assert.equal((await newManagerClient.request(
          "GET", `/resources/${destinationEmployeeResource._id}/content`,
        )).status, 403);
        assert.equal((await newManagerClient.request(
          "GET", `/resources/${sourceManagerResource._id}/content`,
        )).status, 403);

        const event = await AuditLog.findOne({
          eventType: "ROLE_MODIFIED",
          "metadata.targetUserId": String(combinedTransferUser._id),
        }).sort({ createdAt: -1, _id: -1 }).lean();
        assert.ok(event, "the combined role and department update must be audited");
        assert.equal(String(event.userId), String(admin._id));
        assert.equal(event.userName, admin.name);
        assert.equal(event.role, "ADMIN");
        assert.equal(event.status, "SUCCESS");
        assert.deepEqual({
          targetUserId: event.metadata.targetUserId,
          role: event.metadata.role,
          oldDepartmentId: event.metadata.oldDepartmentId,
          oldDepartmentName: event.metadata.oldDepartmentName,
          newDepartmentId: event.metadata.newDepartmentId,
          newDepartmentName: event.metadata.newDepartmentName,
        }, {
          targetUserId: String(combinedTransferUser._id),
          role: "MANAGER",
          oldDepartmentId: String(formerDepartment._id),
          oldDepartmentName: formerDepartment.name,
          newDepartmentId: String(newDepartment._id),
          newDepartmentName: newDepartment.name,
        });
        assert.ok(event.description.includes("role from EMPLOYEE to MANAGER"));
        assert.ok(event.description.includes(
          `Department changed from ${formerDepartment.name} to ${newDepartment.name}.`,
        ));

        const auditApi = await adminClient.request("GET",
          `/audit-logs?eventType=ROLE_MODIFIED&userId=${admin._id}&from=${encodeURIComponent(event.createdAt.toISOString())}`);
        assert.equal(auditApi.status, 200);
        const row = auditApi.body.logs.find((item) => String(item.id) === String(event._id));
        assert.ok(row, "the combined update must be visible through the administrator audit API");
        assert.equal(String(row.userId), String(admin._id));
        assert.equal(row.role, "ADMIN");
        assert.equal(row.metadata.targetUserId, String(combinedTransferUser._id));
        assert.equal(row.metadata.oldDepartmentId, String(formerDepartment._id));
        assert.equal(row.metadata.newDepartmentId, String(newDepartment._id));
      });

      await t.test("both administrator department changes are recorded in the audit trail", async () => {
        for (const [target, destinationDepartment] of [
          [transferredManager, newDepartment],
          [transferredEmployee, newDepartment],
        ]) {
          const event = await AuditLog.findOne({
            eventType: "USER_UPDATED",
            userId: admin._id,
            "metadata.targetUserId": String(target._id),
          }).sort({ createdAt: -1, _id: -1 }).lean();
          assert.ok(event, `department update for ${target.role.toLowerCase()} must be audited`);
          assert.equal(event.role, "ADMIN");
          assert.equal(event.status, "SUCCESS");
          assert.deepEqual({
            oldDepartmentId: event.metadata.oldDepartmentId,
            oldDepartmentName: event.metadata.oldDepartmentName,
            newDepartmentId: event.metadata.newDepartmentId,
            newDepartmentName: event.metadata.newDepartmentName,
          }, {
            oldDepartmentId: String(formerDepartment._id),
            oldDepartmentName: formerDepartment.name,
            newDepartmentId: String(destinationDepartment._id),
            newDepartmentName: destinationDepartment.name,
          });

          const auditApi = await adminClient.request("GET",
            `/audit-logs?eventType=USER_UPDATED&userId=${admin._id}&from=${encodeURIComponent(event.createdAt.toISOString())}`);
          assert.equal(auditApi.status, 200);
          const row = auditApi.body.logs.find((item) => String(item.id) === String(event._id));
          assert.ok(row, "the department change must be available through the administrator audit API");
          assert.deepEqual({
            oldDepartmentId: row.metadata.oldDepartmentId,
            oldDepartmentName: row.metadata.oldDepartmentName,
            newDepartmentId: row.metadata.newDepartmentId,
            newDepartmentName: row.metadata.newDepartmentName,
          }, {
            oldDepartmentId: String(formerDepartment._id),
            oldDepartmentName: formerDepartment.name,
            newDepartmentId: String(destinationDepartment._id),
            newDepartmentName: destinationDepartment.name,
          });
          assert.equal(row.metadata.targetUserId, String(target._id));
          assert.ok(row.description.includes(`Department changed from ${formerDepartment.name} to ${destinationDepartment.name}.`));
          for (const field of ["passwordHash", "mfaSecretEncrypted", "recoveryCodeHashes", "email"]) {
            assert.equal(Object.hasOwn(row.metadata, field), false, `${field} must not appear in transfer audit metadata`);
          }
          assert.equal(row.user, undefined);
          assert.equal(JSON.stringify(row).includes(target.email), false, "the audit API must not include the transferred user's email");
        }

        const retainedLabelEvent = await AuditLog.findOne({
          eventType: "USER_UPDATED",
          "metadata.targetUserId": String(transferredManager._id),
        }).sort({ createdAt: -1, _id: -1 }).lean();
        const renamedDepartment = `${newDepartment.name} renamed for history check`;
        await Department.updateOne({ _id: newDepartment._id }, { $set: { name: renamedDepartment } });
        try {
          const historicalEvent = await AuditLog.findById(retainedLabelEvent._id).lean();
          assert.equal(historicalEvent.metadata.newDepartmentName, newDepartment.name);
          assert.ok(historicalEvent.description.includes(
            `Department changed from ${formerDepartment.name} to ${newDepartment.name}.`,
          ));
        } finally {
          await Department.updateOne({ _id: newDepartment._id }, { $set: { name: newDepartment.name } });
        }
      });

      await t.test("transfer from a named department to unassigned is clear and private in the audit API", async () => {
        const target = await makeUser("EMPLOYEE", {
          departmentId: formerDepartment._id,
          name: "Named department to unassigned audit target",
        });
        const update = await adminClient.request("PATCH", `/users/${target._id}`, { departmentId: null });
        assert.equal(update.status, 200);
        assert.equal(update.body.user.departmentId, null);

        const auditApi = await adminClient.request("GET",
          `/audit-logs?eventType=USER_UPDATED&userId=${admin._id}`);
        assert.equal(auditApi.status, 200);
        const row = auditApi.body.logs.find((item) =>
          item.metadata?.targetUserId === String(target._id) &&
          item.description.includes(`Department changed from ${formerDepartment.name} to Unassigned.`));
        assert.ok(row, "the transfer to unassigned must be visible through the administrator audit API");
        assert.deepEqual({
          oldDepartmentId: row.metadata.oldDepartmentId,
          oldDepartmentName: row.metadata.oldDepartmentName,
          newDepartmentId: row.metadata.newDepartmentId,
          newDepartmentName: row.metadata.newDepartmentName,
        }, {
          oldDepartmentId: String(formerDepartment._id),
          oldDepartmentName: formerDepartment.name,
          newDepartmentId: null,
          newDepartmentName: null,
        });
        assert.equal(row.user, undefined);
        const serializedRow = JSON.stringify(row);
        assert.equal(serializedRow.includes(target.email), false, "the audit API must not include the transferred user's email");
        for (const field of ["passwordHash", "mfaSecretEncrypted", "recoveryCodeHashes"]) {
          assert.equal(Object.hasOwn(row, field), false, `${field} must not appear in the audit row`);
          assert.equal(Object.hasOwn(row.metadata, field), false, `${field} must not appear in transfer audit metadata`);
          assert.equal(serializedRow.includes(field), false, `${field} must not appear anywhere in the audit response`);
        }
      });

      await t.test("transfer from unassigned to a named department is clear and private in the audit API", async () => {
        const target = await makeUser("EMPLOYEE", {
          departmentId: null,
          name: "Unassigned to named department audit target",
        });
        const update = await adminClient.request("PATCH", `/users/${target._id}`, {
          departmentId: String(newDepartment._id),
        });
        assert.equal(update.status, 200);
        assert.equal(update.body.user.departmentId, String(newDepartment._id));

        const auditApi = await adminClient.request("GET",
          `/audit-logs?eventType=USER_UPDATED&userId=${admin._id}`);
        assert.equal(auditApi.status, 200);
        const row = auditApi.body.logs.find((item) =>
          item.metadata?.targetUserId === String(target._id) &&
          item.description.includes(`Department changed from Unassigned to ${newDepartment.name}.`));
        assert.ok(row, "the transfer from unassigned must be visible through the administrator audit API");
        assert.deepEqual({
          oldDepartmentId: row.metadata.oldDepartmentId,
          oldDepartmentName: row.metadata.oldDepartmentName,
          newDepartmentId: row.metadata.newDepartmentId,
          newDepartmentName: row.metadata.newDepartmentName,
        }, {
          oldDepartmentId: null,
          oldDepartmentName: null,
          newDepartmentId: String(newDepartment._id),
          newDepartmentName: newDepartment.name,
        });
        assert.equal(row.user, undefined);
        const serializedRow = JSON.stringify(row);
        assert.equal(serializedRow.includes(target.email), false, "the audit API must not include the transferred user's email");
        for (const field of ["passwordHash", "mfaSecretEncrypted", "recoveryCodeHashes"]) {
          assert.equal(Object.hasOwn(row, field), false, `${field} must not appear in the audit row`);
          assert.equal(Object.hasOwn(row.metadata, field), false, `${field} must not appear in transfer audit metadata`);
          assert.equal(serializedRow.includes(field), false, `${field} must not appear anywhere in the audit response`);
        }
      });
    });

    await t.test("manager promotion revokes the old session and grants global administrator access after fresh sign-in", async () => {
      assert.ok(managerForAdminPromotion, "the prior role-transfer scenario must provide an authenticated manager");
      const promotedUser = managerForAdminPromotion;
      const oldSessionClient = managerSessionForAdminPromotion;
      const oldSession = await Session.findOne({
        userId: promotedUser._id,
        status: "ACTIVE",
      }).sort({ createdAt: -1 });
      assert.ok(oldSession);
      assert.equal(oldSession.roleAtIssue, "MANAGER");

      const search = "Manager promotion cross-department identity";
      const [sourceDepartment, otherDepartment] = await Promise.all([
        Department.create({ name: "Promotion source visibility" }),
        Department.create({ name: "Promotion other visibility" }),
      ]);
      const visibleIdentities = await Promise.all([
        makeUser("EMPLOYEE", {
          name: `${search} source`,
          departmentId: sourceDepartment._id,
        }),
        makeUser("EMPLOYEE", {
          name: `${search} other`,
          departmentId: otherDepartment._id,
        }),
      ]);
      const managerView = await oldSessionClient.request(
        "GET", `/users?q=${encodeURIComponent(search)}`,
      );
      assert.equal(managerView.status, 200);
      assert.equal(managerView.body.total, 0, "the manager must not see identities in other departments");

      const update = await adminClient.request("PATCH", `/users/${promotedUser._id}`, {
        role: "ADMIN",
      });
      assert.equal(update.status, 200);
      assert.equal(update.body.user.role, "ADMIN");

      const revokedSession = await Session.findById(oldSession._id);
      assert.equal(revokedSession.status, "REVOKED");
      assert.equal(revokedSession.revokeReason, "Account role or status changed");
      for (const route of ["/auth/me", "/roles", "/users"]) {
        const response = await oldSessionClient.request("GET", route);
        assert.equal(response.status, 401, `the old manager session must not access ${route}`);
        assert.equal(response.body.code, "SESSION_REVOKED");
      }

      const freshAdminClient = await knownClient(promotedUser, forwardedForAdminPromotion);
      const freshLogin = await signIn(freshAdminClient, promotedUser, "admin");
      assert.equal(freshLogin.status, 200);
      assert.equal(freshLogin.body.authenticated, true);
      assert.equal((await freshAdminClient.request("GET", "/roles")).status, 200);
      const globalIdentities = await freshAdminClient.request(
        "GET", `/users?q=${encodeURIComponent(search)}`,
      );
      assert.equal(globalIdentities.status, 200);
      const userIds = (rows) => rows.map((row) => String(row.id || row._id)).sort();
      assert.deepEqual(
        userIds(globalIdentities.body.users),
        userIds(visibleIdentities),
        "the new administrator session must see matching identities across departments",
      );

      const event = await AuditLog.findOne({
        eventType: "ROLE_MODIFIED",
        "metadata.targetUserId": String(promotedUser._id),
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(event);
      assert.equal(String(event.userId), String(admin._id));
      assert.equal(event.userName, admin.name);
      assert.equal(event.role, "ADMIN");
      assert.equal(event.metadata.targetUserId, String(promotedUser._id));
      assert.equal(event.metadata.role, "ADMIN");
      assert.ok(event.description.includes("role from MANAGER to ADMIN"));

      const auditApi = await adminClient.request(
        "GET",
        `/audit-logs?eventType=ROLE_MODIFIED&userId=${admin._id}&from=${encodeURIComponent(event.createdAt.toISOString())}`,
      );
      assert.equal(auditApi.status, 200);
      const row = auditApi.body.logs.find((item) => String(item.id) === String(event._id));
      assert.ok(row);
      assert.equal(String(row.userId), String(admin._id));
      assert.equal(row.metadata.targetUserId, String(promotedUser._id));
      assert.equal(row.metadata.role, "ADMIN");
    });

    await t.test("identity pages and filtered totals always intersect the manager's scope", async () => {
      const otherDepartment = await Department.create({ name: "Pagination other department" });
      const fixtures = await User.insertMany(Array.from({ length: 265 }, (_, index) => ({
        name: `Paging [literal] ${String(index).padStart(3, "0")}`,
        email: `paging-${index}@example.test`,
        role: index === 0 ? "MANAGER" : "EMPLOYEE",
        status: index === 1 ? "DISABLED" : "ACTIVE",
        departmentId: index < 5 ? otherDepartment._id : department._id,
        passwordHash: "unused-fixture-hash",
      })));
      const adminPage = await adminClient.request("GET", "/users?q=Paging&limit=100&page=3");
      assert.equal(adminPage.status, 200);
      assert.equal(adminPage.body.total, 265);
      assert.equal(adminPage.body.totalPages, 3);
      assert.equal(adminPage.body.users.length, 65);
      const allAdminIds = [];
      const allManagerIds = [];
      for (let page = 1; page <= 3; page++) {
        const adminRows = await adminClient.request("GET", `/users?q=Paging&limit=100&page=${page}`);
        allAdminIds.push(...adminRows.body.users.map((row) => row.id));
        const response = await managerClient.request("GET", `/users?q=Paging&limit=100&page=${page}`);
        assert.equal(response.status, 200);
        assert.equal(response.body.total, 260);
        assert.equal(response.body.totalPages, 3);
        for (const row of response.body.users) {
          assert.equal(row.departmentId, String(department._id));
          assert.equal(row.role, "EMPLOYEE");
          assert.equal(row.status, "ACTIVE");
          assert.equal(row.passwordHash, undefined);
          assert.equal(row.mfaSecretEncrypted, undefined);
        }
        allManagerIds.push(...response.body.users.map((row) => row.id));
      }
      assert.equal(new Set(allAdminIds).size, 265, "stable sort must not repeat or omit tied records");
      assert.equal(new Set(allManagerIds).size, 260);
      for (const query of [
        `departmentId=${otherDepartment._id}`, "role=ADMIN", "role=MANAGER",
        "status=DISABLED", "status=PENDING", "q=Pagination%20other%20department",
        `departmentId=${otherDepartment._id}&q=Paging&page=99`,
      ]) {
        const response = await managerClient.request("GET", `/users?limit=10&${query}`);
        assert.equal(response.status, 200);
        assert.deepEqual(response.body.users, []);
        assert.equal(response.body.total, 0);
        assert.equal(response.body.page, 1);
        assert.equal(response.body.totalPages, 0);
      }
      const last = await managerClient.request("GET", "/users?q=Paging&page=999&limit=100");
      assert.equal(last.body.page, 3);
      assert.equal(last.body.users.length, 60);
      const literal = await managerClient.request("GET", "/users?q=%5Bliteral%5D&limit=10");
      assert.equal(literal.body.total, 260);
      const departmentSearch = await managerClient.request("GET", "/users?q=Test%20engineering&limit=10");
      assert.equal(departmentSearch.body.total, 261);
      assert.ok(departmentSearch.body.users.every((row) => row.departmentId === String(department._id)));
      assert.equal((await pendingClient.request("GET", "/users?page=2&q=Paging")).status, 403);
      await User.updateOne({ _id: manager._id }, { $set: { departmentId: null } });
      const noDepartment = await managerClient.request("GET", `/users?page=2&departmentId=${otherDepartment._id}`);
      assert.equal(noDepartment.status, 200);
      assert.equal(noDepartment.body.total, 0);
      assert.deepEqual(noDepartment.body.users, []);
      await User.updateOne({ _id: manager._id }, { $set: { departmentId: department._id } });
      await User.deleteMany({ _id: { $in: fixtures.map((row) => row._id) } });
    });

    await t.test("administrators can page through all matching device and session records", async () => {
      const deviceFixtures = await Device.insertMany(Array.from({ length: 305 }, (_, index) => ({
        userId: employee._id,
        name: `Device Pagination ${String(index).padStart(3, "0")}`,
        browser: "Pagination test browser",
        operatingSystem: "Test OS",
        credentialHash: hashToken(randomToken(40)),
        status: "APPROVED",
      })));
      const sessionDevice = await Device.create({
        userId: employee._id,
        name: "Session Pagination Device",
        credentialHash: hashToken(randomToken(40)),
        status: "APPROVED",
      });
      const sessionFixtures = await Session.insertMany(Array.from({ length: 305 }, () => ({
        userId: employee._id,
        deviceId: sessionDevice._id,
        roleAtIssue: "EMPLOYEE",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      })));
      try {
        const deviceIds = [];
        const sessionIds = [];
        for (let page = 1; page <= 4; page++) {
          const devices = await adminClient.request("GET", `/devices?q=Device%20Pagination&limit=100&page=${page}`);
          assert.equal(devices.status, 200);
          assert.equal(devices.body.total, 305);
          assert.equal(devices.body.totalPages, 4);
          deviceIds.push(...devices.body.devices.map(({ id }) => String(id)));
          const sessions = await adminClient.request("GET", `/sessions?q=Session%20Pagination%20Device&limit=100&page=${page}`);
          assert.equal(sessions.status, 200);
          assert.equal(sessions.body.total, 305);
          assert.equal(sessions.body.totalPages, 4);
          sessionIds.push(...sessions.body.sessions.map(({ id }) => String(id)));
        }
        assert.equal(new Set(deviceIds).size, 305);
        assert.equal(new Set(sessionIds).size, 305);
      } finally {
        await Promise.all([
          Session.deleteMany({ _id: { $in: sessionFixtures.map(({ _id }) => _id) } }),
          Device.deleteMany({ _id: { $in: [...deviceFixtures.map(({ _id }) => _id), sessionDevice._id] } }),
        ]);
      }
    });

    await t.test("audit pages search all matching events and remain administrator-only", async () => {
      const createdAt = new Date("2020-06-15T12:00:00.000Z");
      await AuditLog.insertMany(Array.from({ length: 265 }, (_, index) => ({
        eventType: "PAGINATION_FIXTURE",
        description: `Paging [literal] event ${index}`,
        userId: index % 2 ? employee._id : manager._id,
        userName: `Paging identity ${index}`,
        ipAddress: "198.51.100.42",
        status: index % 2 ? "CRITICAL" : "SUCCESS",
        createdAt,
      })));
      const ids = [];
      for (let page = 1; page <= 3; page++) {
        const response = await adminClient.request("GET", `/audit-logs?eventType=PAGINATION_FIXTURE&limit=100&page=${page}`);
        assert.equal(response.status, 200);
        assert.equal(response.body.total, 265);
        assert.equal(response.body.totalPages, 3);
        ids.push(...response.body.logs.map((row) => row.id));
      }
      assert.equal(new Set(ids).size, 265);
      const filtered = await adminClient.request("GET", `/audit-logs?eventType=PAGINATION_FIXTURE&q=198.51.100.42&status=CRITICAL&userId=${employee._id}&from=2020-06-15&to=2020-06-16&limit=10&page=2`);
      assert.equal(filtered.body.total, 132);
      assert.equal(filtered.body.logs.length, 10);
      assert.ok(filtered.body.logs.every((row) => row.status === "CRITICAL" && row.userId === String(employee._id)));
      const literal = await adminClient.request("GET", "/audit-logs?q=%5Bliteral%5D&eventType=PAGINATION_FIXTURE");
      assert.equal(literal.body.total, 265);
      const noMatch = await adminClient.request("GET", "/audit-logs?eventType=PAGINATION_FIXTURE&from=2021-01-01&page=50");
      assert.equal(noMatch.body.total, 0);
      assert.equal(noMatch.body.page, 1);
      assert.deepEqual(noMatch.body.logs, []);
      for (const sessionClient of [managerClient, pendingClient]) {
        for (const query of ["page=2&limit=10", "q=Paging&status=CRITICAL", `userId=${manager._id}&page=999`]) {
          const response = await sessionClient.request("GET", `/audit-logs?${query}`);
          assert.equal(response.status, 403);
          assert.equal(response.body.logs, undefined);
          assert.equal(response.body.total, undefined);
        }
      }
      await AuditLog.deleteMany({ eventType: "PAGINATION_FIXTURE" });
    });

    await t.test("invalid list parameters are rejected rather than widening filters", async () => {
      for (const route of ["/users", "/audit-logs", "/devices", "/sessions"]) {
        for (const query of ["page=0", "page=-1", "page=1.5", "page=1e9", "limit=101", "limit=NaN", "page=1&page=2", "q=a&q=b", "status=UNKNOWN", `q=${"x".repeat(81)}`]) {
          const response = await adminClient.request("GET", `${route}?${query}`);
          assert.equal(response.status, 400, `${route}?${query}`);
        }
      }
      for (const route of [
        "/users?departmentId=invalid", "/audit-logs?userId=invalid",
        "/devices?userId=invalid", "/sessions?userId=invalid",
        "/audit-logs?from=invalid", "/audit-logs?from=2021-01-01&to=2020-01-01",
      ]) {
        assert.equal((await adminClient.request("GET", route)).status, 400);
      }
      const defaults = await adminClient.request("GET", "/users");
      assert.equal(defaults.body.page, 1);
      assert.equal(defaults.body.limit, 25);
      assert.equal(defaults.body.total, await User.countDocuments());
    });

    await t.test("rejecting a nonexistent destination department leaves no successful update audit", async () => {
      const target = await makeUser("EMPLOYEE", {
        name: "Rejected department transfer target",
      });
      const before = {
        name: target.name,
        email: target.email,
        role: target.role,
        status: target.status,
        departmentId: String(target.departmentId),
        mfaEnabled: target.mfaEnabled,
      };
      const missingDepartmentId = new mongoose.Types.ObjectId().toString();
      assert.equal(await Department.exists({ _id: missingDepartmentId }), null);

      const auditSince = new Date();
      const update = await adminClient.request("PATCH", `/users/${target._id}`, {
        departmentId: missingDepartmentId,
      });
      assert.equal(update.status, 400);
      assert.equal(update.body.error, "Choose a valid department.");

      const savedTarget = await User.findById(target._id).lean();
      assert.deepEqual({
        name: savedTarget.name,
        email: savedTarget.email,
        role: savedTarget.role,
        status: savedTarget.status,
        departmentId: String(savedTarget.departmentId),
        mfaEnabled: savedTarget.mfaEnabled,
      }, before);

      const malformed = await adminClient.request("PATCH", `/users/${target._id}`, { departmentId: "bad-id" });
      assert.equal(malformed.status, 400);
      assert.equal(malformed.body.code, "INVALID_DEPARTMENT_ID");
      assert.equal(String((await User.findById(target._id)).departmentId), before.departmentId);

      const auditUrl = (page) =>
        `/audit-logs?userId=${admin._id}&from=${encodeURIComponent(auditSince.toISOString())}&limit=100&page=${page}`;
      const auditApi = await adminClient.request(
        "GET",
        auditUrl(1),
      );
      assert.equal(auditApi.status, 200);
      const logs = [...auditApi.body.logs];
      for (let page = 2; page <= auditApi.body.totalPages; page++) {
        const nextPage = await adminClient.request("GET", auditUrl(page));
        assert.equal(nextPage.status, 200);
        logs.push(...nextPage.body.logs);
      }
      assert.equal(
        logs.some((log) => log.metadata?.targetUserId === String(target._id)),
        false,
        "the administrator audit API must not show any successful update record for the rejected transfer",
      );
    });

    await t.test("disabling an employee without a department change is not audited as a transfer", async () => {
      const target = await makeUser("EMPLOYEE", {
        name: "Status-only audit target",
      });
      const originalDepartmentId = String(target.departmentId);
      const update = await adminClient.request("PATCH", `/users/${target._id}`, {
        status: "DISABLED",
      });
      assert.equal(update.status, 200);
      assert.equal(update.body.user.status, "DISABLED");
      assert.equal(String(update.body.user.departmentId), originalDepartmentId);

      const event = await AuditLog.findOne({
        eventType: "ACCOUNT_STATUS_CHANGED",
        "metadata.targetUserId": String(target._id),
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(event, "the status-only update must be audited");
      assert.equal(String(event.userId), String(admin._id));
      assert.equal(event.userName, admin.name);
      assert.equal(event.role, "ADMIN");
      assert.equal(event.status, "WARNING");
      assert.equal(event.metadata.status, "DISABLED");
      assert.equal(event.metadata.targetUserId, String(target._id));
      for (const field of [
        "oldDepartmentId",
        "oldDepartmentName",
        "newDepartmentId",
        "newDepartmentName",
      ]) {
        assert.equal(Object.hasOwn(event.metadata, field), false, `${field} must not appear in status-only audit metadata`);
      }
      assert.doesNotMatch(event.description, /department changed|transfer/i);

      const reactivated = await adminClient.request("PATCH", `/users/${target._id}`, { status: "ACTIVE" });
      assert.equal(reactivated.status, 200);
      assert.equal(reactivated.body.user.status, "ACTIVE");
      assert.equal(String(reactivated.body.user.departmentId), originalDepartmentId);
      const reactivationEvent = await AuditLog.findOne({
        eventType: "ACCOUNT_STATUS_CHANGED",
        "metadata.targetUserId": String(target._id),
        "metadata.status": "ACTIVE",
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(reactivationEvent);
      for (const field of ["oldDepartmentId", "oldDepartmentName", "newDepartmentId", "newDepartmentName"]) {
        assert.equal(Object.hasOwn(reactivationEvent.metadata, field), false);
      }
      assert.doesNotMatch(reactivationEvent.description, /department changed|transfer/i);
    });

    await t.test("combined role and status changes are clear in the audit history", async () => {
      const target = await makeUser("EMPLOYEE", { name: "Combined audit target" });
      const response = await adminClient.request("PATCH", `/users/${target._id}`, {
        role: "MANAGER",
        status: "DISABLED",
      });
      assert.equal(response.status, 200);
      const event = await AuditLog.findOne({
        eventType: "ROLE_MODIFIED",
        "metadata.targetUserId": String(target._id),
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(event);
      assert.equal(event.metadata.role, "MANAGER");
      assert.equal(event.metadata.status, "DISABLED");
      assert.match(event.description, /role from EMPLOYEE to MANAGER/);
      assert.match(event.description, /status to DISABLED/);
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

    await t.test("a demoted administrator loses every existing session and cannot sign in through the old portal", async () => {
      const target = await makeUser("ADMIN", { name: "Demoted administrator fixture" });
      const firstClient = await knownClient(target, "198.51.100.60");
      const secondClient = await knownClient(target, "198.51.100.61");
      assert.equal((await signIn(firstClient, target)).status, 200);
      assert.equal((await signIn(secondClient, target)).status, 200);
      const oldSessions = await Session.find({ userId: target._id, status: "ACTIVE" }).select("_id").lean();
      assert.equal(oldSessions.length, 2);

      const demotion = await adminClient.request("PATCH", `/users/${target._id}`, { role: "EMPLOYEE" });
      assert.equal(demotion.status, 200);
      assert.equal(demotion.body.user.role, "EMPLOYEE");
      assert.equal(await Session.countDocuments({ _id: { $in: oldSessions.map(({ _id }) => _id) }, status: "ACTIVE" }), 0);
      assert.equal((await firstClient.request("GET", "/roles")).status, 401);
      assert.equal((await secondClient.request("GET", "/roles")).status, 401);

      const oldPortalClient = await knownClient(target, "198.51.100.62");
      const oldPortalAttempt = await signIn(oldPortalClient, target, "admin");
      assert.equal(oldPortalAttempt.status, 403);
      assert.equal(oldPortalAttempt.body.code, "PORTAL_ROLE_MISMATCH");
    });

    await t.test("disabling and transferring an employee revokes access and records the administrator action", async () => {
      assert.equal((await pendingClient.request("GET", "/auth/me")).status, 200);
      const oldSession = await Session.findOne({
        userId: employee._id,
        status: "ACTIVE",
      }).sort({ createdAt: -1 });
      assert.ok(oldSession, "the employee must have an active session before the combined update");
      const staleSessionProbe = pendingClient.clone();
      const oldChallengeClient = await knownClient(employee, "198.51.100.24");
      await oldChallengeClient.request("GET", "/auth/csrf");
      const oldChallengeLogin = await oldChallengeClient.request("POST", "/auth/login", {
        portal: "employee",
        email: employee.email,
        password,
      });
      assert.equal(oldChallengeLogin.status, 200);
      assert.equal(oldChallengeLogin.body.requiresMfa, true);
      const oldChallenge = await PreAuth.findOne({
        userId: employee._id,
        portal: "EMPLOYEE",
      }).sort({ createdAt: -1 });
      assert.ok(oldChallenge, "a password-verified, unfinished MFA challenge must exist");

      const destinationDepartment = await Department.create({
        name: "Disabled employee destination",
      });
      const update = await adminClient.request("PATCH", `/users/${employee._id}`, {
        status: "DISABLED",
        departmentId: String(destinationDepartment._id),
      });
      assert.equal(update.status, 200);
      assert.equal(update.body.user.status, "DISABLED");
      assert.equal(String(update.body.user.departmentId), String(destinationDepartment._id));

      const savedEmployee = await User.findById(employee._id);
      assert.equal(savedEmployee.status, "DISABLED");
      assert.equal(String(savedEmployee.departmentId), String(destinationDepartment._id));
      const revokedSession = await Session.findById(oldSession._id);
      assert.equal(revokedSession.status, "REVOKED");
      assert.equal(revokedSession.revokeReason, "Account role or status changed");
      assert.equal(await PreAuth.exists({ _id: oldChallenge._id }), null);

      const followUpAccess = await pendingClient.request("GET", "/profile");
      assert.equal(followUpAccess.status, 401);
      assert.equal(followUpAccess.body.code, "SESSION_REVOKED");
      const blockedSignInClient = await knownClient(employee, "198.51.100.26");
      await blockedSignInClient.request("GET", "/auth/csrf");
      const blockedSignIn = await blockedSignInClient.request("POST", "/auth/login", {
        portal: "employee",
        email: employee.email,
        password,
      });
      assert.equal(blockedSignIn.status, 403);
      assert.equal(blockedSignIn.body.code, "ACCOUNT_INACTIVE");
      assert.equal(await PreAuth.exists({ userId: employee._id }), null);
      assert.ok(await AuditLog.exists({ userId: employee._id, eventType: "LOGIN_BLOCKED" }));

      const event = await AuditLog.findOne({
        eventType: "ACCOUNT_STATUS_CHANGED",
        "metadata.targetUserId": String(employee._id),
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(event, "the combined disable and transfer must be audited");
      assert.equal(String(event.userId), String(admin._id));
      assert.equal(event.userName, admin.name);
      assert.equal(event.role, "ADMIN");
      assert.equal(event.status, "WARNING");
      assert.deepEqual({
        targetUserId: event.metadata.targetUserId,
        role: event.metadata.role,
        status: event.metadata.status,
        oldDepartmentId: event.metadata.oldDepartmentId,
        oldDepartmentName: event.metadata.oldDepartmentName,
        newDepartmentId: event.metadata.newDepartmentId,
        newDepartmentName: event.metadata.newDepartmentName,
      }, {
        targetUserId: String(employee._id),
        role: "EMPLOYEE",
        status: "DISABLED",
        oldDepartmentId: String(department._id),
        oldDepartmentName: department.name,
        newDepartmentId: String(destinationDepartment._id),
        newDepartmentName: destinationDepartment.name,
      });

      const auditApi = await adminClient.request(
        "GET",
        `/audit-logs?eventType=ACCOUNT_STATUS_CHANGED&userId=${admin._id}&from=${encodeURIComponent(event.createdAt.toISOString())}`,
      );
      assert.equal(auditApi.status, 200);
      const row = auditApi.body.logs.find((item) => String(item.id) === String(event._id));
      assert.ok(row);
      assert.equal(String(row.userId), String(admin._id));
      assert.equal(row.status, "WARNING");
      assert.equal(row.metadata.status, "DISABLED");
      assert.equal(row.metadata.targetUserId, String(employee._id));
      assert.equal(row.metadata.oldDepartmentName, department.name);
      assert.equal(row.metadata.newDepartmentName, destinationDepartment.name);
      assert.ok(row.description.includes("status to DISABLED"));
      assert.ok(row.description.includes(
        `Department changed from ${department.name} to ${destinationDepartment.name}.`,
      ));

      const reactivationDepartment = await Department.create({
        name: "Reactivated employee department",
      });
      const reactivation = await adminClient.request("PATCH", `/users/${employee._id}`, {
        status: "ACTIVE",
        departmentId: String(reactivationDepartment._id),
      });
      assert.equal(reactivation.status, 200);
      assert.equal(reactivation.body.user.status, "ACTIVE");
      assert.equal(String(reactivation.body.user.departmentId), String(reactivationDepartment._id));

      const reactivatedEmployee = await User.findById(employee._id);
      assert.equal(reactivatedEmployee.status, "ACTIVE");
      assert.equal(String(reactivatedEmployee.departmentId), String(reactivationDepartment._id));
      assert.equal((await Session.findById(oldSession._id)).status, "REVOKED");
      assert.equal(
        await Session.countDocuments({ userId: employee._id, status: "ACTIVE" }),
        0,
        "reactivating the account must not restore any previously revoked session",
      );
      const staleAccessAfterReactivation = await staleSessionProbe.request("GET", "/profile");
      assert.equal(staleAccessAfterReactivation.status, 401);
      assert.equal(staleAccessAfterReactivation.body.code, "SESSION_REVOKED");

      const staleMfaChallenge = await oldChallengeClient.request("POST", "/auth/mfa/verify", {
        code: generateTotp(secret),
      });
      assert.equal(staleMfaChallenge.status, 401);
      assert.equal(staleMfaChallenge.body.code, "PREAUTH_EXPIRED");

      const freshClient = await knownClient(employee, "198.51.100.25");
      const freshLogin = await signIn(freshClient, employee);
      assert.equal(freshLogin.status, 200);
      assert.equal(freshLogin.body.authenticated, true);
      const freshSession = await Session.findOne({
        userId: employee._id,
        status: "ACTIVE",
      }).sort({ createdAt: -1 });
      assert.ok(freshSession);
      assert.notEqual(String(freshSession._id), String(oldSession._id));
      assert.equal(freshSession.roleAtIssue, "EMPLOYEE");
      const freshIdentity = await freshClient.request("GET", "/auth/me");
      assert.equal(freshIdentity.status, 200);
      assert.equal(freshIdentity.body.user.status, "ACTIVE");
      assert.equal(freshIdentity.body.user.role, "EMPLOYEE");

      const reactivationEvent = await AuditLog.findOne({
        eventType: "ACCOUNT_STATUS_CHANGED",
        userId: admin._id,
        "metadata.targetUserId": String(employee._id),
        "metadata.status": "ACTIVE",
        "metadata.newDepartmentId": String(reactivationDepartment._id),
      }).sort({ createdAt: -1, _id: -1 }).lean();
      assert.ok(reactivationEvent, "reactivation and second transfer must be audited");
      assert.equal(reactivationEvent.userName, admin.name);
      assert.equal(reactivationEvent.role, "ADMIN");
      assert.equal(reactivationEvent.status, "SUCCESS");
      assert.deepEqual({
        targetUserId: reactivationEvent.metadata.targetUserId,
        role: reactivationEvent.metadata.role,
        status: reactivationEvent.metadata.status,
        oldDepartmentId: reactivationEvent.metadata.oldDepartmentId,
        oldDepartmentName: reactivationEvent.metadata.oldDepartmentName,
        newDepartmentId: reactivationEvent.metadata.newDepartmentId,
        newDepartmentName: reactivationEvent.metadata.newDepartmentName,
      }, {
        targetUserId: String(employee._id),
        role: "EMPLOYEE",
        status: "ACTIVE",
        oldDepartmentId: String(destinationDepartment._id),
        oldDepartmentName: destinationDepartment.name,
        newDepartmentId: String(reactivationDepartment._id),
        newDepartmentName: reactivationDepartment.name,
      });
      assert.ok(reactivationEvent.description.includes("status to ACTIVE"));
      assert.ok(reactivationEvent.description.includes(
        `Department changed from ${destinationDepartment.name} to ${reactivationDepartment.name}.`,
      ));

      const reactivationAuditApi = await adminClient.request(
        "GET",
        `/audit-logs?eventType=ACCOUNT_STATUS_CHANGED&userId=${admin._id}&from=${encodeURIComponent(reactivationEvent.createdAt.toISOString())}`,
      );
      assert.equal(reactivationAuditApi.status, 200);
      const reactivationRow = reactivationAuditApi.body.logs.find(
        (item) => String(item.id) === String(reactivationEvent._id),
      );
      assert.ok(reactivationRow);
      assert.equal(String(reactivationRow.userId), String(admin._id));
      assert.equal(reactivationRow.status, "SUCCESS");
      assert.equal(reactivationRow.metadata.targetUserId, String(employee._id));
      assert.equal(reactivationRow.metadata.status, "ACTIVE");
      assert.equal(reactivationRow.metadata.oldDepartmentName, destinationDepartment.name);
      assert.equal(reactivationRow.metadata.newDepartmentName, reactivationDepartment.name);
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

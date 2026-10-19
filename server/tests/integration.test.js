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

    await t.test("department transfers immediately update active manager and employee scopes", async (t) => {
      const [formerDepartment, newDepartment] = await Promise.all([
        Department.create({ name: "Transfer source department" }),
        Department.create({ name: "Transfer destination department" }),
      ]);
      const [transferredManager, sourceManager, destinationManager, transferredEmployee, sourceEmployee, destinationEmployee] = await Promise.all([
        makeUser("MANAGER", { departmentId: formerDepartment._id, name: "Transferred manager" }),
        makeUser("MANAGER", { departmentId: formerDepartment._id, name: "Source manager" }),
        makeUser("MANAGER", { departmentId: newDepartment._id, name: "Destination manager" }),
        makeUser("EMPLOYEE", { departmentId: formerDepartment._id, name: "Transferred employee" }),
        makeUser("EMPLOYEE", { departmentId: formerDepartment._id, name: "Remaining source employee" }),
        makeUser("EMPLOYEE", { departmentId: newDepartment._id, name: "Destination employee" }),
      ]);
      const [transferredManagerClient, sourceManagerClient, destinationManagerClient, transferredEmployeeClient] = await Promise.all([
        knownClient(transferredManager),
        knownClient(sourceManager),
        knownClient(destinationManager),
        knownClient(transferredEmployee),
      ]);
      for (const [sessionClient, user] of [
        [transferredManagerClient, transferredManager],
        [sourceManagerClient, sourceManager],
        [destinationManagerClient, destinationManager],
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
      }).select("_id").lean();
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
      });
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
      for (const route of ["/users", "/audit-logs"]) {
        for (const query of ["page=0", "page=-1", "page=1.5", "page=1e9", "limit=101", "limit=NaN", "page=1&page=2", "q=a&q=b", "status=UNKNOWN", `q=${"x".repeat(81)}`]) {
          const response = await adminClient.request("GET", `${route}?${query}`);
          assert.equal(response.status, 400, `${route}?${query}`);
        }
      }
      for (const route of ["/users?departmentId=invalid", "/audit-logs?userId=invalid", "/audit-logs?from=invalid", "/audit-logs?from=2021-01-01&to=2020-01-01"]) {
        assert.equal((await adminClient.request("GET", route)).status, 400);
      }
      const defaults = await adminClient.request("GET", "/users");
      assert.equal(defaults.body.page, 1);
      assert.equal(defaults.body.limit, 25);
      assert.equal(defaults.body.total, await User.countDocuments());
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

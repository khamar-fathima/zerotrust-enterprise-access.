import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createElement, lazy } from "react";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { createServer } from "vite";

let vite;
before(async () => {
  vite = await createServer({
    configFile: "vite.config.js",
    server: { middlewareMode: true },
    appType: "custom",
  });
});
after(async () => { await vite?.close(); });

const user = {
  id: "render-fixture",
  name: "Test identity",
  email: "identity@example.test",
  role: "ADMIN",
  departmentId: "render-department",
  departmentName: "Engineering",
  mfaEnabled: true,
};
const cases = [
  ["/src/pages/PortalPages.jsx", "PortalHome", {}, "Trust is not"],
  ["/src/pages/PortalPages.jsx", "LoginPage", { portal: "admin" }, "Administrator"],
  ["/src/pages/PortalPages.jsx", "LoginPage", { portal: "manager" }, "Department manager"],
  ["/src/pages/PortalPages.jsx", "LoginPage", { portal: "employee" }, "Employee"],
  ["/src/pages/PortalPages.jsx", "RegisterPage", {}, "Request access."],
  ["/src/pages/PortalPages.jsx", "DeviceVerificationPage", {}, "One more boundary."],
  ["/src/components/ForcePasswordPage.jsx", "default", { user, onUser() {} }, "Update your password."],
  ["/src/pages/console/DashboardPage.jsx", "default", { role: "admin" }, "Good morning."],
  ["/src/pages/console/DashboardPage.jsx", "default", { role: "admin", user: { ...user, isBootstrapAdmin: true } }, "Identity risk review"],
  ["/src/pages/console/DashboardPage.jsx", "default", { role: "manager" }, "Team access, at a glance."],
  ["/src/pages/console/DashboardPage.jsx", "default", { role: "employee" }, "Your access, in focus."],
  ["/src/pages/console/UsersPage.jsx", "default", { role: "admin" }, "User management."],
  ["/src/pages/console/UsersPage.jsx", "default", { role: "manager" }, "People in your department."],
  ["/src/pages/console/ReferencePages.jsx", "RolesPage", {}, "Roles &amp; permissions."],
  ["/src/pages/console/ReferencePages.jsx", "DevicesPage", { role: "admin" }, "Device approvals."],
  ["/src/pages/console/ReferencePages.jsx", "SessionsPage", { role: "admin", user }, "Session monitoring."],
  ["/src/pages/console/ReferencePages.jsx", "SessionsPage", { role: "employee", user, history: true }, "Login history."],
  ["/src/pages/console/ReferencePages.jsx", "AuditPage", {}, "Audit logs."],
  ["/src/pages/console/ResourcesPage.jsx", "default", { role: "admin" }, "Protected resources."],
  ["/src/pages/console/ResourcesPage.jsx", "default", { role: "employee" }, "Protected resources."],
  ["/src/pages/console/AccountPages.jsx", "DepartmentPage", { user }, "Engineering"],
  ["/src/pages/console/AccountPages.jsx", "ProfilePage", { user, onUser() {} }, "Profile &amp; credentials."],
  ["/src/pages/console/AccountPages.jsx", "SecurityPage", { user }, "Security posture."],
  ["/src/pages/console/AccountPages.jsx", "SettingsPage", { user }, "Settings."],
];

for (const [source, name, props, expected] of cases) {
  test(`${source.split("/").at(-1)} ${name} ${props.role || props.portal || ""} renders after extraction`, async () => {
    const module = await vite.ssrLoadModule(source);
    assert.equal(typeof module[name], "function");
    const html = renderToString(createElement(MemoryRouter, null, createElement(module[name], props)));
    assert.ok(html.includes(expected), `Expected rendered content: ${expected}`);
  });
}

test("the extracted role guard initially blocks protected content pending authorization", async () => {
  const { default: Guarded } = await vite.ssrLoadModule("/src/auth/Guarded.jsx");
  const html = renderToString(createElement(MemoryRouter, null, createElement(Guarded, { role: "admin", onUser() {} })));
  assert.ok(html.includes("Checking authorization"));
  assert.ok(!html.includes("Good morning."));
});

test("shared tables retain status, MFA, date, and role formatting", async () => {
  const { DataTable } = await vite.ssrLoadModule("/src/components/Shared.jsx");
  const html = renderToString(createElement(DataTable, {
    rows: [{ id: "row", status: "ACTIVE", mfaEnabled: true, createdAt: "2026-01-01T12:00:00Z", allowedRoles: ["ADMIN", "MANAGER"] }],
    columns: [["status", "Status"], ["mfaEnabled", "MFA"], ["createdAt", "Created"], ["allowedRoles", "Roles"]],
  }));
  assert.ok(html.includes('class="status active"'));
  assert.ok(html.includes("Enabled"));
  assert.ok(html.includes("2026"));
  assert.ok(html.includes("ADMIN, MANAGER"));
});

test("lazy routes show a loading state until their module is available", async () => {
  const { default: LazyBoundary } = await vite.ssrLoadModule("/src/components/LazyBoundary.jsx");
  const PendingPage = lazy(() => new Promise(() => {}));
  const html = renderToString(createElement(MemoryRouter, null,
    createElement(LazyBoundary, { label: "Loading test page" }, createElement(PendingPage))));
  assert.ok(html.includes("Loading test page"));
});

test("a failed page module offers reload instead of displaying protected children", async () => {
  const { PageErrorBoundary } = await vite.ssrLoadModule("/src/components/LazyBoundary.jsx");
  const boundary = new PageErrorBoundary({ children: createElement("p", null, "Protected fixture") });
  boundary.state = PageErrorBoundary.getDerivedStateFromError();
  const html = renderToString(boundary.render());
  assert.ok(html.includes("Reload page"));
  assert.ok(!html.includes("Protected fixture"));
});

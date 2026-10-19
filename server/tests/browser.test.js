import "dotenv/config";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import { createServer as createViteServer } from "vite";
import { chromium } from "playwright-core";
import { AuditLog, Department, Device, User } from "../models/index.js";
import { encryptSecret, generateTotp, hashToken, newTotpSecret, randomToken } from "../lib/security.js";

const mongoUri = process.env.MONGODB_URI;
const chromiumExecutable = process.env.REPLIT_PLAYWRIGHT_CHROMIUM_EXECUTABLE;
const skipReason = !mongoUri
  ? "MONGODB_URI is required for isolated browser acceptance tests."
  : !chromiumExecutable
    ? "REPLIT_PLAYWRIGHT_CHROMIUM_EXECUTABLE is required for browser acceptance tests."
    : false;

test("browser sign-in, MFA enrollment, and pending-device approval", {
  skip: skipReason,
  timeout: 180_000,
}, async (t) => {
  process.env.NODE_ENV = "test";
  process.env.COOKIE_SECURE = "false";
  if (!process.env.SESSION_SECRET) process.env.SESSION_SECRET = crypto.randomBytes(40).toString("base64url");

  const databaseName = `zt_browser_${Date.now()}_${crypto.randomBytes(5).toString("hex")}`;
  assert.ok(Buffer.byteLength(databaseName) <= 38, "Atlas test database names must not exceed 38 bytes.");
  let apiServer;
  let viteServer;
  let browser;
  let databaseConnected = false;

  try {
    await mongoose.connect(mongoUri, { dbName: databaseName, serverSelectionTimeoutMS: 10_000 });
    databaseConnected = true;

    const { default: app } = await import("../app.js");
    apiServer = app.listen(0, "127.0.0.1");
    await new Promise((resolve, reject) => {
      apiServer.once("error", reject);
      apiServer.once("listening", resolve);
    });
    const apiOrigin = `http://127.0.0.1:${apiServer.address().port}`;

    const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
    viteServer = await createViteServer({
      configFile: path.join(projectRoot, "vite.config.js"),
      server: {
        host: "127.0.0.1",
        port: 0,
        strictPort: false,
        proxy: { "/api": { target: apiOrigin, changeOrigin: true } },
      },
    });
    await viteServer.listen();
    const appOrigin = `http://127.0.0.1:${viteServer.httpServer.address().port}`;

    const department = await Department.create({ name: `Browser test ${randomToken(4)}` });
    const adminEmail = `admin-${randomToken(8).toLowerCase()}@example.test`;
    const employeeEmail = `employee-${randomToken(8).toLowerCase()}@example.test`;
    const initialAdminPassword = `Test-${randomToken(18)}-8aA`;
    const employeePassword = `Test-${randomToken(18)}-4bB`;
    const changedAdminPassword = `Changed-${randomToken(18)}-6cC`;
    const employeeSecret = newTotpSecret();

    // This disposable fixture exercises first-administrator setup without reading bootstrap credentials.
    const admin = await User.create({
      name: "Browser Test Administrator",
      email: adminEmail,
      role: "ADMIN",
      status: "ACTIVE",
      departmentId: department._id,
      passwordHash: await bcrypt.hash(initialAdminPassword, 4),
      forcePasswordChange: true,
      mfaEnabled: false,
      isBootstrapAdmin: true,
      bootstrapDeviceUsed: false,
    });
    const employee = await User.create({
      name: "Browser Test Employee",
      email: employeeEmail,
      role: "EMPLOYEE",
      status: "ACTIVE",
      departmentId: department._id,
      passwordHash: await bcrypt.hash(employeePassword, 4),
      mfaEnabled: true,
      mfaSecretEncrypted: encryptSecret(employeeSecret),
    });

    browser = await chromium.launch({
      headless: true,
      executablePath: chromiumExecutable,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    const adminContext = await browser.newContext();
    const adminPage = await adminContext.newPage();
    const pageErrors = [];
    adminPage.on("pageerror", (error) => pageErrors.push(error.message));

    await t.test("public portal opens the visible administrator sign-in", async () => {
      await adminPage.goto(appOrigin);
      await adminPage.getByText("Enter the console").waitFor();
      await adminPage.getByRole("link", { name: /Administrator/ }).click();
      await adminPage.getByRole("heading", { name: "Welcome back." }).waitFor();
      assert.match(adminPage.url(), /\/admin\/login$/);
      await adminPage.locator("#email").fill(adminEmail);
      await adminPage.locator("#password").fill(initialAdminPassword);
      await adminPage.getByRole("button", { name: /Continue securely/ }).click();
      await adminPage.getByRole("heading", { name: "Secure your account." }).waitFor();
    });

    await t.test("first-time administrator enrolls MFA and changes the temporary password", async () => {
      await adminPage.getByRole("img", { name: "Authenticator setup QR code" }).waitFor();
      const manualKeyText = await adminPage.getByText(/Manual key:/).textContent();
      const manualKey = manualKeyText?.match(/Manual key:\s*([A-Z2-7]+)/)?.[1];
      assert.ok(manualKey, "MFA enrollment should show the authenticator's manual key");

      await adminPage.locator("#mfa-code").fill(generateTotp(manualKey));
      await adminPage.getByRole("button", { name: "Confirm and continue" }).click();
      await adminPage.getByText(/Save these recovery codes somewhere private/).waitFor();
      const recoveryCodes = await adminPage.locator(".resource-content").innerText();
      assert.equal(recoveryCodes.split("\n").filter(Boolean).length, 8);
      await adminPage.getByLabel("I have saved these recovery codes.").check();
      await adminPage.getByRole("button", { name: "Continue to console" }).click();

      await adminPage.getByRole("heading", { name: "Update your password." }).waitFor();
      await adminPage.locator('input[autocomplete="current-password"]').fill(initialAdminPassword);
      await adminPage.locator('input[autocomplete="new-password"]').fill(changedAdminPassword);
      await adminPage.getByRole("button", { name: "Save new password" }).click();
      await adminPage.getByRole("heading", { name: "Good morning." }).waitFor();

      const savedAdmin = await User.findById(admin._id).lean();
      assert.equal(savedAdmin.forcePasswordChange, false);
      assert.equal(savedAdmin.mfaEnabled, true);
      assert.ok(await Device.exists({ userId: admin._id, status: "APPROVED" }));
    });

    const employeeContext = await browser.newContext();
    const employeePage = await employeeContext.newPage();
    employeePage.on("pageerror", (error) => pageErrors.push(error.message));

    await t.test("employee completes MFA and sees that the new device is pending", async () => {
      await employeePage.goto(`${appOrigin}/employee/login`);
      await employeePage.getByRole("heading", { name: "Welcome back." }).waitFor();
      await employeePage.locator("#email").fill(employeeEmail);
      await employeePage.locator("#password").fill(employeePassword);
      await employeePage.getByRole("button", { name: /Continue securely/ }).click();
      await employeePage.getByRole("heading", { name: "Verify your identity." }).waitFor();
      await employeePage.locator("#challenge-code").fill(generateTotp(employeeSecret));
      await employeePage.getByRole("button", { name: "Verify code" }).click();
      await employeePage.getByRole("heading", { name: "One more boundary." }).waitFor();
      await employeePage.getByText("PENDING", { exact: true }).waitFor();
      assert.equal(await Device.countDocuments({ userId: employee._id, status: "PENDING" }), 1);
    });

    await t.test("administrator approves the employee's device and employee enters the console", async () => {
      await adminPage.getByRole("link", { name: "Device approvals" }).click();
      await adminPage.getByRole("heading", { name: "Device approvals.", exact: true }).waitFor();
      const employeeRow = adminPage.getByRole("row").filter({ hasText: "Browser Test Employee" });

    const otherDepartment = await Department.create({ name: "Browser other department" });
      page.on("pageerror", (error) => pageErrors.push(error.message));
      await page.goto(`${appOrigin}/manager/login`);
      await page.locator("#email").fill(managerEmail);
      await page.locator("#password").fill(employeePassword);
      await page.getByRole("button", { name: /Continue securely/ }).click();
      await page.locator("#challenge-code").fill(generateTotp(employeeSecret));
      await page.getByRole("button", { name: "Verify code" }).click();
      await page.getByRole("heading", { name: "Team access, at a glance." }).waitFor();
      await page.goto(`${appOrigin}/manager/employees`);
      await page.getByLabel("Search identities").fill("Pagination");
      await waitForPage(page, "1–25 of 30 · Page 1 of 2");
      await page.getByRole("button", { name: "Next", exact: true }).click();
      await waitForPage(page, "26–30 of 30 · Page 2 of 2");
      assert.ok(!(await page.locator("tbody").innerText()).includes("foreign identity"));
      await page.getByLabel("Search identities").fill("Pagination foreign");
      await waitForPage(page, "0–0 of 0 · Page 0 of 0");
      await page.getByRole("heading", { name: "No identities match your search" }).waitFor();
      assert.equal(await page.getByLabel("Filter identities by department").count(), 0);
      await page.goto(`${appOrigin}/manager/audit`);
      await page.getByRole("alert").waitFor();
      assert.equal(await page.locator("tbody tr").count(), 0);
      await context.close();
    });

    assert.deepEqual(pageErrors, [], "browser pages should not report uncaught JavaScript errors");
  } finally {
    if (browser) await browser.close();
    if (viteServer) await viteServer.close();
    if (apiServer?.listening) await new Promise((resolve) => apiServer.close(resolve));
    try {
      if (databaseConnected) await mongoose.connection.dropDatabase();
    } finally {
      await mongoose.disconnect();
    }
  }
});

      let finishSlow;

        const response = await route.fetch();

      const credential = randomToken(40);

      const manager = await User.create({
        name: "Browser manager", email: managerEmail, role: "MANAGER", status: "ACTIVE",
        departmentId: department._id, passwordHash: await bcrypt.hash(employeePassword, 4),
        mfaEnabled: true, mfaSecretEncrypted: encryptSecret(employeeSecret),
      });

      const slowFinished = new Promise((resolve) => { finishSlow = resolve; });

    const waitForPage = async (page, text) => {
      await page.getByRole("navigation", { name: "List pagination" }).getByText(text, { exact: true }).waitFor();
    };

      const context = await browser.newContext();

    const pagination = adminPage.getByRole("navigation", { name: "List pagination" });

      const slowRequest = adminPage.waitForRequest((request) => new URL(request.url()).searchParams.get("q") === "Pagination slow");

      const managerEmail = `manager-${randomToken(6).toLowerCase()}@example.test`;

      const page = await context.newPage();

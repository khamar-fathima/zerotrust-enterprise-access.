import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "vite";
import { chromium } from "playwright-core";

const executablePath = process.env.REPLIT_PLAYWRIGHT_CHROMIUM_EXECUTABLE;

test("risk panel uses explicit AI requests, preserves scores on failure, and hides from ordinary admins (mocked API UI test)", {
  skip: !executablePath && "A Chromium executable is required for the risk-panel UI test.",
  timeout: 180_000,
}, async (t) => {
  let vite;
  let browser;
  try {
    vite = await createServer({ configFile: "vite.config.js", server: { host: "127.0.0.1", port: 0, strictPort: false } });
    await vite.listen();
    browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"] });
    const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
    page.setDefaultTimeout(15_000);
    const browserErrors = [];
    page.on("pageerror", (error) => browserErrors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") browserErrors.push(message.text()); });
    page.on("requestfailed", (request) => browserErrors.push(`${request.method()} ${request.url()}: ${request.failure()?.errorText || "failed"}`));
    let bootstrap = true;
    let analysisRequests = 0;
    let failAnalysis = false;
    const factor = { key: "deniedAccess", label: "Denied access attempts", points: 8, detail: "1 denied event in 7 days." };
    const snapshot = {
      generatedAt: "2026-10-19T12:00:00Z", windowDays: 7,
      windowStart: "2026-10-12T12:00:00Z", windowEnd: "2026-10-19T12:00:00Z",
      organization: {
        score: 43, level: "MODERATE", mfaCoveragePercent: 90,
        activeAccountCount: 10, activeSessionCount: 2, highRiskAccountCount: 1,
        factors: [factor],
        trends: [{ key: "denied", label: "Denied access", current: 1, previous: 0, change: 1 }],
      },
      accounts: [{
        id: "test-account", name: "Risk test identity", role: "EMPLOYEE", mfaEnabled: true,
        activeSessionCount: 2, score: 10, level: "LOW", factors: [factor],
      }],
    };
    const analysis = {
      summary: "A test-only advisory summary.", generatedAt: "2026-10-19T12:00:05Z",
      findings: [{ scope: "account", accountRef: "acct-1", priority: "LOW", title: "Review the denial", evidence: "One recorded denied event.", recommendation: "Review the audit record before taking action." }],
      recommendations: ["Review the access denial."], trendSummary: "Denied events rose from zero to one.",
    };
    const riskHistory = {
      days: 30,
      history: [
        { day: "2026-10-18T00:00:00.000Z", organization: { score: 35, factorTotals: [{ key: "deniedAccess", points: 5 }] }, account: { score: 6, factorTotals: [{ key: "failedAuth", points: 2 }] } },
        { day: "2026-10-19T00:00:00.000Z", organization: { score: 43, factorTotals: [{ key: "deniedAccess", points: 8 }] }, account: { score: 10, factorTotals: [{ key: "failedAuth", points: 5 }] } },
      ],
    };
    await page.route("**/api/**", async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      let status = 200;
      let body = {};
      if (pathname === "/api/auth/me") {
        body = { user: { id: "ui-test-admin", name: "Test reviewer", role: "ADMIN", status: "ACTIVE", mfaEnabled: true, isBootstrapAdmin: bootstrap } };
      } else if (pathname === "/api/dashboard/summary") {
        body = { metrics: {}, recentActivity: [], roleDistribution: [] };
      } else if (pathname === "/api/dashboard/activity") {
        body = { activity: [] };
      } else if (pathname === "/api/dashboard/risk-analysis") {
        if (route.request().method() === "POST") {
          analysisRequests += 1;
          status = failAnalysis ? 503 : 200;
          body = failAnalysis ? { code: "AI_NOT_CONFIGURED", error: "AI is not enabled." } : { snapshot, analysis };
        } else body = { snapshot };
      } else if (pathname === "/api/dashboard/risk-analysis/history") {
        body = riskHistory;
      } else if (pathname === "/api/dashboard/risk-analysis/accounts") {
        body = { accounts: [{ id: "backup-account", name: "Backup identity", role: "MANAGER", status: "ACTIVE" }] };
      } else if (pathname === "/api/dashboard/risk-analysis/evidence") {
        body = { events: [{ eventType: "PORTAL_ROLE_MISMATCH", status: "CRITICAL", userName: "Risk test identity", description: "A recorded access denial.", createdAt: "2026-10-19T12:00:00Z" }] };
      }
      await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    });
    await page.goto(`http://127.0.0.1:${vite.httpServer.address().port}/admin/dashboard`, { timeout: 60_000 });
    t.diagnostic("Dashboard navigation completed.");
    try {
      await page.getByRole("heading", { name: "Identity risk review" }).waitFor();
    } catch (error) {
      t.diagnostic(`Rendered page text: ${(await page.locator("body").innerText()).slice(0, 1800)}`);
      t.diagnostic(`Browser errors: ${browserErrors.join(" | ") || "none"}`);
      throw error;
    }
    await page.locator(".risk-score__inner strong").waitFor();
    assert.equal(await page.locator(".risk-score__inner strong").innerText(), "43");
    t.diagnostic("Risk snapshot rendered.");
    await page.getByRole("heading", { name: "Risk score history" }).waitFor();
    await page.locator(".risk-history__days button").last().click();
    assert.match(await page.locator(".risk-history__detail").innerText(), /43\/100/);
    await page.getByLabel("History scope").selectOption("test-account");
    await page.locator(".risk-history__detail").getByText("10/100").waitFor();
    await page.getByLabel("Search risk history accounts").fill("Backup");
    await page.locator('option[value="backup-account"]').waitFor({ state: "attached" });
    await page.getByLabel("History scope").selectOption("backup-account");
    await page.locator(".risk-history__detail").getByText("10/100").waitFor();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    assert.match((await downloadPromise).suggestedFilename(), /risk-history-account-30d\.csv/);
    assert.equal(analysisRequests, 0, "Loading the dashboard must not send signals to AI.");
    await page.locator(".risk-account summary").click();
    assert.match(await page.locator(".risk-account-reasons").innerText(), /2 active verified session/);
    await page.getByRole("button", { name: "Generate AI advice", exact: true }).click();
    await page.getByText(analysis.summary, { exact: true }).waitFor();
    t.diagnostic("Explicit AI request rendered its report.");
    assert.equal(analysisRequests, 1);
    assert.match(await page.locator(".risk-finding__top").innerText(), /Risk test identity/);
    await page.getByRole("button", { name: "View audit evidence" }).click();
    await page.getByText("A recorded access denial.", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Refresh risk scores" }).click();
    await page.waitForFunction(() => !document.body.textContent.includes("A test-only advisory summary."));
    assert.equal(analysisRequests, 1, "Refreshing scores must not regenerate AI advice.");
    failAnalysis = true;
    await page.getByRole("button", { name: "Generate AI advice", exact: true }).click();
    await page.getByText("AI advice is not configured for this environment.", { exact: false }).waitFor();
    assert.equal(await page.locator(".risk-score__inner strong").innerText(), "43");
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), true);
    bootstrap = false;
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Good morning." }).waitFor();
    assert.equal(await page.locator(".risk-analysis-panel").count(), 0);
  } finally {
    await browser?.close();
    await vite?.close();
  }
});

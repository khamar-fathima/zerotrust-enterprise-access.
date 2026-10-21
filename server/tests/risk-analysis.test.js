import test from "node:test";
import assert from "node:assert/strict";
import {
  buildRedactedRiskInput,
  calculateAccountRisk,
  calculateOrganizationRisk,
  classifyRiskEvent,
  buildRiskHistoryRecord,
  RISK_HISTORY_RETENTION_DAYS,
  riskLevel,
} from "../services/riskAnalysis.js";
import { generateRiskAnalysis, RiskAnalysisSchema } from "../services/aiRiskAnalysis.js";
import { canViewRiskAnalysis } from "../routes/dashboard.js";

test("risk analysis is restricted to an administrator with the bootstrap flag", () => {
  assert.equal(canViewRiskAnalysis({ role: "ADMIN", isBootstrapAdmin: true }), true);
  for (const user of [
    null,
    { role: "ADMIN" },
    { role: "ADMIN", isBootstrapAdmin: false },
    { role: "ADMIN", isBootstrapAdmin: "true" },
    { role: "MANAGER", isBootstrapAdmin: true },
    { role: "EMPLOYEE", isBootstrapAdmin: true },
  ]) assert.equal(canViewRiskAnalysis(user), false);
});

test("risk bands have explicit boundaries and no-data is not a zero-risk result", () => {
  for (const [score, level] of [[null, "NO_DATA"], [0, "LOW"], [24, "LOW"], [25, "MODERATE"], [49, "MODERATE"], [50, "HIGH"], [74, "HIGH"], [75, "CRITICAL"], [100, "CRITICAL"]]) {
    assert.equal(riskLevel(score), level);
  }
});

test("denied and failed events are not counted twice as other critical events", () => {
  assert.equal(classifyRiskEvent("PORTAL_ROLE_MISMATCH", "CRITICAL"), "denied");
  assert.equal(classifyRiskEvent("RISK_ANALYSIS_ACCESS_DENIED", "CRITICAL"), "denied");
  assert.equal(classifyRiskEvent("LOGIN_FAILED", "CRITICAL"), "failed");
  assert.equal(classifyRiskEvent("OTHER_SECURITY_INCIDENT", "CRITICAL"), "critical");
  assert.equal(classifyRiskEvent("LOGIN_SUCCESS", "SUCCESS"), null);
  assert.equal(classifyRiskEvent("RISK_ANALYSIS_GENERATED", "SUCCESS"), null);
});

test("account scores are deterministic, explainable, and capped", () => {
  const low = calculateAccountRisk({ role: "EMPLOYEE", mfaEnabled: true });
  assert.equal(low.score, 0);
  const admin = calculateAccountRisk({ role: "ADMIN", mfaEnabled: false }, { failed: 3, denied: 2, critical: 1 }, 1);
  assert.equal(admin.score, 100);
  assert.equal(admin.factors.find((item) => item.key === "failedAuth").points, 15);
  assert.equal(admin.factors.find((item) => item.key === "privilege").points, 15);
  const extreme = calculateAccountRisk({ role: "ADMIN", mfaEnabled: false }, { failed: 1000, denied: 1000, critical: 1000 }, 1000);
  assert.equal(extreme.score, 100);
  assert.equal(extreme.factors.find((item) => item.key === "failedAuth").points, 20);
  assert.equal(extreme.factors.find((item) => item.key === "criticalEvents").points, 25);
});

test("organization score uses the approved weighted factors and handles no active identities", () => {
  const empty = calculateOrganizationRisk({ activeUsers: [] });
  assert.equal(empty.score, null);
  assert.equal(empty.level, "NO_DATA");
  const result = calculateOrganizationRisk({
    activeUsers: [{ mfaEnabled: true }, { mfaEnabled: true }, { mfaEnabled: true }, { mfaEnabled: false }],
    activity: { failed: 6, denied: 1, critical: 2 },
    stalePendingDevices: 3,
  });
  assert.equal(result.mfaCoveragePercent, 75);
  assert.equal(result.score, 56);
  assert.equal(result.factors.reduce((sum, item) => sum + item.points, 0), result.score);
  const maximum = calculateOrganizationRisk({
    activeUsers: [{ mfaEnabled: false }],
    activity: { failed: 100, denied: 100, critical: 100 },
    stalePendingDevices: 100,
  });
  assert.equal(maximum.score, 100);
});

test("daily risk history stores only numeric scores and factor totals for bounded retention", () => {
  const now = new Date("2026-10-21T15:30:00.000Z");
  const snapshot = {
    organization: {
      score: 21,
      factors: [{ key: "mfaCoverage", points: 10, label: "MFA coverage gap", detail: "Private narrative." }],
    },
  };
  const record = buildRiskHistoryRecord(snapshot, [{
    id: "68f7a011d2a0c80000000001",
    name: "Private Name",
    email: "private@example.test",
    score: 12,
    factors: [{ key: "failedAuth", points: 5, label: "Failed sign-ins", detail: "Private account detail." }],
    analysis: { summary: "Do not persist AI advice." },
  }], now);
  assert.equal(record.day.toISOString(), "2026-10-21T00:00:00.000Z");
  assert.equal(record.expiresAt.getTime() - record.day.getTime(), RISK_HISTORY_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  assert.deepEqual(record.organization, { score: 21, factorTotals: [{ key: "mfaCoverage", points: 10 }] });
  assert.deepEqual(record.accounts, [{
    userId: "68f7a011d2a0c80000000001",
    score: 12,
    factorTotals: [{ key: "failedAuth", points: 5 }],
  }]);
  const serialized = JSON.stringify(record);
  for (const privateValue of ["Private Name", "private@example.test", "Private narrative", "Private account detail", "Do not persist AI advice"]) {
    assert.equal(serialized.includes(privateValue), false);
  }
});

function snapshotFixture() {
  return {
    generatedAt: "2026-10-19T00:00:00.000Z",
    windowDays: 7,
    organization: {
      score: 8, level: "LOW", activeAccountCount: 1, activeSessionCount: 2,
      mfaCoveragePercent: 100, highRiskAccountCount: 0,
      factors: [{ key: "deniedAccess", label: "Denied access", points: 8, detail: "1 denied event." }],
      trends: [{ key: "denied", label: "Denied access", current: 1, previous: 0, change: 1 }],
    },
    accounts: [{
      id: "private-database-id", name: "Private Identity", email: "private@example.test",
      ipAddress: "192.0.2.123", role: "EMPLOYEE", mfaEnabled: true,
      activeSessionCount: 2, score: 10, level: "LOW",
      factors: [{ key: "deniedAccess", label: "Denied access", points: 10, detail: "1 denied event." }],
    }],
    rawAuditDescription: "Untrusted raw text that must not be sent",
  };
}

test("AI input only contains summarized facts and ephemeral account references", () => {
  const { data, refs } = buildRedactedRiskInput(snapshotFixture());
  const serialized = JSON.stringify(data);
  for (const privateValue of ["Private Identity", "private@example.test", "private-database-id", "192.0.2.123", "Untrusted raw text"]) {
    assert.equal(serialized.includes(privateValue), false);
  }
  assert.equal(data.accounts[0].accountRef, "acct-1");
  assert.equal(data.accounts[0].activeSessionCount, 2);
  assert.equal(refs.get("acct-1").name, "Private Identity");
});

test("AI generation sends redacted input and rejects unsupported account references", async () => {
  let sent;
  const client = { chat: { completions: { async create(request) {
    sent = request;
    return { choices: [{ message: { content: JSON.stringify({
      summary: "One denied event requires review; there is not enough evidence to infer compromise.",
      findings: [
        { scope: "account", accountRef: "acct-1", priority: "LOW", title: "Review denial", evidence: "One denied event.", recommendation: "Review the linked audit events." },
        { scope: "account", accountRef: "acct-999", priority: "HIGH", title: "Unknown account", evidence: "Unsupported.", recommendation: "Unsupported." },
      ],
      recommendations: ["Review the recorded denial before taking action."],
      trendSummary: "Denied events increased from zero to one.",
    }) } }] };
  } } } };
  const analysis = await generateRiskAnalysis(snapshotFixture(), { client });
  assert.equal(analysis.findings.length, 1);
  assert.equal(analysis.findings[0].accountRef, "acct-1");
  assert.equal(sent.response_format.type, "json_object");
  assert.equal(sent.messages[1].content.includes("Private Identity"), false);
  assert.equal(sent.messages[1].content.includes("private@example.test"), false);
});

test("AI reports must satisfy the bounded response schema", () => {
  assert.equal(RiskAnalysisSchema.safeParse({ summary: "incomplete" }).success, false);
  assert.equal(RiskAnalysisSchema.safeParse({
    summary: "x".repeat(601), findings: [], recommendations: [], trendSummary: "No trend.",
  }).success, false);
});

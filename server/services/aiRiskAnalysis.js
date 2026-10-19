import OpenAI from "openai";
import { z } from "zod";
import { buildRedactedRiskInput } from "./riskAnalysis.js";

const FindingSchema = z.object({
  scope: z.enum(["organization", "account"]),
  accountRef: z.string().nullable(),
  priority: z.enum(["LOW", "MODERATE", "HIGH", "CRITICAL"]),
  title: z.string().trim().min(1).max(100),
  evidence: z.string().trim().min(1).max(260),
  recommendation: z.string().trim().min(1).max(260),
});

export const RiskAnalysisSchema = z.object({
  summary: z.string().trim().min(1).max(600),
  findings: z.array(FindingSchema).min(1).max(5),
  recommendations: z.array(z.string().trim().min(1).max(240)).max(3),
  trendSummary: z.string().trim().min(1).max(350),
});

export class AiProviderUnavailableError extends Error {
  constructor() {
    super("The managed AI provider is not configured.");
    this.name = "AiProviderUnavailableError";
  }
}

export class AiInvalidResponseError extends Error {
  constructor() {
    super("The AI provider returned an invalid risk analysis.");
    this.name = "AiInvalidResponseError";
  }
}

function makeOpenAIClient() {
  const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
  const baseURL = process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || process.env.OPENAI_BASE_URL;
  if (!apiKey) throw new AiProviderUnavailableError();
  return new OpenAI({ apiKey, ...(baseURL ? { baseURL } : {}), timeout: 20_000, maxRetries: 0 });
}

function safeFindings(analysis, validRefs) {
  const findings = analysis.findings.filter((finding) =>
    finding.scope === "organization"
      ? finding.accountRef === null || finding.accountRef === "organization"
      : validRefs.has(finding.accountRef));
  if (!findings.length) throw new AiInvalidResponseError();
  return { ...analysis, findings };
}

export async function generateRiskAnalysis(snapshot, { client = null } = {}) {
  const { data, refs } = buildRedactedRiskInput(snapshot);
  const openai = client || makeOpenAIClient();
  const response = await openai.chat.completions.create({
    model: process.env.OPENAI_RISK_MODEL || "gpt-4.1-mini",
    temperature: 0.2,
    max_completion_tokens: 1500,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content: [
          "You are a security risk analyst. Analyze only the structured facts in the user message.",
          "The deterministic scores are authoritative; do not recalculate, change, or dispute the numeric scores.",
          "Do not infer compromise, intent, identity, or causes not present in the facts.",
          "Active session counts provide context only and are not themselves evidence of suspicious activity.",
          "Give concise, evidence-linked findings and reversible, human-reviewed recommendations.",
          "Never recommend weakening RBAC, disabling MFA, automatically approving unknown devices, or sharing credentials.",
          "Use only accountRef values present in the input. Never request personal data or secrets.",
          "Return one JSON object with keys: summary, findings, recommendations, trendSummary.",
          "Each finding must contain scope (organization or account), accountRef (null or organization for organization scope; valid acct-N for account scope), priority (LOW, MODERATE, HIGH, CRITICAL), title, evidence, recommendation.",
          "Include 1 to 5 findings and no more than 3 recommendations. If activity is sparse, say that confidence is limited.",
        ].join(" "),
      },
      { role: "user", content: JSON.stringify(data) },
    ],
  });
  const raw = response.choices?.[0]?.message?.content;
  if (typeof raw !== "string" || raw.length > 10_000) throw new AiInvalidResponseError();
  let analysis;
  try {
    analysis = RiskAnalysisSchema.parse(JSON.parse(raw));
  } catch {
    throw new AiInvalidResponseError();
  }
  return { ...safeFindings(analysis, new Set(refs.keys())), generatedAt: new Date().toISOString() };
}

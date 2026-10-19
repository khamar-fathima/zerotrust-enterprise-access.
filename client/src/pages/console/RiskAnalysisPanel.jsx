import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, ArrowDownRight, ArrowRight, ArrowUpRight, Bot, Check, CircleHelp,
  Clock3, Fingerprint, RefreshCw, ShieldAlert, ShieldCheck, Sparkles, Users,
} from "lucide-react";
import { api } from "../../lib/api.js";
import { errorMessage } from "../../lib/identity.js";
import { EmptyState, Notice, Panel } from "../../components/Shared.jsx";
import "./RiskAnalysisPanel.css";

const LEVELS = ["LOW", "MODERATE", "HIGH", "CRITICAL", "NO_DATA"];

function readableDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function readableTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function levelName(level) {
  return LEVELS.includes(level) ? level.replace("_", " ") : "NO DATA";
}

function RiskPill({ level, children }) {
  const safeLevel = LEVELS.includes(level) ? level.toLowerCase() : "no-data";
  return <span className={`risk-pill risk-pill--${safeLevel}`}>{children || levelName(level)}</span>;
}

function ScoreDisplay({ score, level }) {
  const numeric = score !== null && score !== undefined && score !== "" && Number.isFinite(Number(score))
    ? Math.max(0, Math.min(100, Number(score))) : null;
  return <div className={`risk-score risk-score--${(level || "no-data").toLowerCase()}`}>
    <div className="risk-score__inner">
      <strong>{numeric === null ? "—" : numeric}</strong>
      <span>of 100</span>
    </div>
  </div>;
}

function Factors({ factors, compact = false }) {
  const rows = Array.isArray(factors) ? factors : [];
  if (!rows.length) return <p className="risk-muted">No contributing factors were returned.</p>;
  return <ul className={`risk-factors${compact ? " risk-factors--compact" : ""}`}>
    {rows.map((factor, index) => <li key={`${factor.key || factor.label || "factor"}-${index}`}>
      <span className="risk-factor-mark" aria-hidden="true" />
      <span className="risk-factor-copy"><strong>{factor.label || factor.key || "Risk factor"}</strong>{factor.detail && <small>{factor.detail}</small>}</span>
      <span className="risk-points">{Number(factor.points) > 0 ? "+" : ""}{Number(factor.points) || 0}</span>
    </li>)}
  </ul>;
}

function TrendValue({ trend }) {
  const change = Number(trend.change);
  const direction = change > 0 ? "up" : change < 0 ? "down" : "flat";
  const Icon = direction === "up" ? ArrowUpRight : direction === "down" ? ArrowDownRight : ArrowRight;
  return <div className={`risk-trend risk-trend--${direction}`}>
    <div className="risk-trend__label">{trend.label || trend.key}</div>
    <div className="risk-trend__values"><strong>{trend.current ?? "—"}</strong><span>now</span></div>
    <div className={`risk-trend__change risk-trend__change--${direction}`}><Icon size={13} />{change > 0 ? "+" : ""}{Number.isFinite(change) ? change : "—"}</div>
    <div className="risk-trend__prior">was {trend.previous ?? "—"}</div>
  </div>;
}

function accountFindingName(accountRef, accounts) {
  const match = /^acct-(\d+)$/i.exec(String(accountRef || ""));
  if (!match) return null;
  return accounts[Number(match[1]) - 1]?.name || null;
}

function AnalysisContent({ analysis, accounts }) {
  const findings = Array.isArray(analysis?.findings) ? analysis.findings : [];
  const recommendations = Array.isArray(analysis?.recommendations) ? analysis.recommendations : [];
  return <div className="risk-advice-content">
    {analysis?.summary && <p className="risk-analysis-summary">{analysis.summary}</p>}
    {analysis?.trendSummary && <div className="risk-trend-summary"><span className="risk-mini-label">TREND READ</span><p>{analysis.trendSummary}</p></div>}
    {findings.length > 0 && <div className="risk-findings">
      <h4>Signals to review <span>{findings.length}</span></h4>
      {findings.map((finding, index) => {
        const accountName = finding.scope === "account" ? accountFindingName(finding.accountRef, accounts) : null;
        return <article className="risk-finding" key={`${finding.accountRef || finding.scope}-${index}`}>
          <div className="risk-finding__top"><RiskPill level={finding.priority} /><span>{finding.scope === "organization" ? "Organization" : accountName || "Individual account"}</span></div>
          <h5>{finding.title}</h5>
          {finding.evidence && <p>{finding.evidence}</p>}
          {finding.recommendation && <div className="risk-finding__action"><ArrowRight size={13} />{finding.recommendation}</div>}
        </article>;
      })}
    </div>}
    {recommendations.length > 0 && <div className="risk-recommendations">
      <h4>Suggested human checks</h4>
      <ul>{recommendations.map((item, index) => <li key={`${index}-${item}`}><Check size={14} />{item}</li>)}</ul>
    </div>}
    {!analysis?.summary && !analysis?.trendSummary && !findings.length && !recommendations.length && <p className="risk-muted">No advisory findings were returned. The deterministic score and its factors remain available above.</p>}
  </div>;
}

export default function RiskAnalysisPanel() {
  const [snapshot, setSnapshot] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scoreError, setScoreError] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [analysisPending, setAnalysisPending] = useState(false);
  const [analysisError, setAnalysisError] = useState("");
  const [analysisReady, setAnalysisReady] = useState(false);

  const loadSnapshot = useCallback(async () => {
    setLoading(true);
    setScoreError("");
    setAnalysis(null);
    setAnalysisReady(false);
    setAnalysisError("");
    try {
      const response = await api.dashboard.riskAnalysis();
      setSnapshot(response?.snapshot || null);
    } catch (error) {
      setScoreError(errorMessage(error, "Risk scores could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadSnapshot(); }, [loadSnapshot]);

  const generateAdvice = async () => {
    setAnalysisPending(true);
    setAnalysisError("");
    setAnalysis(null);
    setAnalysisReady(false);
    try {
      const response = await api.dashboard.generateRiskAnalysis();
      if (response?.snapshot) setSnapshot(response.snapshot);
      setAnalysis(response?.analysis || null);
      setAnalysisReady(true);
    } catch (error) {
      const code = error?.response?.data?.code;
      const message = errorMessage(error, "Advisory analysis is temporarily unavailable.");
      setAnalysisError(code === "AI_NOT_CONFIGURED"
        ? "AI advice is not configured for this environment. Your deterministic scores and reasons are still available."
        : message);
    } finally {
      setAnalysisPending(false);
    }
  };

  const accounts = Array.isArray(snapshot?.accounts) ? snapshot.accounts : [];
  const organization = snapshot?.organization;
  const trends = Array.isArray(organization?.trends) ? organization.trends : [];
  const activeCount = Number(organization?.activeAccountCount) || 0;
  const cannotAnalyze = loading || analysisPending || !snapshot || Boolean(scoreError) || organization?.score == null;

  return <div className="risk-analysis-panel">
    <Panel
      title="Identity risk review"
      note="Deterministic risk scores · organization and individual accounts"
      className="risk-panel"
      action={<div className="risk-panel-actions">
        <button className="btn btn-outline risk-refresh" onClick={loadSnapshot} disabled={loading || analysisPending} aria-label="Refresh risk scores">
          <RefreshCw size={14} className={loading ? "risk-spin" : ""} /> <span>{loading ? "Refreshing" : "Refresh"}</span>
        </button>
        <button className="btn btn-primary risk-advice-button" onClick={generateAdvice} disabled={cannotAnalyze}>
          <Sparkles size={14} />{analysisPending ? "Preparing advice" : "Generate AI advice"}
        </button>
      </div>}
    >
      <div className="risk-integrity-note"><ShieldCheck size={15} /><span>AI can suggest what to review. It cannot change scores, accounts or access.</span></div>
      {scoreError && <div className="risk-message"><Notice type="error">{scoreError}</Notice><button className="btn btn-outline" onClick={loadSnapshot} disabled={loading}><RefreshCw size={13} />Retry</button></div>}
      {loading && !snapshot ? <div className="risk-loading" aria-label="Loading risk data"><div className="risk-overview-skeleton"><div className="skeleton" /><div><div className="skeleton" /><div className="skeleton" /></div></div><div className="risk-list-skeleton">{[0, 1, 2].map((item) => <div className="skeleton" key={item} />)}</div></div>
        : !snapshot ? !scoreError && <EmptyState title="Risk snapshot unavailable" detail="Refresh to try loading organization and account risk scores." icon={ShieldAlert} />
        : <>
          <div className="risk-snapshot-meta"><span><Clock3 size={13} />Last calculated {readableTime(snapshot.generatedAt)}</span><span>{snapshot.windowDays || 7}-day window · {readableDate(snapshot.windowStart)}—{readableDate(snapshot.windowEnd)}</span></div>
          <section className="risk-overview" aria-label="Organization risk overview">
            <div className="risk-overview__score"><ScoreDisplay score={organization?.score} level={organization?.level} /><div><RiskPill level={organization?.level} /><div className="risk-overview__caption">Organization risk</div></div></div>
            <div className="risk-overview__metrics">
              <div><span>MFA coverage</span><strong>{organization?.mfaCoveragePercent == null ? "—" : `${organization.mfaCoveragePercent}%`}</strong></div>
              <div><span>Active identities</span><strong>{organization?.activeAccountCount ?? "—"}</strong></div>
              <div><span>High risk</span><strong className="risk-metric-alert">{organization?.highRiskAccountCount ?? "—"}</strong></div>
            </div>
          </section>
          <div className="risk-details-grid">
            <section className="risk-detail-block">
              <div className="risk-section-heading"><div><span className="risk-mini-label">WHY THIS SCORE</span><h3>Organization factors</h3></div><CircleHelp size={16} /></div>
              <Factors factors={organization?.factors} />
            </section>
            <section className="risk-detail-block">
              <div className="risk-section-heading"><div><span className="risk-mini-label">LAST {snapshot.windowDays || 7} DAYS</span><h3>Risk signals over time</h3></div><ArrowRight size={16} /></div>
              {trends.length ? <div className="risk-trends">{trends.map((trend, index) => <TrendValue key={trend.key || index} trend={trend} />)}</div> : <p className="risk-muted">No trend data was returned for this window.</p>}
            </section>
          </div>
          <section className="risk-accounts">
            <div className="risk-section-heading risk-accounts-heading"><div><span className="risk-mini-label">ACCOUNT REVIEW</span><h3>Highest-scoring identities</h3><p>Scores are deterministic; open a row to inspect the contributing reasons.</p></div><span className="risk-count"><Users size={13} />{accounts.length} shown</span></div>
            {activeCount === 0 ? <EmptyState title="No active identities to assess" detail="The current organization snapshot has no active accounts." icon={Fingerprint} />
              : accounts.length === 0 ? <EmptyState title="No account risk details" detail="Active identities exist, but no individual account scores were returned." icon={CircleHelp} />
                : <div className="risk-account-list">{accounts.map((account, index) => <details className="risk-account" key={account.id || index}>
                  <summary>
                    <span className="risk-account-rank">{String(index + 1).padStart(2, "0")}</span>
                    <span className="risk-account-identity"><strong>{account.name || "Unnamed identity"}</strong><small>{account.role || "Role not specified"} · MFA {account.mfaEnabled ? "enabled" : "not enabled"}</small></span>
                    <span className="risk-account-score">{account.score ?? "—"}<small>/100</small></span>
                    <RiskPill level={account.level} />
                    <span className="risk-account-toggle" aria-hidden="true"><ArrowRight size={15} /></span>
                  </summary>
                  <div className="risk-account-reasons"><div className="risk-mini-label">CONTRIBUTING REASONS</div><p className="risk-muted">{account.activeSessionCount || 0} active verified session(s), shown as context only. Factor contributions are added and capped at 100.</p><Factors factors={account.factors} compact /></div>
                </details>)}</div>}
          </section>
          <section className="risk-advice">
            <div className="risk-advice__header"><div className="risk-advice__icon"><Bot size={17} /></div><div><span className="risk-mini-label">OPTIONAL · HUMAN REVIEW ONLY</span><h3>AI advisory</h3></div>
              {analysisReady && <span className="risk-advisory-status"><Check size={12} />Generated {readableTime(analysis?.generatedAt)}</span>}
            </div>
            <p className="risk-advice__boundary"><AlertTriangle size={14} />Advisory uses redacted aggregate and pseudonymous signals—not names, emails, IP addresses or raw audit descriptions. Analysis is not stored; generation is audited.</p>
            {analysisError && <div className="risk-analysis-error"><Notice type="info">{analysisError}</Notice></div>}
            {analysisPending ? <div className="risk-analysis-pending" aria-live="polite"><div className="skeleton" /><div className="skeleton" /><span>Reviewing the current risk snapshot…</span></div>
              : analysisReady ? <AnalysisContent analysis={analysis} accounts={accounts} />
                : !analysisError && <div className="risk-analysis-prompt"><span>{organization?.score == null ? "Active identities are required before generating advice." : "Scores are ready. Generate advice only when a human reviewer requests it."}</span><button className="btn btn-quiet" onClick={generateAdvice} disabled={cannotAnalyze}><Sparkles size={13} />Generate advice</button></div>}
          </section>
          {organization?.level === "NO_DATA" && <div className="risk-no-data"><ShieldAlert size={14} />Risk score has no sufficient signal yet; review contributing factors and account coverage.</div>}
        </>}
    </Panel>
  </div>;
}

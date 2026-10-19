import { useCallback, useEffect, useState } from "react";
import { Activity, RefreshCw, Users, Zap } from "lucide-react";
import {
  CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "../../lib/api.js";
import { errorMessage, prettyDate, safeArray } from "../../lib/identity.js";
import { EmptyState, LoadingRows, Notice, PageHeading, Panel } from "../../components/Shared.jsx";

function ActivityChart({ rows }) {
  const chartRows = rows.map((r) => ({ ...r, date: r.date ? new Date(r.date).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "" }));
  return <div className="chart-area" style={{ padding: "16px 14px 8px" }}><ResponsiveContainer width="100%" height="100%">
    <LineChart data={chartRows} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
      <CartesianGrid stroke="#e5ebe4" vertical={false} />
      <XAxis dataKey="date" tick={{ fill: "#71807a", fontSize: 10 }} axisLine={{ stroke: "#d7dfd7" }} tickLine={false} />
      <YAxis allowDecimals={false} tick={{ fill: "#71807a", fontSize: 10 }} axisLine={false} tickLine={false} />
      <Tooltip contentStyle={{ border: "1px solid #d7dfd7", borderRadius: 6, background: "#fbfcf8", fontSize: 11 }} />
      <Legend wrapperStyle={{ fontSize: 10, color: "#53655c" }} />
      <Line type="monotone" dataKey="logins" name="Logins" stroke="#44986D" strokeWidth={2.2} dot={false} />
      <Line type="monotone" dataKey="alerts" name="Alerts" stroke="#E98E2E" strokeWidth={2} dot={false} />
      <Line type="monotone" dataKey="denied" name="Denied" stroke="#61A9BD" strokeWidth={2} dot={false} />
    </LineChart>
  </ResponsiveContainer></div>;
}

function RoleDistributionChart({ rows }) {
  const colors = ["#61A9BD", "#44986D", "#E98E2E", "#DD83C9", "#979797"];
  const chartRows = rows.map((item) => ({ name: String(item.role || "").toUpperCase(), value: Number(item.count) || 0 })).filter((item) => item.name && Number.isFinite(item.value));
  if (!chartRows.length) return <EmptyState title="No role distribution" detail="No role counts were returned by the service." icon={Users} />;
  return <div className="chart-area" style={{ display: "flex", alignItems: "center", gap: 5, padding: "8px 18px" }}><ResponsiveContainer width="58%" height="100%"><PieChart><Pie data={chartRows} dataKey="value" nameKey="name" innerRadius="57%" outerRadius="82%" paddingAngle={2}>{chartRows.map((item, index) => <Cell key={item.name} fill={colors[index % colors.length]} />)}</Pie><Tooltip contentStyle={{ border: "1px solid #d7dfd7", borderRadius: 6, background: "#fbfcf8", fontSize: 11 }} /></PieChart></ResponsiveContainer><div style={{ display: "grid", gap: 11, flex: 1 }}>{chartRows.map((item, index) => <div key={item.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11 }}><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: colors[index % colors.length] }} />{item.name}</span><strong>{item.value}</strong></div>)}</div></div>;
}

export default function DashboardPage({ role }) {
  const [data, setData] = useState(null);
  const [activityData, setActivityData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [summary, activityResponse] = await Promise.all([api.dashboard.summary(), api.dashboard.activity("7d")]);
      setData(summary); setActivityData(safeArray(activityResponse));
    } catch (err) { setError(errorMessage(err, "Dashboard data could not be loaded.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  const metrics = data?.metrics || {};
  const cards = role === "admin" ? [
    ["Total identities", metrics.totalUsers, "Across the institution"],
    ["Active identities", metrics.activeUsers, "Enabled accounts"],
    ["Active sessions", metrics.activeSessions, "Currently authorized"],
    ["Devices to review", metrics.pendingDevices, "Awaiting approval"],
    ["Failed logins", metrics.failedLoginAttempts, "Reported authentication failures"],
    ["Critical events", metrics.criticalEvents, "Events requiring attention"],
  ] : role === "manager" ? [
    ["Department employees", metrics.employees, "People within your scope"],
    ["Protected resources", metrics.resources, "Department access"],
    ["Active sessions", metrics.activeSessions, "Currently authorized"],
  ] : [
    ["Accessible resources", metrics.resources, "Assigned to your identity"],
    ["Active sessions", metrics.activeSessions, "Currently authorized"],
  ];
  const recentActivity = safeArray(data?.recentActivity);
  const roleDistribution = safeArray(data?.roleDistribution);
  return <main className="content">
    <PageHeading kicker="Access posture / live" title={role === "admin" ? "Good morning." : role === "manager" ? "Team access, at a glance." : "Your access, in focus."} description="A measured view of identity, device and resource activity." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice>
    <div className="metric-grid">{cards.map(([label, value, foot]) => <div className="panel metric-card" key={label}><div className="metric-label">{label}</div>{loading ? <div className="skeleton" style={{ height: 30, width: 82, marginTop: 16 }} /> : <><div className="metric-value">{value ?? "—"}</div><div className="metric-foot">{foot}</div></>}</div>)}</div>
    <div className="dashboard-grid">
      <Panel title="Login & security events" note="Daily logins, alerts and denied access · last 7 days" action={<span className="mono">7D</span>}>
        {loading ? <div className="chart-area skeleton" /> : activityData.length ? <ActivityChart rows={activityData} /> : <EmptyState title="No activity to chart" detail="The service returned no login or security activity for this period." icon={Activity} />}
      </Panel>
      {role === "admin" ? <Panel title="Role distribution" note="Identity count by assigned role">
        {loading ? <div className="chart-area skeleton" /> : roleDistribution.length ? <RoleDistributionChart rows={roleDistribution} /> : <EmptyState title="No role distribution" detail="No role counts were returned by the service." icon={Users} />}
      </Panel> : <Panel title="Recent security activity" note="Latest identity and access events">
        {loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : recentActivity.length ? <div className="activity-list">{recentActivity.slice(0, 6).map((item, i) => <div className="activity-row" key={item.id || i}><span className="activity-dot" /><div><div className="activity-title">{item.description || item.eventType || "Access event"}</div><div className="activity-meta">{item.userName || "Identity service"} · {prettyDate(item.createdAt)}</div></div></div>)}</div> : <EmptyState title="No recent security activity" detail="The service returned no recent events." icon={Zap} />}
      </Panel>}
    </div>
    {role === "admin" && <div style={{ marginTop: 17 }}><Panel title="Recent security activity" note="Latest audit events across the institution">
      {loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : recentActivity.length ? <div className="activity-list">{recentActivity.slice(0, 8).map((item, i) => <div className="activity-row" key={item.id || i}><span className="activity-dot" /><div><div className="activity-title">{item.description || item.eventType || "Access event"}</div><div className="activity-meta">{item.userName || "Identity service"} · {prettyDate(item.createdAt)} · {item.status || "Recorded"}</div></div></div>)}</div> : <EmptyState title="No recent security activity" detail="The service returned no recent audit events." icon={Zap} />}
    </Panel></div>}
  </main>;
}

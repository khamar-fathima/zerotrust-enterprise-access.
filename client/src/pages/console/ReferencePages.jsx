import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Building2, Eye, FileKey2, LogOut, RefreshCw, Users, X } from "lucide-react";
import { api } from "../../lib/api.js";
import {
  errorMessage, normalizeStatus, safeArray,
} from "../../lib/identity.js";
import {
  DataTable, EmptyState, LoadingRows, Modal, Notice, PageHeading, Panel, useRemote,
} from "../../components/Shared.jsx";
import { COLUMNS } from "../../lib/identity.js";

export function RolesPage() {
  const [roles, setRoles] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [roleResponse, departmentResponse] = await Promise.all([api.roles(), api.departments()]);
      setRoles(safeArray(roleResponse)); setDepartments(safeArray(departmentResponse));
    } catch (err) { setError(errorMessage(err, "Role reference could not be loaded.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  return <main className="content"><PageHeading kicker="Policy reference" title="Roles & permissions." description="Read-only view of role definitions returned by the identity service." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice>
    {loading ? <div className="panel" style={{ padding: 20 }}><LoadingRows /></div> : roles.length ? <section className="panel"><div className="reference-grid">{roles.map((role, i) => <article className="role-card" key={role.id || role.name || i}><div className="eyebrow">{role.scope || "Access role"}</div><h3>{role.name || role.role || "Role"}</h3><p>{role.description || role.summary || "Role definition supplied by the identity service."}</p><div className="role-list">{(role.permissions || role.allowedResources || []).map((permission) => <span className="role-pill" key={permission}>{typeof permission === "string" ? permission : permission.name || permission.key}</span>)}</div></article>)}</div></section> : <EmptyState title="Role catalog unavailable" detail="The service returned no role definitions." icon={FileKey2} />}
    <div style={{ marginTop: 16 }}><Panel title="Departments" note="Organizational scopes available to the service">{departments.length ? <div className="table-wrap"><table><thead><tr><th>Department</th><th>Identifier</th><th>Description</th></tr></thead><tbody>{departments.map((department) => <tr key={department.id || department._id}><td><strong>{department.name}</strong></td><td className="mono">{department.id || department._id}</td><td>{department.description || "—"}</td></tr>)}</tbody></table></div> : <EmptyState title="No departments returned" icon={Building2} />}</Panel></div>
  </main>;
}

export function DevicesPage({ role }) {
  const [query, setQuery] = useState("");
  const [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false);
  const { rows, loading, error, refresh, setError } = useRemote(() => api.devices.list(), []);
  const filtered = rows.filter((row) => `${row.userName} ${row.name} ${row.browser} ${row.operatingSystem} ${row.status}`.toLowerCase().includes(query.toLowerCase()));
  const decide = async (status) => {
    setBusy(true); setError("");
    try { await api.devices.review(confirm.id || confirm._id, status); setConfirm(null); await refresh(); }
    catch (err) { setError(errorMessage(err, "Device review could not be saved.")); }
    finally { setBusy(false); }
  };
  return <main className="content"><PageHeading kicker="Device posture" title="Device approvals." description={role === "manager" ? "Review devices associated with your department." : "Review and control devices requesting organizational access."} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Search devices or owners" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} devices`} note="Approval decisions are recorded server-side">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.devices} empty="No device records found" renderActions={(device) => role === "admin" && normalizeStatus(device.status) === "pending" ? <button className="icon-button" title="Review device" aria-label="Review device" onClick={() => setConfirm(device)}><Eye size={14} /></button> : role === "employee" && normalizeStatus(device.status) !== "revoked" ? <button className="icon-button" title="Revoke this device" aria-label={`Revoke ${device.name}`} onClick={() => setConfirm(device)}><X size={14} /></button> : null} />}</Panel>
    {confirm && <Modal title={role === "admin" ? "Review this device?" : "Revoke this device?"} description={`${confirm.name || "Device"} · ${confirm.userName || "Current account"}`} onClose={() => setConfirm(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>{role === "admin" ? "Approve or reject this device through the identity service. Approval does not replace account or MFA verification." : "This device will no longer be trusted for your account. You may need to verify again on a future sign-in."}</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setConfirm(null)}>Cancel</button>{role === "admin" ? <><button className="btn btn-danger" disabled={busy} onClick={() => decide("REJECTED")}>{busy ? "Saving..." : "Reject device"}</button><button className="btn btn-primary" disabled={busy} onClick={() => decide("APPROVED")}>{busy ? "Saving..." : "Approve device"}</button></> : <button className="btn btn-danger" disabled={busy} onClick={() => decide("REVOKED")}>{busy ? "Revoking..." : "Revoke device"}</button>}</div></Modal>}
  </main>;
}

export function SessionsPage({ role, user, history = false }) {
  const [query, setQuery] = useState("");
  const [confirm, setConfirm] = useState(null);
  const [revokeAllOpen, setRevokeAllOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const { rows, loading, error, refresh, setError } = useRemote(() => history ? api.auth.loginHistory() : api.sessions.list(), [history]);
  const filtered = rows.filter((row) => `${row.userName} ${row.role} ${row.ipAddress} ${row.deviceName} ${row.status} ${row.eventType} ${row.description}`.toLowerCase().includes(query.toLowerCase()));
  const revoke = async () => {
    setBusy(true); setError("");
    try { await api.sessions.revoke(confirm.id || confirm._id); setConfirm(null); await refresh(); }
    catch (err) { setError(errorMessage(err, "Session could not be revoked.")); }
    finally { setBusy(false); }
  };
  const revokeAllMine = async () => {
    setBusy(true); setError("");
    try {
      await api.sessions.revokeAll(user.id || user._id);
      setRevokeAllOpen(false);
      try { await api.auth.logout(); } catch { /* session may already be revoked */ }
      navigate(`/${role}/login`, { replace: true });
    } catch (err) { setError(errorMessage(err, "Your sessions could not be revoked.")); }
    finally { setBusy(false); }
  };
  return <main className="content"><PageHeading kicker={history ? "Account security" : "Active access"} title={history ? "Login history." : "Session monitoring."} description={history ? "Review authentication events returned for your account." : role === "admin" ? "Inspect and revoke active identity sessions." : "Review current sessions in your department."} action={!history ? <button className="btn btn-outline" onClick={() => setRevokeAllOpen(true)}><LogOut size={14} /> Revoke my sessions</button> : null} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Search identity, IP or device" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} ${history ? "login events" : "session records"}`} note={history ? "Authentication history returned by the identity service" : "Revoking a session immediately removes its access"}>{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={history ? COLUMNS.audit : COLUMNS.sessions} empty="No records returned" renderActions={!history ? (session) => normalizeStatus(session.status) !== "revoked" && <button className="icon-button" title="Revoke session" aria-label="Revoke session" onClick={() => setConfirm(session)}><LogOut size={14} /></button> : undefined} />}</Panel>
    {confirm && <Modal title="Revoke this session?" description={`${confirm.userName || "Identity"} · ${confirm.deviceName || confirm.ipAddress || "Session"}`} onClose={() => setConfirm(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>This action will be sent to the identity service and may interrupt the active session.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setConfirm(null)}>Keep session</button><button className="btn btn-danger" disabled={busy} onClick={revoke}>{busy ? "Revoking..." : "Revoke session"}</button></div></Modal>}
    {revokeAllOpen && <Modal title="Revoke all your sessions?" description="You will be signed out of this device." onClose={() => setRevokeAllOpen(false)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>The identity service will revoke every active session tied to your account. This console will return to sign-in afterward.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setRevokeAllOpen(false)}>Cancel</button><button className="btn btn-danger" disabled={busy} onClick={revokeAllMine}>{busy ? "Revoking..." : "Revoke all sessions"}</button></div></Modal>}
  </main>;
}

export function AuditPage() {
  const [query, setQuery] = useState("");
  const { rows, loading, error, refresh } = useRemote(() => api.audit(), []);
  const filtered = rows.filter((row) => `${row.eventType} ${row.description} ${row.userName} ${row.ipAddress} ${row.status}`.toLowerCase().includes(query.toLowerCase()));
  return <main className="content"><PageHeading kicker="Accountability" title="Audit logs." description="A record of access and policy events supplied by the identity service." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Filter events" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
    <Panel title={`${filtered.length} audit events`} note="Audit events are read-only">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.audit} empty="No audit events found" />}</Panel>
  </main>;
}

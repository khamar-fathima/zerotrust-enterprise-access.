import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Laptop, RefreshCw, ShieldAlert, Users } from "lucide-react";
import { api } from "../../lib/api.js";
import {
  COLUMNS, errorMessage, getName, initials, normalizeRole, prettyDate, safeArray, statusClass, validPassword, ROLE_LABEL,
} from "../../lib/identity.js";
import {
  DataTable, EmptyState, LoadingRows, Modal, Notice, PageHeading, Panel,
} from "../../components/Shared.jsx";

export function DepartmentPage({ user }) {
  const [department, setDepartment] = useState(null);
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    Promise.all([api.departments(), api.users.list()]).then(([departmentResponse, userResponse]) => {
      if (!active) return;
      const departments = safeArray(departmentResponse);
      const id = user.departmentId || user.department?.id || user.department?._id;
      const match = departments.find((item) => String(item.id || item._id) === String(id)) || departments.find((item) => item.name === user.departmentName);
      setDepartment(match || (user.departmentName ? { name: user.departmentName, id } : null));
      setMembers(id || user.departmentName ? safeArray(userResponse).filter((person) => String(person.departmentId) === String(id) || (user.departmentName && person.departmentName === user.departmentName)) : []);
    }).catch((err) => { if (active) setError(errorMessage(err, "Department details could not be loaded.")); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user]);
  return <main className="content"><PageHeading kicker="Organizational scope" title={department?.name || user.departmentName || "Department overview."} description="Department details and people available within your current manager scope." />
    <Notice type="error">{error}</Notice>{loading ? <div className="panel" style={{ padding: 20 }}><LoadingRows /></div> : <><div className="metric-grid"><div className="panel metric-card"><div className="metric-label">Department identity</div><div className="metric-value" style={{ fontSize: 20 }}>{department?.name || "Not assigned"}</div><div className="metric-foot">Service-sourced organization</div></div><div className="panel metric-card"><div className="metric-label">People in scope</div><div className="metric-value">{members.length}</div><div className="metric-foot">Users returned for this department</div></div></div><Panel title="Department directory" note="No cross-department data is presented">{members.length ? <DataTable rows={members} columns={COLUMNS.users} /> : <EmptyState title="No department members returned" detail="The service did not return identities in this scope." icon={Users} />}</Panel></>}</main>;
}

export function ProfilePage({ user, onUser }) {
  const [form, setForm] = useState({ name: user.name || "", email: user.email || "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [profileLoading, setProfileLoading] = useState(true);
  const [profileError, setProfileError] = useState("");
  useEffect(() => {
    let active = true;
    setProfileLoading(true); setProfileError("");
    api.profile.get().then((response) => {
      if (!active) return;
      const profile = response?.profile || response?.user || response;
      setForm({ name: profile.name || user.name || "", email: profile.email || user.email || "" });
    }).catch((err) => {
      if (active) { setForm({ name: user.name || "", email: user.email || "" }); setProfileError(errorMessage(err, "Profile details could not be loaded.")); }
    }).finally(() => { if (active) setProfileLoading(false); });
    return () => { active = false; };
  }, [user]);
  const save = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setSuccess("");
    try {
      const result = await api.profile.update({ name: form.name });
      const next = result?.profile || result?.user || result;
      onUser(next);
      setSuccess("Profile changes saved.");
    } catch (err) { setError(errorMessage(err, "Profile could not be updated.")); }
    finally { setBusy(false); }
  };
  const [passwords, setPasswords] = useState({ current: "", next: "" });
  const [pwMessage, setPwMessage] = useState("");
  const [pwError, setPwError] = useState("");
  const changePassword = async (event) => {
    event.preventDefault(); setPwMessage(""); setPwError("");
    if (!validPassword(passwords.next)) { setPwError("New password must be at least 12 characters and include uppercase, lowercase and a number."); return; }
    try {
      await api.auth.changePassword(passwords.current, passwords.next);
      setPasswords({ current: "", next: "" });
      setPwMessage("Password updated by the identity service.");
    } catch (err) { setPwError(errorMessage(err, "Password could not be changed.")); }
  };
  return <main className="content"><PageHeading kicker="Personal identity" title="Profile & credentials." description="Maintain your account details and password through the identity service." />
    <div className="profile-layout"><section className="panel profile-card"><div className="profile-portrait">{initials(getName(user))}</div><h2 className="panel-title" style={{ fontSize: 17 }}>{getName(user)}</h2><p className="subheading">{user.email}</p><div className="security-list" style={{ marginTop: 20 }}><div className="security-item"><strong>Role</strong><span>{ROLE_LABEL[normalizeRole(user.role)] || user.role}</span></div><div className="security-item"><strong>Department</strong><span>{user.departmentName || "—"}</span></div><div className="security-item"><strong>MFA</strong><span>{user.mfaEnabled ? "Enabled" : "Not enabled"}</span></div></div></section>
      <div style={{ display: "grid", gap: 15 }}><Panel title="Profile details"><div style={{ padding: 20 }}><Notice type="error">{profileError || error}</Notice><Notice type="success">{success}</Notice>{profileLoading ? <LoadingRows /> : <form onSubmit={save} className="auth-form"><div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div><div className="form-field"><label>Email · read-only</label><input className="field" type="email" value={form.email} readOnly /></div><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : "Save profile"}</button></form>}</div></Panel>
        <Panel title="Change password" note="12+ characters with uppercase, lowercase and a number"><div style={{ padding: 20 }}><Notice type="error">{pwError}</Notice><Notice type="success">{pwMessage}</Notice><form className="auth-form" onSubmit={changePassword}><div className="form-field"><label>Current password</label><input className="field" type="password" autoComplete="current-password" required value={passwords.current} onChange={(e) => setPasswords({ ...passwords, current: e.target.value })} /></div><div className="form-field"><label>New password</label><input className="field" type="password" minLength="12" autoComplete="new-password" required value={passwords.next} onChange={(e) => setPasswords({ ...passwords, next: e.target.value })} /></div><button className="btn btn-outline">Update password</button></form></div></Panel></div>
    </div></main>;
}

export function SecurityPage({ user }) {
  const navigate = useNavigate();
  const [deviceRows, setDeviceRows] = useState([]);
  const [latestUser, setLatestUser] = useState(user);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [disableOpen, setDisableOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [me, devices] = await Promise.all([api.auth.me(), api.devices.list()]);
      setLatestUser(me?.user || me);
      setDeviceRows(safeArray(devices));
    } catch (err) { setError(errorMessage(err, "Security status unavailable.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  const disableMfa = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setSuccess("");
    try {
      await api.auth.disableMfa(password, code);
      setDisableOpen(false);
      setSuccess("MFA was disabled. The service revoked all sessions; sign in again to continue. MFA enrollment is required at your next login.");
      setPassword(""); setCode("");
      window.setTimeout(() => navigate(`/${normalizeRole(user.role)}/login`, { replace: true }), 1800);
    } catch (err) { setError(errorMessage(err, "MFA could not be disabled.")); }
    finally { setBusy(false); }
  };
  return <main className="content"><PageHeading kicker="Personal security" title="Security posture." description="Current identity and known-device details from protected endpoints." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice><Notice type="success">{success}</Notice><div className="dashboard-grid">
      <Panel title="Authentication" note="MFA changes require proof of account ownership"><div style={{ padding: 20 }} className="security-list">
        <div className="security-item"><strong>Multi-factor authentication</strong><span className={`status ${(latestUser?.mfaEnabled ?? user.mfaEnabled) ? "active" : "pending"}`}>{(latestUser?.mfaEnabled ?? user.mfaEnabled) ? "Enabled" : "Not enabled"}</span></div>
        <div className="security-item"><strong>Account role</strong><span>{ROLE_LABEL[normalizeRole(latestUser?.role || user.role)] || latestUser?.role || user.role}</span></div>
        <div className="security-item"><strong>Device records</strong><span>{loading ? "Checking…" : deviceRows.length}</span></div>
        {(latestUser?.mfaEnabled ?? user.mfaEnabled) && <button className="btn btn-danger" style={{ marginTop: 15, alignSelf: "start" }} onClick={() => setDisableOpen(true)}><ShieldAlert size={14} /> Disable MFA</button>}
      </div></Panel>
      <Panel title="Known devices" note="Device details returned by the authenticated device endpoint">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : deviceRows.length ? <div className="table-wrap"><table><thead><tr><th>Device</th><th>Browser</th><th>Operating system</th><th>Status</th><th>Last activity</th></tr></thead><tbody>{deviceRows.map((device) => <tr key={device.id || device._id}><td><strong>{device.name || "Device"}{device.isCurrent || device.current ? " · Current" : ""}</strong></td><td>{device.browser || "—"}</td><td>{device.operatingSystem || "—"}</td><td><span className={`status ${statusClass(device.status)}`}>{device.status || "Unknown"}</span></td><td className="mono">{prettyDate(device.lastActivity)}</td></tr>)}</tbody></table></div> : <EmptyState title="No known devices" detail="No device records were returned for this identity." icon={Laptop} />}</Panel>
    </div>
    {disableOpen && <Modal title="Disable multi-factor authentication?" description="This is a security-sensitive change." onClose={() => setDisableOpen(false)}><Notice type="error">The service will disable MFA and revoke all active sessions. MFA enrollment will be required at your next sign-in.</Notice><form onSubmit={disableMfa} className="auth-form"><div className="form-field"><label>Current password</label><input className="field" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></div><div className="form-field"><label>Current authenticator code</label><input className="field code-input" inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} /></div><div className="modal-footer"><button type="button" className="btn btn-outline" onClick={() => setDisableOpen(false)}>Keep MFA enabled</button><button className="btn btn-danger" disabled={busy}>{busy ? "Disabling..." : "Confirm disable"}</button></div></form></Modal>}
  </main>;
}

export function SettingsPage({ user }) {
  return <main className="content"><PageHeading kicker="Console configuration" title="Settings." description="Review account and session controls available in this environment." />
    <div className="dashboard-grid"><Panel title="Session security" note="Service-enforced controls"><div style={{ padding: 20 }} className="security-list"><div className="security-item"><strong>Current session</strong><span className="status active">Verified</span></div><div className="security-item"><strong>Role boundary</strong><span>{ROLE_LABEL[normalizeRole(user.role)] || user.role}</span></div><div className="security-item"><strong>Cross-role access</strong><span>Denied by portal guard</span></div><div className="security-item"><strong>Account MFA</strong><span>{user.mfaEnabled ? "Enabled" : "Not enabled"}</span></div></div></Panel>
      <Panel title="Access principles" note="This demo preserves the authorization boundary"><div style={{ padding: 20, display: "grid", gap: 16 }}><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Verify explicitly</div><div className="activity-meta">Sign-in, device posture and role are checked before portal entry.</div></div></div><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Least privilege</div><div className="activity-meta">Resource endpoints enforce authorization independently.</div></div></div><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Use real service responses</div><div className="activity-meta">Unavailable operations are reported rather than simulated.</div></div></div></div></Panel></div>
  </main>;
}

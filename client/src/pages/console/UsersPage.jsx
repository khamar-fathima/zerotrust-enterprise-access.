import { useEffect, useState } from "react";
import { Check, LogOut, Pencil, Plus, RefreshCw, Search, UserCog, X } from "lucide-react";
import { api } from "../../lib/api.js";
import {
  COLUMNS, errorMessage, normalizeStatus, safeArray, validPassword,
} from "../../lib/identity.js";
import {
  DataTable, LoadingRows, Modal, Notice, PageHeading, Panel,
} from "../../components/Shared.jsx";
import usePaginatedRemote from "../../hooks/usePaginatedRemote.js";
import Pagination from "../../components/Pagination.jsx";

export default function UsersPage({ role, user }) {
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [departments, setDepartments] = useState([]);
  const [form, setForm] = useState({ name: "", email: "", role: "EMPLOYEE", status: "ACTIVE", departmentId: "", temporaryPassword: "" });
  const [busy, setBusy] = useState(false);
  const [revokeUser, setRevokeUser] = useState(null);
  const { rows, params, total, totalPages, setFilter, setPage, loading, error, refresh, setError } = usePaginatedRemote(api.users.list, "users", `${user?.id || ""}:${role}:${user?.departmentId || ""}`);
  useEffect(() => { api.departments().then((d) => setDepartments(safeArray(d))).catch(() => {}); }, []);
  const review = async (user, decision) => {
    setError("");
    try { await api.users.review(user.id || user._id, decision); await refresh(); }
    catch (err) { setError(errorMessage(err, "Identity review failed.")); }
  };
  const updateStatus = async (user, status) => {
    setError("");
    try { await api.users.update(user.id || user._id, { status }); await refresh(); }
    catch (err) { setError(errorMessage(err, "Identity status could not be updated.")); }
  };
  const saveUser = async (e) => {
    e.preventDefault(); setBusy(true); setError("");
    try {
      if (!editing && !validPassword(form.temporaryPassword)) throw new Error("Temporary password must be at least 12 characters and include uppercase, lowercase and a number.");
      const departmentId = form.departmentId || undefined;
      if (editing) {
        await api.users.update(editing.id || editing._id, { name: form.name, role: form.role, status: form.status, departmentId });
      } else {
        await api.users.create({ name: form.name, email: form.email, role: form.role, departmentId, temporaryPassword: form.temporaryPassword });
      }
      setModal(false); setEditing(null); setForm({ name: "", email: "", role: "EMPLOYEE", status: "ACTIVE", departmentId: "", temporaryPassword: "" }); await refresh();
    } catch (err) { setError(errorMessage(err, `Identity could not be ${editing ? "updated" : "created"}.`)); }
    finally { setBusy(false); }
  };
  const openEdit = (user) => {
    setEditing(user);
    setForm({ name: user.name || "", email: user.email || "", role: String(user.role || "EMPLOYEE").toUpperCase(), status: String(user.status || "ACTIVE").toUpperCase(), departmentId: user.departmentId || "", temporaryPassword: "" });
    setModal(true);
  };
  const revokeAll = async () => {
    setBusy(true); setError("");
    try { await api.sessions.revokeAll(revokeUser.id || revokeUser._id); setRevokeUser(null); }
    catch (err) { setError(errorMessage(err, "Sessions could not be revoked.")); }
    finally { setBusy(false); }
  };
  const renderUserActions = (user) => {
    const pending = normalizeStatus(user.status) === "pending";
    if (role !== "admin") return null;
    return <>
      <button className="icon-button" aria-label={`Edit ${user.name}`} title="Edit identity" onClick={() => openEdit(user)}><Pencil size={14} /></button>
      <button className="icon-button" aria-label={`Revoke all sessions for ${user.name}`} title="Revoke all sessions" onClick={() => setRevokeUser(user)}><LogOut size={14} /></button>
      {pending ? <>
        <button className="icon-button" aria-label="Approve identity" title="Approve" onClick={() => review(user, "APPROVE")}><Check size={14} /></button>
        <button className="icon-button" aria-label="Reject identity" title="Reject" onClick={() => review(user, "REJECT")}><X size={14} /></button>
      </> : <button className="icon-button" aria-label="Toggle identity status" title={normalizeStatus(user.status) === "active" ? "Disable identity" : "Enable identity"} onClick={() => updateStatus(user, normalizeStatus(user.status) === "active" ? "DISABLED" : "ACTIVE")}><UserCog size={14} /></button>}
    </>;
  };
  return <main className="content">
    <PageHeading kicker={role === "manager" ? "Department scope" : "Identity directory"} title={role === "manager" ? "People in your department." : "User management."} description="Review identity state and manage access requests." action={role === "admin" ? <button className="btn btn-primary" onClick={() => { setEditing(null); setForm({ name: "", email: "", role: "EMPLOYEE", status: "ACTIVE", departmentId: "", temporaryPassword: "" }); setModal(true); }}><Plus size={15} /> Add identity</button> : null} />
    <Notice type="error">{error}</Notice>
    <div className="toolbar list-filters"><div style={{ position: "relative", flex: "1 1 240px" }}><Search size={15} style={{ position: "absolute", top: 11, left: 11, color: "#71807a" }} /><input className="field search-field" aria-label="Search identities" placeholder="Search people, roles or departments" maxLength={80} value={params.q} onChange={(e) => setFilter("q", e.target.value)} style={{ paddingLeft: 34 }} /></div>
      {role === "admin" && <>
        <select className="select" aria-label="Filter identities by role" value={params.role || ""} onChange={(e) => setFilter("role", e.target.value)}><option value="">All roles</option><option value="ADMIN">Administrator</option><option value="MANAGER">Manager</option><option value="EMPLOYEE">Employee</option></select>
        <select className="select" aria-label="Filter identities by status" value={params.status || ""} onChange={(e) => setFilter("status", e.target.value)}><option value="">All statuses</option>{["PENDING", "ACTIVE", "DISABLED", "REJECTED"].map((status) => <option key={status}>{status}</option>)}</select>
        <select className="select" aria-label="Filter identities by department" value={params.departmentId || ""} onChange={(e) => setFilter("departmentId", e.target.value)}><option value="">All departments</option>{departments.map((department) => <option key={department.id || department._id} value={department.id || department._id}>{department.name}</option>)}</select>
      </>}
      <button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={loading ? "Loading identities" : `${total} identities`} note={role === "manager" ? "Active employees in your department only" : "Changes are recorded by the identity service"}>
      {loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={rows} columns={COLUMNS.users} empty={error ? "Identities could not be loaded" : "No identities match your search"} renderActions={renderUserActions} />}
      <Pagination page={params.page} limit={params.limit} total={total} totalPages={totalPages} loading={loading} onPage={setPage} onLimit={(value) => setFilter("limit", value)} />
    </Panel>
    {modal && <Modal title={editing ? "Edit identity" : "Create an identity"} description="Save user changes through the identity service." onClose={() => { setModal(false); setEditing(null); }}><form onSubmit={saveUser}>
      <div className="form-grid"><div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>{editing ? <div className="form-field"><label>Email · read-only</label><input className="field" type="email" value={editing.email || ""} readOnly /></div> : <div className="form-field"><label>Email</label><input className="field" required type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>}<div className="form-field"><label>Role</label><select className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="EMPLOYEE">Employee</option><option value="MANAGER">Manager</option><option value="ADMIN">Administrator</option></select></div><div className="form-field"><label>Department</label><select className="select" value={form.departmentId} onChange={(e) => setForm({ ...form, departmentId: e.target.value })}><option value="">Select</option>{departments.map((d) => <option key={d.id || d._id} value={d.id || d._id}>{d.name}</option>)}</select></div>{editing ? <div className="form-field"><label>Status</label><select className="select" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}><option value="ACTIVE">Active</option><option value="PENDING">Pending</option><option value="DISABLED">Disabled</option></select></div> : <div className="form-field"><label>Temporary password</label><input className="field" type="password" required minLength="12" value={form.temporaryPassword} onChange={(e) => setForm({ ...form, temporaryPassword: e.target.value })} /><span className="panel-note">12+ characters with uppercase, lowercase and a number.</span></div>}</div>
      <div className="modal-footer"><button type="button" className="btn btn-outline" onClick={() => { setModal(false); setEditing(null); }}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : editing ? "Save changes" : "Create identity"}</button></div>
    </form></Modal>}
    {revokeUser && <Modal title="Revoke all sessions?" description={`${revokeUser.name} · ${revokeUser.email}`} onClose={() => setRevokeUser(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>Every active session for this identity will be revoked by the service.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setRevokeUser(null)}>Cancel</button><button className="btn btn-danger" disabled={busy} onClick={revokeAll}>{busy ? "Revoking..." : "Revoke all sessions"}</button></div></Modal>}
  </main>;
}

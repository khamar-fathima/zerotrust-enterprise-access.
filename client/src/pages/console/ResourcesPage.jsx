import { useEffect, useState } from "react";
import { ArrowRight, Pencil, Plus, RefreshCw } from "lucide-react";
import { api } from "../../lib/api.js";
import { COLUMNS, errorMessage, safeArray } from "../../lib/identity.js";
import {
  DataTable, LoadingRows, Modal, Notice, PageHeading, Panel,
} from "../../components/Shared.jsx";
import useRemote from "../../hooks/useRemote.js";

export default function ResourcesPage({ role }) {
  const [query, setQuery] = useState("");
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" });
  const { rows, loading, error, refresh, setError } = useRemote(() => api.resources.list(), []);
  const filtered = rows.filter((resource) => `${resource.name} ${resource.description} ${resource.classification} ${resource.departmentName}`.toLowerCase().includes(query.toLowerCase()));
  const [departments, setDepartments] = useState([]);
  useEffect(() => { api.departments().then((data) => setDepartments(safeArray(data))).catch(() => {}); }, []);
  const saveResource = async (event) => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const data = { name: form.name, description: form.description, classification: form.classification.toUpperCase(), allowedRoles: form.allowedRoles.split(",").map((value) => value.trim().toUpperCase()).filter(Boolean), departmentId: form.departmentId || undefined, active: form.active };
      if (editing) await api.resources.update(editing.id || editing._id, data);
      else await api.resources.create({ ...data, content: form.content });
      setModal(false); setEditing(null); setForm({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" }); await refresh();
    } catch (err) { setError(errorMessage(err, `Resource could not be ${editing ? "updated" : "created"}.`)); }
    finally { setBusy(false); }
  };
  const openEdit = (resource) => {
    setEditing(resource);
    setForm({ name: resource.name || "", description: resource.description || "", classification: String(resource.classification || "INTERNAL").toUpperCase(), allowedRoles: (resource.allowedRoles || []).map((value) => String(value).toUpperCase()).join(", "), departmentId: resource.departmentId || "", active: resource.active !== false, content: "" });
    setModal(true);
  };
  const getAccess = async (resource) => {
    setError(""); setSelected({ ...resource, content: null, loading: true });
    try {
      const response = await api.resources.access(resource.id || resource._id);
      setSelected({ ...resource, content: response?.resource?.content ?? response?.resource ?? response?.content ?? response });
    } catch (err) { setSelected(null); setError(errorMessage(err, "Resource access was denied or unavailable.")); }
  };
  return <main className="content"><PageHeading kicker="Least privilege" title="Protected resources." description="Resource availability and content access are determined by the identity service." action={role === "admin" ? <button className="btn btn-primary" onClick={() => { setEditing(null); setForm({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" }); setModal(true); }}><Plus size={15} /> Add resource</button> : null} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Search protected resources" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} protected resources`} note="A visible listing does not guarantee content access">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.resources} empty="No resources are available" renderActions={(resource) => <>{role === "admin" && <button className="icon-button" title="Edit resource" aria-label={`Edit ${resource.name}`} onClick={() => openEdit(resource)}><Pencil size={14} /></button>}<button className="icon-button" title="Request resource access" aria-label={`Access ${resource.name}`} onClick={() => getAccess(resource)}><ArrowRight size={14} /></button></>} />}</Panel>
    {role === "employee" && <div className="notice info" style={{ marginTop: 14 }}>Resource access is checked by the server for your verified identity and role. A listed resource may still be restricted.</div>}
    {modal && <Modal title={editing ? "Edit protected resource" : "Add protected resource"} description="Save resource metadata through the service." onClose={() => { setModal(false); setEditing(null); }}><form onSubmit={saveResource}><div className="form-grid">
      <div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
      <div className="form-field"><label>Classification</label><select className="select" value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}><option value="INTERNAL">Internal</option><option value="CONFIDENTIAL">Confidential</option><option value="RESTRICTED">Restricted</option></select></div>
      <div className="form-field"><label>Allowed roles (comma separated)</label><input className="field" required value={form.allowedRoles} onChange={(e) => setForm({ ...form, allowedRoles: e.target.value })} /></div>
      <div className="form-field"><label>Department</label><select className="select" value={form.departmentId} onChange={(e) => setForm({ ...form, departmentId: e.target.value })}><option value="">Institution-wide</option>{departments.map((department) => <option key={department.id || department._id} value={department.id || department._id}>{department.name}</option>)}</select></div>
      <div className="form-field" style={{ gridColumn: "1/-1" }}><label>Description</label><textarea className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
      {!editing && <div className="form-field" style={{ gridColumn: "1/-1" }}><label>Protected content</label><textarea className="textarea" value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} /></div>}
      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#53655c" }}><input type="checkbox" checked={form.active} onChange={(e) => setForm({ ...form, active: e.target.checked })} /> Resource active</label>
    </div><div className="modal-footer"><button type="button" className="btn btn-outline" onClick={() => { setModal(false); setEditing(null); }}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : editing ? "Save changes" : "Create resource"}</button></div></form></Modal>}
    {selected && <Modal title={selected.name} description={selected.description} onClose={() => setSelected(null)}>{selected.loading ? <div className="skeleton" style={{ height: 100 }} /> : <><div className="notice info">Content returned by the resource access endpoint.</div><div className="resource-content">{typeof selected.content === "string" ? selected.content : JSON.stringify(selected.content, null, 2)}</div></>}</Modal>}
  </main>;
}

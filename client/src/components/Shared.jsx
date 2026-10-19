import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Shield, ShieldCheck, X } from "lucide-react";
import {
  prettyDate, ROLE_LABEL, safeArray, statusClass,
} from "../lib/identity.js";

export function Brand({ light = false }) {
  return <div className={`brand ${light ? "portal-brand" : ""}`}><div className="brand-mark"><Shield size={19} strokeWidth={2.1} /></div><div><div className="brand-name">zerotrust</div><div className="brand-sub">enterprise access management</div></div></div>;
}

export function Notice({ type = "info", children }) {
  if (!children) return null;
  return <div className={`notice ${type}`} role={type === "error" ? "alert" : "status"}>{children}</div>;
}

export function EmptyState({ title = "Nothing to review", detail = "When records are available, they will appear here.", icon: Icon = ShieldCheck }) {
  return <div className="empty-state"><div className="empty-mark"><Icon size={19} /></div><h3>{title}</h3><p>{detail}</p></div>;
}

export function LoadingRows() {
  return <div className="content-loader" aria-label="Loading"><div className="skeleton" style={{ height: 45 }} /><div className="skeleton" style={{ height: 58 }} /><div className="skeleton" style={{ height: 58 }} /><div className="skeleton" style={{ height: 58 }} /></div>;
}

export function PageLoading({ label = "Loading workspace" }) {
  return <main className="content" aria-live="polite"><div className="eyebrow">{label}</div><LoadingRows /></main>;
}

export function AuthFrame({ children, portal, label = "Identity verification" }) {
  const labelText = portal ? ROLE_LABEL[portal] : "New account";
  return <div className="auth-page">
    <aside className="auth-aside"><Link to="/"><Brand light /></Link><div className="auth-aside-copy"><div className="portal-kicker"><span className="kicker-line" /> {label}</div><h2>Identity is the first layer of access.</h2><p>This college demonstration applies verification at every boundary—account, device and protected resource.</p></div><div className="auth-aside-foot">ZERO TRUST / {labelText.toUpperCase()}</div></aside>
    <main className="auth-main">{children}</main>
  </div>;
}

export function PageHeading({ kicker, title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{kicker}</div><h1>{title}</h1><p className="subheading">{description}</p></div>{action}</div>;
}

export function Panel({ title, note, children, action, className = "" }) {
  return <section className={`panel ${className}`}><header className="panel-head"><div><h2 className="panel-title">{title}</h2>{note && <div className="panel-note" style={{ marginTop: 5 }}>{note}</div>}</div>{action}</header>{children}</section>;
}

export function DataTable({ rows, columns, empty, renderActions }) {
  if (!rows.length) return <EmptyState title={empty || "No records found"} />;
  return <div className="table-wrap"><table><thead><tr>{columns.map(([, label]) => <th key={label}>{label}</th>)}{renderActions && <th>Actions</th>}</tr></thead><tbody>{rows.map((row, idx) => <tr key={row.id || row._id || idx}>
    {columns.map(([key]) => <td key={key}>{key === "status" || key === "active" ? <span className={`status ${statusClass(key === "active" ? row[key] ? "active" : "inactive" : row[key])}`}>{key === "active" ? row[key] ? "Active" : "Inactive" : row[key] || "Unknown"}</span> : key === "mfaEnabled" ? <span className={`status ${row[key] ? "active" : "pending"}`}>{row[key] ? "Enabled" : "Not set"}</span> : key.toLowerCase().includes("activity") || key === "createdAt" ? <span className="mono">{prettyDate(row[key])}</span> : Array.isArray(row[key]) ? <span>{row[key].join(", ") || "—"}</span> : <span>{row[key] ?? "—"}</span>}</td>)}
    {renderActions && <td><div className="table-actions">{renderActions(row)}</div></td>}
  </tr>)}</tbody></table></div>;
}

export function useRemote(load, deps = []) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRows(safeArray(await load()));
    } catch (error) {
      setError(error?.response?.data?.error || error?.response?.data?.message || error?.message || "The requested records could not be loaded.");
    } finally {
      setLoading(false);
    }
  // The loader is provided together with the explicit dependencies by each page.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { refresh(); }, [refresh]);
  return { rows, setRows, loading, error, refresh, setError };
}

export function Modal({ title, description, onClose, children }) {
  return <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}><section className="modal" role="dialog" aria-modal="true" aria-label={title}><header className="modal-header"><div><h2>{title}</h2>{description && <p>{description}</p>}</div><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={16} /></button></header>{children}</section></div>;
}

import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { LogOut, Menu, ShieldCheck } from "lucide-react";
import { getName, initials, ROLE_HOME, ROLE_LABEL, ROLE_NAV, ROLE_TITLES } from "../lib/identity.js";
import { Brand } from "./Shared.jsx";

export default function AppLayout({ user, role, onLogout, children }) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const nav = ROLE_NAV[role] || ROLE_NAV.employee;
  const active = nav.find(([, path]) => path === location.pathname) || nav[0];
  return <div className="app-shell">
    <aside className={`sidebar ${mobileOpen ? "open" : ""}`}>
      <Link to={ROLE_HOME[role]} onClick={() => setMobileOpen(false)}><Brand /></Link>
      <div className="nav-label">Workspace</div>
      <nav className="side-nav">{nav.map(([label, path, Icon]) => <Link key={path} className={`nav-item ${location.pathname === path ? "active" : ""}`} to={path} onClick={() => setMobileOpen(false)}><Icon size={16} />{label}</Link>)}</nav>
      <div className="side-bottom"><div className="identity-chip"><div className="avatar">{initials(getName(user))}</div><div><div className="identity-name">{getName(user)}</div><div className="identity-role">{ROLE_LABEL[role]}</div></div></div><button className="logout-link" onClick={onLogout}><LogOut size={15} /> Sign out</button></div>
    </aside>
    <section className="main-area">
      <header className="topbar"><button aria-label="Open navigation" className="icon-button mobile-menu" onClick={() => setMobileOpen((v) => !v)}><Menu size={17} /></button><div className="crumb">{ROLE_TITLES[role]} <span style={{ margin: "0 7px", color: "#b0bcb3" }}>/</span> {active[0]}</div><div className="topbar-right"><div className="secure-tag"><ShieldCheck size={13} /> Verified session</div><div className="avatar" style={{ width: 30, height: 30 }}>{initials(getName(user))}</div></div></header>
      {children}
    </section>
  </div>;
}

import { useCallback, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import {
  Activity, ArrowLeft, ArrowRight, Building2, Check, ClipboardList, Database, Eye, FileKey2, Fingerprint,
  History, Laptop, LayoutDashboard, LockKeyhole, LogOut, Menu, MonitorCog, Pencil, Plus, RefreshCw,
  Search, Settings, Shield, ShieldAlert, ShieldCheck, Smartphone, UserCog, UserRound, Users, X, Zap,
} from "lucide-react";
import { CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "./lib/api.js";

const ROLE_HOME = { admin: "/admin/dashboard", manager: "/manager/dashboard", employee: "/employee/dashboard" };
const ROLE_LABEL = { admin: "Administrator", manager: "Department manager", employee: "Employee" };
const ROLE_NAV = {
  admin: [
    ["Overview", "/admin/dashboard", LayoutDashboard],
    ["User management", "/admin/users", Users],
    ["Roles & permissions", "/admin/roles", FileKey2],
    ["Device approvals", "/admin/devices", Laptop],
    ["Session monitoring", "/admin/sessions", MonitorCog],
    ["Audit logs", "/admin/audit", ClipboardList],
    ["Protected resources", "/admin/resources", Database],
    ["Settings", "/admin/settings", Settings],
  ],
  manager: [
    ["Overview", "/manager/dashboard", LayoutDashboard],
    ["Department", "/manager/department", Building2],
    ["Employees", "/manager/employees", Users],
    ["Resources", "/manager/resources", Database],
    ["Devices", "/manager/devices", Laptop],
    ["Sessions", "/manager/sessions", MonitorCog],
    ["Profile", "/manager/profile", UserRound],
  ],
  employee: [
    ["Overview", "/employee/dashboard", LayoutDashboard],
    ["Resources", "/employee/resources", Database],
    ["Devices", "/employee/devices", Laptop],
    ["Sessions", "/employee/sessions", MonitorCog],
    ["Login history", "/employee/history", History],
    ["Security", "/employee/security", ShieldCheck],
    ["Profile", "/employee/profile", UserRound],
  ],
};
const ROLE_TITLES = { admin: "Identity control", manager: "Department access", employee: "My access" };
const safeArray = (value) => {
  if (Array.isArray(value)) return value;
  for (const key of ["users", "devices", "sessions", "logs", "roles", "departments", "resources", "items", "data", "activity"]) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
};
const normalizeRole = (value) => String(value || "").toLowerCase();
const normalizeStatus = (value) => String(value || "").toLowerCase();
const errorMessage = (err, fallback) => err?.response?.data?.error || err?.response?.data?.message || err?.message || fallback;
const validPassword = (value) => value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
const getName = (user) => user?.name || user?.email || "Account";
const initials = (name = "") => name.split(/\s+/).filter(Boolean).slice(0, 2).map((s) => s[0]).join("").toUpperCase() || "ZT";
const prettyDate = (date) => date ? new Date(date).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
const statusClass = (status = "") => String(status).toLowerCase().replace(/\s+/g, "-");

function Brand({ light = false }) {
  return <div className={`brand ${light ? "portal-brand" : ""}`}><div className="brand-mark"><Shield size={19} strokeWidth={2.1} /></div><div><div className="brand-name">zerotrust</div><div className="brand-sub">enterprise access management</div></div></div>;
}

function Notice({ type = "info", children }) {
  if (!children) return null;
  return <div className={`notice ${type}`} role={type === "error" ? "alert" : "status"}>{children}</div>;
}

function EmptyState({ title = "Nothing to review", detail = "When records are available, they will appear here.", icon: Icon = ShieldCheck }) {
  return <div className="empty-state"><div className="empty-mark"><Icon size={19} /></div><h3>{title}</h3><p>{detail}</p></div>;
}

function LoadingRows() {
  return <div className="content-loader" aria-label="Loading"><div className="skeleton" style={{ height: 45 }} /><div className="skeleton" style={{ height: 58 }} /><div className="skeleton" style={{ height: 58 }} /><div className="skeleton" style={{ height: 58 }} /></div>;
}

function PortalHome() {
  const portals = [
    { label: "Administrator", path: "/admin/login", text: "Govern identity, policy and organizational access.", Icon: UserCog },
    { label: "Department manager", path: "/manager/login", text: "Review people, devices and access within your team.", Icon: Building2 },
    { label: "Employee", path: "/employee/login", text: "Reach approved resources and manage your security.", Icon: Fingerprint },
  ];
  return <div className="portal-page">
    <nav className="portal-nav"><Brand light /><Link className="portal-nav-link" to="/register">Request an account <ArrowRight size={14} style={{ verticalAlign: "middle", marginLeft: 5 }} /></Link></nav>
    <main>
      <section className="portal-hero">
        <div><div className="portal-kicker"><span className="kicker-line" /> COLLEGE CYBERSECURITY DEMONSTRATION</div>
          <h1 className="portal-title">Trust is not<br />a <em>checkbox.</em></h1>
          <p className="portal-lead">Never Trust. Always Verify. Every sign-in is a decision. Every permission has a boundary. Explore a working identity console built around verification, device posture and least privilege.</p>
          <div style={{ display: "flex", gap: 10, marginTop: 25, flexWrap: "wrap" }}>
            <a className="btn btn-primary" href="#portals">Choose your portal <ArrowRight size={15} /></a>
            <Link className="btn btn-outline" to="/register">Request access</Link>
          </div>
        </div>
        <div className="portal-visual" aria-label="Identity assurance illustration">
          <div className="orbit" /><div className="orbit two" />
          <div className="visual-core"><ShieldCheck size={48} strokeWidth={1.5} /></div>
          <div className="visual-node node-one"><UserRound size={17} /></div><div className="visual-node node-two"><Laptop size={17} /></div>
          <div className="visual-node node-three"><LockKeyhole size={17} /></div><div className="visual-node node-four"><Database size={17} /></div>
        </div>
      </section>
      <section className="portal-section" id="portals">
        <div className="portal-section-head"><h2>Enter the console</h2><span>IDENTITY · DEVICE · RESOURCE</span></div>
        <div className="portal-cards">{portals.map(({ label, path, text, Icon }) => <Link className="portal-card" key={path} to={path}>
          <div className="portal-card-icon"><Icon size={20} /></div><h3>{label}</h3><p>{text}</p>
        </Link>)}</div>
      </section>
    </main>
    <footer className="portal-foot"><span>ZeroTrust / College demo environment</span><span>Verify first. Grant only what is needed.</span></footer>
  </div>;
}

function AuthFrame({ children, portal, label = "Identity verification" }) {
  const labelText = portal ? ROLE_LABEL[portal] : "New account";
  return <div className="auth-page">
    <aside className="auth-aside"><Link to="/"><Brand light /></Link><div className="auth-aside-copy"><div className="portal-kicker"><span className="kicker-line" /> {label}</div><h2>Identity is the first layer of access.</h2><p>This college demonstration applies verification at every boundary—account, device and protected resource.</p></div><div className="auth-aside-foot">ZERO TRUST / {labelText.toUpperCase()}</div></aside>
    <main className="auth-main">{children}</main>
  </div>;
}

function LoginPage({ portal }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [stage, setStage] = useState("login");
  const [code, setCode] = useState("");
  const [mfaInfo, setMfaInfo] = useState(null);
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [recoveryAcknowledged, setRecoveryAcknowledged] = useState(false);
  const [mfaResult, setMfaResult] = useState(null);
  const portalName = ROLE_LABEL[portal] || "Account";
  const finishAuthorizedLogin = async () => {
    const current = await api.auth.me();
    const role = current?.user?.role || current?.role;
    const routeRole = normalizeRole(role);
    if (!routeRole || routeRole !== portal || !ROLE_HOME[routeRole]) throw new Error("Your identity was not authorized for this portal. No access was granted.");
    navigate(ROLE_HOME[routeRole], { replace: true });
  };
  const completeMfaFlow = async (result) => {
    if (result?.deviceApprovalRequired) {
      navigate("/device-verification", { state: { email, portal }, replace: true });
      return;
    }
    await finishAuthorizedLogin();
  };
  const submit = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      await api.csrf();
      const response = await api.auth.login(portal, { email, password });
      if (response?.requiresMfaSetup) {
        const info = await api.auth.setupMfa();
        setMfaInfo(info);
        setStage("setup");
        return;
      }
      if (response?.requiresMfa) { setStage("challenge"); setNotice("Enter the current code from your authenticator to continue."); return; }
      if (response?.deviceApprovalRequired) { navigate("/device-verification", { state: { email, portal }, replace: true }); return; }
      await finishAuthorizedLogin();
    } catch (err) {
      const data = err?.response?.data;
      if (data?.requiresMfaSetup) {
        try { setMfaInfo(await api.auth.setupMfa()); setStage("setup"); }
        catch (setupError) { setError(errorMessage(setupError, "Multi-factor setup could not be started.")); }
      } else if (data?.requiresMfa) { setStage("challenge"); setNotice("Enter the current code from your authenticator to continue."); }
      else if (data?.deviceApprovalRequired) navigate("/device-verification", { state: { email, portal }, replace: true });
      else setError(errorMessage(err, "Unable to sign in. Check your details and try again."));
    } finally { setBusy(false); }
  };
  const submitCode = async (event) => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = stage === "setup" ? await api.auth.confirmMfa(code) : await api.auth.verifyMfa(code);
      if (stage === "setup" && result?.recoveryCodes?.length) {
        setMfaResult(result);
        setRecoveryCodes(result.recoveryCodes);
        setStage("recovery");
        return;
      }
      await completeMfaFlow(result);
    } catch (err) { setError(errorMessage(err, "That verification code could not be confirmed.")); }
    finally { setBusy(false); }
  };
  const acknowledgeRecoveryCodes = async () => {
    if (!recoveryAcknowledged) return;
    setBusy(true); setError("");
    try { await completeMfaFlow(mfaResult); }
    catch (err) { setError(errorMessage(err, "Your session could not be verified. Sign in again.")); }
    finally { setBusy(false); }
  };
  return <AuthFrame portal={portal} label="Secure sign-in">
    <section className="auth-card">
      <div className="eyebrow">{stage === "login" ? portalName : "Additional verification"}</div>
      <h1>{stage === "login" ? "Welcome back." : stage === "setup" ? "Secure your account." : "Verify your identity."}</h1>
      <p className="subheading">{stage === "login" ? "Sign in to continue to your identity console." : stage === "setup" ? "Set up multi-factor authentication before proceeding." : stage === "recovery" ? "Save these recovery codes somewhere private. They are shown only once." : "A second factor is required before access can be checked."}</p>
      <Notice type="error">{error}</Notice><Notice>{notice}</Notice>
      {stage === "login" ? <form className="auth-form" onSubmit={submit}>
        <div className="form-field"><label htmlFor="email">Institutional email</label><input className="field" id="email" type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@college.edu" /></div>
        <div className="form-field"><label htmlFor="password">Password</label><input className="field" id="password" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Your password" /></div>
        <button className="btn btn-primary" disabled={busy}>{busy ? "Verifying..." : <>Continue securely <ArrowRight size={15} /></>}</button>
      </form> : stage === "setup" ? <form className="auth-form" onSubmit={submitCode}>
        {(mfaInfo?.qrCodeDataUrl || mfaInfo?.manualEntryKey) && <div className="device-banner"><ShieldCheck size={20} /><p><strong>Authenticator setup</strong>{mfaInfo.qrCodeDataUrl ? <img src={mfaInfo.qrCodeDataUrl} alt="Authenticator setup QR code" style={{ display: "block", maxWidth: 180, marginTop: 10 }} /> : null}{mfaInfo.manualEntryKey ? <span className="mono" style={{ display: "block", marginTop: 8 }}>Manual key: {mfaInfo.manualEntryKey}</span> : null}</p></div>}
        <div className="form-field"><label htmlFor="mfa-code">Authenticator code</label><input className="field code-input" id="mfa-code" inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} placeholder="000000" /></div>
        <button className="btn btn-primary" disabled={busy}>{busy ? "Confirming..." : "Confirm and continue"}</button>
      </form> : stage === "recovery" ? <div className="auth-form">
        <div className="resource-content" style={{ fontFamily: "'DM Mono', monospace", fontSize: 13 }}>{recoveryCodes.join("\n")}</div>
        <label style={{ display: "flex", alignItems: "center", gap: 9, fontSize: 12, color: "#53655c" }}><input type="checkbox" checked={recoveryAcknowledged} onChange={(e) => setRecoveryAcknowledged(e.target.checked)} /> I have saved these recovery codes.</label>
        <button className="btn btn-primary" disabled={!recoveryAcknowledged || busy} onClick={acknowledgeRecoveryCodes}>{busy ? "Verifying..." : "Continue to console"}</button>
      </div> : <form className="auth-form" onSubmit={submitCode}>
        <div className="form-field"><label htmlFor="challenge-code">6-digit code</label><input className="field code-input" id="challenge-code" inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} placeholder="000000" /></div>
        <button className="btn btn-primary" disabled={busy}>{busy ? "Checking..." : "Verify code"}</button>
      </form>}
      {stage === "login" && <p className="auth-switch">Need an account? <Link to="/register">Request access</Link></p>}
      {stage !== "login" && stage !== "recovery" && <button className="btn btn-quiet" onClick={() => { setStage("login"); setError(""); setNotice(""); }}><ArrowLeft size={14} /> Back to sign in</button>}
    </section>
  </AuthFrame>;
}

function RegisterPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", departmentId: "" });
  const [departments, setDepartments] = useState([]);
  const [error, setError] = useState(""); const [success, setSuccess] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { api.auth.departments().then((data) => setDepartments(safeArray(data))).catch((err) => setError(errorMessage(err, "Departments could not be loaded."))); }, []);
  const change = (e) => setForm({ ...form, [e.target.name]: e.target.value });
  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setError(""); setSuccess("");
    if (!validPassword(form.password)) { setError("Use at least 12 characters with uppercase, lowercase and a number."); setBusy(false); return; }
    try {
      await api.csrf();
      const result = await api.auth.register({ name: form.name, email: form.email, password: form.password, departmentId: form.departmentId || undefined });
      setSuccess(result?.message || "Account request submitted. Access remains pending until it is reviewed.");
      setTimeout(() => navigate("/employee/login"), 1600);
    } catch (err) { setError(errorMessage(err, "Account registration could not be completed.")); }
    finally { setBusy(false); }
  };
  return <AuthFrame label="Account request"><div className="auth-card">
    <div className="eyebrow">New identity</div><h1>Request access.</h1><p className="subheading">Create an account request for the college demo environment.</p>
    <Notice type="error">{error}</Notice><Notice type="success">{success}</Notice>
    <form className="auth-form" onSubmit={submit}>
      <div className="form-field"><label htmlFor="name">Full name</label><input className="field" id="name" name="name" required value={form.name} onChange={change} /></div>
      <div className="form-field"><label htmlFor="reg-email">Institutional email</label><input className="field" id="reg-email" name="email" type="email" required value={form.email} onChange={change} /></div>
      <div className="form-field"><label htmlFor="reg-password">Password</label><input className="field" id="reg-password" name="password" type="password" minLength="12" required value={form.password} onChange={change} /><span className="panel-note">12+ characters with uppercase, lowercase and a number.</span></div>
      <div className="form-field"><label htmlFor="departmentId">Department</label><select className="select" id="departmentId" name="departmentId" value={form.departmentId} onChange={change}><option value="">Select department</option>{departments.map((d) => <option key={d.id || d._id} value={d.id || d._id}>{d.name}</option>)}</select></div>
      <button className="btn btn-primary" disabled={busy}>{busy ? "Submitting..." : <>Submit request <ArrowRight size={15} /></>}</button>
    </form>
    <p className="auth-switch">Already have access? <Link to="/employee/login">Sign in</Link></p>
  </div></AuthFrame>;
}

function DeviceVerificationPage() {
  const [status, setStatus] = useState(null); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  const [completing, setCompleting] = useState(false);
  const navigate = useNavigate();
  const refresh = useCallback(async () => {
    try { setStatus(await api.auth.deviceStatus()); setError(""); } catch (err) { setError(errorMessage(err, "Device verification status is unavailable.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);
  const currentStatus = String(status?.status || "").toUpperCase();
  const continueToPortal = async () => {
    setCompleting(true); setError("");
    try {
      await api.auth.completeDeviceVerification();
      const me = await api.auth.me();
      const role = normalizeRole(me?.user?.role || me?.role);
      if (!ROLE_HOME[role]) throw new Error("The identity service did not authorize a valid role.");
      navigate(ROLE_HOME[role], { replace: true });
    } catch (err) { setError(errorMessage(err, "Device verification could not be completed.")); }
    finally { setCompleting(false); }
  };
  return <div className="portal-page"><nav className="portal-nav"><Link to="/"><Brand light /></Link><Link className="portal-nav-link" to="/">Return home</Link></nav>
    <div className="verify-wrap"><div className="verify-card panel">
      <div className="eyebrow">Device posture check</div><h1>One more boundary.</h1><p className="subheading">This device must be approved before the account can be authorized.</p>
      <Notice type="error">{error}</Notice>
      {loading && !status ? <LoadingRows /> : <><div className="device-banner"><Smartphone size={20} /><p><strong>{status?.deviceName || "Current device"}</strong>Approval state is checked automatically while this page is open.</p></div>
        <div className="security-item"><strong>Approval status</strong><span className={`status ${statusClass(currentStatus || "pending")}`}>{currentStatus || "PENDING"}</span></div>
        {currentStatus === "APPROVED" && <Notice type="success">Device approved. Continue to complete verification and establish your session.</Notice>}
      </>}
      <div style={{ display: "flex", gap: 8, marginTop: 20, flexWrap: "wrap" }}><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh status</button>{currentStatus === "APPROVED" && <button className="btn btn-primary" onClick={continueToPortal} disabled={completing}>{completing ? "Verifying..." : <>Continue <ArrowRight size={14} /></>}</button>}</div>
    </div></div>
  </div>;
}

function AppLayout({ user, role, onLogout, children }) {
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

function ForcePasswordPage({ user, onUser }) {
  const [values, setValues] = useState({ currentPassword: "", newPassword: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault(); setError("");
    if (!validPassword(values.newPassword)) {
      setError("New password must be at least 12 characters and include uppercase, lowercase and a number.");
      return;
    }
    setBusy(true);
    try {
      await api.auth.changePassword(values.currentPassword, values.newPassword);
      const response = await api.auth.me();
      const next = response?.user || response;
      if (!next || next.forcePasswordChange) throw new Error("Password change is not yet confirmed by the identity service.");
      onUser(next);
    } catch (err) { setError(errorMessage(err, "Password could not be changed.")); }
    finally { setBusy(false); }
  };
  return <AuthFrame label="Required credential update"><div className="auth-card">
    <div className="eyebrow">Action required · {getName(user)}</div><h1>Update your password.</h1>
    <p className="subheading">Your account must use a new password before protected access can continue.</p>
    <Notice type="error">{error}</Notice>
    <form className="auth-form" onSubmit={submit}>
      <div className="form-field"><label>Current password</label><input className="field" type="password" autoComplete="current-password" required value={values.currentPassword} onChange={(e) => setValues({ ...values, currentPassword: e.target.value })} /></div>
      <div className="form-field"><label>New password</label><input className="field" type="password" autoComplete="new-password" minLength="12" required value={values.newPassword} onChange={(e) => setValues({ ...values, newPassword: e.target.value })} /><span className="panel-note">12+ characters with uppercase, lowercase and a number.</span></div>
      <button className="btn btn-primary" disabled={busy}>{busy ? "Updating..." : "Save new password"}</button>
    </form>
  </div></AuthFrame>;
}

function Guarded({ role, onUser }) {
  const [state, setState] = useState({ loading: true, user: null, error: "" });
  const navigate = useNavigate();
  useEffect(() => {
    let active = true;
    api.auth.me().then(async (res) => {
      const user = res?.user || res;
      if (!active) return;
      if (!user?.role || normalizeRole(user.role) !== role) {
        await api.auth.portalCheck(role);
        setState({ loading: false, user: null, error: "Your account does not have access to this portal." });
        return;
      }
      onUser(user); setState({ loading: false, user, error: "" });
    }).catch((err) => {
      if (!active) return;
      if (err?.response?.status === 401) setState({ loading: false, user: null, error: "" });
      else setState({ loading: false, user: null, error: errorMessage(err, "Unable to verify your session.") });
    });
    return () => { active = false; };
  }, [role, onUser]);
  const logout = async () => {
    try { await api.auth.logout(); } catch { /* session may already be expired */ }
    onUser(null); navigate("/", { replace: true });
  };
  if (state.loading) return <div className="app-shell"><main className="content" style={{ margin: "10vh auto" }}><div className="eyebrow">Checking authorization</div><div className="skeleton" style={{ height: 45, width: 250, marginBottom: 20 }} /><LoadingRows /></main></div>;
  if (!state.user) return state.error ? <div className="auth-main"><div className="auth-card"><Notice type="error">{state.error}</Notice><Link className="btn btn-primary" to={`/${role}/login`}>Sign in to continue</Link></div></div> : <Navigate to={`/${role}/login`} replace />;
  if (state.user.forcePasswordChange) return <ForcePasswordPage user={state.user} onUser={(next) => {
    setState((current) => ({ ...current, user: next }));
    onUser(next);
  }} />;
  return <AppLayout user={state.user} role={role} onLogout={logout}><Routes>
    <Route index element={<DashboardPage role={role} />} />
    <Route path="dashboard" element={<DashboardPage role={role} />} />
    <Route path="users" element={<UsersPage role={role} />} />
    <Route path="roles" element={<RolesPage />} />
    <Route path="devices" element={<DevicesPage role={role} />} />
    <Route path="sessions" element={<SessionsPage role={role} user={state.user} />} />
    <Route path="audit" element={<AuditPage />} />
    <Route path="resources" element={<ResourcesPage role={role} />} />
    <Route path="department" element={<DepartmentPage user={state.user} />} />
    <Route path="employees" element={<UsersPage role={role} />} />
    <Route path="history" element={<SessionsPage role={role} user={state.user} history />} />
    <Route path="security" element={<SecurityPage user={state.user} />} />
    <Route path="settings" element={<SettingsPage user={state.user} />} />
    <Route path="profile" element={<ProfilePage user={state.user} onUser={(next) => {
      const merged = { ...state.user, ...next };
      setState((current) => ({ ...current, user: merged }));
      onUser(merged);
    }} />} />
    <Route path="*" element={<Navigate to={ROLE_HOME[role]} replace />} />
  </Routes></AppLayout>;
}

function PageHeading({ kicker, title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{kicker}</div><h1>{title}</h1><p className="subheading">{description}</p></div>{action}</div>;
}

function Panel({ title, note, children, action, className = "" }) {
  return <section className={`panel ${className}`}><header className="panel-head"><div><h2 className="panel-title">{title}</h2>{note && <div className="panel-note" style={{ marginTop: 5 }}>{note}</div>}</div>{action}</header>{children}</section>;
}

function DashboardPage({ role }) {
  const [data, setData] = useState(null); const [activityData, setActivityData] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
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

const COLUMNS = {
  users: [
    ["name", "Identity"], ["email", "Email"], ["role", "Role"], ["departmentName", "Department"], ["status", "Status"], ["mfaEnabled", "MFA"],
  ],
  devices: [["userName", "Owner"], ["name", "Device"], ["browser", "Browser"], ["operatingSystem", "Operating system"], ["status", "Status"], ["lastActivity", "Last activity"]],
  sessions: [["userName", "Identity"], ["role", "Role"], ["ipAddress", "IP address"], ["deviceName", "Device"], ["status", "Status"], ["lastActivity", "Last activity"]],
  audit: [["eventType", "Event"], ["description", "Description"], ["userName", "Identity"], ["role", "Role"], ["ipAddress", "IP address"], ["status", "Status"], ["createdAt", "Time"]],
  resources: [["name", "Resource"], ["description", "Description"], ["classification", "Classification"], ["departmentName", "Department"], ["allowedRoles", "Allowed roles"], ["active", "Status"]],
};

function DataTable({ rows, columns, empty, renderActions }) {
  if (!rows.length) return <EmptyState title={empty || "No records found"} />;
  return <div className="table-wrap"><table><thead><tr>{columns.map(([, label]) => <th key={label}>{label}</th>)}{renderActions && <th>Actions</th>}</tr></thead><tbody>{rows.map((row, idx) => <tr key={row.id || row._id || idx}>
    {columns.map(([key]) => <td key={key}>{key === "status" || key === "active" ? <span className={`status ${statusClass(key === "active" ? row[key] ? "active" : "inactive" : row[key])}`}>{key === "active" ? row[key] ? "Active" : "Inactive" : row[key] || "Unknown"}</span> : key === "mfaEnabled" ? <span className={`status ${row[key] ? "active" : "pending"}`}>{row[key] ? "Enabled" : "Not set"}</span> : key.toLowerCase().includes("activity") || key === "createdAt" ? <span className="mono">{prettyDate(row[key])}</span> : Array.isArray(row[key]) ? <span>{row[key].join(", ") || "—"}</span> : <span>{row[key] ?? "—"}</span>}</td>)}
    {renderActions && <td><div className="table-actions">{renderActions(row)}</div></td>}
  </tr>)}</tbody></table></div>;
}

function useRemote(load, deps = []) {
  const [rows, setRows] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try { setRows(safeArray(await load())); } catch (err) { setError(errorMessage(err, "The requested records could not be loaded.")); }
    finally { setLoading(false); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { refresh(); }, [refresh]);
  return { rows, setRows, loading, error, refresh, setError };
}

function Modal({ title, description, onClose, children }) {
  return <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}><section className="modal" role="dialog" aria-modal="true" aria-label={title}><header className="modal-header"><div><h2>{title}</h2>{description && <p>{description}</p>}</div><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={16} /></button></header>{children}</section></div>;
}

function UsersPage({ role }) {
  const [query, setQuery] = useState(""); const [modal, setModal] = useState(false); const [editing, setEditing] = useState(null); const [departments, setDepartments] = useState([]);
  const [form, setForm] = useState({ name: "", email: "", role: "EMPLOYEE", status: "ACTIVE", departmentId: "", temporaryPassword: "" }); const [busy, setBusy] = useState(false);
  const [revokeUser, setRevokeUser] = useState(null);
  const { rows, loading, error, refresh, setError } = useRemote(() => api.users.list(), []);
  useEffect(() => { api.departments().then((d) => setDepartments(safeArray(d))).catch(() => {}); }, []);
  const filtered = rows.filter((u) => `${u.name} ${u.email} ${u.role} ${u.departmentName} ${u.status}`.toLowerCase().includes(query.toLowerCase()));
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
    }
    catch (err) { setError(errorMessage(err, `Identity could not be ${editing ? "updated" : "created"}.`)); }
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
  const renderUserActions = (u) => {
    const pending = normalizeStatus(u.status) === "pending";
    if (role === "admin") return <>
      <button className="icon-button" aria-label={`Edit ${u.name}`} title="Edit identity" onClick={() => openEdit(u)}><Pencil size={14} /></button>
      <button className="icon-button" aria-label={`Revoke all sessions for ${u.name}`} title="Revoke all sessions" onClick={() => setRevokeUser(u)}><LogOut size={14} /></button>
      {pending ? <>
        <button className="icon-button" aria-label="Approve identity" title="Approve" onClick={() => review(u, "APPROVE")}><Check size={14} /></button>
        <button className="icon-button" aria-label="Reject identity" title="Reject" onClick={() => review(u, "REJECT")}><X size={14} /></button>
      </> : <button className="icon-button" aria-label="Toggle identity status" title={normalizeStatus(u.status) === "active" ? "Disable identity" : "Enable identity"} onClick={() => updateStatus(u, normalizeStatus(u.status) === "active" ? "DISABLED" : "ACTIVE")}><UserCog size={14} /></button>}
    </>;
    return null;
  };
  return <main className="content">
    <PageHeading kicker={role === "manager" ? "Department scope" : "Identity directory"} title={role === "manager" ? "People in your department." : "User management."} description="Review identity state and manage access requests." action={role === "admin" ? <button className="btn btn-primary" onClick={() => { setEditing(null); setForm({ name: "", email: "", role: "EMPLOYEE", status: "ACTIVE", departmentId: "", temporaryPassword: "" }); setModal(true); }}><Plus size={15} /> Add identity</button> : null} />
    <Notice type="error">{error}</Notice>
    <div className="toolbar"><div style={{ position: "relative", flex: 1 }}><Search size={15} style={{ position: "absolute", top: 11, left: 11, color: "#71807a" }} /><input className="field search-field" aria-label="Search identities" placeholder="Search people, roles or departments" value={query} onChange={(e) => setQuery(e.target.value)} style={{ paddingLeft: 34 }} /></div><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} identities`} note="Changes are recorded by the identity service">
      {loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.users} empty="No identities match your search" renderActions={renderUserActions} />}
    </Panel>
    {modal && <Modal title={editing ? "Edit identity" : "Create an identity"} description="Save user changes through the identity service." onClose={() => { setModal(false); setEditing(null); }}><form onSubmit={saveUser}>
      <div className="form-grid"><div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>{editing ? <div className="form-field"><label>Email · read-only</label><input className="field" type="email" value={editing.email || ""} readOnly /></div> : <div className="form-field"><label>Email</label><input className="field" required type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>}<div className="form-field"><label>Role</label><select className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="EMPLOYEE">Employee</option><option value="MANAGER">Manager</option><option value="ADMIN">Administrator</option></select></div><div className="form-field"><label>Department</label><select className="select" value={form.departmentId} onChange={(e) => setForm({ ...form, departmentId: e.target.value })}><option value="">Select</option>{departments.map((d) => <option key={d.id || d._id} value={d.id || d._id}>{d.name}</option>)}</select></div>{editing ? <div className="form-field"><label>Status</label><select className="select" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}><option value="ACTIVE">Active</option><option value="PENDING">Pending</option><option value="DISABLED">Disabled</option></select></div> : <div className="form-field"><label>Temporary password</label><input className="field" type="password" required minLength="12" value={form.temporaryPassword} onChange={(e) => setForm({ ...form, temporaryPassword: e.target.value })} /><span className="panel-note">12+ characters with uppercase, lowercase and a number.</span></div>}</div>
      <div className="modal-footer"><button type="button" className="btn btn-outline" onClick={() => { setModal(false); setEditing(null); }}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : editing ? "Save changes" : "Create identity"}</button></div>
    </form></Modal>}
    {revokeUser && <Modal title="Revoke all sessions?" description={`${revokeUser.name} · ${revokeUser.email}`} onClose={() => setRevokeUser(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>Every active session for this identity will be revoked by the service.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setRevokeUser(null)}>Cancel</button><button className="btn btn-danger" disabled={busy} onClick={revokeAll}>{busy ? "Revoking..." : "Revoke all sessions"}</button></div></Modal>}
  </main>;
}

function RolesPage() {
  const [roles, setRoles] = useState([]); const [departments, setDepartments] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try { const [r, d] = await Promise.all([api.roles(), api.departments()]); setRoles(safeArray(r)); setDepartments(safeArray(d)); }
    catch (err) { setError(errorMessage(err, "Role reference could not be loaded.")); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  return <main className="content"><PageHeading kicker="Policy reference" title="Roles & permissions." description="Read-only view of role definitions returned by the identity service." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice>
    {loading ? <div className="panel" style={{ padding: 20 }}><LoadingRows /></div> : roles.length ? <section className="panel"><div className="reference-grid">{roles.map((role, i) => <article className="role-card" key={role.id || role.name || i}><div className="eyebrow">{role.scope || "Access role"}</div><h3>{role.name || role.role || "Role"}</h3><p>{role.description || role.summary || "Role definition supplied by the identity service."}</p><div className="role-list">{(role.permissions || role.allowedResources || []).map((p) => <span className="role-pill" key={p}>{typeof p === "string" ? p : p.name || p.key}</span>)}</div></article>)}</div></section> : <EmptyState title="Role catalog unavailable" detail="The service returned no role definitions." icon={FileKey2} />}
    <div style={{ marginTop: 16 }}><Panel title="Departments" note="Organizational scopes available to the service">{departments.length ? <div className="table-wrap"><table><thead><tr><th>Department</th><th>Identifier</th><th>Description</th></tr></thead><tbody>{departments.map((d) => <tr key={d.id || d._id}><td><strong>{d.name}</strong></td><td className="mono">{d.id || d._id}</td><td>{d.description || "—"}</td></tr>)}</tbody></table></div> : <EmptyState title="No departments returned" icon={Building2} />}</Panel></div>
  </main>;
}

function DevicesPage({ role }) {
  const [query, setQuery] = useState(""); const [confirm, setConfirm] = useState(null); const [busy, setBusy] = useState(false);
  const { rows, loading, error, refresh, setError } = useRemote(() => api.devices.list(), []);
  const filtered = rows.filter((r) => `${r.userName} ${r.name} ${r.browser} ${r.operatingSystem} ${r.status}`.toLowerCase().includes(query.toLowerCase()));
  const decide = async (status) => {
    setBusy(true); setError("");
    try { await api.devices.review(confirm.id || confirm._id, status); setConfirm(null); await refresh(); }
    catch (err) { setError(errorMessage(err, "Device review could not be saved.")); }
    finally { setBusy(false); }
  };
  return <main className="content"><PageHeading kicker="Device posture" title="Device approvals." description={role === "manager" ? "Review devices associated with your department." : "Review and control devices requesting organizational access."} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Search devices or owners" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} devices`} note="Approval decisions are recorded server-side">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.devices} empty="No device records found" renderActions={(d) => role === "admin" && normalizeStatus(d.status) === "pending" ? <button className="icon-button" title="Review device" aria-label="Review device" onClick={() => setConfirm(d)}><Eye size={14} /></button> : role === "employee" && normalizeStatus(d.status) !== "revoked" ? <button className="icon-button" title="Revoke this device" aria-label={`Revoke ${d.name}`} onClick={() => setConfirm(d)}><X size={14} /></button> : null} />}</Panel>
    {confirm && <Modal title={role === "admin" ? "Review this device?" : "Revoke this device?"} description={`${confirm.name || "Device"} · ${confirm.userName || "Current account"}`} onClose={() => setConfirm(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>{role === "admin" ? "Approve or reject this device through the identity service. Approval does not replace account or MFA verification." : "This device will no longer be trusted for your account. You may need to verify again on a future sign-in."}</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setConfirm(null)}>Cancel</button>{role === "admin" ? <><button className="btn btn-danger" disabled={busy} onClick={() => decide("REJECTED")}>{busy ? "Saving..." : "Reject device"}</button><button className="btn btn-primary" disabled={busy} onClick={() => decide("APPROVED")}>{busy ? "Saving..." : "Approve device"}</button></> : <button className="btn btn-danger" disabled={busy} onClick={() => decide("REVOKED")}>{busy ? "Revoking..." : "Revoke device"}</button>}</div></Modal>}
  </main>;
}

function SessionsPage({ role, user, history = false }) {
  const [query, setQuery] = useState(""); const [confirm, setConfirm] = useState(null); const [revokeAllOpen, setRevokeAllOpen] = useState(false); const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const { rows, loading, error, refresh, setError } = useRemote(() => history ? api.auth.loginHistory() : api.sessions.list(), [history]);
  const filtered = rows.filter((r) => `${r.userName} ${r.role} ${r.ipAddress} ${r.deviceName} ${r.status} ${r.eventType} ${r.description}`.toLowerCase().includes(query.toLowerCase()));
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
    <Panel title={`${filtered.length} ${history ? "login events" : "session records"}`} note={history ? "Authentication history returned by the identity service" : "Revoking a session immediately removes its access"}>{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={history ? COLUMNS.audit : COLUMNS.sessions} empty="No records returned" renderActions={!history ? (s) => normalizeStatus(s.status) !== "revoked" && <button className="icon-button" title="Revoke session" aria-label="Revoke session" onClick={() => setConfirm(s)}><LogOut size={14} /></button> : undefined} />}</Panel>
    {confirm && <Modal title="Revoke this session?" description={`${confirm.userName || "Identity"} · ${confirm.deviceName || confirm.ipAddress || "Session"}`} onClose={() => setConfirm(null)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>This action will be sent to the identity service and may interrupt the active session.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setConfirm(null)}>Keep session</button><button className="btn btn-danger" disabled={busy} onClick={revoke}>{busy ? "Revoking..." : "Revoke session"}</button></div></Modal>}
    {revokeAllOpen && <Modal title="Revoke all your sessions?" description="You will be signed out of this device." onClose={() => setRevokeAllOpen(false)}><p style={{ color: "#5f7067", fontSize: 12, lineHeight: 1.6 }}>The identity service will revoke every active session tied to your account. This console will return to sign-in afterward.</p><div className="modal-footer"><button className="btn btn-outline" onClick={() => setRevokeAllOpen(false)}>Cancel</button><button className="btn btn-danger" disabled={busy} onClick={revokeAllMine}>{busy ? "Revoking..." : "Revoke all sessions"}</button></div></Modal>}
  </main>;
}

function AuditPage() {
  const [query, setQuery] = useState(""); const { rows, loading, error, refresh } = useRemote(() => api.audit(), []);
  const filtered = rows.filter((r) => `${r.eventType} ${r.description} ${r.userName} ${r.ipAddress} ${r.status}`.toLowerCase().includes(query.toLowerCase()));
  return <main className="content"><PageHeading kicker="Accountability" title="Audit logs." description="A record of access and policy events supplied by the identity service." action={<button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button>} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Filter events" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
    <Panel title={`${filtered.length} audit events`} note="Audit events are read-only">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.audit} empty="No audit events found" />}</Panel>
  </main>;
}

function ResourcesPage({ role }) {
  const [query, setQuery] = useState(""); const [modal, setModal] = useState(false); const [editing, setEditing] = useState(null); const [selected, setSelected] = useState(null); const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" });
  const { rows, loading, error, refresh, setError } = useRemote(() => api.resources.list(), []);
  const filtered = rows.filter((r) => `${r.name} ${r.description} ${r.classification} ${r.departmentName}`.toLowerCase().includes(query.toLowerCase()));
  const [departments, setDepartments] = useState([]);
  useEffect(() => { api.departments().then((d) => setDepartments(safeArray(d))).catch(() => {}); }, []);
  const saveResource = async (e) => {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const data = { name: form.name, description: form.description, classification: form.classification.toUpperCase(), allowedRoles: form.allowedRoles.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean), departmentId: form.departmentId || undefined, active: form.active };
      if (editing) await api.resources.update(editing.id || editing._id, data);
      else await api.resources.create({ ...data, content: form.content });
      setModal(false); setEditing(null); setForm({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" }); await refresh();
    }
    catch (err) { setError(errorMessage(err, `Resource could not be ${editing ? "updated" : "created"}.`)); }
    finally { setBusy(false); }
  };
  const openEdit = (resource) => {
    setEditing(resource);
    setForm({ name: resource.name || "", description: resource.description || "", classification: String(resource.classification || "INTERNAL").toUpperCase(), allowedRoles: (resource.allowedRoles || []).map((r) => String(r).toUpperCase()).join(", "), departmentId: resource.departmentId || "", active: resource.active !== false, content: "" });
    setModal(true);
  };
  const getAccess = async (resource) => {
    setError(""); setSelected({ ...resource, content: null, loading: true });
    try {
      const response = await api.resources.access(resource.id || resource._id);
      setSelected({ ...resource, content: response?.resource?.content ?? response?.resource ?? response?.content ?? response });
    }
    catch (err) { setSelected(null); setError(errorMessage(err, "Resource access was denied or unavailable.")); }
  };
  return <main className="content"><PageHeading kicker="Least privilege" title="Protected resources." description="Resource availability and content access are determined by the identity service." action={role === "admin" ? <button className="btn btn-primary" onClick={() => { setEditing(null); setForm({ name: "", description: "", classification: "INTERNAL", allowedRoles: "EMPLOYEE", departmentId: "", active: true, content: "" }); setModal(true); }}><Plus size={15} /> Add resource</button> : null} />
    <Notice type="error">{error}</Notice><div className="toolbar"><input className="field search-field" placeholder="Search protected resources" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn btn-outline" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
    <Panel title={`${filtered.length} protected resources`} note="A visible listing does not guarantee content access">{loading ? <div style={{ padding: 20 }}><LoadingRows /></div> : <DataTable rows={filtered} columns={COLUMNS.resources} empty="No resources are available" renderActions={(r) => <>{role === "admin" && <button className="icon-button" title="Edit resource" aria-label={`Edit ${r.name}`} onClick={() => openEdit(r)}><Pencil size={14} /></button>}<button className="icon-button" title="Request resource access" aria-label={`Access ${r.name}`} onClick={() => getAccess(r)}><ArrowRight size={14} /></button></>} />}</Panel>
    {role === "employee" && <div className="notice info" style={{ marginTop: 14 }}>Resource access is checked by the server for your verified identity and role. A listed resource may still be restricted.</div>}
    {modal && <Modal title={editing ? "Edit protected resource" : "Add protected resource"} description="Save resource metadata through the service." onClose={() => { setModal(false); setEditing(null); }}><form onSubmit={saveResource}><div className="form-grid">
      <div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
      <div className="form-field"><label>Classification</label><select className="select" value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}><option value="INTERNAL">Internal</option><option value="CONFIDENTIAL">Confidential</option><option value="RESTRICTED">Restricted</option></select></div>
      <div className="form-field"><label>Allowed roles (comma separated)</label><input className="field" required value={form.allowedRoles} onChange={(e) => setForm({ ...form, allowedRoles: e.target.value })} /></div>
      <div className="form-field"><label>Department</label><select className="select" value={form.departmentId} onChange={(e) => setForm({ ...form, departmentId: e.target.value })}><option value="">Institution-wide</option>{departments.map((d) => <option key={d.id || d._id} value={d.id || d._id}>{d.name}</option>)}</select></div>
      <div className="form-field" style={{ gridColumn: "1/-1" }}><label>Description</label><textarea className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
      {!editing && <div className="form-field" style={{ gridColumn: "1/-1" }}><label>Protected content</label><textarea className="textarea" value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} /></div>}
      <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#53655c" }}><input type="checkbox" checked={form.active} onChange={(e) => setForm({ ...form, active: e.target.checked })} /> Resource active</label>
    </div><div className="modal-footer"><button type="button" className="btn btn-outline" onClick={() => { setModal(false); setEditing(null); }}>Cancel</button><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : editing ? "Save changes" : "Create resource"}</button></div></form></Modal>}
    {selected && <Modal title={selected.name} description={selected.description} onClose={() => setSelected(null)}>{selected.loading ? <div className="skeleton" style={{ height: 100 }} /> : <><div className="notice info">Content returned by the resource access endpoint.</div><div className="resource-content">{typeof selected.content === "string" ? selected.content : JSON.stringify(selected.content, null, 2)}</div></>}</Modal>}
  </main>;
}

function DepartmentPage({ user }) {
  const [department, setDepartment] = useState(null); const [members, setMembers] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    Promise.all([api.departments(), api.users.list()]).then(([depts, users]) => {
      if (!active) return;
      const all = safeArray(depts); const id = user.departmentId || user.department?.id || user.department?._id;
      const match = all.find((d) => String(d.id || d._id) === String(id)) || all.find((d) => d.name === user.departmentName);
      setDepartment(match || (user.departmentName ? { name: user.departmentName, id } : null));
      setMembers(id || user.departmentName ? safeArray(users).filter((u) => String(u.departmentId) === String(id) || (user.departmentName && u.departmentName === user.departmentName)) : []);
    }).catch((err) => { if (active) setError(errorMessage(err, "Department details could not be loaded.")); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user]);
  return <main className="content"><PageHeading kicker="Organizational scope" title={department?.name || user.departmentName || "Department overview."} description="Department details and people available within your current manager scope." />
    <Notice type="error">{error}</Notice>{loading ? <div className="panel" style={{ padding: 20 }}><LoadingRows /></div> : <><div className="metric-grid"><div className="panel metric-card"><div className="metric-label">Department identity</div><div className="metric-value" style={{ fontSize: 20 }}>{department?.name || "Not assigned"}</div><div className="metric-foot">Service-sourced organization</div></div><div className="panel metric-card"><div className="metric-label">People in scope</div><div className="metric-value">{members.length}</div><div className="metric-foot">Users returned for this department</div></div></div><Panel title="Department directory" note="No cross-department data is presented">{members.length ? <DataTable rows={members} columns={COLUMNS.users} /> : <EmptyState title="No department members returned" detail="The service did not return identities in this scope." icon={Users} />}</Panel></>}</main>;
}

function ProfilePage({ user, onUser }) {
  const [form, setForm] = useState({ name: user.name || "", email: user.email || "" }); const [busy, setBusy] = useState(false); const [error, setError] = useState(""); const [success, setSuccess] = useState("");
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
  const save = async (e) => {
    e.preventDefault(); setBusy(true); setError(""); setSuccess("");
    try { const result = await api.profile.update({ name: form.name }); const next = result?.profile || result?.user || result; onUser(next); setSuccess("Profile changes saved."); }
    catch (err) { setError(errorMessage(err, "Profile could not be updated.")); }
    finally { setBusy(false); }
  };
  const [passwords, setPasswords] = useState({ current: "", next: "" }); const [pwMessage, setPwMessage] = useState(""); const [pwError, setPwError] = useState("");
  const changePassword = async (e) => {
    e.preventDefault(); setPwMessage(""); setPwError("");
    if (!validPassword(passwords.next)) { setPwError("New password must be at least 12 characters and include uppercase, lowercase and a number."); return; }
    try { await api.auth.changePassword(passwords.current, passwords.next); setPasswords({ current: "", next: "" }); setPwMessage("Password updated by the identity service."); }
    catch (err) { setPwError(errorMessage(err, "Password could not be changed.")); }
  };
  return <main className="content"><PageHeading kicker="Personal identity" title="Profile & credentials." description="Maintain your account details and password through the identity service." />
    <div className="profile-layout"><section className="panel profile-card"><div className="profile-portrait">{initials(getName(user))}</div><h2 className="panel-title" style={{ fontSize: 17 }}>{getName(user)}</h2><p className="subheading">{user.email}</p><div className="security-list" style={{ marginTop: 20 }}><div className="security-item"><strong>Role</strong><span>{ROLE_LABEL[normalizeRole(user.role)] || user.role}</span></div><div className="security-item"><strong>Department</strong><span>{user.departmentName || "—"}</span></div><div className="security-item"><strong>MFA</strong><span>{user.mfaEnabled ? "Enabled" : "Not enabled"}</span></div></div></section>
      <div style={{ display: "grid", gap: 15 }}><Panel title="Profile details"><div style={{ padding: 20 }}><Notice type="error">{profileError || error}</Notice><Notice type="success">{success}</Notice>{profileLoading ? <LoadingRows /> : <form onSubmit={save} className="auth-form"><div className="form-field"><label>Name</label><input className="field" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div><div className="form-field"><label>Email · read-only</label><input className="field" type="email" value={form.email} readOnly /></div><button className="btn btn-primary" disabled={busy}>{busy ? "Saving..." : "Save profile"}</button></form>}</div></Panel>
      <Panel title="Change password" note="12+ characters with uppercase, lowercase and a number"><div style={{ padding: 20 }}><Notice type="error">{pwError}</Notice><Notice type="success">{pwMessage}</Notice><form className="auth-form" onSubmit={changePassword}><div className="form-field"><label>Current password</label><input className="field" type="password" autoComplete="current-password" required value={passwords.current} onChange={(e) => setPasswords({ ...passwords, current: e.target.value })} /></div><div className="form-field"><label>New password</label><input className="field" type="password" minLength="12" autoComplete="new-password" required value={passwords.next} onChange={(e) => setPasswords({ ...passwords, next: e.target.value })} /></div><button className="btn btn-outline">Update password</button></form></div></Panel></div>
    </div></main>;
}

function SecurityPage({ user }) {
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

function SettingsPage({ user }) {
  return <main className="content"><PageHeading kicker="Console configuration" title="Settings." description="Review account and session controls available in this environment." />
    <div className="dashboard-grid"><Panel title="Session security" note="Service-enforced controls"><div style={{ padding: 20 }} className="security-list"><div className="security-item"><strong>Current session</strong><span className="status active">Verified</span></div><div className="security-item"><strong>Role boundary</strong><span>{ROLE_LABEL[normalizeRole(user.role)] || user.role}</span></div><div className="security-item"><strong>Cross-role access</strong><span>Denied by portal guard</span></div><div className="security-item"><strong>Account MFA</strong><span>{user.mfaEnabled ? "Enabled" : "Not enabled"}</span></div></div></Panel>
      <Panel title="Access principles" note="This demo preserves the authorization boundary"><div style={{ padding: 20, display: "grid", gap: 16 }}><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Verify explicitly</div><div className="activity-meta">Sign-in, device posture and role are checked before portal entry.</div></div></div><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Least privilege</div><div className="activity-meta">Resource endpoints enforce authorization independently.</div></div></div><div className="activity-row"><div className="activity-dot" /><div><div className="activity-title">Use real service responses</div><div className="activity-meta">Unavailable operations are reported rather than simulated.</div></div></div></div></Panel></div>
  </main>;
}

function App() {
  const [user, setUser] = useState(null);
  const updateUser = useCallback((next) => setUser(next), []);
  useEffect(() => { api.csrf().catch(() => {}); }, []);
  return <Routes>
    <Route path="/" element={<PortalHome />} />
    <Route path="/admin/login" element={<LoginPage portal="admin" />} />
    <Route path="/manager/login" element={<LoginPage portal="manager" />} />
    <Route path="/employee/login" element={<LoginPage portal="employee" />} />
    <Route path="/register" element={<RegisterPage />} />
    <Route path="/device-verification" element={<DeviceVerificationPage />} />
    <Route path="/admin/*" element={<Guarded role="admin" onUser={updateUser} />} />
    <Route path="/manager/*" element={<Guarded role="manager" onUser={updateUser} />} />
    <Route path="/employee/*" element={<Guarded role="employee" onUser={updateUser} />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}

export default App;

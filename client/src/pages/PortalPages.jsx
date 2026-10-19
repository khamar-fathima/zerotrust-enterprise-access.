import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowLeft, ArrowRight, Building2, Database, Fingerprint, Laptop, LockKeyhole,
  RefreshCw, ShieldCheck, Smartphone, UserCog, UserRound,
} from "lucide-react";
import { api } from "../lib/api.js";
import {
  errorMessage, normalizeRole, ROLE_HOME, ROLE_LABEL, safeArray, statusClass, validPassword,
} from "../lib/identity.js";
import { AuthFrame, Brand, LoadingRows, Notice } from "../components/Shared.jsx";

export function PortalHome() {
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

export function LoginPage({ portal }) {
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

export function RegisterPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", departmentId: "" });
  const [departments, setDepartments] = useState([]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busy, setBusy] = useState(false);
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

export function DeviceVerificationPage() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [completing, setCompleting] = useState(false);
  const navigate = useNavigate();
  const refresh = useCallback(async () => {
    try { setStatus(await api.auth.deviceStatus()); setError(""); }
    catch (err) { setError(errorMessage(err, "Device verification status is unavailable.")); }
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

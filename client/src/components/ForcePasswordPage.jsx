import { useState } from "react";
import { api } from "../lib/api.js";
import { errorMessage, getName, validPassword } from "../lib/identity.js";
import { AuthFrame, Notice } from "./Shared.jsx";

export default function ForcePasswordPage({ user, onUser }) {
  const [values, setValues] = useState({ currentPassword: "", newPassword: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setError("");
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
    } catch (err) {
      setError(errorMessage(err, "Password could not be changed."));
    } finally {
      setBusy(false);
    }
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

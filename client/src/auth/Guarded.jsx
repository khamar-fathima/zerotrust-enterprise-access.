import { lazy, Suspense, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import {
  errorMessage, normalizeRole, ROLE_HOME,
} from "../lib/identity.js";
import { LoadingRows, Notice, PageLoading } from "../components/Shared.jsx";
import AppLayout from "../components/AppLayout.jsx";
import ForcePasswordPage from "../components/ForcePasswordPage.jsx";

const DashboardPage = lazy(() => import("../pages/console/DashboardPage.jsx"));
const UsersPage = lazy(() => import("../pages/console/UsersPage.jsx"));
const RolesPage = lazy(() => import("../pages/console/ReferencePages.jsx").then((module) => ({ default: module.RolesPage })));
const DevicesPage = lazy(() => import("../pages/console/ReferencePages.jsx").then((module) => ({ default: module.DevicesPage })));
const SessionsPage = lazy(() => import("../pages/console/ReferencePages.jsx").then((module) => ({ default: module.SessionsPage })));
const AuditPage = lazy(() => import("../pages/console/ReferencePages.jsx").then((module) => ({ default: module.AuditPage })));
const ResourcesPage = lazy(() => import("../pages/console/ResourcesPage.jsx"));
const DepartmentPage = lazy(() => import("../pages/console/AccountPages.jsx").then((module) => ({ default: module.DepartmentPage })));
const ProfilePage = lazy(() => import("../pages/console/AccountPages.jsx").then((module) => ({ default: module.ProfilePage })));
const SecurityPage = lazy(() => import("../pages/console/AccountPages.jsx").then((module) => ({ default: module.SecurityPage })));
const SettingsPage = lazy(() => import("../pages/console/AccountPages.jsx").then((module) => ({ default: module.SettingsPage })));

export default function Guarded({ role, onUser }) {
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
      onUser(user);
      setState({ loading: false, user, error: "" });
    }).catch((err) => {
      if (!active) return;
      if (err?.response?.status === 401) setState({ loading: false, user: null, error: "" });
      else setState({ loading: false, user: null, error: errorMessage(err, "Unable to verify your session.") });
    });
    return () => { active = false; };
  }, [role, onUser]);

  const logout = async () => {
    try { await api.auth.logout(); } catch { /* session may already be expired */ }
    onUser(null);
    navigate("/", { replace: true });
  };

  if (state.loading) return <div className="app-shell"><main className="content" style={{ margin: "10vh auto" }}><div className="eyebrow">Checking authorization</div><div className="skeleton" style={{ height: 45, width: 250, marginBottom: 20 }} /><LoadingRows /></main></div>;
  if (!state.user) return state.error ? <div className="auth-main"><div className="auth-card"><Notice type="error">{state.error}</Notice><Link className="btn btn-primary" to={`/${role}/login`}>Sign in to continue</Link></div></div> : <Navigate to={`/${role}/login`} replace />;
  if (state.user.forcePasswordChange) return <ForcePasswordPage user={state.user} onUser={(next) => {
    setState((current) => ({ ...current, user: next }));
    onUser(next);
  }} />;

  const updateProfile = (next) => {
    const merged = { ...state.user, ...next };
    setState((current) => ({ ...current, user: merged }));
    onUser(merged);
  };

  return <AppLayout user={state.user} role={role} onLogout={logout}>
    <Suspense fallback={<PageLoading />}>
      <Routes>
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
        <Route path="profile" element={<ProfilePage user={state.user} onUser={updateProfile} />} />
        <Route path="*" element={<Navigate to={ROLE_HOME[role]} replace />} />
      </Routes>
    </Suspense>
  </AppLayout>;
}

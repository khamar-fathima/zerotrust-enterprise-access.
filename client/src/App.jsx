import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api } from "./lib/api.js";
import Guarded from "./auth/Guarded.jsx";
import {
  DeviceVerificationPage, LoginPage, PortalHome, RegisterPage,
} from "./pages/PortalPages.jsx";

export default function App() {
  const [, setUser] = useState(null);
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

import axios from "axios";

const http = axios.create({
  baseURL: "/api",
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

function readCookie(name) {
  const row = document.cookie.split("; ").find((item) => item.startsWith(`${name}=`));
  return row ? decodeURIComponent(row.split("=").slice(1).join("=")) : "";
}

http.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (!["get", "head", "options"].includes(method)) {
    const token = readCookie("zt_csrf");
    if (token) config.headers["X-CSRF-Token"] = token;
  }
  return config;
});

const request = async (promise) => (await promise).data;

export const api = {
  csrf: () => request(http.get("/auth/csrf")),
  auth: {
    login: (portal, credentials) => request(http.post("/auth/login", { portal, ...credentials })),
    register: (details) => request(http.post("/auth/register", details)),
    me: () => request(http.get("/auth/me")),
    portalCheck: (portal) => request(http.get(`/auth/portal/${portal}`)),
    logout: () => request(http.post("/auth/logout")),
    setupMfa: () => request(http.post("/auth/mfa/setup")),
    confirmMfa: (code) => request(http.post("/auth/mfa/confirm", { code })),
    verifyMfa: (code) => request(http.post("/auth/mfa/verify", { code })),
    deviceStatus: () => request(http.get("/auth/device-status")),
    completeDeviceVerification: () => request(http.post("/auth/device/complete")),
    departments: () => request(http.get("/auth/departments")),
    disableMfa: (password, code) => request(http.post("/auth/mfa/disable", { password, code })),
    loginHistory: () => request(http.get("/profile/login-history")),
    changePassword: (currentPassword, newPassword) => request(http.post("/auth/change-password", { currentPassword, newPassword })),
  },
  dashboard: {
    summary: () => request(http.get("/dashboard/summary")),
    activity: (range = "7d") => request(http.get("/dashboard/activity", { params: { range } })),
    riskAnalysis: () => request(http.get("/dashboard/risk-analysis")),
    riskAnalysisHistory: (params) => request(http.get("/dashboard/risk-analysis/history", { params })),
    riskAnalysisAccounts: (q) => request(http.get("/dashboard/risk-analysis/accounts", { params: q ? { q } : {} })),
    riskAnalysisEvidence: (params) => request(http.get("/dashboard/risk-analysis/evidence", { params })),
    generateRiskAnalysis: () => request(http.post("/dashboard/risk-analysis")),
  },
  users: {
    list: (params, options = {}) => request(http.get("/users", { ...options, params })),
    create: (data) => request(http.post("/users", data)),
    update: (id, data) => request(http.patch(`/users/${id}`, data)),
    review: (id, decision) => request(http.post(`/users/${id}/review`, { decision })),
  },
  roles: () => request(http.get("/roles")),
  departments: () => request(http.get("/departments")),
  devices: {
    list: (params, options = {}) => request(http.get("/devices", { ...options, params })),
    review: (id, status) => request(http.patch(`/devices/${id}`, { status })),
  },
  sessions: {
    list: (params, options = {}) => request(http.get("/sessions", { ...options, params })),
    revoke: (id) => request(http.delete(`/sessions/${id}`)),
    revokeAll: (userId) => request(http.post("/sessions/revoke-all", { userId })),
  },
  audit: (params, options = {}) => request(http.get("/audit-logs", { ...options, params })),
  resources: {
    list: () => request(http.get("/resources")),
    create: (data) => request(http.post("/resources", data)),
    update: (id, data) => request(http.patch(`/resources/${id}`, data)),
    access: (id) => request(http.get(`/resources/${id}/content`)),
  },
  profile: {
    get: () => request(http.get("/profile")),
    update: (data) => request(http.patch("/profile", data)),
  },
  http,
};

export { http };

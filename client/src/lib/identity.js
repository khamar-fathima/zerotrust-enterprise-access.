import {
  Building2, ClipboardList, Database, FileKey2, History, Laptop, LayoutDashboard,
  MonitorCog, Settings, ShieldCheck, UserRound, Users,
} from "lucide-react";

export const ROLE_HOME = {
  admin: "/admin/dashboard",
  manager: "/manager/dashboard",
  employee: "/employee/dashboard",
};

export const ROLE_LABEL = {
  admin: "Administrator",
  manager: "Department manager",
  employee: "Employee",
};

export const ROLE_NAV = {
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

export const ROLE_TITLES = {
  admin: "Identity control",
  manager: "Department access",
  employee: "My access",
};

export const COLUMNS = {
  users: [
    ["name", "Identity"], ["email", "Email"], ["role", "Role"],
    ["departmentName", "Department"], ["status", "Status"], ["mfaEnabled", "MFA"],
  ],
  devices: [
    ["userName", "Owner"], ["name", "Device"], ["browser", "Browser"],
    ["operatingSystem", "Operating system"], ["status", "Status"], ["lastActivity", "Last activity"],
  ],
  sessions: [
    ["userName", "Identity"], ["role", "Role"], ["ipAddress", "IP address"],
    ["deviceName", "Device"], ["status", "Status"], ["lastActivity", "Last activity"],
  ],
  audit: [
    ["eventType", "Event"], ["description", "Description"], ["userName", "Identity"],
    ["role", "Role"], ["ipAddress", "IP address"], ["status", "Status"], ["createdAt", "Time"],
  ],
  resources: [
    ["name", "Resource"], ["description", "Description"], ["classification", "Classification"],
    ["departmentName", "Department"], ["allowedRoles", "Allowed roles"], ["active", "Status"],
  ],
};

export const safeArray = (value) => {
  if (Array.isArray(value)) return value;
  for (const key of ["users", "devices", "sessions", "logs", "roles", "departments", "resources", "items", "data", "activity"]) {
    if (Array.isArray(value?.[key])) return value[key];
  }
  return [];
};

export const normalizeRole = (value) => String(value || "").toLowerCase();
export const normalizeStatus = (value) => String(value || "").toLowerCase();
export const errorMessage = (err, fallback) => err?.response?.data?.error || err?.response?.data?.message || err?.message || fallback;
export const validPassword = (value) => value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value);
export const getName = (user) => user?.name || user?.email || "Account";
export const initials = (name = "") => name.split(/\s+/).filter(Boolean).slice(0, 2).map((s) => s[0]).join("").toUpperCase() || "ZT";
export const prettyDate = (date) => date ? new Date(date).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
export const statusClass = (status = "") => String(status).toLowerCase().replace(/\s+/g, "-");

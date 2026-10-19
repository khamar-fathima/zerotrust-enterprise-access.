import bcrypt from "bcryptjs";
import { Department, Permission, Resource, Role, User } from "../models/index.js";

const permissions = [
  ["users:read", "View users", "Users"],
  ["users:manage", "Manage users and roles", "Users"],
  ["devices:manage", "Approve or revoke devices", "Security"],
  ["sessions:read", "View active sessions", "Security"],
  ["sessions:revoke", "Revoke sessions", "Security"],
  ["audit:read", "Read security audit events", "Security"],
  ["resources:manage", "Manage protected resources", "Resources"],
  ["resources:read", "Access authorized resources", "Resources"],
  ["department:read", "View assigned department", "Department"],
];

const roles = [
  {
    key: "ADMIN",
    label: "Administrator",
    description: "Organization-wide identity, access, device, and security oversight.",
    permissions: permissions.map(([key]) => key),
  },
  {
    key: "MANAGER",
    label: "Manager",
    description: "Department-scoped employee and resource access.",
    permissions: ["resources:read", "department:read", "sessions:read"],
  },
  {
    key: "EMPLOYEE",
    label: "Employee",
    description: "Personal profile, sessions, devices, and assigned resources.",
    permissions: ["resources:read", "sessions:read"],
  },
];

export async function seedBaseData() {
  for (const [key, label, group] of permissions) {
    await Permission.updateOne({ key }, { $setOnInsert: { key, label, group, description: "" } }, { upsert: true });
  }
  for (const role of roles) {
    await Role.updateOne({ key: role.key }, { $set: { ...role, systemRole: true } }, { upsert: true });
  }
  const departmentDocs = await Promise.all(
    ["Engineering", "Operations", "People"].map((name) =>
      Department.findOneAndUpdate({ name }, { $setOnInsert: { name, description: `${name} department` } }, { upsert: true, returnDocument: "after" }),
    ),
  );
  const engineering = departmentDocs.find((dept) => dept.name === "Engineering");
  const examples = [
    {
      name: "Employee handbook",
      description: "Policies and guidance for all team members.",
      classification: "INTERNAL",
      content: "Employee Handbook\\n\\nThis protected resource is available to all active employees. Use least privilege and report suspicious access attempts to your administrator.",
      allowedRoles: ["ADMIN", "MANAGER", "EMPLOYEE"],
    },
    {
      name: "Department operations report",
      description: "Department-level operational notes for authorized staff.",
      classification: "CONFIDENTIAL",
      content: "Operations Report\\n\\nThis sample report is restricted to authorized managers and administrators.",
      allowedRoles: ["ADMIN", "MANAGER"],
    },
    {
      name: "Administrator security brief",
      description: "Restricted security operations information.",
      classification: "RESTRICTED",
      content: "Security Brief\\n\\nThis sample resource is restricted to administrators.",
      allowedRoles: ["ADMIN"],
    },
  ];
  for (const resource of examples) {
    await Resource.updateOne({ name: resource.name }, { $setOnInsert: { ...resource, departmentId: engineering?._id || null } }, { upsert: true });
  }
  const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  const validBootstrap = email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && password?.length >= 12 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password);
  if ((email || password) && !validBootstrap) {
    console.error("[bootstrap] Configure both an email and a password of at least 12 characters with uppercase, lowercase, and a digit.");
  }
  if (validBootstrap) {
    const exists = await User.exists({ role: "ADMIN", status: "ACTIVE" });
    if (!exists) {
      const passwordHash = await bcrypt.hash(password, 12);
      await User.create({
        name: "Security Administrator",
        email,
        passwordHash,
        role: "ADMIN",
        status: "ACTIVE",
        isBootstrapAdmin: true,
        bootstrapDeviceUsed: false,
        forcePasswordChange: true,
      });
      console.info("[db] The first administrator was bootstrapped; password change and MFA enrollment are required.");
    }
  }
}

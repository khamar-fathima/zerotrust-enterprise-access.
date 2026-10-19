import { AuditLog } from "../models/index.js";
import { requestContext } from "./security.js";

const sensitiveKeys = /password|otp|token|secret|recovery|credential|cookie|authorization/i;

function safeMetadata(value) {
  if (!value || typeof value !== "object") return {};
  return Object.fromEntries(Object.entries(value).filter(([key]) => !sensitiveKeys.test(key)).slice(0, 20));
}

export async function writeAudit(req, { eventType, description, status = "SUCCESS", user = null, metadata = {} }) {
  const context = requestContext(req);
  await AuditLog.create({
    eventType,
    description: String(description).slice(0, 500),
    userId: user?._id || null,
    userName: user?.name || "",
    role: user?.role || "",
    ipAddress: context.ipAddress,
    status,
    metadata: safeMetadata(metadata),
  });
}

export function auditFailure(req, options) {
  writeAudit(req, options).catch((error) => console.error("[audit] Could not persist security event:", error.message));
}

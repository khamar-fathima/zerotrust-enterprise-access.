import mongoose from "mongoose";

const { Schema, model, models } = mongoose;
const timestamps = { timestamps: true };

const userSchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["ADMIN", "MANAGER", "EMPLOYEE"], required: true, index: true },
  status: { type: String, enum: ["PENDING", "ACTIVE", "DISABLED", "REJECTED"], default: "PENDING", index: true },
  departmentId: { type: Schema.Types.ObjectId, ref: "Department", default: null, index: true },
  mfaEnabled: { type: Boolean, default: false },
  mfaSecretEncrypted: { type: String, default: "" },
  recoveryCodeHashes: { type: [String], default: [] },
  forcePasswordChange: { type: Boolean, default: false },
  isBootstrapAdmin: { type: Boolean, default: false },
  bootstrapDeviceUsed: { type: Boolean, default: false },
  lastLoginAt: { type: Date, default: null },
  rejectedReason: { type: String, default: "" },
}, timestamps);
userSchema.index({ departmentId: 1, role: 1, status: 1 });
userSchema.index({ createdAt: -1, _id: -1 });
userSchema.index({ departmentId: 1, role: 1, status: 1, name: 1, _id: 1 });
userSchema.pre(["deleteOne", "deleteMany", "findOneAndDelete"], async function () {
  const deletedUsers = await this.model.find(this.getFilter()).select("_id").lean();
  this._riskHistoryUserIds = deletedUsers.map((user) => user._id);
});
userSchema.post(["deleteOne", "deleteMany", "findOneAndDelete"], async function () {
  const deletedIds = this._riskHistoryUserIds || [];
  if (!deletedIds.length || !models.RiskHistory) return;
  await models.RiskHistory.updateMany({}, { $pull: { accounts: { userId: { $in: deletedIds } } } });
});
userSchema.post("deleteOne", { document: true, query: false }, async function () {
  if (models.RiskHistory) {
    await models.RiskHistory.updateMany({}, { $pull: { accounts: { userId: this._id } } });
  }
});

const roleSchema = new Schema({
  key: { type: String, required: true, unique: true },
  label: { type: String, required: true },
  description: { type: String, default: "" },
  permissions: [{ type: String }],
  systemRole: { type: Boolean, default: true },
}, timestamps);

const permissionSchema = new Schema({
  key: { type: String, required: true, unique: true },
  label: { type: String, required: true },
  description: { type: String, default: "" },
  group: { type: String, default: "General" },
}, timestamps);

const departmentSchema = new Schema({
  name: { type: String, required: true, unique: true, trim: true },
  description: { type: String, default: "" },
}, timestamps);

const deviceSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  name: { type: String, default: "Unrecognized device" },
  browser: { type: String, default: "Unknown browser" },
  operatingSystem: { type: String, default: "Unknown OS" },
  credentialHash: { type: String, required: true, unique: true, select: false },
  status: { type: String, enum: ["PENDING", "APPROVED", "REVOKED"], default: "PENDING", index: true },
  ipAddress: { type: String, default: "" },
  lastActivity: { type: Date, default: Date.now },
  approvedAt: { type: Date, default: null },
  approvedBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
}, timestamps);
deviceSchema.index({ userId: 1, status: 1 });

const sessionSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  deviceId: { type: Schema.Types.ObjectId, ref: "Device", required: true },
  roleAtIssue: { type: String, required: true },
  ipAddress: { type: String, default: "" },
  browser: { type: String, default: "Unknown browser" },
  status: { type: String, enum: ["ACTIVE", "EXPIRED", "REVOKED"], default: "ACTIVE", index: true },
  lastActivity: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: true },
  revokedAt: { type: Date, default: null },
  revokeReason: { type: String, default: "" },
}, timestamps);
sessionSchema.index({ userId: 1, status: 1 });

const auditLogSchema = new Schema({
  eventType: { type: String, required: true, index: true },
  description: { type: String, required: true },
  userId: { type: Schema.Types.ObjectId, ref: "User", default: null, index: true },
  userName: { type: String, default: "" },
  role: { type: String, default: "" },
  ipAddress: { type: String, default: "" },
  status: { type: String, enum: ["SUCCESS", "WARNING", "CRITICAL"], default: "SUCCESS", index: true },
  metadata: { type: Schema.Types.Mixed, default: {} },
}, { ...timestamps, versionKey: false });
auditLogSchema.index({ createdAt: -1, eventType: 1 });
auditLogSchema.index({ createdAt: -1, _id: -1 });

const resourceSchema = new Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  description: { type: String, default: "", maxlength: 500 },
  classification: { type: String, enum: ["INTERNAL", "CONFIDENTIAL", "RESTRICTED"], default: "INTERNAL" },
  content: { type: String, required: true },
  allowedRoles: [{ type: String, enum: ["ADMIN", "MANAGER", "EMPLOYEE"] }],
  departmentId: { type: Schema.Types.ObjectId, ref: "Department", default: null },
  active: { type: Boolean, default: true },
  createdBy: { type: Schema.Types.ObjectId, ref: "User", default: null },
}, timestamps);
resourceSchema.index({ active: 1, allowedRoles: 1 });

const preAuthSchema = new Schema({
  challengeHash: { type: String, required: true, unique: true, select: false },
  userId: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  portal: { type: String, enum: ["ADMIN", "MANAGER", "EMPLOYEE"], required: true },
  expiresAt: { type: Date, required: true, expires: 0 },
  mfaSecretEncrypted: { type: String, default: "" },
  mfaVerified: { type: Boolean, default: false },
  deviceId: { type: Schema.Types.ObjectId, ref: "Device", default: null },
}, timestamps);

const riskHistoryAccountSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, required: true },
  score: { type: Number, min: 0, max: 100, required: true },
  factorTotals: [{ key: { type: String, required: true }, points: { type: Number, required: true } }],
}, { _id: false });
const riskHistorySchema = new Schema({
  day: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
  organization: {
    score: { type: Number, min: 0, max: 100, default: null },
    factorTotals: [{ key: String, points: Number }],
  },
  accounts: { type: [riskHistoryAccountSchema], default: [] },
}, { versionKey: false });
riskHistorySchema.index({ day: 1 }, { unique: true });
riskHistorySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const User = models.User || model("User", userSchema);
export const Role = models.Role || model("Role", roleSchema);
export const Permission = models.Permission || model("Permission", permissionSchema);
export const Department = models.Department || model("Department", departmentSchema);
export const Device = models.Device || model("Device", deviceSchema);
export const Session = models.Session || model("Session", sessionSchema);
export const AuditLog = models.AuditLog || model("AuditLog", auditLogSchema);
export const Resource = models.Resource || model("Resource", resourceSchema);
export const PreAuth = models.PreAuth || model("PreAuth", preAuthSchema);
export const RiskHistory = models.RiskHistory || model("RiskHistory", riskHistorySchema);

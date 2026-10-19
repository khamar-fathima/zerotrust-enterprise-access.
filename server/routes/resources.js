import { Router } from "express";
import { z } from "zod";
import { Resource } from "../models/index.js";
import { writeAudit } from "../lib/audit.js";
import { requireAuth, requireRole } from "../middleware/auth.js";

const router = Router();
const resourceSchema = z.object({
  name: z.string().trim().min(2).max(120),
  description: z.string().max(500).default(""),
  classification: z.enum(["INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
  content: z.string().min(1).max(20000),
  allowedRoles: z.array(z.enum(["ADMIN", "MANAGER", "EMPLOYEE"])).min(1),
  departmentId: z.string().nullable().optional(),
  active: z.boolean().optional().default(true),
});

function canAccess(resource, user) {
  if (user.role === "ADMIN") return true;
  if (!resource.active || !resource.allowedRoles.includes(user.role)) return false;
  const departmentId = user.departmentId?._id?.toString() || user.departmentId?.toString() || "";
  const resourceDepartmentId = resource.departmentId?._id?.toString() || resource.departmentId?.toString() || "";
  return !resourceDepartmentId || resourceDepartmentId === departmentId;
}

function publicResource(resource) {
  return {
    id: resource._id,
    name: resource.name,
    description: resource.description,
    classification: resource.classification,
    allowedRoles: resource.allowedRoles,
    departmentId: resource.departmentId?._id || resource.departmentId || null,
    departmentName: resource.departmentId?.name || "",
    active: resource.active,
    content: resource.content,
    createdAt: resource.createdAt,
  };
}

router.get("/resources", requireAuth, async (req, res, next) => {
  try {
    const resources = await Resource.find(req.user.role === "ADMIN" ? {} : { active: true })
      .populate("departmentId", "name")
      .sort({ classification: 1, name: 1 })
      .limit(250);
    res.json({
      resources: resources.filter((resource) => canAccess(resource, req.user)).map((resource) => ({
        ...publicResource(resource),
        content: undefined,
      })),
    });
  } catch (error) { next(error); }
});

router.post("/resources", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    const input = resourceSchema.parse(req.body);
    const resource = await Resource.create({ ...input, createdBy: req.user._id });
    await writeAudit(req, {
      eventType: "RESOURCE_CREATED",
      description: "Administrator created a protected resource.",
      user: req.user,
      metadata: { resourceId: resource._id.toString(), resourceName: resource.name },
    });
    res.status(201).json({ resource: publicResource(resource) });
  } catch (error) { next(error); }
});

router.patch("/resources/:id", requireAuth, requireRole("ADMIN"), async (req, res, next) => {
  try {
    const input = resourceSchema.partial().refine((value) => Object.keys(value).length > 0).parse(req.body);
    const resource = await Resource.findByIdAndUpdate(req.params.id, { $set: input }, { new: true, runValidators: true }).populate("departmentId", "name");
    if (!resource) return res.status(404).json({ error: "Resource not found." });
    await writeAudit(req, {
      eventType: "RESOURCE_UPDATED",
      description: "Administrator updated a protected resource or its access policy.",
      user: req.user,
      metadata: { resourceId: resource._id.toString(), resourceName: resource.name },
    });
    res.json({ resource: publicResource(resource) });
  } catch (error) { next(error); }
});

router.get("/resources/:id/content", requireAuth, async (req, res, next) => {
  try {
    const resource = await Resource.findById(req.params.id).populate("departmentId", "name");
    if (!resource || !canAccess(resource, req.user)) {
      await writeAudit(req, {
        eventType: "UNAUTHORIZED_RESOURCE_ACCESS",
        description: "A user attempted to access a resource outside their authorization scope.",
        status: "CRITICAL",
        user: req.user,
        metadata: { resourceId: req.params.id },
      });
      return res.status(403).json({ error: "You are not authorized to access this resource.", code: "FORBIDDEN" });
    }
    await writeAudit(req, {
      eventType: "RESOURCE_ACCESSED",
      description: "User accessed an authorized protected resource.",
      user: req.user,
      metadata: { resourceId: resource._id.toString(), resourceName: resource.name },
    });
    res.json({ resource: publicResource(resource) });
  } catch (error) { next(error); }
});

export default router;

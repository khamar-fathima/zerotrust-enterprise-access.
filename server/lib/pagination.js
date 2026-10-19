import { z } from "zod";

const integerParam = (fallback, max) => z.string().regex(/^[1-9]\d*$/)
  .transform(Number).pipe(z.number().int().min(1).max(max)).prefault(String(fallback));
const optionalId = z.string().regex(/^[a-f\d]{24}$/i).or(z.literal("")).optional();
const optionalDate = z.string().refine((value) => !value || !Number.isNaN(Date.parse(value)), "Invalid date").optional();
const common = {
  page: integerParam(1, 1_000_000),
  limit: integerParam(25, 100),
  q: z.string().trim().max(80).optional(),
};

export const usersQuery = z.object({
  ...common,
  status: z.enum(["", "PENDING", "ACTIVE", "DISABLED", "REJECTED"]).optional(),
  role: z.enum(["", "ADMIN", "MANAGER", "EMPLOYEE"]).optional(),
  departmentId: optionalId,
});

export const auditQuery = z.object({
  ...common,
  status: z.enum(["", "SUCCESS", "WARNING", "CRITICAL"]).optional(),
  eventType: z.string().trim().max(80).optional(),
  userId: optionalId,
  from: optionalDate,
  to: optionalDate,
}).refine((value) => !value.from || !value.to || Date.parse(value.from) <= Date.parse(value.to), {
  message: "Start date must not follow end date", path: ["to"],
});

export function literalSearch(value) {
  return { $regex: value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), $options: "i" };
}

// Use the exact same scoped filter for the count and the page; never count globally.
export async function paginate(model, filters, { page: requestedPage, limit }) {
  const total = await model.countDocuments(filters);
  const totalPages = Math.ceil(total / limit);
  const page = Math.min(requestedPage, Math.max(1, totalPages));
  return { total, page, limit, totalPages, skip: (page - 1) * limit };
}

export function pageMetadata({ skip, ...metadata }) {
  return metadata;
}

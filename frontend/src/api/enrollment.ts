import { api } from "./client";
import type { EnrollmentToken, EnrollmentTokenCreated } from "@/types/api";

export const enrollmentApi = {
  listTokens: () => api<EnrollmentToken[]>("/api/enrollment/tokens"),
  createToken: (body: { label?: string; ttl_hours?: number }) =>
    api<EnrollmentTokenCreated>("/api/enrollment/tokens", { method: "POST", body }),
  revokeToken: (id: string) => api<void>(`/api/enrollment/tokens/${id}`, { method: "DELETE" }),
};

import { api } from "./client";
import type { Host, HostStatus, OsFamily, Page } from "@/types/api";

export interface HostListParams {
  status_?: HostStatus;
  os_family?: OsFamily;
  q?: string;
  limit?: number;
  offset?: number;
}

export const hostsApi = {
  list: (params: HostListParams = {}) =>
    api<Page<Host>>("/api/hosts", { query: params as Record<string, string | number> }),
  get: (id: string) => api<Host>(`/api/hosts/${id}`),
  update: (id: string, body: { policy_id?: string | null; status?: HostStatus }) =>
    api<Host>(`/api/hosts/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/hosts/${id}`, { method: "DELETE" }),
};

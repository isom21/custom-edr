import { api } from "./client";
import type { HostGroup, Page } from "@/types/api";

export const hostGroupsApi = {
  list: (params: { q?: string; limit?: number; offset?: number } = {}) =>
    api<Page<HostGroup>>("/api/host-groups", {
      query: params as Record<string, string | number>,
    }),
};

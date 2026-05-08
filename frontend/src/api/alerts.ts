import { api } from "./client";
import type { Alert, AlertDetail, AlertState, Page, Severity } from "@/types/api";

export interface AlertListParams {
  state?: AlertState;
  severity?: Severity;
  host_id?: string;
  rule_id?: string;
  limit?: number;
  offset?: number;
}

export const alertsApi = {
  list: (params: AlertListParams = {}) =>
    api<Page<Alert>>("/api/alerts", { query: params as Record<string, string | number> }),
  get: (id: string) => api<AlertDetail>(`/api/alerts/${id}`),
  changeState: (id: string, body: { to_state: AlertState; comment?: string | null }) =>
    api<AlertDetail>(`/api/alerts/${id}/state`, { method: "POST", body }),
  assign: (id: string, body: { assignee_id: string | null }) =>
    api<AlertDetail>(`/api/alerts/${id}/assign`, { method: "POST", body }),
};

import { api } from "./client";
import type { AuditEntry, Page } from "@/types/api";

export interface AuditListParams {
  action?: string;
  resource_type?: string;
  resource_id?: string;
  actor_kind?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export interface AuditChainBreak {
  seq: number;
  row_id: string;
  reason: string;
  expected_hmac_hex: string | null;
  actual_hmac_hex: string | null;
}

export interface AuditVerifyResult {
  ok: boolean;
  rows_examined: number;
  chain_rows: number;
  breaks: AuditChainBreak[];
}

export const auditApi = {
  list: (params: AuditListParams = {}) =>
    api<Page<AuditEntry>>("/api/audit", {
      query: params as Record<string, string | number>,
    }),
  verify: () => api<AuditVerifyResult>("/api/audit/verify"),
};

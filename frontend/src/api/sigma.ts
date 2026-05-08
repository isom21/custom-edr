import { api } from "./client";

export interface SigmaCompileResponse {
  ok: boolean;
  query: string | null;
  title: string | null;
  description: string | null;
  error: string | null;
}

export interface SigmaTestSampleHit {
  timestamp: string | null;
  host_id: string | null;
  event_id: string | null;
  process: Record<string, unknown> | null;
  file: Record<string, unknown> | null;
}

export interface SigmaTestResponse {
  query: string;
  total: number;
  samples: SigmaTestSampleHit[];
}

export const sigmaApi = {
  compile: (body: string) =>
    api<SigmaCompileResponse>("/api/sigma/compile", { method: "POST", body: { body } }),
  testAdhoc: (body: string, lookbackHours = 24) =>
    api<SigmaTestResponse>("/api/sigma/test", {
      method: "POST",
      body: { body, lookback_hours: lookbackHours },
    }),
  testSavedRule: (ruleId: string, body: string | null = null, lookbackHours = 24) =>
    api<SigmaTestResponse>(`/api/sigma/rules/${ruleId}/test`, {
      method: "POST",
      body: { body, lookback_hours: lookbackHours },
    }),
};

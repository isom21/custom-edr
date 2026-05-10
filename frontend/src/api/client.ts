/**
 * Tiny fetch wrapper with auth + JSON conventions.
 *
 * - Reads/writes tokens via tokenStore (localStorage-backed).
 * - On 401, attempts a one-shot refresh; on failure, clears tokens.
 * - Throws ApiError({ status, detail }) on non-2xx so callers can render messages.
 */
import { tokenStore } from "./tokens";

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(`${status}: ${detail}`);
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
}

let refreshPromise: Promise<boolean> | null = null;

async function refreshOnce(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  const refresh = tokenStore.getRefreshToken();
  if (!refresh) return false;
  refreshPromise = (async () => {
    try {
      const res = await fetch("/api/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!res.ok) return false;
      const data = (await res.json()) as { access_token: string; refresh_token: string };
      tokenStore.setTokens(data.access_token, data.refresh_token);
      return true;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) params.append(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function doFetch(path: string, opts: RequestOptions, retried: boolean): Promise<Response> {
  const access = tokenStore.getAccessToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (access) headers.Authorization = `Bearer ${access}`;

  const res = await fetch(buildUrl(path, opts.query), {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  if (res.status === 401 && !retried && tokenStore.getRefreshToken()) {
    const ok = await refreshOnce();
    if (ok) return doFetch(path, opts, true);
    tokenStore.clear();
  }
  return res;
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await doFetch(path, opts, false);
  if (res.status === 204) return undefined as T;
  let body: unknown = null;
  if (res.headers.get("content-type")?.includes("application/json")) {
    body = await res.json().catch(() => null);
  }
  if (!res.ok) {
    const detail =
      (body as { detail?: string } | null)?.detail ?? res.statusText ?? "request failed";
    throw new ApiError(res.status, detail);
  }
  return body as T;
}

/**
 * Token store after M-frontend-auth #10.
 *
 * The refresh token lives in a server-set HttpOnly + SameSite=Strict
 * cookie (`vigil_refresh`, scope `/api/auth`). JS can't read it, so
 * an XSS in the SPA can't exfiltrate it. The access token sits in a
 * module-scoped variable that disappears on page reload — short
 * enough TTL (`VIGIL_JWT_ACCESS_TTL_MINUTES`, default 60) that a
 * one-off XSS pop has at most that window to ride along; the next
 * /refresh call uses the cookie that XSS can't see.
 *
 * Migration from the old localStorage-backed shape: this module's
 * surface is unchanged enough that existing call sites
 * (`tokens.getAccessToken()`, `tokens.setTokens(access, _refresh)`)
 * still work. `setTokens` ignores the refresh arg now — the server
 * already set the cookie on /login + /refresh.
 *
 * On page reload, the access token is gone but the refresh cookie
 * persists. `bootstrap()` triggers a /refresh on load to mint a
 * fresh access into memory; if the cookie's missing or expired the
 * call returns 401 and the SPA shows the login page.
 */

type Listener = () => void;
const listeners = new Set<Listener>();

let accessToken: string | null = null;

export const tokenStore = {
  getAccessToken: () => accessToken,
  /** Kept for back-compat — XSS can't reach the refresh cookie so JS
   * never needs to read it. Returns null so any caller that still
   * checks `if (getRefreshToken())` falls through to a /refresh call,
   * which is the right behaviour (the server reads the cookie). */
  getRefreshToken: () => null as string | null,
  setTokens(access: string, _refresh?: string) {
    accessToken = access;
    listeners.forEach((l) => l());
  },
  clear() {
    accessToken = null;
    listeners.forEach((l) => l());
  },
  subscribe(l: Listener): () => void {
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  },
};

/** Best-effort restore on page load: if the refresh cookie is still
 * valid we'll get a fresh access token; otherwise the SPA shows the
 * login screen. Awaited by main.tsx before mounting the router so
 * authenticated pages don't flash a 401. */
export async function bootstrap(): Promise<boolean> {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { access_token: string };
    tokenStore.setTokens(data.access_token);
    return true;
  } catch {
    return false;
  }
}

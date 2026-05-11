import { api } from "./client";
import { tokenStore } from "./tokens";
import type { TokenPair, User } from "@/types/api";

export async function login(email: string, password: string): Promise<User> {
  // The /login response also Set-Cookies the HttpOnly `vigil_refresh`
  // cookie (M-frontend-auth #10). Same-origin fetch picks it up
  // automatically; only the access token needs to land in memory.
  const tokens = await api<TokenPair>("/api/auth/login", {
    method: "POST",
    body: { email, password },
  });
  tokenStore.setTokens(tokens.access_token);
  return getMe();
}

export async function logout(): Promise<void> {
  // Best-effort: clear the cookie server-side, then drop in-memory
  // state. We don't await ApiError handling — even if the network
  // call fails the user expects "logout" to leave them logged out.
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  } catch {
    // ignore — we still clear local state below
  }
  tokenStore.clear();
}

export function getMe(): Promise<User> {
  return api<User>("/api/me");
}

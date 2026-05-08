import { api } from "./client";
import { tokenStore } from "./tokens";
import type { TokenPair, User } from "@/types/api";

export async function login(email: string, password: string): Promise<User> {
  const tokens = await api<TokenPair>("/api/auth/login", {
    method: "POST",
    body: { email, password },
  });
  tokenStore.setTokens(tokens.access_token, tokens.refresh_token);
  return getMe();
}

export async function logout(): Promise<void> {
  tokenStore.clear();
}

export function getMe(): Promise<User> {
  return api<User>("/api/me");
}

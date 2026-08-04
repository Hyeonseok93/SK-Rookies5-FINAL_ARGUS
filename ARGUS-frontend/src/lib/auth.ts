const TOKEN_KEY = "argus_access_token";
const USER_KEY = "argus_user";

export type AuthUser = {
  id: string;
  username: string;
  created_at?: string;
};

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export function setSession(token: string, user: AuthUser): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function authHeaders(extra?: HeadersInit): HeadersInit {
  const token = getToken();
  const headers = new Headers(extra);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return headers;
}

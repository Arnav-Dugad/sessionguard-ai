import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api, ApiError } from "./api";
import type { SessionInfo, User } from "./types";

interface AuthState {
  user: User | null;
  session: SessionInfo | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  reauth: (password: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      const r = await api.get<{ user: User; session: SessionInfo }>("/auth/me");
      setUser(r.user);
      setSession(r.session);
    } catch {
      setUser(null);
      setSession(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const login = async (username: string, password: string) => {
    const r = await api.post<{ user: User; session: SessionInfo }>("/auth/login", { username, password });
    setUser(r.user);
    setSession(r.session);
  };

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* ignore */
    }
    setUser(null);
    setSession(null);
  };

  const reauth = async (password: string) => {
    const r = await api.post<{ session: SessionInfo }>("/auth/reauthenticate", { password });
    setSession(r.session);
    await refresh();
  };

  return <Ctx.Provider value={{ user, session, loading, login, logout, reauth, refresh }}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth must be used within AuthProvider");
  return c;
}

export function isAuthError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

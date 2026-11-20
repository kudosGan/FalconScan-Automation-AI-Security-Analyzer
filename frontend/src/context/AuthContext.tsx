import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { LoginInfo } from "../types";

type AuthState = {
  signedIn: boolean;
  user?: string;
  login: LoginInfo | null;
  error: string;
  start: () => Promise<void>;
  signOut: () => Promise<void>;
};

const Ctx = createContext<AuthState | null>(null);
export const useAuth = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [signedIn, setSignedIn] = useState(false);
  const [user, setUser] = useState<string>();
  const [login, setLogin] = useState<LoginInfo | null>(null);
  const [error, setError] = useState("");

  // Restore session if the backend is already signed in.
  useEffect(() => {
    api.status().then((s) => { if (s.status === "signed_in") { setSignedIn(true); setUser(s.user); } }).catch(() => {});
  }, []);

  // Poll while the device-code login is pending.
  useEffect(() => {
    if (!login) return;
    const t = setInterval(async () => {
      try {
        const s = await api.status();
        if (s.status === "signed_in") { setSignedIn(true); setUser(s.user); setLogin(null); }
        if (s.status === "error") { setError(s.error ?? "Login failed"); setLogin(null); }
      } catch (e) { setError(String(e)); setLogin(null); }
    }, 2000);
    return () => clearInterval(t);
  }, [login]);

  const start = async () => {
    setError("");
    try { setLogin(await api.login()); } catch (e) { setError((e as Error).message); }
  };
  const signOut = async () => { await api.logout(); setSignedIn(false); setUser(undefined); };

  return <Ctx.Provider value={{ signedIn, user, login, error, start, signOut }}>{children}</Ctx.Provider>;
}

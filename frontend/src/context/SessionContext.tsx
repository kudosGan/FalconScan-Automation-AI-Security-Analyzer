import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Role, SessionUser } from "../types";

const RANK: Record<Role, number> = { viewer: 1, assessor: 2, admin: 3 };

type SessionState = {
  ready: boolean;                      // the first check with the server has finished
  authEnabled: boolean;                // false = single-user mode: no sign-in, data stays in this browser
  setupRequired: boolean;              // true until the first administrator exists
  user: SessionUser | null;
  notice: string;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string, displayName: string, setupToken: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (role: Role) => boolean;
};
const Ctx = createContext<SessionState | null>(null);

export const useSession = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSession outside SessionProvider");
  return c;
};

/** Who is signed in, and what they may do. With sign-in switched off on the server everyone is the local administrator. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const [user, setUser] = useState<SessionUser | null>(null);
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async () => {
    try {
      const s = await api.accountState();
      setAuthEnabled(s.authEnabled); setSetupRequired(s.setupRequired); setUser(s.user); setNotice("");
    } catch (e) { setNotice((e as Error).message); }
    setReady(true);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  // Any request the server refuses with "sign in required" ends the session here.
  useEffect(() => {
    const onOut = () => setUser((u) => { if (u) setNotice("Your session ended. Please sign in again."); return null; });
    window.addEventListener("falcon:unauthorized", onOut);
    return () => window.removeEventListener("falcon:unauthorized", onOut);
  }, []);

  const login: SessionState["login"] = async (username, password) => { const r = await api.accountLogin(username, password); setUser(r.user); setNotice(""); };
  const setup: SessionState["setup"] = async (u, p, n, t) => { const r = await api.accountSetup(u, p, n, t); setUser(r.user); setSetupRequired(false); setNotice(""); };
  const logout = async () => { try { await api.accountLogout(); } finally { setUser(null); setNotice(""); } };
  const can = (role: Role) => !authEnabled || (user !== null && RANK[user.role] >= RANK[role]);

  return <Ctx.Provider value={{ ready, authEnabled, setupRequired, user, notice, login, setup, logout, can }}>{children}</Ctx.Provider>;
}

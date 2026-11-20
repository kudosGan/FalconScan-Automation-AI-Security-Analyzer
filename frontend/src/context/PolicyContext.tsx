import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Policy } from "../types";
import { useServerData } from "./ServerDataContext";

const KEY = "murphygan.policy";
export const DEFAULT_POLICY: Policy = { name: "Normal scan", disabled: [], severity: {}, custom: [] };

type PolicyState = { policy: Policy; setPolicy: (p: Policy) => void };
const Ctx = createContext<PolicyState | null>(null);

export const usePolicy = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("usePolicy outside PolicyProvider");
  return c;
};

function load(): Policy {
  try { return { ...DEFAULT_POLICY, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") }; } catch { return DEFAULT_POLICY; }
}

/** The active scan configuration. When sign-in is on it is shared, so everyone scans with the same rules. */
export function PolicyProvider({ children }: { children: ReactNode }) {
  const { serverMode, data, fail } = useServerData();
  const [policy, setLocal] = useState<Policy>(() => (serverMode && data ? { ...DEFAULT_POLICY, ...data.policy } : load()));
  useEffect(() => { if (serverMode && data) setLocal({ ...DEFAULT_POLICY, ...data.policy }); }, [serverMode, data]);
  useEffect(() => {
    if (serverMode) return;
    try { localStorage.setItem(KEY, JSON.stringify(policy)); } catch { /* ignore */ }
  }, [policy, serverMode]);
  const setPolicy = (p: Policy) => { setLocal(p); if (serverMode) api.setPolicy(p).catch(fail); };
  return <Ctx.Provider value={{ policy, setPolicy }}>{children}</Ctx.Provider>;
}

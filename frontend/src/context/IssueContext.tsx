import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { IssueState } from "../types";
import { useServerData } from "./ServerDataContext";

const KEY = "murphygan.issues";
const OPEN: IssueState = { status: "Open", comment: "", updatedAt: "" };
const TYPING_DELAY = 700;           // a comment is sent once the person stops typing, not on every key

type IssueStore = {
  get: (key: string) => IssueState & { updatedBy?: string };
  set: (key: string, patch: Partial<Pick<IssueState, "status" | "comment">>) => void;
};
const Ctx = createContext<IssueStore | null>(null);

export const useIssues = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useIssues outside IssueProvider");
  return c;
};

function load(): Record<string, IssueState> {
  try { return JSON.parse(localStorage.getItem(KEY) ?? "{}"); } catch { return {}; }
}

/** Triage state (status + comment) per finding, keyed by application + finding fingerprint so it survives rescans. */
export function IssueProvider({ children }: { children: ReactNode }) {
  const { serverMode, data, fail } = useServerData();
  const [issues, setIssues] = useState<Record<string, IssueState & { updatedBy?: string }>>(() => (serverMode && data ? data.issues : load()));
  const queued = useRef(new Map<string, Partial<Pick<IssueState, "status" | "comment">>>());
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  useEffect(() => { if (serverMode && data) setIssues(data.issues); }, [serverMode, data]);
  useEffect(() => {
    if (serverMode) return;
    try { localStorage.setItem(KEY, JSON.stringify(issues)); } catch { /* ignore */ }
  }, [issues, serverMode]);

  const get = (key: string) => issues[key] ?? OPEN;
  const set: IssueStore["set"] = (key, patch) => {
    setIssues((cur) => ({ ...cur, [key]: { ...(cur[key] ?? OPEN), ...patch, updatedAt: new Date().toISOString() } }));
    if (!serverMode) return;
    queued.current.set(key, { ...queued.current.get(key), ...patch });
    clearTimeout(timers.current.get(key));
    timers.current.set(key, setTimeout(() => {
      const p = queued.current.get(key);
      queued.current.delete(key); timers.current.delete(key);
      if (p) api.setIssue(key, p).catch(fail);
    }, patch.comment !== undefined ? TYPING_DELAY : 0));
  };
  return <Ctx.Provider value={{ get, set }}>{children}</Ctx.Provider>;
}

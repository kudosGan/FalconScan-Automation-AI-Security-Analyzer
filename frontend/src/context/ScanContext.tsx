import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { ScanRecord, ScanResponse } from "../types";
import { useServerData } from "./ServerDataContext";

const KEY = "murphygan.scans";
const MAX_LOCAL = 10;               // a browser has little room; the shared database keeps far more

type ScanState = {
  history: ScanRecord[];
  scan: ScanResponse | null;          // the currently selected scan (used by the Results page)
  addScan: (r: ScanResponse, source: ScanRecord["source"], meta?: Partial<Pick<ScanRecord, "appId" | "appName" | "config" | "disabled">>) => string;
  selectScan: (id: string) => void;
  markCompleted: (id: string) => void;
  removeScan: (id: string) => void;
  clearHistory: () => void;
};
const Ctx = createContext<ScanState | null>(null);

export const useScan = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useScan outside ScanProvider");
  return c;
};

function load(): ScanRecord[] {
  try { return JSON.parse(localStorage.getItem(KEY) ?? "[]"); } catch { return []; }
}

export function ScanProvider({ children }: { children: ReactNode }) {
  const { serverMode, data, fail } = useServerData();
  const [history, setHistory] = useState<ScanRecord[]>(() => (serverMode && data ? data.assessments : load()));
  const [currentId, setCurrentId] = useState<string | null>(() => (serverMode && data ? data.assessments : load())[0]?.id ?? null);

  useEffect(() => { if (serverMode && data) setHistory(data.assessments); }, [serverMode, data]);
  useEffect(() => {
    if (serverMode) return;
    try { localStorage.setItem(KEY, JSON.stringify(history.slice(0, MAX_LOCAL))); } catch { /* storage full: ignore */ }
  }, [history, serverMode]);

  const addScan: ScanState["addScan"] = (response, source, meta) => {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const rec: ScanRecord = { id, createdAt: new Date().toISOString(), source, response, completed: false, ...meta };
    setHistory((h) => [rec, ...h].slice(0, serverMode ? 100 : MAX_LOCAL));
    setCurrentId(id);
    if (serverMode) api.addAssessment(rec).catch(fail);
    return id;
  };
  const markCompleted = (id: string) => {
    const was = history.find((r) => r.id === id);
    setHistory((h) => h.map((r) => (r.id === id && !r.completed ? { ...r, completed: true } : r)));
    if (serverMode && was && !was.completed) api.completeAssessment(id).catch(fail);
  };
  const removeScan = (id: string) => {
    setHistory((h) => h.filter((r) => r.id !== id));
    setCurrentId((c) => (c === id ? null : c));
    if (serverMode) api.deleteAssessment(id).catch(fail);
  };
  const clearHistory = () => {
    setHistory([]); setCurrentId(null);
    if (serverMode) api.deleteAllAssessments().catch(fail);
  };

  const scan = history.find((r) => r.id === currentId)?.response ?? null;
  return (
    <Ctx.Provider value={{ history, scan, addScan, selectScan: setCurrentId, markCompleted, removeScan, clearHistory }}>
      {children}
    </Ctx.Provider>
  );
}

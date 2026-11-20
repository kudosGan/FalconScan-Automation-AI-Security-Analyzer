import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Application, FlowFile } from "../types";
import { useServerData } from "./ServerDataContext";

const KEY = "murphygan.apps";

type AppState = {
  apps: Application[];
  addApp: (name: string, description: string, workingDir: string, flows: FlowFile[]) => string;
  addFlows: (id: string, flows: FlowFile[]) => void;
  removeFlow: (id: string, filename: string) => void;
  removeApp: (id: string) => void;
  renameApp: (id: string, name: string) => void;
};
const Ctx = createContext<AppState | null>(null);

export const useApps = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useApps outside ApplicationProvider");
  return c;
};

function load(): Application[] {
  try { return JSON.parse(localStorage.getItem(KEY) ?? "[]"); } catch { return []; }
}

/** Applications live in the shared database when sign-in is on, and in this browser when it is off. */
export function ApplicationProvider({ children }: { children: ReactNode }) {
  const { serverMode, data, fail } = useServerData();
  const [apps, setApps] = useState<Application[]>(() => (serverMode && data ? data.applications : load()));

  useEffect(() => { if (serverMode && data) setApps(data.applications); }, [serverMode, data]);
  useEffect(() => {
    if (serverMode) return;
    try { localStorage.setItem(KEY, JSON.stringify(apps)); } catch { /* storage full: ignore */ }
  }, [apps, serverMode]);

  const save = (app: Application) => { if (serverMode) api.saveApp(app).catch(fail); };

  const addApp: AppState["addApp"] = (name, description, workingDir, flows) => {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const app: Application = { id, name, description, workingDir, createdAt: new Date().toISOString(), flows };
    setApps((a) => [...a, app]);
    save(app);
    return id;
  };
  const change = (id: string, edit: (a: Application) => Application) => {
    const cur = apps.find((x) => x.id === id);
    if (!cur) return;
    const next = edit(cur);
    setApps((a) => a.map((x) => (x.id === id ? next : x)));
    save(next);
  };
  const addFlows: AppState["addFlows"] = (id, flows) =>
    change(id, (x) => ({ ...x, flows: [...x.flows.filter((f) => !flows.some((n) => n.filename === f.filename)), ...flows] }));
  const removeFlow: AppState["removeFlow"] = (id, filename) => change(id, (x) => ({ ...x, flows: x.flows.filter((f) => f.filename !== filename) }));
  const renameApp: AppState["renameApp"] = (id, name) => { const n = name.trim(); if (n) change(id, (x) => ({ ...x, name: n })); };
  const removeApp = (id: string) => {
    setApps((a) => a.filter((x) => x.id !== id));
    if (serverMode) api.deleteApp(id).catch(fail);
  };

  return <Ctx.Provider value={{ apps, addApp, addFlows, removeFlow, removeApp, renameApp }}>{children}</Ctx.Provider>;
}

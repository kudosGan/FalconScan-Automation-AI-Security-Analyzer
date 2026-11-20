import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Bootstrap, TicketLink } from "../types";
import { useSession } from "./SessionContext";

type ServerData = {
  /** True when the shared database is the source of truth (sign-in is on and someone is signed in). */
  serverMode: boolean;
  data: Bootstrap | null;
  reload: () => Promise<void>;
  tickets: Record<string, TicketLink>;
  addTicket: (key: string, t: TicketLink) => void;
  fail: (e: unknown) => void;
};
const Ctx = createContext<ServerData | null>(null);

export const useServerData = () => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useServerData outside ServerDataProvider");
  return c;
};

/** Loads the shared data once someone is signed in. Children are not shown until it has arrived, so every screen starts with the real data. */
export function ServerDataProvider({ children }: { children: ReactNode }) {
  const { authEnabled, user } = useSession();
  const serverMode = authEnabled && user !== null;
  const [data, setData] = useState<Bootstrap | null>(null);
  const [tickets, setTickets] = useState<Record<string, TicketLink>>({});
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    try { const d = await api.bootstrap(); setData(d); setTickets(d.tickets); setError(""); }
    catch (e) { setError((e as Error).message); }
  }, []);

  useEffect(() => { if (serverMode) reload(); else { setData(null); setError(""); } }, [serverMode, user?.id, reload]);

  // A write that fails (for example the role does not allow it) is reported and the screen is put back in step with the server.
  const fail = useCallback((e: unknown) => { alert(`The server did not accept that change: ${(e as Error).message}`); reload(); }, [reload]);

  if (serverMode && !data) {
    return <div style={{ padding: 40, textAlign: "center" }}>{error
      ? <><p className="error">Could not load the shared data: {error}</p><button className="btn" onClick={reload}>Try again</button></>
      : <p className="muted">Loading…</p>}</div>;
  }
  return <Ctx.Provider value={{ serverMode, data, reload, tickets, addTicket: (k, t) => setTickets((m) => ({ ...m, [k]: t })), fail }}>{children}</Ctx.Provider>;
}

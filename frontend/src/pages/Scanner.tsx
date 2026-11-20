import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { Env, Flow } from "../types";
import { useScan } from "../context/ScanContext";
import EnvironmentSelect from "../components/EnvironmentSelect";
import FlowTable from "../components/FlowTable";
import JsonViewer from "../components/JsonViewer";

export default function Scanner() {
  const nav = useNavigate();
  const { addScan } = useScan();
  const [envs, setEnvs] = useState<Env[]>([]);
  const [env, setEnv] = useState("");
  const [admin, setAdmin] = useState(false);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [json, setJson] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => { api.environments().then(setEnvs).catch((e) => setErr(e.message)); }, []);

  useEffect(() => {
    setFlows([]); setSelected(new Set()); setErr("");
    if (!env) return;
    setLoading(true);
    api.flows(env, admin).then(setFlows).catch((e) => setErr(e.message)).finally(() => setLoading(false));
  }, [env, admin]);

  const toggle = (id: string) =>
    setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAll = () =>
    setSelected(selected.size === flows.length ? new Set() : new Set(flows.map((f) => f.id)));

  const view = (id: string) => api.flow(env, id, admin).then(setJson).catch((e) => setErr(e.message));

  const runScan = async () => {
    setScanning(true); setErr("");
    try {
      const id = addScan(await api.scan(env, [...selected], admin), "live");
      nav(`/scan/run/${id}`);
    } catch (e) { setErr((e as Error).message); } finally { setScanning(false); }
  };

  return (
    <div className="card">
      <h2>Scanner</h2>
      <EnvironmentSelect envs={envs} value={env} admin={admin} onChange={setEnv} onAdminChange={setAdmin} />
      {err && <p className="error">{err}</p>}
      {loading && <p className="muted">Loading flows…</p>}
      {flows.length > 0 && (
        <>
          <FlowTable flows={flows} selected={selected} onToggle={toggle} onToggleAll={toggleAll} onView={view} />
          <div className="toolbar">
            <span className="muted">{selected.size} of {flows.length} selected</span>
            <button className="btn" disabled={selected.size === 0 || scanning} onClick={runScan}>
              {scanning ? "Scanning…" : "Scan selected"}
            </button>
          </div>
        </>
      )}
      {!loading && env && flows.length === 0 && !err && <p className="muted">No flows found in this environment.</p>}
      {json !== null && <JsonViewer data={json} onClose={() => setJson(null)} />}
    </div>
  );
}

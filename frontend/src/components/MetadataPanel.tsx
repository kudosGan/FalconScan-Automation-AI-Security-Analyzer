import "./MetadataPanel.css";
import type { FlowResult } from "../types";

const DATE_KEYS = new Set(["Created", "Last modified"]);

function show(key: string, v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (DATE_KEYS.has(key)) { const d = new Date(String(v)); return isNaN(+d) ? String(v) : d.toLocaleString(); }
  return String(v);
}

/** Flow-level facts: identity, owner, type, dates, size. Taken from metadata only, never run data. */
export default function MetadataPanel({ result }: { result: FlowResult }) {
  const meta = result.metadata;
  if (!meta) return null;
  return (
    <div className="meta-panel">
      <div className="meta-head"><span>Flow metadata</span><span className="muted">{result.name}</span></div>
      <div className="meta-grid">
        {Object.entries(meta).map(([k, v]) => (
          <div key={k} className="meta-cell" title={`${k}: ${show(k, v)}`}>
            <small>{k}</small><span>{show(k, v)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

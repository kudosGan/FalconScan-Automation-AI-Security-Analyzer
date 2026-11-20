import "./Explorer.css";
import { useState } from "react";
import type { Application } from "../../types";

export type ExplorerTarget = { appId: string; flow?: string };
type Props = {
  apps: Application[]; selectedId: string | null;
  onSelect: (id: string | null) => void; onNew: () => void;
  onContextMenu: (x: number, y: number, target: ExplorerTarget) => void;
};

export default function Explorer({ apps, selectedId, onSelect, onNew, onContextMenu }: Props) {
  const [rootOpen, setRootOpen] = useState(true);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  return (
    <div className="explorer">
      <div className="view-head"><b>Explorer</b><button title="New application" onClick={onNew}>＋</button></div>
      <div className="tree">
        <div className="tree-row" onClick={() => setRootOpen(!rootOpen)}>
          <span className="tw">{rootOpen ? "▼" : "▶"}</span><span className="ico">▣</span>All Applications
        </div>
        {rootOpen && apps.length === 0 && <div className="tree-empty">No applications. Use File ▸ Add Application…</div>}
        {rootOpen && apps.map((a) => (
          <div key={a.id}>
            <div className={`tree-row ${selectedId === a.id ? "sel" : ""}`} style={{ paddingLeft: 20 }}
              onClick={() => onSelect(a.id)} onDoubleClick={() => toggle(a.id)}
              onContextMenu={(e) => { e.preventDefault(); onContextMenu(e.clientX, e.clientY, { appId: a.id }); }}>
              <span className="tw" onClick={(e) => { e.stopPropagation(); toggle(a.id); }}>{open.has(a.id) ? "▼" : "▶"}</span>
              <span className="ico">◉</span>{a.name}
            </div>
            {open.has(a.id) && a.flows.map((f) => (
              <div key={f.filename} className="tree-row" style={{ paddingLeft: 50 }} onClick={() => onSelect(a.id)}
                onContextMenu={(e) => { e.preventDefault(); onContextMenu(e.clientX, e.clientY, { appId: a.id, flow: f.filename }); }}>
                <span className="ico flow">▤</span>{f.filename}
              </div>
            ))}
            {open.has(a.id) && a.flows.length === 0 && <div className="tree-empty" style={{ paddingLeft: 50 }}>No flows</div>}
          </div>
        ))}
        <div className="tree-row" style={{ marginTop: 4 }}><span className="tw">▶</span><span className="ico">▢</span>All Folders</div>
      </div>
    </div>
  );
}

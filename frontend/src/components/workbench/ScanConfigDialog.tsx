import "./ScanConfigDialog.css";
import "./NewApplicationWizard.css";
import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import type { Policy, Rule, Severity } from "../../types";
import { DEFAULT_POLICY } from "../../context/PolicyContext";

type Props = { policy: Policy; onSave: (p: Policy) => void; onClose: () => void };

const SEVS: Severity[] = ["High", "Medium", "Low"];
const PRESETS = ["Normal scan", "High & Medium only", "Secrets, data & AI"];

/** Choose which rules run and what severity each reports. Saved as the active scan configuration. */
export default function ScanConfigDialog({ policy, onSave, onClose }: Props) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [name, setName] = useState(policy.name);
  const [disabled, setDisabled] = useState(new Set(policy.disabled));
  const [sev, setSev] = useState<Record<string, Severity>>(policy.severity);
  const [err, setErr] = useState("");

  useEffect(() => { api.rules().then(setRules).catch((e) => setErr(e.message)); }, []);

  const touch = () => { if (PRESETS.includes(name)) setName("Custom scan"); };
  const toggle = (id: string) => { touch(); setDisabled((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; }); };
  const setSeverity = (r: Rule, v: Severity) => {
    touch();
    setSev((s) => { const n = { ...s }; if (v === r.severity) delete n[r.id]; else n[r.id] = v; return n; });
  };

  const preset = (p: string) => {
    setName(p); setSev({});
    if (p === "Normal scan") setDisabled(new Set());
    else if (p === "High & Medium only") setDisabled(new Set(rules.filter((r) => r.severity === "Low").map((r) => r.id)));
    else setDisabled(new Set(rules.filter((r) => !/^(PA-(SEC|CON|AI|ACT-004)|AG-|RPA-SEC)/.test(r.id)).map((r) => r.id)));
  };

  const enabled = useMemo(() => rules.length - disabled.size, [rules, disabled]);

  return (
    <div className="wiz-backdrop">
      <div className="cfg" role="dialog" aria-label="Scan Configuration">
        <div className="wiz-title"><span>Scan Configuration</span><button onClick={onClose} aria-label="Close">✕</button></div>
        <div className="cfg-top">
          <label>Name <input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <span className="grow" />
          <span className="cfg-note">Presets:</span>
          {PRESETS.map((p) => <button key={p} onClick={() => preset(p)} disabled={!rules.length}>{p}</button>)}
        </div>
        <div className="cfg-body">
          {err && <p className="error" style={{ padding: 10 }}>{err}</p>}
          <table className="cfg-table">
            <thead><tr><th>Run</th><th>Rule</th><th>Category</th><th>CWE</th><th>OWASP</th><th>Severity</th></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className={disabled.has(r.id) ? "off" : ""}>
                  <td><input type="checkbox" checked={!disabled.has(r.id)} onChange={() => toggle(r.id)} aria-label={`Run ${r.id}`} /></td>
                  <td title={r.description}><b>{r.id}</b> {r.title}</td>
                  <td>{r.category}</td><td>{r.cwe ?? "—"}</td><td>{r.owasp ?? "—"}</td>
                  <td>
                    <select value={sev[r.id] ?? r.severity} onChange={(e) => setSeverity(r, e.target.value as Severity)}>
                      {SEVS.map((s) => <option key={s} value={s}>{s}{s === r.severity ? " (default)" : ""}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="cfg-foot">
          <span className="cfg-note">{enabled} of {rules.length} rules enabled · {Object.keys(sev).length} severity override(s)</span>
          <span className="btns">
            <button onClick={() => { setName(DEFAULT_POLICY.name); setDisabled(new Set()); setSev({}); }}>Reset</button>
            <button className="primary" onClick={() => onSave({ ...policy, name: name.trim() || "Custom scan", disabled: [...disabled], severity: sev })}>Save</button>
            <button onClick={onClose}>Cancel</button>
          </span>
        </div>
      </div>
    </div>
  );
}

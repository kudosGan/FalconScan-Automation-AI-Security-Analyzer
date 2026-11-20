import "./RuleLibraryTab.css";
import { useEffect, useMemo, useState } from "react";
import type { CustomRule, Policy, Rule, Severity } from "../../types";

type Props = {
  rules: Rule[]; policy: Policy; canEdit: boolean;
  category: string; onCategory: (c: string) => void;
  onSavePolicy: (p: Policy) => void;
};

const SEVS: Severity[] = ["High", "Medium", "Low"];
const MAX_RULES = 50;

/** The built-in rules grouped into bundles (categories), plus the custom rules this team has added. */
export default function RuleLibraryTab({ rules, policy, canEdit, category, onCategory, onSavePolicy }: Props) {
  const [q, setQ] = useState("");
  const [draft, setDraft] = useState<CustomRule[]>(policy.custom ?? []);
  const saved = JSON.stringify(policy.custom ?? []);
  useEffect(() => setDraft(policy.custom ?? []), [saved]);   // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = JSON.stringify(draft) !== saved;

  const categories = useMemo(() => [...new Set(rules.map((r) => r.category))].sort(), [rules]);
  const shown = useMemo(() => rules.filter((r) =>
    (!category || r.category === category) &&
    (!q || `${r.id} ${r.title} ${r.category} ${r.cwe ?? ""} ${r.owasp ?? ""} ${r.description}`.toLowerCase().includes(q.toLowerCase()))), [rules, category, q]);

  const edit = (i: number, patch: Partial<CustomRule>) => setDraft((d) => d.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const add = () => setDraft((d) => [...d, { id: "", title: "", severity: "Medium", text: "", fix: "", enabled: true }]);
  // A rule keeps its id for good, so triage decisions stay attached when other rules are added or removed.
  const save = () => {
    const keep = draft.filter((r) => r.text.trim());
    const used = new Set(keep.map((r) => r.id).filter(Boolean));
    let n = 0;
    const next = () => { do n++; while (used.has(`CUS-${String(n).padStart(3, "0")}`)); const id = `CUS-${String(n).padStart(3, "0")}`; used.add(id); return id; };
    onSavePolicy({ ...policy, custom: keep.map((r) => (r.id ? r : { ...r, id: next() })) });
  };
  const off = new Set(policy.disabled);

  return (
    <div className="rules-tab">
      <section id="custom-rules">
        <h3>Custom rules</h3>
        <p className="muted">Add words or phrases that must not appear in an automation file, such as an internal server name or a forbidden connector.
          Each is matched as plain text, ignoring capitals. When one is found the file gets a finding with your title and fix. The matched text is never repeated in reports.</p>
        {draft.length > 0 && (
          <table className="rules-table">
            <thead><tr><th>On</th><th>Id</th><th>Title</th><th>Text to look for</th><th>Severity</th><th>How to fix</th><th /></tr></thead>
            <tbody>
              {draft.map((r, i) => (
                <tr key={i}>
                  <td><input type="checkbox" checked={r.enabled} disabled={!canEdit} onChange={(e) => edit(i, { enabled: e.target.checked })} aria-label="Rule on" /></td>
                  <td>{r.id || "new"}</td>
                  <td><input value={r.title} maxLength={120} disabled={!canEdit} onChange={(e) => edit(i, { title: e.target.value })} placeholder="Internal server name" /></td>
                  <td><input value={r.text} maxLength={200} disabled={!canEdit} onChange={(e) => edit(i, { text: e.target.value })} placeholder="corp-sql-01" /></td>
                  <td><select value={r.severity} disabled={!canEdit} onChange={(e) => edit(i, { severity: e.target.value as Severity })}>{SEVS.map((s) => <option key={s}>{s}</option>)}</select></td>
                  <td><input value={r.fix} maxLength={500} disabled={!canEdit} onChange={(e) => edit(i, { fix: e.target.value })} placeholder="Use the environment variable instead" /></td>
                  <td>{canEdit && <button onClick={() => setDraft((d) => d.filter((_, j) => j !== i))} aria-label="Delete rule" title="Delete rule">✕</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {canEdit
          ? <p><button onClick={add} disabled={draft.length >= MAX_RULES}>+ Add custom rule</button>{" "}
              <button className="primary" onClick={save} disabled={!dirty}>Save custom rules</button>
              {dirty && <span className="muted"> Unsaved changes. Rules apply to the next scan.</span>}</p>
          : <p className="muted">You have read-only access, so custom rules cannot be changed.</p>}
      </section>

      <section>
        <h3>Rule library ({shown.length} of {rules.length})</h3>
        <div className="rules-filter">
          <label>Bundle <select value={category} onChange={(e) => onCategory(e.target.value)}>
            <option value="">All bundles</option>{categories.map((c) => <option key={c}>{c}</option>)}
          </select></label>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rule, CWE, OWASP…" />
        </div>
        <table className="rules-table">
          <thead><tr><th>Rule</th><th>Bundle</th><th>Severity</th><th>CWE</th><th>OWASP</th><th>In this scan configuration</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} title={r.description} className={off.has(r.id) ? "off" : ""}>
                <td><b>{r.id}</b> {r.title}</td><td>{r.category}</td>
                <td>{policy.severity[r.id] ?? r.severity}{policy.severity[r.id] ? " (changed)" : ""}</td>
                <td>{r.cwe ?? "—"}</td><td>{r.owasp ?? "—"}</td><td>{off.has(r.id) ? "Off" : "On"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">Switch rules on or off, or change severities, under Tools ▸ Scan Configuration.</p>
      </section>
    </div>
  );
}

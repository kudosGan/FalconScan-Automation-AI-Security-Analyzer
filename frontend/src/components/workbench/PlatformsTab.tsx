import "./AssessmentsTable.css";
import "./PlatformsTab.css";
import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import { PLATFORMS } from "../../data/platforms";
import { BRAND } from "../../brand";
import type { Rule } from "../../types";

export default function PlatformsTab() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.rules().then(setRules).catch((e) => setErr((e as Error).message)); }, []);

  // What the scanners really check, grouped by category from the live rule catalog (AG- rules are the AI ones).
  const group = (list: Rule[]) => {
    const m = new Map<string, Rule[]>();
    list.forEach((r) => m.set(r.category, [...(m.get(r.category) ?? []), r]));
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  };
  const flowRules = useMemo(() => group((rules ?? []).filter((r) => r.id.startsWith("PA-") && !r.id.startsWith("PA-DLP"))), [rules]);
  const rpaRules = useMemo(() => group((rules ?? []).filter((r) => r.id.startsWith("RPA-") || r.id.startsWith("UIP-"))), [rules]);
  const aiRules = useMemo(() => group((rules ?? []).filter((r) => r.id.startsWith("AG-"))), [rules]);
  const count = (g: [string, Rule[]][]) => g.reduce((n, [, rs]) => n + rs.length, 0);
  const table = (g: [string, Rule[]][]) => (
    <table className="grid coverage">
      <thead><tr><th>Category</th><th>Rules</th><th>What is checked</th></tr></thead>
      <tbody>
        {g.map(([cat, rs]) => (
          <tr key={cat} className="row"><td>{cat}</td><td>{rs.length}</td><td>{rs.map((r) => r.title).join(" · ")}</td></tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="pane-pad">
      <h3>Platform Integrations</h3>
      <p className="muted">{BRAND.name} is built to assess several automation technologies. Power Automate flows, AI agent / MCP files and UiPath projects can be scanned today. Automation Anywhere and Blue Prism have basic checks only. Anything marked planned is not functional yet.</p>
      <div className="platform-grid">
        {PLATFORMS.map((p) => (
          <section key={p.id} className={`platform-card ${p.status}`}>
            <header>
              <span className="phase">Phase {p.phase}</span>
              <span className={`pill ${p.status}`}>{p.status === "active" ? "Active" : p.status === "limited" ? "Limited · basic checks" : "Planned · Coming soon"}</span>
            </header>
            <h4>{p.name}</h4>
            <ul>{p.covers.map((c) => <li key={c}>{c}</li>)}</ul>
          </section>
        ))}
      </div>

      <h3 className="coverage-title">Checked today: Power Automate cloud flows</h3>
      {err && <p className="error">Could not load the rule catalog: {err}</p>}
      {!rules && !err && <p className="muted">Loading…</p>}
      {rules && (
        <>
          <p className="muted">{count(flowRules)} rules in {flowRules.length} categories. Turn rules on or off under Tools ▸ Scan Configuration.</p>
          {table(flowRules)}
          <h3 className="coverage-title">Checked today: MCP configurations and AI agent definitions</h3>
          <p className="muted">{count(aiRules)} rules in {aiRules.length} categories. These read configuration files only. Checks on prompt-injection and data-exposure paths are
            heuristics based on tool names and descriptions, so treat them as combinations to review rather than proven exploits.</p>
          {table(aiRules)}
          <h3 className="coverage-title">Checked today: RPA files (UiPath, plus basic checks for Automation Anywhere and Blue Prism)</h3>
          <p className="muted">{count(rpaRules)} rules in {rpaRules.length} categories. The UiPath-specific rules (UIP-) read project.json and .xaml workflows. For Automation Anywhere and Blue Prism only the shared
            RPA- rules apply, using value checks that do not depend on the vendor file layout, which has not been verified against real exports.</p>
          {table(rpaRules)}
        </>
      )}
    </div>
  );
}

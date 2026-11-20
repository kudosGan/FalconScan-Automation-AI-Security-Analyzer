import "./Dashboard.css";
import { useMemo, useState } from "react";
import type { Application, IssueState, ScanRecord, Severity } from "../../types";
import { ISSUE_STATUSES } from "../../types";
import { toRows, type FindingRow } from "../../lib/findingRows";
import { countBySeverity } from "../../lib/compare";

type Props = {
  history: ScanRecord[]; apps: Application[]; issueOf: (key: string) => IssueState;
  /** When the dashboard was last cleared, and how many saved assessments that hides. */
  since?: string | null; hidden?: number; onShowAll?: () => void;
};

const SEVS: Severity[] = ["High", "Medium", "Low"];
const COLOR: Record<Severity, string> = { High: "var(--high)", Medium: "var(--medium)", Low: "var(--low)" };
const BLUE = "var(--series-1)";
const isOpen = (s: string) => s === "Open" || s === "In progress";
const short = (iso: string) => new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
const clock = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });

type Bar = { label: string; value: number; color: string; note?: string };

/** One horizontal bar per row: label, thin bar with a rounded tip, value at the tip. */
function HBars({ data, table }: { data: Bar[]; table: boolean }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  if (data.every((d) => d.value === 0)) return <div className="dash-empty">Nothing to show yet.</div>;
  if (table) return <table><thead><tr><th>Item</th><th>Count</th></tr></thead><tbody>{data.map((d) => <tr key={d.label}><td>{d.label}</td><td className="num">{d.value}</td></tr>)}</tbody></table>;
  return (
    <>
      {data.map((d) => (
        <div className="hb" key={d.label} title={`${d.label}: ${d.value}${d.note ? ` · ${d.note}` : ""}`}>
          <span className="hb-label">{d.label}</span>
          <span className="hb-track"><div className="hb-bar" style={{ width: `${(d.value / max) * 100}%`, background: d.color, maxWidth: "100%" }} /></span>
          <span className="hb-val">{d.value}</span>
        </div>
      ))}
    </>
  );
}

function Legend() {
  return <div className="legend-row">{SEVS.map((s) => <span key={s}><i style={{ background: COLOR[s] }} />{s}</span>)}</div>;
}

export default function Dashboard({ history, apps, issueOf, since, hidden = 0, onShowAll }: Props) {
  const [table, setTable] = useState(false);
  const [trendApp, setTrendApp] = useState("");

  // Newest assessment per application (or per ad-hoc scan): the current state of each.
  const latest = useMemo(() => {
    const seen = new Set<string>();
    return history.filter((r) => { const k = r.appId ?? `adhoc-${r.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  }, [history]);
  const data = useMemo(() => latest.map((r) => ({
    record: r, rows: toRows(r).map((row): FindingRow & { status: string } => ({ ...row, status: issueOf(row.issueKey).status })),
  })), [latest, issueOf]);

  const all = data.flatMap((d) => d.rows);
  const open = all.filter((r) => isOpen(r.status));
  const bySev = (s: Severity) => open.filter((r) => r.severity === s).length;
  const flowsScanned = latest.reduce((n, r) => n + r.response.results.length, 0);

  const byApp = data.map((d) => ({
    label: d.record.appName ?? "Ad hoc",
    parts: SEVS.map((s) => d.rows.filter((r) => isOpen(r.status) && r.severity === s).length),
  }));
  const maxApp = Math.max(1, ...byApp.map((a) => a.parts.reduce((x, y) => x + y, 0)));

  const ruleCounts = Object.entries(open.reduce<Record<string, { n: number; title: string }>>((m, r) => {
    (m[r.ruleId] ??= { n: 0, title: r.type }).n++; return m; }, {}))
    .sort((a, b) => b[1].n - a[1].n).slice(0, 8);

  const standards = Object.entries(open.reduce<Record<string, number>>((m, r) => {
    const k = `${r.cwe} · ${r.owasp}`; m[k] = (m[k] ?? 0) + 1; return m; }, {})).sort((a, b) => b[1] - a[1]);

  const trendOptions = apps.filter((a) => history.some((r) => r.appId === a.id));
  const trendId = trendApp || trendOptions[0]?.id || "";
  const trend = history.filter((r) => r.appId === trendId).slice(0, 12).reverse();
  const tMax = Math.max(1, ...trend.map((r) => { const c = countBySeverity(r); return c.High + c.Medium + c.Low; }));

  const STEP = 56, COL = 22, W = trend.length * STEP + 44, H = 176, top = 10, base = H - 34, usable = base - top;

  return (
    <div className="dash">
      <div className="dash-head">
        <h3>Security dashboard</h3>
        <label><input type="checkbox" checked={table} onChange={(e) => setTable(e.target.checked)} /> Table view</label>
      </div>

      {since && (
        <div className="dash-note">
          Dashboard cleared at {new Date(since).toLocaleString()}. Showing {history.length} assessment(s) since then.
          {hidden > 0 && <button onClick={onShowAll}>Show all {history.length + hidden} saved assessments</button>}
        </div>
      )}

      <div className="kpis">
        <div className="kpi"><b>{apps.length}</b><span>Applications</span></div>
        <div className="kpi"><b>{history.length}</b><span>Assessments</span></div>
        <div className="kpi"><b>{flowsScanned}</b><span>Flows (latest scans)</span></div>
        <div className="kpi"><b>{open.length}</b><span>Open findings</span></div>
        <div className="kpi high"><b>{bySev("High")}</b><span>Open High</span></div>
        <div className="kpi"><b>{all.length - open.length}</b><span>Resolved / accepted</span></div>
      </div>

      {history.length === 0 ? <div className="dash-panel"><div className="dash-empty">{since ? "Nothing scanned since the dashboard was cleared. Run a scan to populate it." : "Run a scan to populate the dashboard."}</div></div> : (
        <div className="dash-grid">
          <div className="dash-panel">
            <h4>Open findings by severity</h4><div className="sub">Latest assessment of each application</div>
            <HBars table={table} data={SEVS.map((s) => ({ label: s, value: bySev(s), color: COLOR[s] }))} />
          </div>

          <div className="dash-panel">
            <h4>Open findings by application</h4><div className="sub">Stacked by severity</div>
            <Legend />
            {table ? (
              <table><thead><tr><th>Application</th>{SEVS.map((s) => <th key={s}>{s}</th>)}</tr></thead>
                <tbody>{byApp.map((a) => <tr key={a.label}><td>{a.label}</td>{a.parts.map((p, i) => <td key={i} className="num">{p}</td>)}</tr>)}</tbody></table>
            ) : byApp.map((a) => {
              const total = a.parts.reduce((x, y) => x + y, 0);
              return (
                <div className="hb" key={a.label} title={`${a.label}: ${SEVS.map((s, i) => `${a.parts[i]} ${s}`).join(", ")}`}>
                  <span className="hb-label">{a.label}</span>
                  <span className="hb-track"><div className="stack" style={{ width: `${(total / maxApp) * 100}%` }}>
                    {a.parts.map((p, i) => p > 0 && <div key={i} style={{ flex: p, background: COLOR[SEVS[i]] }} />)}
                  </div></span>
                  <span className="hb-val">{total}</span>
                </div>
              );
            })}
          </div>

          <div className="dash-panel">
            <h4>Trend over assessments</h4>
            <div className="sub">
              {trendOptions.length > 0 ? <select value={trendId} onChange={(e) => setTrendApp(e.target.value)} aria-label="Application">
                {trendOptions.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select> : "Scan an application twice to see a trend."}
            </div>
            {trend.length > 0 && <Legend />}
            {trend.length === 0 ? null : table ? (
              <table><thead><tr><th>Date</th>{SEVS.map((s) => <th key={s}>{s}</th>)}</tr></thead>
                <tbody>{trend.map((r) => { const c = countBySeverity(r); return <tr key={r.id}><td>{new Date(r.createdAt).toLocaleString()}</td>{SEVS.map((s) => <td key={s} className="num">{c[s]}</td>)}</tr>; })}</tbody></table>
            ) : (
              <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label="Findings per assessment, stacked by severity">
                {[0, 0.5, 1].map((t) => (
                  <g key={t}><line x1="30" x2={W} y1={base - usable * t} y2={base - usable * t} stroke={t === 0 ? "var(--axis)" : "var(--grid)"} strokeWidth="1" />
                    <text x="26" y={base - usable * t + 3} textAnchor="end">{Math.round(tMax * t)}</text></g>
                ))}
                {trend.map((r, i) => {
                  const c = countBySeverity(r); const x = 40 + i * STEP; let y = base;
                  return (
                    <g key={r.id}>
                      {SEVS.slice().reverse().map((s) => {
                        const h = (c[s] / tMax) * usable; if (!h) return null; y -= h;
                        return <rect key={s} x={x} y={y} width={COL} height={Math.max(0, h - 2)} rx="3" fill={COLOR[s]}><title>{`${short(r.createdAt)} ${clock(r.createdAt)}: ${c[s]} ${s}`}</title></rect>;
                      })}
                      <text x={x + COL / 2} y={H - 20} textAnchor="middle">{short(r.createdAt)}</text><text x={x + COL / 2} y={H - 8} textAnchor="middle">{clock(r.createdAt)}</text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>

          <div className="dash-panel">
            <h4>Top rules</h4><div className="sub">Open findings</div>
            <HBars table={table} data={ruleCounts.map(([id, v]) => ({ note: id, label: v.title, value: v.n, color: BLUE }))} />
          </div>

          <div className="dash-panel">
            <h4>Standards coverage</h4><div className="sub">Open findings by CWE and OWASP reference (indicative)</div>
            {standards.length === 0 ? <div className="dash-empty">No open findings.</div> : (
              <table><thead><tr><th>CWE · OWASP</th><th>Open</th></tr></thead>
                <tbody>{standards.map(([k, n]) => <tr key={k}><td>{k}</td><td className="num">{n}</td></tr>)}</tbody></table>
            )}
          </div>

          <div className="dash-panel">
            <h4>Triage status</h4><div className="sub">All findings in the latest assessments</div>
            <HBars table={table} data={ISSUE_STATUSES.map((s) => ({ label: s, value: all.filter((r) => r.status === s).length, color: BLUE }))} />
          </div>
        </div>
      )}
    </div>
  );
}

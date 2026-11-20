import "./FindingsPanel.css";
import "./AssessmentsTable.css";
import "../StepReview.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type { IssueState, IssueStatus, Severity, TicketConfig, TicketLink } from "../../types";
import { ISSUE_STATUSES } from "../../types";
import Splitter from "./Splitter";
import type { FindingRow } from "../../lib/findingRows";
import type { Diff } from "../../lib/compare";

export type BottomTab = "console" | "findings" | "changes";
/** A command from the menus: focus the search box, jump to the next match, or show only excluded findings. */
export type FindCmd = { id: number; kind: "find" | "next" | "excluded" | "all" };

type Props = {
  tab: BottomTab; onTab: (t: BottomTab) => void;
  rows: FindingRow[]; selected: FindingRow | null; onSelect: (r: FindingRow) => void;
  log: string[]; label: string;
  issueOf: (r: FindingRow) => IssueState;
  onIssue: (r: FindingRow, patch: Partial<Pick<IssueState, "status" | "comment">>) => void;
  diff: Diff | null; previousLabel: string | null;
  readOnly?: boolean;
  ticketCfg?: TicketConfig | null;
  ticketOf?: (r: FindingRow) => TicketLink | undefined;
  onTicket?: (r: FindingRow) => void;
  cmd?: FindCmd;
};

/** Only web links are shown as links, whatever the ticket system returned. */
const safeHref = (u: string) => (/^https?:\/\//i.test(u) ? u : undefined);

export default function FindingsPanel({ tab, onTab, rows, selected, onSelect, log, label, issueOf, onIssue, diff, previousLabel, readOnly, ticketCfg, ticketOf, onTicket, cmd }: Props) {
  const [sev, setSev] = useState<"" | Severity>("");
  const [status, setStatus] = useState<"" | IssueStatus | "Excluded">("");
  const search = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");

  const shown = useMemo(() => rows.filter((r) =>
    (!sev || r.severity === sev) && (!status || (status === "Excluded" ? ["Noise", "Accepted risk"].includes(issueOf(r).status) : issueOf(r).status === status)) &&
    (!q || `${r.type} ${r.ruleId} ${r.sink} ${r.source} ${r.cwe} ${r.owasp}`.toLowerCase().includes(q.toLowerCase()))),
  [rows, sev, status, q, issueOf]);
  useEffect(() => {
    if (!cmd) return;
    if (cmd.kind === "find") search.current?.focus();
    else if (cmd.kind === "next" && shown.length) {
      const at = shown.findIndex((r) => r.key === selected?.key);
      onSelect(shown[(at + 1) % shown.length]);
    } else if (cmd.kind === "excluded") { setStatus("Excluded"); setSev(""); setQ(""); }
    else if (cmd.kind === "all") { setStatus(""); setSev(""); setQ(""); }
  }, [cmd?.id]);   // eslint-disable-line react-hooks/exhaustive-deps
  const open = rows.filter((r) => ["Open", "In progress"].includes(issueOf(r).status)).length;

  return (
    <div className="bottom">
      <div className="tabstrip">
        <button className={tab === "console" ? "on" : ""} onClick={() => onTab("console")}>Console</button>
        <button className={tab === "findings" ? "on" : ""} onClick={() => onTab("findings")}>Findings</button>
        <button className={tab === "changes" ? "on" : ""} onClick={() => onTab("changes")}>
          Changes{diff ? ` (+${diff.added} / −${diff.fixed.length})` : ""}
        </button>
        <span className="spacer" />
        <span className="count">{label} · {rows.length} finding(s) · {open} open</span>
      </div>

      {tab === "console" && (
        <div className="console">{log.length === 0 ? <span className="muted">Console is empty.</span> : log.map((l, i) => <div key={i}>{l}</div>)}</div>
      )}

      {tab === "changes" && (
        <div className="console changes">
          {!diff ? <span className="muted">No earlier assessment of this application to compare with. Scan it again after changes to see what is new and what was fixed.</span> : (
            <>
              <p><b>Compared with {previousLabel}:</b> {diff.added} new · {diff.fixed.length} fixed · {diff.unchanged} unchanged<br /><span className="muted">Rules switched off in either scan configuration are left out: not running a rule is not the same as fixing it.</span></p>
              <table className="grid">
                <thead><tr><th>Change</th><th>Severity</th><th>Issue</th><th>Flow</th><th>Where</th></tr></thead>
                <tbody>
                  {rows.filter((r) => r.isNew).map((r) => (
                    <tr key={r.key} className="row"><td><span className="chg new">New</span></td><td>{r.severity}</td><td>{r.type}</td><td>{r.sink}</td><td>{r.source}</td></tr>
                  ))}
                  {diff.fixed.map((x, i) => (
                    <tr key={i} className="row"><td><span className="chg fixed">Fixed</span></td><td>{x.finding.severity}</td><td>{x.finding.title}</td><td>{x.flow}</td><td>{x.finding.location}</td></tr>
                  ))}
                </tbody>
              </table>
              {diff.added + diff.fixed.length === 0 && <p className="muted">No change between the two assessments.</p>}
            </>
          )}
        </div>
      )}

      {tab === "findings" && (
        <div className="bottom-body">
          <div className="detail-pane">
            {!selected ? <span className="muted">Select a finding to see details and triage it.</span> : (() => {
              const st = issueOf(selected);
              return (
                <>
                  <b>{selected.type}</b>
                  <p>{selected.detail}</p>
                  <p className="muted">{selected.ruleId} · {selected.classification}<br />{selected.cwe} · {selected.owasp}<br />{selected.source}</p>
                  <div className="fix-box">
                    <h5>How to fix</h5>
                    {selected.fix.length ? <ol>{selected.fix.map((t, k) => <li key={k}>{t}</li>)}</ol>
                      : <span className="muted">No guidance saved with this scan. Run the scan again to refresh it.</span>}
                    {selected.example && (
                      <div className="fix-example">
                        <div><small>Before</small><pre className="ex-before">{selected.example.before}</pre></div>
                        <div><small>After</small><pre className="ex-after">{selected.example.after}</pre></div>
                      </div>
                    )}
                    {selected.alternative && (
                      <><h5 className="alt">Alternative: {selected.alternative.title}</h5><ol>{selected.alternative.steps.map((t, k) => <li key={k}>{t}</li>)}</ol></>
                    )}
                  </div>
                  {(() => {
                    const tk = ticketOf?.(selected);
                    if (tk) return <p>Ticket: {safeHref(tk.url) ? <a href={safeHref(tk.url)} target="_blank" rel="noopener noreferrer">{tk.id}</a> : tk.id} <span className="muted">({tk.system}, by {tk.createdBy})</span></p>;
                    return ticketCfg?.configured && !readOnly && onTicket ? <p><button className="btn ghost" onClick={() => onTicket(selected)}>Create {ticketCfg.system === "jira" ? "Jira" : "Azure DevOps"} ticket</button></p> : null;
                  })()}
                  <label className="triage-field">Status
                    <select value={st.status} disabled={readOnly} onChange={(e) => onIssue(selected, { status: e.target.value as IssueStatus })}>
                      {ISSUE_STATUSES.map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </label>
                  <label className="triage-field">Comment
                    <textarea rows={3} value={st.comment} disabled={readOnly} placeholder="Why is this accepted, who is fixing it…"
                      onChange={(e) => onIssue(selected, { comment: e.target.value })} />
                  </label>
                  {st.updatedAt && <p className="muted">Updated {new Date(st.updatedAt).toLocaleString()}</p>}
                  <pre>{JSON.stringify(selected.stepJson, null, 2)}</pre>
                </>
              );
            })()}
          </div>
          <Splitter axis="x" cssVar="--detail-w" grows="prev" min={160} collapsed={0} label="the finding detail" />
          <div className="table-pane">
            <div className="filter-row">
              <select value={sev} onChange={(e) => setSev(e.target.value as "" | Severity)} aria-label="Severity filter">
                <option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option>
              </select>
              <select value={status} onChange={(e) => setStatus(e.target.value as "" | IssueStatus | "Excluded")} aria-label="Status filter">
                <option value="">All statuses</option><option value="Excluded">Excluded (noise or accepted)</option>{ISSUE_STATUSES.map((s) => <option key={s}>{s}</option>)}
              </select>
              <input ref={search} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rule, flow, CWE…" />
              <span className="muted">{shown.length} shown</span>
            </div>
            <table className="grid">
              <thead>
                <tr><th>Trace</th><th>Severity</th><th>Status</th><th>Classification</th><th>Vulnerability Type</th><th>CWE</th><th>API</th><th>Source</th><th>Sink</th><th>Directory</th></tr>
              </thead>
              <tbody>
                {shown.map((r) => {
                  const st = issueOf(r).status;
                  return (
                    <tr key={r.key} className={`row ${selected?.key === r.key ? "sel" : ""} ${["Fixed", "Noise"].includes(st) ? "dim" : ""}`} onClick={() => onSelect(r)}>
                      <td>{r.trace}</td>
                      <td><span className={`sev-dot ${r.severity}`} />{r.severity}</td>
                      <td>{st}</td>
                      <td>{r.classification}</td>
                      <td>{r.type}{r.isNew && <span className="chg new">New</span>}</td>
                      <td>{r.cwe}</td><td>{r.api}</td>
                      <td title={r.source}>{r.source}</td><td>{r.sink}</td><td>{r.directory}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {shown.length === 0 && <div className="grid-empty">No findings to show.</div>}
          </div>
        </div>
      )}
    </div>
  );
}

import "./AssessmentsTable.css";
import type { ScanRecord } from "../../types";
import { countBySeverity, diff, previousOf } from "../../lib/compare";

type Props = {
  records: ScanRecord[]; history: ScanRecord[]; selectedId: string | null;
  onSelect: (id: string) => void; onOpen: (id: string) => void;
};

const stamp = (iso: string) => new Date(iso).toLocaleString();

export default function AssessmentsTable({ records, history, selectedId, onSelect, onOpen }: Props) {
  if (records.length === 0) return <div className="grid-empty">No assessments yet. Select an application and choose Scan ▸ Scan Application.</div>;
  return (
    <table className="grid">
      <thead>
        <tr><th>Name</th><th>Type</th><th>Scan Configuration</th><th>High</th><th>Med</th><th>Low</th><th>Since previous</th><th>Modified</th><th>Location</th><th>Targets</th><th>Date</th></tr>
      </thead>
      <tbody>
        {records.map((r) => {
          const c = countBySeverity(r);
          const prev = previousOf(history, r);
          const d = prev ? diff(r, prev) : null;
          return (
            <tr key={r.id} className={`row ${r.id === selectedId ? "sel" : ""}`}
              onClick={() => onSelect(r.id)} onDoubleClick={() => onOpen(r.id)}>
              <td>{r.appName ?? "Ad hoc"} - {stamp(r.createdAt)}</td>
              <td title={r.source}>{r.source === "live" ? "☁" : "▤"}</td>
              <td>{r.config ?? "Normal scan"}</td>
              <td className="n high">{c.High}</td><td className="n medium">{c.Medium}</td><td className="n low">{c.Low}</td>
              <td>{d ? <><span className={`chg ${d.added ? "new" : "zero"}`}>+{d.added}</span> <span className={`chg ${d.fixed.length ? "fixed" : "zero"}`}>−{d.fixed.length}</span></> : "—"}</td>
              <td>{r.completed ? "No" : "Running"}</td>
              <td>{r.source === "live" ? "Power Platform" : "Uploaded flow files"}</td>
              <td>{r.response.results.map((x) => x.name).join(", ")}</td>
              <td>{stamp(r.createdAt)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

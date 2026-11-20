import "./ResultsTable.css";
import { Fragment, useState } from "react";
import type { FlowResult } from "../types";
import SeverityBadge from "./SeverityBadge";
import FindingsList from "./FindingsList";

export default function ResultsTable({ results }: { results: FlowResult[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <table className="table">
      <thead>
        <tr><th>Flow</th><th>Connectors</th><th>Findings</th><th>Risk</th></tr>
      </thead>
      <tbody>
        {results.map((r) => (
          <Fragment key={r.flowId}>
            <tr className="clickable" onClick={() => setOpen(open === r.flowId ? null : r.flowId)}>
              <td>{r.name}</td>
              <td>{r.connectors.length}</td>
              <td>{r.error ? "error" : r.findings.length}</td>
              <td><SeverityBadge level={r.risk} /></td>
            </tr>
            {open === r.flowId && (
              <tr key={`${r.flowId}-d`}>
                <td colSpan={4}>
                  {r.error ? <p className="error">{r.error}</p> : <FindingsList result={r} />}
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </table>
  );
}

import "./FindingsList.css";
import type { FlowResult } from "../types";
import SeverityBadge from "./SeverityBadge";
import PencilIcon from "./PencilIcon";

export default function FindingsList({ result }: { result: FlowResult }) {
  return (
    <div className="findings">
      <p className="muted">
        Connectors: {result.connectors.join(", ") || "none"} · {result.triggerCount} trigger(s) · {result.actionCount} action(s)
      </p>
      {result.findings.length === 0 && <p><PencilIcon name="party" size={22} /> No findings</p>}
      {result.findings.map((f, i) => (
        <div key={i} className="finding">
          <SeverityBadge level={f.severity} />
          <div>
            <b>{f.title}</b> <span className="muted">{f.ruleId} · {f.location}</span>
            <div>{f.detail}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

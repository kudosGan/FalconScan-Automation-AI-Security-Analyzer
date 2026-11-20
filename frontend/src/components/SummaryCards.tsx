import "./SummaryCards.css";
import type { FlowResult } from "../types";

export default function SummaryCards({ results }: { results: FlowResult[] }) {
  const all = results.flatMap((r) => r.findings);
  const count = (s: string) => all.filter((f) => f.severity === s).length;
  const cards = [
    { label: "Flows scanned", value: results.length, cls: "" },
    { label: "Findings", value: all.length, cls: "" },
    { label: "High", value: count("High"), cls: "high" },
    { label: "Medium", value: count("Medium"), cls: "medium" },
    { label: "Low", value: count("Low"), cls: "low" },
  ];
  return (
    <div className="cards">
      {cards.map((c) => (
        <div key={c.label} className={`card stat ${c.cls}`}>
          <div className="stat-value">{c.value}</div>
          <div className="muted">{c.label}</div>
        </div>
      ))}
    </div>
  );
}

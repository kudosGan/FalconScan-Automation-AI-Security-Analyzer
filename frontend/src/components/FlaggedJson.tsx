import "./FlaggedJson.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Severity, Step } from "../types";
import { jsonLines, lineFor } from "../lib/jsonLines";

type Item = { flowName: string; step: Step };

const RANK: Record<Severity, number> = { High: 3, Medium: 2, Low: 1 };

/** JSON of every inspected step, with lines that carry a finding coloured by severity. */
export default function FlaggedJson({ items, finished }: { items: Item[]; finished: boolean }) {
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  const blocks = useMemo(() => items.map(({ flowName, step }) => {
    const { lines, index } = jsonLines(step.json);
    const marks = new Map<number, { sev: Severity; tags: string[] }>();
    for (const f of step.findings) {
      const n = lineFor(index, f.jsonPath);
      const cur = marks.get(n);
      const tag = `${f.ruleId} ${f.title}`;
      marks.set(n, { sev: cur && RANK[cur.sev] > RANK[f.severity] ? cur.sev : f.severity, tags: [...(cur?.tags ?? []), tag] });
    }
    return { flowName, step, lines, marks };
  }), [items]);

  const shown = onlyFlagged ? blocks.filter((b) => b.marks.size > 0) : blocks;

  // Follow the scan: keep the newest inspected step in view.
  useEffect(() => {
    const el = bodyRef.current;
    if (el && !finished) el.scrollTop = el.scrollHeight;
  }, [items.length, finished]);

  return (
    <div className="flagged">
      <div className="flagged-head">
        <span>Flagged JSON</span>
        <span className="legend">
          <span><i className="High" />High</span><span><i className="Medium" />Medium</span><span><i className="Low" />Low</span>
          <label><input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} /> Only steps with findings</label>
        </span>
      </div>
      <div className="flagged-body" ref={bodyRef}>
        {shown.length === 0 && <div className="flagged-empty">Inspected steps appear here, with risky lines highlighted by severity.</div>}
        {shown.map((b) => (
          <div key={`${b.flowName}-${b.step.id}`}>
            <div className="fl-step"><b>{b.step.name}</b> · {b.step.type} · {b.flowName}
              {b.marks.size > 0 ? ` · ${b.step.findings.length} finding(s)` : " · clean"}</div>
            {b.lines.map((l, i) => {
              const m = b.marks.get(i);
              return (
                <div key={i} className={`fl ${m?.sev ?? ""}`}>
                  <span className="no">{i + 1}</span>{l}
                  {m && <span className="tag">◄ {m.tags.join(" · ")}</span>}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

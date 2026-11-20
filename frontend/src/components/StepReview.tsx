import "./StepReview.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Severity, Step } from "../types";
import { jsonLines, lineFor } from "../lib/jsonLines";
import SeverityBadge from "./SeverityBadge";

const LINE_H = 18;
const RANK: Record<Severity, number> = { High: 3, Medium: 2, Low: 1 };

type Props = {
  step: Step; flowName: string; filter: Severity | null; finished: boolean; onClose: () => void;
};

/** Pinned view of one step: its JSON with flagged lines coloured, why each finding was raised, and how to fix it. */
export default function StepReview({ step, flowName, filter, finished, onClose }: Props) {
  const { lines, index } = useMemo(() => jsonLines(step.json), [step]);
  const [showAll, setShowAll] = useState(false);
  const [focus, setFocus] = useState<number | null>(null);
  const [openFix, setOpenFix] = useState<Set<number>>(new Set());
  const codeRef = useRef<HTMLDivElement>(null);

  const located = useMemo(() => step.findings.map((f, i) => ({ f, i, line: lineFor(index, f.jsonPath) })), [step, index]);
  const marks = useMemo(() => {
    const m = new Map<number, Severity>();
    for (const { f, line } of located) {
      const cur = m.get(line);
      if (!cur || RANK[f.severity] > RANK[cur]) m.set(line, f.severity);
    }
    return m;
  }, [located]);
  const visible = located.filter(({ f }) => showAll || !filter || f.severity === filter);

  const scrollTo = (line: number) => {
    const el = codeRef.current;
    if (el) el.scrollTop = Math.max(0, line * LINE_H - el.clientHeight / 3);
  };
  // Jump to the first line of the chosen severity when the review opens.
  useEffect(() => {
    const first = visible[0];
    if (first) { setFocus(first.i); scrollTo(first.line); } else { setFocus(null); if (codeRef.current) codeRef.current.scrollTop = 0; }
  }, [step, filter]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleFix = (i: number) => setOpenFix((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n; });
  const focusLine = focus !== null ? located.find((x) => x.i === focus)?.line : undefined;

  return (
    <div className="review">
      <div className="review-meta">
        <span><b>{step.name}</b> <span className="muted">· {step.kind} · {step.type} · {flowName}</span></span>
        <button className="btn ghost" onClick={onClose}>{finished ? "✕ Close review" : "▶ Resume scan"}</button>
      </div>

      <div className="review-code" ref={codeRef}>
        {lines.map((l, i) => (
          <div key={i} className={`rl ${marks.get(i) ?? ""} ${focusLine === i ? "focus" : ""}`}>
            <span className="no">{i + 1}</span>{l}
          </div>
        ))}
      </div>

      <div className="review-why">
        {step.findings.length === 0 ? (
          <div className="review-clean">No findings on this step.</div>
        ) : (
          <>
            <div className="why-head">
              <span>{visible.length} of {step.findings.length} finding(s){filter && !showAll ? ` · ${filter} only` : ""}</span>
              {filter && <button onClick={() => setShowAll(!showAll)}>{showAll ? `Show ${filter} only` : "Show all severities"}</button>}
            </div>
            {visible.map(({ f, i, line }) => (
              <div key={i} className={`why-item ${focus === i ? "focus" : ""}`}>
                <div className="why-top" onClick={() => { setFocus(i); scrollTo(line); }} title="Show this line in the code">
                  <SeverityBadge level={f.severity} /><b>{f.title}</b><span className="why-meta">line {line + 1}</span>
                </div>
                <div className="why-text"><b>Why it is flagged:</b> {f.detail}</div>
                <div className="why-meta">{f.ruleId} · {f.location}</div>
                <button className={`fix-btn ${openFix.has(i) ? "open" : ""}`} onClick={() => toggleFix(i)}>
                  {openFix.has(i) ? "Hide fix" : "How to fix"}
                </button>
                {openFix.has(i) && (
                  f.fix?.length ? (
                    <div className="fix-box">
                      <h5>Recommended fix</h5>
                      <ol>{f.fix.map((t, k) => <li key={k}>{t}</li>)}</ol>
                      {f.example && (
                        <div className="fix-example">
                          <div><small>Before</small><pre className="ex-before">{f.example.before}</pre></div>
                          <div><small>After</small><pre className="ex-after">{f.example.after}</pre></div>
                        </div>
                      )}
                      {f.alternative && (
                        <>
                          <h5 className="alt">Alternative: {f.alternative.title}</h5>
                          <ol>{f.alternative.steps.map((t, k) => <li key={k}>{t}</li>)}</ol>
                        </>
                      )}
                      <p className="verify">Then re-run the scan: this finding should disappear.</p>
                    </div>
                  ) : <div className="fix-box">No guidance recorded for this rule. Re-run the scan to refresh it.</div>
                )}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

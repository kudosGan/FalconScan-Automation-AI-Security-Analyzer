import "./ScanRunner.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { FlowResult, Severity, Step } from "../types";
import SeverityBadge from "./SeverityBadge";
import FlaggedJson from "./FlaggedJson";
import MetadataPanel from "./MetadataPanel";
import StepReview from "./StepReview";
import ConnectionAnalysis from "./ConnectionAnalysis";
import { annotateLine } from "../lib/annotateLine";

type QItem = { flowName: string; result: FlowResult; step: Step; lines: string[] };
const TICK = 50;
const LINE_H = 18;

// Slow, line-by-line pace: about 0.45s per JSON line plus a short pause per step.
const LINE_MS = 450;
const durationOf = (lines: number) => Math.min(30000, 900 + lines * LINE_MS);
const fmt = (ms: number) => {
  const s = Math.floor(ms / 1000);
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
};

type Props = { results: FlowResult[]; startCompleted: boolean; onComplete: () => void };

export default function ScanRunner({ results, startCompleted, onComplete }: Props) {
  const queue: QItem[] = useMemo(
    () => results.flatMap((r) => (r.steps ?? []).map((step) => ({
      flowName: r.name, result: r, step, lines: JSON.stringify(step.json, null, 2).split("\n"),
    }))),
    [results],
  );
  const total = queue.length;
  const [idx, setIdx] = useState(startCompleted ? total : 0);
  const [progress, setProgress] = useState(0);
  const [paused, setPaused] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [elapsed, setElapsed] = useState(0);
  const [pin, setPin] = useState<{ i: number; sev: Severity | null } | null>(null);
  const finished = idx >= total;
  const current = finished ? null : queue[idx];

  useEffect(() => {
    if (paused || finished) return;
    const t = setInterval(() => {
      setElapsed((e) => e + TICK);
      setProgress((p) => {
        const next = p + (TICK * speed) / durationOf(queue[idx].lines.length);
        if (next >= 1) { setIdx((i) => i + 1); return 0; }
        return next;
      });
    }, TICK);
    return () => clearInterval(t);
  }, [paused, finished, speed, idx, queue]);

  const completedRef = useRef(false);
  useEffect(() => {
    if (finished && total > 0 && !completedRef.current) { completedRef.current = true; onComplete(); }
  }, [finished, total, onComplete]);

  // Keep the active timeline row and JSON line in view.
  const tlRef = useRef<HTMLDivElement>(null);
  const jsonRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = tlRef.current?.querySelector<HTMLElement>(".tl-item.running");
    if (el && tlRef.current) tlRef.current.scrollTop = el.offsetTop - tlRef.current.clientHeight / 2;
  }, [idx]);
  const scannedLines = current ? Math.floor(progress * current.lines.length) : 0;
  useEffect(() => {
    if (jsonRef.current) jsonRef.current.scrollTop = scannedLines * LINE_H - jsonRef.current.clientHeight / 2;
  }, [scannedLines]);

  // Reviewing a step pauses a running scan; closing the review resumes it.
  const review = (i: number, sev: Severity | null) => { setPin({ i, sev }); if (!finished) setPaused(true); };
  const closeReview = () => { setPin(null); if (!finished) setPaused(false); };
  const restart = () => { setPin(null); completedRef.current = false; setIdx(0); setProgress(0); setElapsed(0); setPaused(false); };
  const skip = () => { setIdx(total); setProgress(0); };

  if (total === 0) {
    return (
      <div className="card">
        <p>Nothing to inspect: these flows returned no steps.</p>
        {results.filter((r) => r.error).map((r) => <p key={r.flowId} className="error">{r.name}: {r.error}</p>)}
      </div>
    );
  }

  const overall = Math.min(100, ((finished ? total : idx + progress) / total) * 100);
  const done = queue.slice(0, idx);
  const found = done.flatMap((q) => q.step.findings.map((f) => ({ f, q }))).reverse();
  const sev = (s: string) => found.filter((x) => x.f.severity === s).length;

  return (
    <>
      <div className="runner-top">
        <div className="runner-top-row">
          <b>{finished ? "Scan complete" : `Inspecting step ${idx + 1} of ${total}`}
            <span className="muted"> · {Math.round(overall)}% · elapsed {fmt(elapsed)}</span></b>
          <div className="runner-controls">
            {!finished && <button className="btn ghost" onClick={() => setPaused(!paused)}>{paused ? "▶ Resume" : "❚❚ Pause"}</button>}
            {!finished && (
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="Speed">
                <option value={1}>1× (detailed)</option><option value={2}>2×</option><option value={4}>4×</option><option value={8}>8×</option>
              </select>
            )}
            {!finished && <button className="btn ghost" onClick={skip}>Skip to end</button>}
            {finished && <button className="btn ghost" onClick={restart}>↻ Replay</button>}
          </div>
        </div>
        <div className="bar"><div style={{ width: `${overall}%` }} /></div>
      </div>

      {finished && (
        <div className="runner-done">
          <span><b>{found.length} finding(s)</b> across {total} steps — High {sev("High")} · Medium {sev("Medium")} · Low {sev("Low")}</span>
          <Link className="btn" to="/results">View full report</Link>
        </div>
      )}

      <MetadataPanel result={(current ?? queue[total - 1]).result} />

      <div className="runner-grid">
        <div className="panel">
          <div className="panel-head">Steps</div>
          <div className="panel-body" ref={tlRef}>
            {queue.map((q, i) => {
              const prev = queue[i - 1];
              const state = i < idx ? "done" : i === idx && !finished ? "running" : "pending";
              return (
                <div key={i}>
                  {(!prev || prev.flowName !== q.flowName) && <div className="tl-flow">{q.flowName}</div>}
                  <div className={`tl-item ${state} ${pin?.i === i ? "pinned" : ""}`} style={{ paddingLeft: 14 + q.step.depth * 14 }}
                    onClick={() => state === "done" && review(i, null)}>
                    <span className="tl-dot">{state === "done" ? "✔" : state === "running" ? "▶" : "○"}</span>
                    <span className="tl-name" title={q.step.path}>{q.step.name}</span>
                    {state === "done" && q.step.findings.length === 0 && <span className="sev-pill clean" title="No findings">0</span>}
                    {state === "done" && (["High", "Medium", "Low"] as Severity[]).map((sv) => {
                      const n = q.step.findings.filter((f) => f.severity === sv).length;
                      return n > 0 && (
                        <button key={sv} className={`sev-pill ${sv}`} title={`Review ${n} ${sv} finding(s)`}
                          onClick={(e) => { e.stopPropagation(); review(i, sv); }}>{n}</button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">{pin ? "Inspector — step review" : "Inspector"}</div>
          {pin ? (
            <StepReview key={`${pin.i}-${pin.sev}`} step={queue[pin.i].step} flowName={queue[pin.i].flowName}
              filter={pin.sev} finished={finished} onClose={closeReview} />
          ) : current ? (
            <>
              <div className="inspect-meta">
                <b>{current.step.name}</b> <span className="muted">· {current.step.kind} · {current.step.type}</span>
                <div className="muted">{current.step.path}{current.step.connector ? ` · connector: ${current.step.connector}` : ""}</div>
                <div className="bar thin"><div style={{ width: `${progress * 100}%` }} /></div>
              </div>
              <div className="line-note">
                <span className="ln">Line {Math.min(scannedLines + 1, current.lines.length)} / {current.lines.length}</span>
                <span>{annotateLine(current.lines[Math.min(scannedLines, current.lines.length - 1)], current.step)}</span>
              </div>
              <div className="json-lines" ref={jsonRef}>
                {current.lines.map((l, i) => (
                  <div key={i} className={`jl ${i < scannedLines ? "scanned" : i === scannedLines ? "current" : ""}`}>
                    <span className="no">{i + 1}</span>{l}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="inspect-idle">All steps inspected.<br />Review the findings, or open the full report.</div>
          )}
        </div>

        <div className="panel">
          <div className="panel-head">Findings so far ({found.length})</div>
          <div className="panel-body">
            {found.length === 0 && <p className="muted" style={{ padding: 14 }}>{finished ? "No findings." : "Nothing found yet…"}</p>}
            {found.map(({ f, q }, i) => (
              <div key={`${q.step.id}-${f.ruleId}-${i}`} className="f-item">
                <SeverityBadge level={f.severity} /> <b>{f.title}</b>
                <div>{f.detail}</div>
                <small>{f.ruleId} · {q.step.path}</small>
              </div>
            ))}
          </div>
        </div>
      </div>

      <ConnectionAnalysis
        active={pin ? queue[pin.i] : current ?? queue[total - 1]}
        done={done} />

      <FlaggedJson items={done} finished={finished} />
    </>
  );
}

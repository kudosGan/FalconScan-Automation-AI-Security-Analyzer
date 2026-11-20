import "./ConnectionAnalysis.css";
import type { Connection, FlowResult, Step } from "../types";

type Item = { flowName: string; result: FlowResult; step: Step };

const pubClass = (p: string) => p === "Microsoft" ? "ms" : p === "Third-party" ? "tp" : p === "External HTTP" ? "ext" : "cus";
const pubLabel = (c: Connection) => c.publisher === "Microsoft" ? "Microsoft" : c.publisher;

type Props = { active: Item | undefined; done: Item[] };

/** For the step being inspected: who runs the connection, where data goes, how sensitive it is, AI exposure. */
export default function ConnectionAnalysis({ active, done }: Props) {
  const c = active?.step.connection ?? null;
  const flows = active ? active.result.dataFlows?.filter((f) => f.to === active.step.name || f.from === active.step.name) ?? [] : [];
  const rows = done.filter((d) => d.step.connection);

  return (
    <div className="conn">
      <div className="panel">
        <div className="panel-head">Connection analysis{active ? ` — ${active.step.name}` : ""}</div>
        {!active ? <div className="conn-none">No step selected.</div>
          : !c ? <div className="conn-none">This step ({active.step.type}) does not use a connection: it is a built-in control or data action, so no data leaves the flow here.</div>
          : (
            <div className="conn-card">
              <div className="conn-row"><span>Connector</span><span><b>{c.name}</b> <span className={`ctag ${pubClass(c.publisher)}`}>{pubLabel(c)}</span>{c.thirdParty && <span className="ctag tp">third party</span>}</span></div>
              <div className="conn-row"><span>Goes to</span><span>{c.destination}</span></div>
              <div className="conn-row"><span>Why</span><span>{c.why}</span></div>
              <div className="conn-row"><span>Data touched</span><span><span className={`ctag ${c.sensitivity}`}>{c.sensitivity} sensitivity</span>{c.dataTypes.map((d) => <span key={d} className="ctag">{d}</span>)}</span></div>
              {c.target && <div className="conn-row"><span>Target</span><span>{c.target}</span></div>}
              <div className="conn-row"><span>AI exposure</span><span>{c.ai
                ? <><span className="ctag ai">AI: {c.ai.provider}</span><span className={`ctag ${c.ai.microsoft ? "ms" : "tp"}`}>{c.ai.microsoft ? "inside Microsoft" : "third-party AI"}</span></>
                : <span className="ctag noai">No AI involved</span>}</span></div>
              {flows.length > 0 && (
                <div className="conn-row"><span>Data flow</span><span>{flows.map((f, i) => (
                  <div key={i} className="flow-line">
                    {f.from} ({f.fromConnector}, {f.sensitivity}) → {f.to} ({f.toConnector}){f.ai ? " · AI" : f.thirdParty ? " · third party" : ""}
                  </div>
                ))}</span></div>
              )}
            </div>
          )}
      </div>

      <div className="panel">
        <div className="panel-head">Connections found so far ({rows.length})</div>
        <div className="panel-body">
          <table className="conn-table">
            <thead><tr><th>Step</th><th>Connector</th><th>Run by</th><th>Goes to</th><th>Sensitivity</th><th>AI</th></tr></thead>
            <tbody>
              {rows.map((r, i) => {
                const k = r.step.connection!;
                return (
                  <tr key={i} className={k.thirdParty || k.ai ? "risk" : ""}>
                    <td title={r.step.path}>{r.step.name}</td><td>{k.name}</td>
                    <td><span className={`ctag ${pubClass(k.publisher)}`}>{pubLabel(k)}</span></td>
                    <td title={k.destination}>{k.destination}</td>
                    <td><span className={`ctag ${k.sensitivity}`}>{k.sensitivity}</span></td>
                    <td>{k.ai ? <span className="ctag ai">{k.ai.provider}</span> : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {rows.length === 0 && <div className="conn-none">Connections appear here as each step is inspected.</div>}
        </div>
      </div>
    </div>
  );
}

import type { Flow } from "../types";

type Props = {
  flows: Flow[]; selected: Set<string>;
  onToggle: (id: string) => void; onToggleAll: () => void; onView: (id: string) => void;
};

export default function FlowTable({ flows, selected, onToggle, onToggleAll, onView }: Props) {
  const all = flows.length > 0 && selected.size === flows.length;
  return (
    <table className="table">
      <thead>
        <tr>
          <th><input type="checkbox" checked={all} onChange={onToggleAll} aria-label="Select all" /></th>
          <th>Flow</th><th>State</th><th>Last modified</th><th />
        </tr>
      </thead>
      <tbody>
        {flows.map((f) => (
          <tr key={f.id}>
            <td><input type="checkbox" checked={selected.has(f.id)} onChange={() => onToggle(f.id)} /></td>
            <td>{f.displayName}</td>
            <td>{f.state}</td>
            <td>{f.lastModifiedTime ? new Date(f.lastModifiedTime).toLocaleString() : "—"}</td>
            <td><button className="btn ghost" onClick={() => onView(f.id)}>View JSON</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

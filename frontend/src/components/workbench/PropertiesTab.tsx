import "./CenterTabs.css";
import FileDropzone from "../FileDropzone";
import type { Application, FlowFile } from "../../types";

type Props = {
  app: Application | undefined;
  onAddFlows: (id: string, flows: FlowFile[]) => void;
  onRemoveFlow: (id: string, filename: string) => void;
  onError: (msg: string) => void;
  readOnly?: boolean;
};

export default function PropertiesTab({ app, onAddFlows, onRemoveFlow, onError, readOnly }: Props) {
  if (!app) return <div className="pane-pad muted">Select an application in the Explorer to see its properties.</div>;

  const add = async (files: File[]) => {
    try {
      const flows = await Promise.all(files.map(async (f) => {
        try { return { filename: f.name, content: JSON.parse(await f.text()) }; }
        catch { throw new Error(`${f.name} is not valid JSON`); }
      }));
      onAddFlows(app.id, flows);
    } catch (e) { onError((e as Error).message); }
  };

  return (
    <div className="pane-pad">
      <h3>{app.name}</h3>
      <table className="prop-table"><tbody>
        <tr><td>Working directory</td><td>{app.workingDir || "—"}</td></tr>
        <tr><td>Created</td><td>{new Date(app.createdAt).toLocaleString()}</td></tr>
        <tr><td>Flows</td><td>{app.flows.length}</td></tr>
      </tbody></table>
      <ul className="file-list">
        {app.flows.map((f) => (
          <li key={f.filename}>{f.filename}
            {!readOnly && <button className="btn ghost" onClick={() => onRemoveFlow(app.id, f.filename)}>Remove</button>}</li>
        ))}
      </ul>
      {readOnly ? <p className="muted">You have read-only access, so files cannot be added.</p> : <FileDropzone onFiles={add} />}
    </div>
  );
}

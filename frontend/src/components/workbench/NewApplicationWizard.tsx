import "./NewApplicationWizard.css";
import { useRef, useState } from "react";
import FileDropzone from "../FileDropzone";
import { expandUploads } from "../../lib/solutionZip";
import type { FlowFile } from "../../types";

type Props = {
  onCancel: () => void;
  onFinish: (name: string, description: string, workingDir: string, flows: FlowFile[]) => void;
};

async function readFlows(files: File[]): Promise<FlowFile[]> {
  return Promise.all(files.map(async (f) => {
    try { return { filename: f.name, content: JSON.parse(await f.text()) }; }
    catch { throw new Error(`${f.name} is not valid JSON`); }
  }));
}

export default function NewApplicationWizard({ onCancel, onFinish }: Props) {
  const [page, setPage] = useState(1);
  const [name, setName] = useState("");
  const [workingDir, setWorkingDir] = useState("");
  const [flows, setFlows] = useState<FlowFile[]>([]);
  const [err, setErr] = useState("");
  const [picked, setPicked] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  // Browse: pick one or more flow .json files.
  const onFiles = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    const expanded = await expandUploads(Array.from(list));
    const files = expanded.files;
    const ok: FlowFile[] = [];
    const bad: string[] = [];
    for (const f of files) {
      try { ok.push({ filename: f.name, content: JSON.parse(await f.text()) }); } catch { bad.push(f.name); }
    }
    setFlows((cur) => [...cur.filter((c) => !ok.some((r) => r.filename === c.filename)), ...ok]);
    if (ok.length) {
      setWorkingDir(ok.length === 1 ? ok[0].filename : `${ok.length} files selected`);
      if (!name.trim()) setName(ok[0].filename.replace(/\.json$/i, ""));
    }
    const extra = expanded.notes.length ? ` ${expanded.notes.join(" ")}` : "";
    setPicked((ok.length ? `${ok.length} flow file(s) loaded${bad.length ? `; not valid JSON: ${bad.join(", ")}` : ""}.`
                        : `No valid .json file or solution .zip selected${bad.length ? ` (not valid JSON: ${bad.join(", ")})` : ""}.`) + extra);
    setErr("");
    if (fileInput.current) fileInput.current.value = "";   // allow picking the same file again
  };

  const add = async (files: File[]) => {
    try {
      const read = await readFlows(files);
      setFlows((cur) => [...cur.filter((c) => !read.some((r) => r.filename === c.filename)), ...read]);
      setErr("");
    } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div className="wiz-backdrop">
      <div className="wiz" role="dialog" aria-label="New Application Wizard">
        <div className="wiz-title"><span>New Application Wizard</span><button onClick={onCancel} aria-label="Close">✕</button></div>
        <div className="wiz-head">
          <h4>{page === 1 ? "Application Information" : "Flow files"}</h4>
          <span className="muted">{page === 1 ? "Specify the application name and where its flows come from." : "Add the exported flow JSON files to scan. You can add more later."}</span>
        </div>
        <div className="wiz-body">
          {page === 1 ? (
            <>
              <div className="wiz-row"><label>Name:</label><input autoFocus value={name} onChange={(e) => setName(e.target.value)} /></div>
              <div className="wiz-row"><label>Working Directory:</label>
                <input value={workingDir} placeholder="Browse to select exported flow .json file(s)"
                  onChange={(e) => setWorkingDir(e.target.value)} />
                <button type="button" className="wiz-browse" title="Browse for flow JSON files"
                  onClick={() => fileInput.current?.click()}>…</button>
                <input ref={fileInput} type="file" accept=".json,.zip,.nupkg,.xaml,.bot,.atmx,.bprelease,.bpobject,.bpprocess,.xml,application/json" hidden multiple
                  onChange={(e) => onFiles(e.target.files)} />
              </div>
              {picked && <p className="wiz-note">{picked}</p>}
              <p className="wiz-note muted">Hold Ctrl or Shift to select several files. A browser cannot show the full disk path, so only the file name is shown.</p>
            </>
          ) : (
            <>
              <FileDropzone onFiles={add} />
              <ul className="file-list">
                {flows.map((f) => (
                  <li key={f.filename}>{f.filename}
                    <button className="btn ghost" onClick={() => setFlows(flows.filter((x) => x !== f))}>Remove</button></li>
                ))}
              </ul>
              {err && <p className="error">{err}</p>}
            </>
          )}
        </div>
        <div className="wiz-foot">
          <button disabled={page === 1} onClick={() => setPage(1)}>&lt; Back</button>
          <button disabled={page === 2 || !name.trim()} onClick={() => setPage(2)}>Next &gt;</button>
          <button className="primary" disabled={!name.trim()} onClick={() => onFinish(name.trim(), "", workingDir.trim(), flows)}>Finish</button>
          <button onClick={onCancel}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

import "./NewApplicationWizard.css";
import { useRef, useState } from "react";
import FileDropzone from "../FileDropzone";
import { expandUploads } from "../../lib/solutionZip";
import { readFolder } from "../../lib/folderImport";
import type { FlowFile } from "../../types";

type Props = {
  onCancel: () => void;
  onFinish: (name: string, description: string, workingDir: string, flows: FlowFile[]) => void;
};

/** What kind of automation the application holds. It decides which files the Browse button offers. */
const PROJECT_TYPES: { group: string; items: { id: string; label: string; accept: string }[] }[] = [
  { group: "Automation platforms", items: [
    { id: "pa-cloud", label: "Power Automate cloud flows", accept: ".json,.zip,application/json" },
    { id: "pa-solution", label: "Power Platform solution package", accept: ".zip" },
    { id: "uipath", label: "UiPath", accept: ".xaml,.nupkg,.json,.zip" },
    { id: "aa", label: "Automation Anywhere", accept: ".bot,.atmx,.json,.zip" },
    { id: "bp", label: "Blue Prism", accept: ".bprelease,.bpobject,.bpprocess,.xml" },
    { id: "n8n", label: "n8n workflow", accept: ".json" },
    { id: "make", label: "Make scenario blueprint", accept: ".json" },
  ] },
  { group: "AI and agents", items: [
    { id: "mcp", label: "MCP server configuration", accept: ".json" },
    { id: "agent", label: "AI agent definition", accept: ".json,.yaml,.yml,.md" },
  ] },
  { group: "Other", items: [
    { id: "any", label: "Any supported file (detect automatically)", accept: ".json,.zip,.nupkg,.xaml,.bot,.atmx,.bprelease,.bpobject,.bpprocess,.xml,application/json" },
  ] },
];
const ALL_TYPES = PROJECT_TYPES.flatMap((g) => g.items);

async function readFlows(files: File[]): Promise<FlowFile[]> {
  return Promise.all(files.map(async (f) => {
    try { return { filename: f.name, content: JSON.parse(await f.text()) }; }
    catch { throw new Error(`${f.name} is not valid JSON`); }
  }));
}

export default function NewApplicationWizard({ onCancel, onFinish }: Props) {
  const [page, setPage] = useState(0);
  const [typeId, setTypeId] = useState("pa-cloud");
  const type = ALL_TYPES.find((t) => t.id === typeId)!;
  const [name, setName] = useState("");
  const [workingDir, setWorkingDir] = useState("");
  const [flows, setFlows] = useState<FlowFile[]>([]);
  const [err, setErr] = useState("");
  const [picked, setPicked] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);

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

  // Browse for a folder: every supported file inside it (and its sub-folders) is loaded.
  const onFolder = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    const got = await readFolder(Array.from(list));
    setFlows((cur) => [...cur.filter((c) => !got.flows.some((r) => r.filename === c.filename)), ...got.flows]);
    setWorkingDir(got.name);
    if (got.flows.length && !name.trim()) setName(got.name);
    setPicked((got.flows.length ? `${got.flows.length} file(s) loaded from folder "${got.name}".` : `No supported automation files found in "${got.name}".`)
      + (got.notes.length ? ` ${got.notes.join(" ")}` : ""));
    setErr("");
    if (dirInput.current) dirInput.current.value = "";
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
          <h4>{page === 0 ? "Select Project Type" : page === 1 ? "Application Information" : "Flow files"}</h4>
          <span className="muted">{page === 0 ? "Select the type of project to create." : page === 1 ? "Specify the application name and where its files come from." : "Add the exported files to scan. You can add more later."}</span>
        </div>
        <div className="wiz-body">
          {page === 0 ? (
            <div role="radiogroup" aria-label="Project type">
              {PROJECT_TYPES.map((g) => (
                <fieldset key={g.group} className="wiz-group"><legend>{g.group}</legend>
                  {g.items.map((t) => (
                    <label key={t.id} className="wiz-radio">
                      <input type="radio" name="ptype" checked={typeId === t.id} onChange={() => setTypeId(t.id)} /> {t.label}
                    </label>
                  ))}
                </fieldset>
              ))}
            </div>
          ) : page === 1 ? (
            <>
              <div className="wiz-row"><label>Name:</label><input autoFocus value={name} onChange={(e) => setName(e.target.value)} /></div>
              <div className="wiz-row"><label>Working Directory:</label>
                <input value={workingDir} placeholder="Browse to select the folder that holds the exported files"
                  onChange={(e) => setWorkingDir(e.target.value)} />
                <button type="button" className="wiz-browse" title="Browse for a folder"
                  onClick={() => dirInput.current?.click()}>…</button>
                <button type="button" className="wiz-browse wide" title="Pick individual files instead"
                  onClick={() => fileInput.current?.click()}>Files…</button>
                <input ref={dirInput} type="file" hidden multiple onChange={(e) => onFolder(e.target.files)}
                  {...({ webkitdirectory: "", directory: "" } as Record<string, string>)} />
                <input ref={fileInput} type="file" accept={type.accept} hidden multiple
                  onChange={(e) => onFiles(e.target.files)} />
              </div>
              {picked && <p className="wiz-note">{picked}</p>}
              <p className="wiz-note muted">"…" picks a whole folder (the browser then asks to confirm the upload; nothing leaves your computer). "Files…" picks individual files. A browser cannot show the full disk path, so only the name is shown.</p>
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
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>&lt; Back</button>
          <button disabled={page === 2 || (page === 1 && !name.trim())} onClick={() => setPage(page + 1)}>Next &gt;</button>
          <button className="primary" disabled={page === 0 || !name.trim()} onClick={() => onFinish(name.trim(), `Type: ${type.label}`, workingDir.trim(), flows)}>Finish</button>
          <button onClick={onCancel}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

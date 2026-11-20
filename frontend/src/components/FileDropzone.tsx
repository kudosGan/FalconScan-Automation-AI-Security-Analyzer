import "./FileDropzone.css";
import { useRef, useState } from "react";
import { expandUploads } from "../lib/solutionZip";

export default function FileDropzone({ onFiles }: { onFiles: (files: File[]) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [notes, setNotes] = useState<string[]>([]);
  const pick = async (list: FileList | null) => {
    if (!list) return;
    const got = await expandUploads(Array.from(list));
    setNotes(got.notes);
    if (got.files.length) onFiles(got.files);
    if (input.current) input.current.value = "";
  };
  return (
    <div
      className={`dropzone ${over ? "over" : ""}`}
      onClick={() => input.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); pick(e.dataTransfer.files); }}
    >
      <p><b>Drop flow, MCP, agent or RPA files (.json, .xaml, .bot, .bprelease), or a .zip / .nupkg, here</b> or click to browse</p>
      <p className="muted">Files are scanned locally by your backend and never sent to Microsoft.</p>
      {notes.map((n) => <p key={n} className="muted">{n}</p>)}
      <input ref={input} type="file" accept=".json,.zip,.nupkg,.xaml,.bot,.atmx,.bprelease,.bpobject,.bpprocess,.xml" multiple hidden onChange={(e) => pick(e.target.files)} />
    </div>
  );
}

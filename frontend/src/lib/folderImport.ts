import { expandUploads } from "./solutionZip";
import type { FlowFile } from "../types";

const SUPPORTED = /\.(json|zip|nupkg|xaml|bot|atmx|bprelease|bpobject|bpprocess|xml)$/i;
const MAX_BYTES = 20 * 1024 * 1024;

export type FolderRead = { name: string; flows: FlowFile[]; notes: string[] };

/** Read every supported file in a chosen folder (and its sub-folders). Files that are not automation files are skipped and counted. */
export async function readFolder(files: File[]): Promise<FolderRead> {
  const rel = (f: File) => f.webkitRelativePath || f.name;
  const name = rel(files[0] ?? new File([], "Folder")).split("/")[0] || "Folder";
  const flows: FlowFile[] = [];
  const notes: string[] = [];
  let skipped = 0;
  for (const f of files) {
    if (!SUPPORTED.test(f.name) || f.size > MAX_BYTES) { skipped++; continue; }
    const sub = rel(f).split("/").slice(1, -1).join("/");        // folder path below the chosen folder
    const got = await expandUploads([f]);
    notes.push(...got.notes);
    for (const g of got.files) {
      const label = sub && !/\.(zip|nupkg)$/i.test(f.name) ? `${sub}/${g.name}` : g.name;
      try { flows.push({ filename: uniqueName(label, flows), content: JSON.parse(await g.text()) }); }
      catch { skipped++; }
    }
  }
  if (skipped) notes.push(`${skipped} file(s) skipped (not automation files, not readable, or over 20 MB).`);
  return { name, flows, notes };
}

function uniqueName(label: string, taken: FlowFile[]): string {
  if (!taken.some((t) => t.filename === label)) return label;
  const dot = label.lastIndexOf(".");
  const stem = dot > 0 ? label.slice(0, dot) : label;
  const ext = dot > 0 ? label.slice(dot) : "";
  for (let n = 2; ; n++) if (!taken.some((t) => t.filename === `${stem} (${n})${ext}`)) return `${stem} (${n})${ext}`;
}

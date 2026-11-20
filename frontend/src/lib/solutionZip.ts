import { api } from "../api/client";

const isZip = (f: File) => /\.(zip|nupkg)$/i.test(f.name);
// RPA exports are text (XML or JSON) and travel in a small wrapper so the backend can tell what they are.
const RPA_TEXT = /\.(xaml|bot|atmx|bprelease|bpobject|bpprocess|xml)$/i;

async function toBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export type Expanded = { files: File[]; notes: string[] };

/** Keep .json files as they are; read each Power Platform solution .zip on the backend and return its cloud flows as .json files. */
export async function expandUploads(list: File[]): Promise<Expanded> {
  const files: File[] = [];
  const notes: string[] = [];
  for (const f of list) {
    const name = f.name.toLowerCase();
    if (name.endsWith(".json")) { files.push(f); continue; }
    if (RPA_TEXT.test(f.name)) {
      const text = await f.text();
      files.push(new File([JSON.stringify({ format: "rpa-file", name: f.name, text })], f.name, { type: "application/json" }));
      continue;
    }
    if (!isZip(f)) continue;
    try {
      const got = await api.extractSolution(f.name, await toBase64(f));
      got.flows.forEach((x) => files.push(new File([JSON.stringify(x.content)], x.filename, { type: "application/json" })));
      notes.push(`${f.name}: ${got.flows.length} file(s) read${got.skipped.length ? `, ${got.skipped.length} file(s) skipped (not flows or RPA files)` : ""}.`);
    } catch (e) {
      notes.push(`${f.name}: ${(e as Error).message}`);
    }
  }
  return { files, notes };
}

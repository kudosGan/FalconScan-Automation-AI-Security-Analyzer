import "./NewScan.css";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import FileDropzone from "../components/FileDropzone";

export default function NewScan() {
  const nav = useNavigate();
  const { signedIn } = useAuth();
  const { addScan } = useScan();
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const add = (fs: File[]) => setFiles((cur) => [...cur, ...fs.filter((f) => !cur.some((c) => c.name === f.name))]);

  const start = async () => {
    setBusy(true); setErr("");
    try {
      const parsed = await Promise.all(files.map(async (f) => {
        try { return { filename: f.name, content: JSON.parse(await f.text()) }; }
        catch { throw new Error(`${f.name} is not valid JSON`); }
      }));
      const id = addScan(await api.scanUpload(parsed), "upload");
      nav(`/scan/run/${id}`);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <>
      <h2>New scan</h2>
      <div className="source-grid">
        <div className="card">
          <h3>Upload flow files</h3>
          <p className="muted">Export a flow as a Logic Apps template (.json) or package definition and drop it here. No sign-in needed.</p>
          <FileDropzone onFiles={add} />
          {files.length > 0 && (
            <ul className="file-list">
              {files.map((f) => (
                <li key={f.name}>{f.name}
                  <button className="btn ghost" onClick={() => setFiles(files.filter((x) => x !== f))}>Remove</button>
                </li>
              ))}
            </ul>
          )}
          {err && <p className="error">{err}</p>}
          <button className="btn" disabled={!files.length || busy} onClick={start}>
            {busy ? "Preparing…" : "Start scan"}
          </button>
        </div>
        <div className="card">
          <h3>Live from Power Platform</h3>
          <p className="muted">Sign in, pick an environment and scan flows directly.</p>
          <Link className="btn" to={signedIn ? "/scanner" : "/connect"}>{signedIn ? "Open live scanner" : "Connect to Microsoft"}</Link>
        </div>
      </div>
    </>
  );
}

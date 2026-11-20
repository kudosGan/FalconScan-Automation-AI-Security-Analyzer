import "./AdminPanel.css";
import "./AssessmentsTable.css";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api } from "../../api/client";
import type { Application, Schedule, SchedulesResponse } from "../../types";

const EVERY: [string, number][] = [["Every hour", 60], ["Every 6 hours", 360], ["Every day", 1440], ["Every week", 10080]];
const every = (m: number) => EVERY.find(([, v]) => v === m)?.[0] ?? (m % 60 === 0 ? `Every ${m / 60} hours` : `Every ${m} minutes`);
const when = (t: number | null) => (t ? new Date(t * 1000).toLocaleString() : "never");

type Props = { apps: Application[]; canEdit: boolean; onChanged: () => void };

/** Re-scan an application or a server folder on a timetable, and see whether the release gate would pass. */
export default function SchedulesPanel({ apps, canEdit, onChanged }: Props) {
  const [data, setData] = useState<SchedulesResponse | null>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [form, setForm] = useState({ name: "", sourceType: "application", sourceRef: "", intervalMinutes: 1440, failOn: "High" });

  const load = useCallback(() => api.schedules().then(setData).catch((e) => setMsg(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, ok = "") => {
    try { await fn(); setMsg(ok); await load(); onChanged(); } catch (e) { setMsg((e as Error).message); }
  };
  const create = (e: FormEvent) => {
    e.preventDefault();
    const ref = form.sourceType === "application" ? form.sourceRef || apps[0]?.id || "" : form.sourceRef;
    act(async () => { await api.createSchedule({ ...form, sourceRef: ref }); setForm({ ...form, name: "" }); }, `Schedule "${form.name}" created.`);
  };
  const label = (s: Schedule) => (s.sourceType === "application" ? apps.find((a) => a.id === s.sourceRef)?.name ?? "(deleted application)" : `Folder: ${s.sourceRef}`);

  return (
    <div className="pane-pad admin-pane">
      <h3>Scheduled scans</h3>
      <p className="muted">A schedule re-scans an application you saved{data?.folderSchedules ? `, or a folder under "${data.scanRootName}" on the server,` : ""} and records the result under My Assessments.
        The gate result ignores findings you marked Fixed, Accepted risk or Noise. The backend must stay running for schedules to fire.</p>
      {msg && <p className="admin-msg" role="status">{msg}</p>}
      <table className="grid">
        <thead><tr><th>Name</th><th>Source</th><th>Runs</th><th>Gate</th><th>On</th><th>Last run</th><th>Result</th><th>Next run</th><th /></tr></thead>
        <tbody>
          {data?.schedules.map((s) => (
            <tr key={s.id} className="row">
              <td>{s.name}</td><td>{label(s)}</td><td>{every(s.intervalMinutes)}</td><td>{s.failOn === "none" ? "report only" : `fail on ${s.failOn}`}</td>
              <td><input type="checkbox" checked={s.enabled} disabled={!canEdit} onChange={(e) => act(() => api.updateSchedule(s.id, { enabled: e.target.checked }))} /></td>
              <td>{when(s.lastRun)}</td>
              <td className={s.lastStatus.startsWith("Gate failed") || s.lastStatus.startsWith("Error") ? "bad-text" : ""}>{s.lastStatus || "not run yet"}</td>
              <td>{s.enabled ? when(s.nextRun) : "paused"}</td>
              <td>{canEdit && <>
                <button disabled={busy === s.id} onClick={async () => { setBusy(s.id); await act(() => api.runSchedule(s.id), `"${s.name}" ran.`); setBusy(null); }}>{busy === s.id ? "Running…" : "Run now"}</button>{" "}
                <button onClick={() => confirm(`Delete the schedule "${s.name}"?`) && act(() => api.deleteSchedule(s.id), "Schedule deleted.")}>Delete</button></>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data && data.schedules.length === 0 && <p className="muted">No schedules yet.</p>}
      {canEdit && (
        <>
          <h4>New schedule</h4>
          <form className="admin-form" onSubmit={create}>
            <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <select value={form.sourceType} onChange={(e) => setForm({ ...form, sourceType: e.target.value, sourceRef: "" })}>
              <option value="application">Saved application</option>{data?.folderSchedules && <option value="folder">Server folder</option>}
            </select>
            {form.sourceType === "application"
              ? <select value={form.sourceRef || apps[0]?.id || ""} onChange={(e) => setForm({ ...form, sourceRef: e.target.value })}>
                  {apps.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select>
              : <input placeholder={`Folder under ${data?.scanRootName ?? "the scan folder"}`} value={form.sourceRef} onChange={(e) => setForm({ ...form, sourceRef: e.target.value })} required />}
            <select value={form.intervalMinutes} onChange={(e) => setForm({ ...form, intervalMinutes: Number(e.target.value) })}>
              {EVERY.map(([l, v]) => <option key={v} value={v}>{l}</option>)}</select>
            <select value={form.failOn} onChange={(e) => setForm({ ...form, failOn: e.target.value })}>
              <option value="High">Fail on High</option><option value="Medium">Fail on Medium</option><option value="Low">Fail on Low</option><option value="none">Report only</option></select>
            <button className="btn" disabled={form.sourceType === "application" && apps.length === 0}>Create schedule</button>
          </form>
          {!data?.folderSchedules && <p className="muted">Folder schedules are off. Set FALCON_SCAN_ROOT on the server to a folder that exports are dropped into to turn them on.</p>}
        </>
      )}
    </div>
  );
}

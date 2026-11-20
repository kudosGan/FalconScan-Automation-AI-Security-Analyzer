import "./AdminPanel.css";
import "./AssessmentsTable.css";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api } from "../../api/client";
import type { AdminUser, AuditEntry, AuditVerify, Role } from "../../types";

const ROLES: Role[] = ["viewer", "assessor", "admin"];
const ROLE_HELP: Record<Role, string> = {
  viewer: "reads everything, changes nothing", assessor: "scans, triages, manages applications, tickets and schedules", admin: "everything, plus users and the audit log",
};

function Users() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [msg, setMsg] = useState("");
  const [form, setForm] = useState({ username: "", displayName: "", password: "", role: "viewer" as Role });
  const [reset, setReset] = useState<{ id: number; password: string } | null>(null);

  const load = useCallback(() => api.adminUsers().then(setUsers).catch((e) => setMsg(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, ok = "") => {
    try { await fn(); setMsg(ok); await load(); } catch (e) { setMsg((e as Error).message); }
  };
  const create = (e: FormEvent) => {
    e.preventDefault();
    act(async () => { await api.adminCreateUser(form); setForm({ username: "", displayName: "", password: "", role: "viewer" }); }, `User ${form.username} created.`);
  };

  return (
    <>
      <p className="muted">Roles: {ROLES.map((r) => <span key={r}><b>{r}</b> {ROLE_HELP[r]}. </span>)}</p>
      {msg && <p className="admin-msg" role="status">{msg}</p>}
      <table className="grid">
        <thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Active</th><th>Last sign-in</th><th>Status</th><th /></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} className="row">
              <td>{u.username}</td><td>{u.displayName}</td>
              <td><select value={u.role} onChange={(e) => act(() => api.adminUpdateUser(u.id, { role: e.target.value as Role }), `${u.username} is now ${e.target.value}.`)}>
                {ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
              <td><input type="checkbox" checked={u.active} onChange={(e) => act(() => api.adminUpdateUser(u.id, { active: e.target.checked }), `${u.username} ${e.target.checked ? "re-enabled" : "disabled"}.`)} /></td>
              <td>{u.lastLogin ? new Date(u.lastLogin).toLocaleString() : "never"}</td>
              <td>{u.locked ? <>Locked <button onClick={() => act(() => api.adminUpdateUser(u.id, { unlock: true }), `${u.username} unlocked.`)}>Unlock</button></> : u.active ? "OK" : "Disabled"}</td>
              <td>{reset?.id === u.id
                ? <span className="inline-form"><input type="password" placeholder="New password (12+ characters)" value={reset.password} autoFocus
                    onChange={(e) => setReset({ id: u.id, password: e.target.value })} />
                    <button onClick={() => act(async () => { await api.adminUpdateUser(u.id, { password: reset.password }); setReset(null); }, `Password reset for ${u.username}; their sessions were ended.`)}>Save</button>
                    <button onClick={() => setReset(null)}>Cancel</button></span>
                : <button onClick={() => setReset({ id: u.id, password: "" })}>Reset password</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>Add a user</h4>
      <form className="admin-form" onSubmit={create}>
        <input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        <input placeholder="Display name" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
        <input type="password" placeholder="Password (12+ characters)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required autoComplete="new-password" />
        <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
        <button className="btn">Add user</button>
      </form>
    </>
  );
}

function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [filter, setFilter] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async (before?: number) => {
    try {
      const r = await api.adminAudit(filter, before);
      setEntries((cur) => (before ? [...cur, ...r.entries] : r.entries)); setVerify(r.verify); setErr("");
    } catch (e) { setErr((e as Error).message); }
  }, [filter]);
  useEffect(() => { load(); }, [load]);

  return (
    <>
      <div className="admin-form">
        <input placeholder="Filter by action, for example login or scan" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <button onClick={() => load()}>Refresh</button>
        <a className="btn ghost" href="/api/admin/audit.csv" download>Export CSV</a>
        {verify && <span className={verify.ok ? "chain ok" : "chain bad"} title={`Head ${verify.head}`}>
          {verify.ok ? `Log intact (${verify.checked} entries)` : `Log altered at entry ${verify.brokenAt}`}</span>}
      </div>
      {err && <p className="error">{err}</p>}
      <table className="grid">
        <thead><tr><th>Time</th><th>Who</th><th>Role</th><th>Action</th><th>Target</th><th>Details</th><th>From</th></tr></thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className="row">
              <td>{new Date(e.ts).toLocaleString()}</td><td>{e.actor}</td><td>{e.role}</td><td><b>{e.action}</b></td><td title={e.target}>{e.target}</td>
              <td title={JSON.stringify(e.detail)}>{Object.entries(e.detail).map(([k, v]) => `${k}=${v}`).join(" ")}</td><td>{e.ip}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {entries.length > 0 && entries.length % 100 === 0 && <button onClick={() => load(entries[entries.length - 1].id)}>Load older entries</button>}
      <p className="muted">Each entry carries a fingerprint of the one before it, so editing or removing an entry in the middle is detected. Export the log regularly and keep the copy elsewhere to also detect removal of the newest entries.</p>
    </>
  );
}

export default function AdminPanel() {
  const [tab, setTab] = useState<"users" | "audit">("users");
  return (
    <div className="pane-pad admin-pane">
      <h3>Administration</h3>
      <div className="subtabs">
        <button className={tab === "users" ? "on" : ""} onClick={() => setTab("users")}>Users</button>
        <button className={tab === "audit" ? "on" : ""} onClick={() => setTab("audit")}>Audit log</button>
      </div>
      {tab === "users" ? <Users /> : <Audit />}
    </div>
  );
}

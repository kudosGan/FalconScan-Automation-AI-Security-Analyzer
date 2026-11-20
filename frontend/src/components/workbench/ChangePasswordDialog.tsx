import "./SaaReportDialog.css";
import "./NewApplicationWizard.css";
import { useState, type FormEvent } from "react";
import { api } from "../../api/client";

export default function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [msg, setMsg] = useState("");
  const [done, setDone] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== again) { setMsg("The two new passwords do not match."); return; }
    try { await api.accountPassword(current, next); setDone(true); setMsg("Password changed. Other sessions of yours were signed out."); }
    catch (x) { setMsg((x as Error).message); }
  };

  return (
    <div className="wiz-backdrop">
      <form className="saa" role="dialog" aria-label="Change password" onSubmit={submit}>
        <div className="wiz-title"><span>Change password</span><button type="button" onClick={onClose} aria-label="Close">✕</button></div>
        <div className="saa-body">
          <label>Current password<input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required autoFocus /></label>
          <label>New password<input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required /></label>
          <label>Repeat the new password<input type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required /></label>
          <p className="saa-note">At least 12 characters, and not easy to guess.</p>
          {msg && <p className={done ? "saa-note" : "error"} role="alert">{msg}</p>}
        </div>
        <div className="saa-foot">
          <button type="button" onClick={onClose}>{done ? "Close" : "Cancel"}</button>
          {!done && <button className="primary">Change password</button>}
        </div>
      </form>
    </div>
  );
}

import "./Login.css";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import Logo from "../components/Logo";
import { BRAND } from "../brand";
import { useSession } from "../context/SessionContext";


/** A password box with an eye button to show or hide what was typed. */
function PasswordInput({ value, onChange, autoComplete }: { value: string; onChange: (v: string) => void; autoComplete: string }) {
  const [show, setShow] = useState(false);
  return (
    <span className="pw">
      <input type={show ? "text" : "password"} value={value} onChange={(e) => onChange(e.target.value)} required autoComplete={autoComplete} />
      <button type="button" className="eye" onClick={() => setShow(!show)} aria-label={show ? "Hide password" : "Show password"} title={show ? "Hide password" : "Show password"}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z" /><circle cx="12" cy="12" r="3" />
          {show && <path d="M3 3l18 18" />}
        </svg>
      </button>
    </span>
  );
}

/** Sign-in, or the first-run screen that creates the first administrator. */
export default function Login() {
  const { setupRequired, login, setup, notice } = useSession();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [token, setToken] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    if (setupRequired && password !== again) { setErr("The two passwords do not match."); return; }
    setBusy(true);
    try { await (setupRequired ? setup(username, password, displayName, token) : login(username, password)); }
    catch (x) { setErr((x as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <Link to="/" className="back">← Back to home</Link>
        <Logo size={84} />
        <h1>{BRAND.name}</h1>
        <p className="tag">{BRAND.tagline}</p>
        <h2>{setupRequired ? "Create the first administrator" : "Sign in"}</h2>
        {setupRequired && <p className="muted">No accounts exist yet. This account will be able to add everyone else.</p>}
        {notice && !err && <p className="muted">{notice}</p>}
        <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required /></label>
        {setupRequired && <label>Display name (optional)<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>}
        <label>Password<PasswordInput value={password} onChange={setPassword} autoComplete={setupRequired ? "new-password" : "current-password"} /></label>
        {setupRequired && (
          <>
            <label>Repeat the password<PasswordInput value={again} onChange={setAgain} autoComplete="new-password" /></label>
            <p className="muted">At least 12 characters, and not easy to guess.</p>
            <details><summary>Not on the server itself?</summary>
              <label>Setup token<input value={token} onChange={(e) => setToken(e.target.value)} placeholder="FALCON_SETUP_TOKEN" /></label>
              <p className="muted">Set on the server as FALCON_SETUP_TOKEN. It is only needed when you open this page from another computer.</p>
            </details>
          </>
        )}
        {err && <p className="error" role="alert">{err}</p>}
        <button className="btn big" disabled={busy}>{busy ? "Please wait…" : setupRequired ? "Create account" : "Sign in"}</button>
      </form>
    </div>
  );
}

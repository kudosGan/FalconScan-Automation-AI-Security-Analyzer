import "./DeviceLogin.css";
import { useAuth } from "../context/AuthContext";

export default function DeviceLogin() {
  const { login, error, start } = useAuth();
  return (
    <div className="card center">
      <h2>Connect to Microsoft Power Platform</h2>
      <p className="muted">Sign in with an account that can read your cloud flows. Read-only; run data is never accessed.</p>
      {!login && <button className="btn" onClick={start}>Sign in with Microsoft</button>}
      {login && (
        <div className="code-box">
          <p>Open <a href={login.verification_uri} target="_blank" rel="noreferrer">{login.verification_uri}</a> and enter:</p>
          <div className="code">{login.user_code}</div>
          <p className="muted">Waiting for sign-in…</p>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

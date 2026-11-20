import "./AccountMenu.css";
import { useState } from "react";
import { useSession } from "../../context/SessionContext";
import ChangePasswordDialog from "./ChangePasswordDialog";

/** Who is signed in, with a role badge, a password change and sign out. Hidden when sign-in is switched off on the server. */
export default function AccountMenu() {
  const { authEnabled, user, logout } = useSession();
  const [pw, setPw] = useState(false);
  if (!authEnabled || !user) return null;
  return (
    <>
      <span className="who" title={`Signed in as ${user.username}`}>{user.displayName}<i className={`role ${user.role}`}>{user.role}</i></span>
      <button className="btn ghost" onClick={() => setPw(true)}>Password</button>
      <button className="btn ghost" onClick={logout}>Sign out</button>
      {pw && <ChangePasswordDialog onClose={() => setPw(false)} />}
    </>
  );
}

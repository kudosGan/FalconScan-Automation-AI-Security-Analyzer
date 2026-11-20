import "./Navbar.css";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import Logo from "./Logo";
import { BRAND } from "../brand";

export default function Navbar() {
  const { signedIn, user, signOut } = useAuth();
  return (
    <header className="navbar">
      <Link to="/" className="brand"><Logo size={36} /> <span>{BRAND.name}<small>{BRAND.tagline}</small></span></Link>
      <nav />
      <div className="nav-right">
        {signedIn ? (
          <>
            <span className="muted">{user}</span>
            <button className="btn ghost" onClick={signOut}>Sign out</button>
          </>
        ) : (
          <Link className="btn" to="/connect">Connect</Link>
        )}
      </div>
    </header>
  );
}

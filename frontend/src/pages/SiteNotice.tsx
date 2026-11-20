import "./Login.css";
import { Link } from "react-router-dom";
import Logo from "../components/Logo";
import { BRAND } from "../brand";

/** Shown instead of the login form on the public website, which has no application behind it. */
export default function SiteNotice() {
  return (
    <div className="login-page">
      <div className="login-card">
        <Link to="/" className="back">← Back to home</Link>
        <Logo size={84} />
        <h1>{BRAND.name}</h1>
        <p className="tag">{BRAND.tagline}</p>
        <h2>Private application</h2>
        <p className="muted">This public website is an overview of {BRAND.name}. The application itself is private and is available to authorised users only.</p>
        <p className="muted">To request access, contact the owner of this product.</p>
      </div>
    </div>
  );
}

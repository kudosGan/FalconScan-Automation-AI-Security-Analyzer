import "./SiteHeader.css";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import Logo from "./Logo";
import PencilIcon, { type IconName } from "./PencilIcon";
import { BRAND } from "../brand";
import { useSession } from "../context/SessionContext";

type Item = { label: string; href: string; icon: IconName; note?: string };
type Column = { heading: string; items: Item[] };
type Menu = { label: string; columns: Column[] };

/** Every link goes to a section on the landing page, so nothing here promises a feature that does not exist. */
const MENUS: Menu[] = [
  { label: "Platform", columns: [
    { heading: "What it does", items: [
      { label: "Static scanner", href: "#how", icon: "search", note: "Finds risky settings before go-live" },
      { label: "Fix guidance", href: "#how", icon: "puzzle", note: "A fix and an example for each finding" },
      { label: "Release gate", href: "#needs", icon: "link", note: "Block a release from the command line" },
      { label: "Reports", href: "#needs", icon: "chart", note: "SA&A report, POA&M and executive summary" },
    ] },
    { heading: "For teams", items: [
      { label: "Shared workspace", href: "#needs", icon: "link", note: "Sign-in, roles and an audit log" },
      { label: "Scheduled scans", href: "#needs", icon: "chart", note: "Re-scan on a timetable" },
      { label: "Jira and Azure DevOps", href: "#needs", icon: "puzzle", note: "File a ticket per finding" },
    ] },
  ] },
  { label: "Use cases", columns: [
    { heading: "By platform", items: [
      { label: "Power Automate", href: "#platforms", icon: "link" },
      { label: "UiPath", href: "#platforms", icon: "puzzle" },
      { label: "Automation Anywhere", href: "#platforms", icon: "puzzle", note: "Basic checks" },
      { label: "Blue Prism", href: "#platforms", icon: "puzzle", note: "Basic checks" },
      { label: "MCP servers", href: "#platforms", icon: "search" },
      { label: "AI agents", href: "#platforms", icon: "search" },
    ] },
    { heading: "By risk type", items: [
      { label: "Hard-coded secrets", href: "#risks", icon: "search" },
      { label: "Data leakage", href: "#risks", icon: "chart" },
      { label: "Destructive actions", href: "#risks", icon: "puzzle" },
      { label: "Insecure connections", href: "#risks", icon: "link" },
    ] },
    { heading: "By business need", items: [
      { label: "Release approval", href: "#needs", icon: "link" },
      { label: "Compliance evidence", href: "#needs", icon: "chart" },
      { label: "Ongoing monitoring", href: "#needs", icon: "search" },
    ] },
  ] },
  { label: "Resources", columns: [
    { heading: "Get started", items: [
      { label: "How it works", href: "#how", icon: "search" },
      { label: "Try the sample files", href: "#how", icon: "puzzle", note: "Built-in sample application" },
    ] },
  ] },
  { label: "Company", columns: [
    { heading: "About", items: [{ label: BRAND.name, href: "#top", icon: "link", note: BRAND.tagline }] },
  ] },
];

export default function SiteHeader() {
  const { authEnabled, user } = useSession();
  const [open, setOpen] = useState<number | null>(null);
  const bar = useRef<HTMLElement>(null);

  useEffect(() => {
    const away = (e: MouseEvent) => { if (bar.current && !bar.current.contains(e.target as Node)) setOpen(null); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(null); };
    document.addEventListener("mousedown", away); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, []);

  // With sign-in switched off on the server there is nothing to log in to, so the button goes straight in.
  const action = !authEnabled ? { to: "/workbench", text: "Open workbench" }
    : user ? { to: "/workbench", text: "Open workbench" } : { to: "/login", text: "Login" };

  return (
    <header className="site-header" ref={bar} id="top">
      <Link to="/" className="brand"><Logo size={36} /> <span>{BRAND.name}<small>{BRAND.tagline}</small></span></Link>
      <nav className="site-nav" aria-label="Main">
        {MENUS.map((m, i) => (
          <div key={m.label} className={"site-menu" + (open === i ? " open" : "")} onMouseEnter={() => setOpen(i)} onMouseLeave={() => setOpen(null)}>
            <button type="button" aria-expanded={open === i} onClick={() => setOpen(open === i ? null : i)}>{m.label} <span className="caret">{open === i ? "▴" : "▾"}</span></button>
            {open === i && (
              <div className="mega" style={{ gridTemplateColumns: `repeat(${m.columns.length}, minmax(190px, 1fr))` }}>
                {m.columns.map((c) => (
                  <div key={c.heading}>
                    <h4>{c.heading}</h4>
                    {c.items.map((it) => (
                      <a key={it.label} href={it.href} onClick={() => setOpen(null)}>
                        <span className="ico"><PencilIcon name={it.icon} size={18} /></span>
                        <span>{it.label}{it.note && <small>{it.note}</small>}</span>
                      </a>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </nav>
      <Link className="btn login-btn" to={action.to}>{action.text}</Link>
    </header>
  );
}

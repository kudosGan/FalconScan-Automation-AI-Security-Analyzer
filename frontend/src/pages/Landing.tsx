import "./Landing.css";
import AppLink from "../components/AppLink";
import Logo from "../components/Logo";
import SiteHeader from "../components/SiteHeader";
import { BRAND } from "../brand";
import { useSession } from "../context/SessionContext";
import PencilIcon, { type IconName } from "../components/PencilIcon";

const platforms: { title: string; status: string; text: string }[] = [
  { title: "Power Automate", status: "Active", text: "Cloud flows and solution .zip files: triggers, actions, connectors, secrets, data flow and DLP policy." },
  { title: "UiPath", status: "Active", text: "project.json, .xaml workflows and .nupkg packages: credentials, insecure calls, logging and dependencies." },
  { title: "n8n and Make", status: "Active", text: "Workflow exports: open webhooks, hard-coded secrets, plain HTTP, disabled TLS checks, shell and code steps, SQL built from data and AI services." },
  { title: "MCP servers and AI agents", status: "Active", text: "MCP configs and agent definitions: risky tools, auto-approval, exposed secrets and unsafe prompts." },
  { title: "Automation Anywhere and Blue Prism", status: "Basic checks", text: "Exports are scanned for secrets and plain-HTTP addresses. Vendor-specific rules are not yet built." },
];

const risks: { icon: IconName; title: string; text: string }[] = [
  { icon: "search", title: "Hard-coded secrets", text: "Keys, passwords and tokens left in definitions, with the value hidden in the report." },
  { icon: "chart", title: "Data leakage", text: "Sensitive data sent to the wrong connector, and connector policy breaches." },
  { icon: "puzzle", title: "Destructive actions", text: "Delete, run-anything and auto-approved tools that can do damage unattended." },
  { icon: "link", title: "Insecure connections", text: "Plain HTTP, disabled certificate checks and unprotected inputs and outputs." },
];

const needs: { icon: IconName; title: string; text: string }[] = [
  { icon: "link", title: "Release gate", text: "A command-line check that stops a release when blocking findings remain. Waivers need a reason and an expiry." },
  { icon: "puzzle", title: "Fix guidance and auto-fix", text: "Each finding explains the fix. A few mechanical problems can be corrected in a copy of the file." },
  { icon: "chart", title: "Assessment reports", text: "SA&A report, POA&M spreadsheet, executive summary and PDF, ready to send." },
  { icon: "search", title: "Shared workspace", text: "Sign-in with roles, an audit log, scheduled scans and tickets in Jira or Azure DevOps." },
];

export default function Landing() {
  const { authEnabled, user } = useSession();
  const cta = !authEnabled || user ? { to: "/workbench", text: "Open workbench" } : { to: "/login", text: "Login to start scanning" };
  return (
    <div className="site">
      <SiteHeader />
      <section className="hero">
        <Logo size={90} />
        <h1>{BRAND.name}</h1>
        <p className="tagline">{BRAND.tagline}</p>
        <p className="statement">{BRAND.statement}</p>
        <p>Find risky triggers and tools, hard-coded secrets, insecure calls and governance gaps in your automations and AI agents, and fix them before they reach production.</p>
        <AppLink className="btn big" to={cta.to}>{cta.text}</AppLink>{" "}
        <a className="btn big ghost" href="#platforms">See what it scans</a>
      </section>

      <section id="platforms" className="band">
        <h2>What it scans</h2>
        <div className="cards">
          {platforms.map((p) => (
            <div key={p.title} className="card">
              <span className={"pill " + (p.status === "Active" ? "on" : "basic")}>{p.status}</span>
              <h3>{p.title}</h3>
              <p className="muted">{p.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="risks" className="band alt">
        <h2>The risks it looks for</h2>
        <div className="cards">
          {risks.map((f) => (
            <div key={f.title} className="card">
              <div className="icon"><PencilIcon name={f.icon} size={40} /></div>
              <h3>{f.title}</h3>
              <p className="muted">{f.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="needs" className="band">
        <h2>From finding to approval</h2>
        <div className="cards">
          {needs.map((f) => (
            <div key={f.title} className="card">
              <div className="icon"><PencilIcon name={f.icon} size={40} /></div>
              <h3>{f.title}</h3>
              <p className="muted">{f.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how" className="band alt steps">
        <h2>How it works</h2>
        <ol>
          <li>Sign in</li><li>Upload files or a solution .zip</li><li>Review findings and fixes</li><li>Report or gate the release</li>
        </ol>
        <p className="muted">Scanning is static. Falcon Scan reads exported definitions, so it never runs your automations or touches live data.</p>
        <AppLink className="btn big" to={cta.to}>{cta.text}</AppLink>
      </section>
      <footer className="site-foot">{BRAND.name}&trade; is a proprietary software application developed and owned by MurphyGAN. &copy; {new Date().getFullYear()} MurphyGAN. All rights reserved.</footer>
    </div>
  );
}

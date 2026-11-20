import "./CenterTabs.css";
import { Link } from "react-router-dom";
import { BRAND } from "../../brand";

type Props = { onNewApp: () => void; onSample: () => void; readOnly?: boolean };

export default function WelcomeTab({ onNewApp, onSample, readOnly }: Props) {
  return (
    <div className="pane-pad">
      <h3>Welcome to {BRAND.name}</h3>
      <p><i>{BRAND.statement}</i></p>
      <p>Static security analysis for Power Automate cloud flows, UiPath and other RPA files, MCP server configurations and AI agent definitions. Nothing is executed and no run data is read.</p>
      <ol>
        <li>Create an application and add exported flow JSON files, a Power Platform solution .zip, MCP configuration files (such as mcp.json), AI agent definition files, or UiPath files (.xaml, project.json, .nupkg) to it.</li>
        <li>Choose <b>Scan ▸ Scan Application</b>. The Analysis perspective inspects every trigger and action.</li>
        <li>Review results in <b>My Assessments</b> and the <b>Findings</b> view (Triage perspective). Right-click a flow for <b>Generate fixed copy</b>, and use <b>Scan ▸ Release gate check</b> before promoting to production.</li>
      </ol>
      <div className="pane-actions">
        <button className="btn" onClick={onNewApp} disabled={readOnly}>Create a new application…</button>
        <button className="btn ghost" onClick={onSample} disabled={readOnly}>Load sample application</button>
        <Link className="btn ghost" to="/scanner">Import from Power Platform…</Link>
      </div>
    </div>
  );
}

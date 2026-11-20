import "./SaaReportDialog.css";
import "./NewApplicationWizard.css";
import { useState } from "react";
import type { SaaMeta } from "../../lib/saaReport";

type Props = {
  defaultSystem: string;
  onOpen: (m: SaaMeta) => void;
  onDownload: (m: SaaMeta) => void;
  onPdf: (m: SaaMeta) => void;
  onClose: () => void;
  title?: string;
  systemLabel?: string;
};

const KEY = "falconscan.saa";
const load = (): Partial<SaaMeta> => { try { return JSON.parse(localStorage.getItem(KEY) ?? "{}"); } catch { return {}; } };

/** Who the report is for. The people and organization are remembered; the system name follows the assessment. */
export default function SaaReportDialog({ defaultSystem, onOpen, onDownload, onPdf, onClose, title = "SA&A assessment report", systemLabel = "System / application" }: Props) {
  const saved = load();
  const [m, setM] = useState<SaaMeta>({
    system: defaultSystem, organization: saved.organization ?? "", assessor: saved.assessor ?? "",
    authorizingOfficial: saved.authorizingOfficial ?? "", purpose: "",
  });
  const set = (k: keyof SaaMeta) => (e: { target: { value: string } }) => setM((c) => ({ ...c, [k]: e.target.value }));
  const remember = () => {
    try { localStorage.setItem(KEY, JSON.stringify({ organization: m.organization, assessor: m.assessor, authorizingOfficial: m.authorizingOfficial })); }
    catch { /* storage full: ignore */ }
  };
  const go = (fn: (m: SaaMeta) => void) => () => { remember(); fn(m); onClose(); };

  return (
    <div className="wiz-backdrop">
      <div className="saa" role="dialog" aria-label={title}>
        <div className="wiz-title"><span>{title}</span><button onClick={onClose} aria-label="Close">✕</button></div>
        <div className="saa-body">
          <p className="saa-note">Built from your assessments and triage decisions. Fields left blank print as "Not stated".</p>
          <label>{systemLabel}<input value={m.system} onChange={set("system")} /></label>
          <label>Organization<input value={m.organization} onChange={set("organization")} /></label>
          <label>Assessor<input value={m.assessor} onChange={set("assessor")} /></label>
          <label>Authorizing official<input value={m.authorizingOfficial} onChange={set("authorizingOfficial")} /></label>
          <label>Purpose or notes (optional)<textarea rows={3} value={m.purpose} onChange={set("purpose")} /></label>
        </div>
        <div className="saa-foot">
          <button onClick={onClose}>Cancel</button>
          <button onClick={go(onDownload)}>Download (.html)</button>
          <button onClick={go(onOpen)}>Open (print)</button>
          <button className="primary" onClick={go(onPdf)}>Download PDF</button>
        </div>
      </div>
    </div>
  );
}

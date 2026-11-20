import { logoSrc } from "./logoData";
import type { IssueState, ScanRecord } from "../types";
import type { FindingRow } from "./findingRows";
import type { Diff } from "./compare";

/** Security Assessment and Authorization (SA&A) report and POA&M built from one assessment and its triage state. */
export type SaaMeta = { system: string; organization: string; assessor: string; authorizingOfficial: string; purpose: string };
type IssueOf = (row: FindingRow) => IssueState;

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const SEV = ["High", "Medium", "Low"] as const;
const rank = (s: string) => SEV.indexOf(s as (typeof SEV)[number]);
const isOpen = (s: string) => s === "Open" || s === "In progress";
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });

/** Findings in report order (High first) with a stable report ID. */
function ordered(rows: FindingRow[]) {
  return [...rows].sort((a, b) => rank(a.severity) - rank(b.severity) || a.sink.localeCompare(b.sink) || a.trace - b.trace)
    .map((r, i) => ({ r, id: `F-${String(i + 1).padStart(3, "0")}` }));
}

export function toPoamCsv(record: ScanRecord, rows: FindingRow[], issueOf: IssueOf): string {
  const head = ["POA&M ID", "Weakness", "Weakness description", "Rule", "CWE", "OWASP", "Severity", "Flow", "Location", "Status",
    "Recommended remediation", "Responsible party", "Resources required", "Scheduled completion date", "Milestones", "Comments", "Date detected", "Assessment ID"];
  const q = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = ordered(rows).filter(({ r }) => isOpen(issueOf(r).status)).map(({ r, id }) =>
    [id.replace("F-", "POAM-"), r.type, r.detail, r.ruleId, r.cwe, r.owasp, r.severity, r.sink, r.source, issueOf(r).status,
      r.fix.map((t, n) => `${n + 1}. ${t}`).join(" "), "", "", "", "", issueOf(r).comment, record.createdAt.slice(0, 10), record.id].map(q).join(","));
  return "﻿" + [head.map(q).join(","), ...lines].join("\r\n");   // BOM so Excel reads UTF-8
}

export function toSaaHtml(record: ScanRecord, rows: FindingRow[], issueOf: IssueOf, diff: Diff | null, meta: SaaMeta): string {
  const items = ordered(rows);
  const results = record.response.results;
  const st = (r: FindingRow) => issueOf(r).status;
  const openRows = items.filter(({ r }) => isOpen(st(r)));
  const accepted = items.filter(({ r }) => st(r) === "Accepted risk");
  const fixed = items.filter(({ r }) => st(r) === "Fixed").length;
  const noise = items.filter(({ r }) => st(r) === "Noise").length;
  const openBy = (s: string) => openRows.filter(({ r }) => r.severity === s).length;
  const total = (s: string) => rows.filter((r) => r.severity === s).length;
  const system = meta.system.trim() || record.appName || "Not stated";
  const off = record.disabled ?? [];

  const indicator = openBy("High") > 0
    ? { cls: "bad", text: `Not ready for production: ${openBy("High")} High finding(s) are still open. Remediate them, or accept the risk formally, before the system is promoted.` }
    : openBy("Medium") > 0
      ? { cls: "warn", text: `Conditionally ready: no High findings are open, but ${openBy("Medium")} Medium finding(s) need to be tracked in the POA&M.` }
      : { cls: "ok", text: "No High or Medium findings are open at the time of this assessment." };

  const flowRows = results.map((f) => {
    const m = f.metadata ?? {};
    return `<tr><td>${esc(f.name)}</td><td>${esc(m["Type"] ?? "")}</td><td>${esc(f.state ?? m["State"] ?? "")}</td><td>${esc(m["Owner"] ?? "Not in export")}</td><td>${f.triggerCount ?? ""} / ${f.actionCount ?? ""}</td><td>${esc(f.connectors.join(", "))}</td><td class="${esc(f.risk)}">${esc(f.risk)}</td><td>${f.findings.length}</td></tr>`;
  }).join("");

  const statuses = ["Open", "In progress", "Fixed", "Accepted risk", "Noise"];
  const sevStatus = SEV.map((s) => `<tr><td class="${s}">${s}</td>${statuses.map((x) => `<td>${rows.filter((r) => r.severity === s && st(r) === x).length}</td>`).join("")}<td><b>${total(s)}</b></td></tr>`).join("");

  const cats = [...new Set(rows.map((r) => r.classification))].sort();
  const catRows = cats.map((c) => `<tr><td>${esc(c)}</td>${SEV.map((s) => `<td>${rows.filter((r) => r.classification === c && r.severity === s).length}</td>`).join("")}<td><b>${rows.filter((r) => r.classification === c).length}</b></td></tr>`).join("");

  const exposure = results.flatMap((f) => (f.connections ?? []).filter((c) => c.thirdParty || c.ai).map((c) =>
    `<tr><td>${esc(f.name)}</td><td>${esc(c.name)}</td><td>${esc(c.publisher)}</td><td>${c.ai ? esc("AI: " + c.ai.provider + (c.ai.microsoft ? " (Microsoft)" : " (third party)")) : "Third party"}</td><td>${esc(c.sensitivity)}</td></tr>`)).join("");
  const flows = results.flatMap((f) => (f.dataFlows ?? []).map((d) =>
    `<tr><td>${esc(f.name)}</td><td>${esc(d.from)} (${esc(d.fromConnector)})</td><td>${esc(d.to)} (${esc(d.toConnector)})</td><td>${esc(d.sensitivity)}</td><td>${d.ai ? "AI service" : d.thirdParty ? "Third party" : ""}</td></tr>`)).join("");

  const detail = items.map(({ r, id }) => {
    const i = issueOf(r);
    return `<tr><td>${id}</td><td class="${r.severity}">${r.severity}</td><td>${esc(i.status)}</td>
<td><b>${esc(r.type)}</b>${r.isNew ? " <b>(new)</b>" : ""}<br><small>${esc(r.ruleId)} · ${esc(r.cwe)} · ${esc(r.owasp)}</small></td>
<td>${esc(r.sink)}<br><small>${esc(r.source)}</small></td>
<td>${esc(r.detail)}${r.fix.length ? `<br><b>Recommended remediation:</b><ol>${r.fix.map((t) => `<li>${esc(t)}</li>`).join("")}</ol>` : ""}${i.comment ? `<br><i>Assessor/owner comment: ${esc(i.comment)}${i.updatedAt ? ` (${esc(day(i.updatedAt))})` : ""}</i>` : ""}</td></tr>`;
  }).join("");

  const acceptedRows = accepted.map(({ r, id }) => {
    const i = issueOf(r);
    return `<tr><td>${id}</td><td class="${r.severity}">${r.severity}</td><td>${esc(r.type)}<br><small>${esc(r.sink)} · ${esc(r.source)}</small></td><td>${i.comment ? esc(i.comment) : "<b>No justification recorded</b>"}</td><td>${i.updatedAt ? esc(day(i.updatedAt)) : ""}</td></tr>`;
  }).join("");

  const poam = openRows.map(({ r, id }) => `<tr><td>${id.replace("F-", "POAM-")}</td><td class="${r.severity}">${r.severity}</td><td>${esc(r.type)}<br><small>${esc(r.sink)} · ${esc(r.source)}</small></td><td>${esc(r.fix[0] ?? "See finding " + id)}</td><td></td><td></td><td>${esc(st(r))}</td></tr>`).join("");

  return `<!doctype html><html><head><meta charset="utf-8"><title>Security Assessment Report: ${esc(system)}</title><style>
body{font:13px/1.5 Segoe UI,Arial,sans-serif;color:#1b2333;margin:28px;max-width:1100px}
h1{font-size:24px;margin:0;color:#06142a}h2{font-size:16px;margin:26px 0 6px;color:#06142a;border-bottom:2px solid #19b8f2;padding-bottom:3px;break-after:avoid}h3{font-size:13px;margin:14px 0 4px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #c9cfdd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#eef3fb}
tr{break-inside:avoid}.kpi{display:flex;gap:10px;margin:10px 0;flex-wrap:wrap}.kpi div{border:1px solid #c9cfdd;padding:8px 14px;border-radius:4px;min-width:90px}.kpi b{font-size:20px;display:block}
td.High,.High{color:#b42318;font-weight:700}td.Medium,.Medium{color:#b54708;font-weight:700}td.Low,.Low{color:#067647;font-weight:700}small{color:#667}td ol{margin:4px 0 0;padding-left:18px}
.banner{padding:10px 14px;border-radius:4px;border:1px solid;margin:10px 0;font-weight:600}.banner.bad{background:#fef3f2;border-color:#fda29b}.banner.warn{background:#fffaeb;border-color:#fec84b}.banner.ok{background:#ecfdf3;border-color:#75e0a7}
.cover{display:flex;align-items:center;gap:14px;margin-bottom:6px}.sign td{height:42px}.pb{break-before:page}.note{color:#555}
@page{margin:14mm}@media print{body{margin:0}}</style></head><body>
<div class="cover"><img src="${logoSrc()}" height="64" alt=""><div><h1>Security Assessment Report</h1><div class="note">Falcon Scan: Automation &amp; AI Security Analyzer</div></div></div>
<table><tr><th>System / application</th><td>${esc(system)}</td><th>Report ID</th><td>${esc(record.id)}</td></tr>
<tr><th>Organization</th><td>${esc(meta.organization || "Not stated")}</td><th>Assessment date</th><td>${esc(day(record.createdAt))}</td></tr>
<tr><th>Assessor</th><td>${esc(meta.assessor || "Not stated")}</td><th>Report generated</th><td>${esc(day(new Date().toISOString()))}</td></tr>
<tr><th>Authorizing official</th><td>${esc(meta.authorizingOfficial || "Not stated")}</td><th>Scan configuration</th><td>${esc(record.config ?? "Normal scan")}</td></tr></table>
${meta.purpose.trim() ? `<h3>Purpose</h3><p>${esc(meta.purpose)}</p>` : ""}

<h2>1. Executive summary</h2>
<div class="banner ${indicator.cls}">${esc(indicator.text)}</div>
<div class="kpi"><div><b>${results.length}</b>Flows assessed</div><div><b>${rows.length}</b>Findings</div><div><b>${openRows.length}</b>Open</div><div class="High"><b>${openBy("High")}</b>Open High</div><div class="Medium"><b>${openBy("Medium")}</b>Open Medium</div><div class="Low"><b>${openBy("Low")}</b>Open Low</div><div><b>${accepted.length}</b>Accepted risk</div><div><b>${fixed}</b>Fixed</div><div><b>${noise}</b>Noise</div></div>
<p>This indicator comes from an automated static analysis of exported automation definitions. It supports, and does not replace, the judgement of the assessor and the authorizing official.</p>
${diff ? `<p>Compared with the previous assessment of this application: <b>${diff.added}</b> new finding(s), <b>${diff.fixed.length}</b> fixed, <b>${diff.unchanged}</b> unchanged.</p>` : ""}

<h2>2. Scope and method</h2>
<p><b>In scope:</b> ${results.length} definition(s) supplied for ${esc(system)} (Power Automate cloud flows, MCP server configurations, AI agent definitions or RPA files from UiPath, Automation Anywhere or Blue Prism), listed below. <b>Method:</b> static analysis of each trigger, action, connection reference and expression, and for AI files each MCP server, tool, permission and instruction text, against the enabled Falcon Scan rules${off.length ? ` (${off.length} switched off in this configuration: ${esc(off.join(", "))})` : " (none switched off)"}. Nothing was executed and no run history was read.</p>
<p><b>Not covered:</b> runtime behaviour, run history and live model behaviour; tenant settings such as data loss prevention policies, sharing and licensing; the identity and permissions of each connection; network and infrastructure controls; and any automation not supplied for this assessment. Findings reflect the exported definitions at the assessment date only.</p>
<h3>Flows assessed</h3>
<table><tr><th>Flow</th><th>Type</th><th>State</th><th>Owner</th><th>Triggers / actions</th><th>Connectors</th><th>Risk</th><th>Findings</th></tr>${flowRows}</table>

<h2>3. Results summary</h2>
<h3>By severity and triage status</h3>
<table><tr><th>Severity</th>${statuses.map((s) => `<th>${s}</th>`).join("")}<th>Total</th></tr>${sevStatus}</table>
<h3>By category</h3>
<table><tr><th>Category</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>${catRows || '<tr><td colspan="5">No findings.</td></tr>'}</table>

<h2>4. Data exposure</h2>
${exposure ? `<h3>Third-party and AI services used</h3><table><tr><th>Flow</th><th>Connector</th><th>Publisher</th><th>Type</th><th>Data sensitivity</th></tr>${exposure}</table>` : "<p>No third-party or AI connectors were identified.</p>"}
${flows ? `<h3>Traced data flows to third-party or AI services</h3><table><tr><th>Flow</th><th>From</th><th>To</th><th>Sensitivity</th><th>Destination</th></tr>${flows}</table>` : ""}

<h2 class="pb">5. Detailed findings</h2>
${detail ? `<table><tr><th>ID</th><th>Severity</th><th>Status</th><th>Weakness</th><th>Where</th><th>Description and remediation</th></tr>${detail}</table>` : "<p>No findings were raised.</p>"}

<h2>6. Residual risk and accepted risks</h2>
<p>${openRows.length} finding(s) remain open and are carried into the POA&amp;M. ${accepted.length} finding(s) are marked as accepted risk${accepted.length ? "; each should have a written justification and an approver" : ""}.</p>
${acceptedRows ? `<table><tr><th>ID</th><th>Severity</th><th>Weakness</th><th>Justification</th><th>Recorded</th></tr>${acceptedRows}</table>` : ""}

<h2 class="pb">7. Plan of action and milestones (POA&amp;M)</h2>
${poam ? `<table><tr><th>ID</th><th>Severity</th><th>Weakness</th><th>Planned remediation</th><th>Responsible party</th><th>Scheduled completion</th><th>Status</th></tr>${poam}</table><p class="note">Responsible party and scheduled completion are left blank for the system owner to complete. The same items are available as a CSV export.</p>` : "<p>There are no open findings, so no POA&amp;M items are required.</p>"}

<h2>8. Limitations</h2>
<p>This is an automated, static assessment. Checks on AI agents and MCP servers are configuration reviews; the prompt-injection and data-exposure checks are heuristics based on tool names and descriptions and indicate combinations to review, not proven exploits. CWE and OWASP references are indicative mappings to support triage; they are not a compliance certification and are not mapped to the controls of any specific framework. A complete authorization decision needs evidence this tool does not collect.</p>

<h2>9. Review and sign-off</h2>
<table class="sign"><tr><th>Role</th><th>Name</th><th>Signature</th><th>Date</th></tr>
<tr><td>Assessor</td><td>${esc(meta.assessor)}</td><td></td><td></td></tr>
<tr><td>System owner</td><td></td><td></td><td></td></tr>
<tr><td>Authorizing official</td><td>${esc(meta.authorizingOfficial)}</td><td></td><td></td></tr></table>
</body></html>`;
}

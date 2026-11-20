import { logoSrc } from "./logoData";
import type { IssueState, ScanRecord } from "../types";
import type { FindingRow } from "./findingRows";
import type { Diff } from "./compare";

type IssueOf = (row: FindingRow) => IssueState;

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

export function download(filename: string, text: string, mime: string) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export function toCsv(rows: FindingRow[], issueOf: IssueOf): string {
  const head = ["Severity", "Status", "Rule", "Vulnerability Type", "Classification", "CWE", "OWASP", "Flow", "Location", "API", "New", "Why", "How to fix", "Comment"];
  const q = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = rows.map((r) => {
    const i = issueOf(r);
    return [r.severity, i.status, r.ruleId, r.type, r.classification, r.cwe, r.owasp, r.sink, r.source, r.api, r.isNew ? "Yes" : "", r.detail, r.fix.map((t, n) => `${n + 1}. ${t}`).join(" "), i.comment].map(q).join(",");
  });
  return "﻿" + [head.map(q).join(","), ...lines].join("\r\n");   // BOM so Excel reads UTF-8
}

/** A standalone HTML report: open it and use Print > Save as PDF. */
export function toHtml(record: ScanRecord, rows: FindingRow[], issueOf: IssueOf, diff: Diff | null): string {
  const count = (s: string) => rows.filter((r) => r.severity === s).length;
  const flows = record.response.results;
  const body = rows.map((r) => {
    const i = issueOf(r);
    return `<tr><td class="${r.severity}">${r.severity}</td><td>${esc(i.status)}</td><td>${esc(r.type)}${r.isNew ? " <b>(new)</b>" : ""}<br><small>${esc(r.ruleId)} · ${esc(r.cwe)} · ${esc(r.owasp)}</small></td><td>${esc(r.sink)}<br><small>${esc(r.source)}</small></td><td>${esc(r.detail)}${r.fix.length ? `<br><b>How to fix:</b><ol>${r.fix.map((t) => `<li>${esc(t)}</li>`).join("")}</ol>` : ""}${i.comment ? `<br><i>Comment: ${esc(i.comment)}</i>` : ""}</td></tr>`;
  }).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>Falcon Scan report</title><style>
body{font:13px/1.45 Segoe UI,Arial,sans-serif;color:#1b2333;margin:24px}h1{font-size:20px;margin:0;color:#06142a}h2{font-size:15px;margin-top:22px}
.kpi{display:flex;gap:10px;margin:12px 0}.kpi div{border:1px solid #d0d5e2;padding:8px 14px;border-radius:4px}.kpi b{font-size:20px;display:block}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d5e2;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f1f4fa}
td.High{color:#b42318;font-weight:700}td.Medium{color:#b54708;font-weight:700}td.Low{color:#067647;font-weight:700}small{color:#667}td ol{margin:4px 0 0;padding-left:18px}
@media print{body{margin:8px}}</style></head><body>
<h1><img src="${logoSrc()}" height="40" style="vertical-align:middle;margin-right:8px" alt="">Falcon Scan: security assessment report</h1><p><small>Automation &amp; AI Security Analyzer</small></p>
<p>${esc(record.appName ?? "Ad hoc scan")} · ${new Date(record.createdAt).toLocaleString()} · configuration: ${esc(record.config ?? "Normal scan")} · ${flows.length} flow(s)</p>
<div class="kpi"><div><b>${rows.length}</b>Findings</div><div><b>${count("High")}</b>High</div><div><b>${count("Medium")}</b>Medium</div><div><b>${count("Low")}</b>Low</div></div>
${diff ? `<p>Compared with the previous assessment: <b>${diff.added}</b> new, <b>${diff.fixed.length}</b> fixed, <b>${diff.unchanged}</b> unchanged.</p>` : ""}
<h2>Flows</h2><table><tr><th>Flow</th><th>Risk</th><th>Findings</th><th>Connectors</th></tr>${flows.map((f) =>
  `<tr><td>${esc(f.name)}</td><td>${esc(f.risk)}</td><td>${f.findings.length}</td><td>${esc(f.connectors.join(", "))}</td></tr>`).join("")}</table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Status</th><th>Issue</th><th>Where</th><th>Why it is flagged and how to fix it</th></tr>${body}</table>
<p><small>CWE and OWASP references are indicative mappings to support triage; they are not a compliance certification.</small></p>
</body></html>`;
}

export function openPrintable(html: string) {
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

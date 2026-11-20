import { logoSrc } from "./logoData";
import type { Application, IssueState, ScanRecord } from "../types";
import { fingerprintsOf, toRows, type FindingRow } from "./findingRows";
import { countBySeverity, previousOf } from "./compare";
import type { SaaMeta } from "./saaReport";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const isOpen = (s: string) => s === "Open" || s === "In progress";
const DAY = 86_400_000;
const kindOf = (r: ScanRecord["response"]["results"][number]) => {
  const md = r.metadata ?? {};
  if (md["Platform"]) return String(md["Platform"]);
  return /AI agent|MCP/i.test(String(md["Type"] ?? "")) ? "AI agents and MCP" : "Power Automate";
};

/** A one-to-two page management summary across every application: where things stand, what needs attention, and what to do next. */
export function toExecHtml(history: ScanRecord[], apps: Application[], issueOf: (key: string) => IssueState, meta: SaaMeta): string {
  const seen = new Set<string>();
  const latest = history.filter((r) => { const k = r.appId ?? `adhoc-${r.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  const fps = new Map<string, Set<string>>();
  const fpsOf = (r: ScanRecord) => fps.get(r.id) ?? (fps.set(r.id, fingerprintsOf(r)), fps.get(r.id)!);
  const now = Date.now();
  const firstSeen = (rec: ScanRecord, fp: string) => {
    const same = history.filter((h) => (h.appId ?? `adhoc-${h.id}`) === (rec.appId ?? `adhoc-${rec.id}`) && fpsOf(h).has(fp));
    return Math.min(...same.map((h) => Date.parse(h.createdAt)), Date.parse(rec.createdAt));
  };

  type Row = FindingRow & { status: string; rec: ScanRecord };
  const perApp = latest.map((rec) => {
    const rows: Row[] = toRows(rec, previousOf(history, rec)).map((r) => ({ ...r, status: issueOf(r.issueKey).status, rec }));
    const prev = previousOf(history, rec);
    const open = rows.filter((r) => isOpen(r.status));
    const c = (s: string) => open.filter((r) => r.severity === s).length;
    const worst = rec.response.results.some((x) => x.risk === "High") ? "High" : rec.response.results.some((x) => x.risk === "Medium") ? "Medium" : "Low";
    const total = (x: ScanRecord) => { const k = countBySeverity(x); return k.High + k.Medium + k.Low; };
    return { rec, rows, open, name: rec.appName ?? "Ad hoc scan", High: c("High"), Medium: c("Medium"), Low: c("Low"), worst,
             change: prev ? total(rec) - total(prev) : null };
  });
  const all = perApp.flatMap((a) => a.rows);
  const open = all.filter((r) => isOpen(r.status));
  const openBy = (s: string) => open.filter((r) => r.severity === s).length;
  const accepted = all.filter((r) => r.status === "Accepted risk");
  const unjustified = accepted.filter((r) => !issueOf(r.issueKey).comment.trim()).length;
  const fixed = all.filter((r) => r.status === "Fixed").length;
  const noise = all.filter((r) => r.status === "Noise").length;
  const unscanned = apps.filter((a) => !history.some((h) => h.appId === a.id));

  const topHigh = open.filter((r) => r.severity === "High")
    .map((r) => ({ r, days: Math.floor((now - firstSeen(r.rec, r.fingerprint)) / DAY) })).sort((a, b) => b.days - a.days).slice(0, 10);
  const byCat = Object.entries(open.filter((r) => r.severity !== "Low").reduce<Record<string, number>>((m, r) => { m[r.classification] = (m[r.classification] ?? 0) + 1; return m; }, {}))
    .sort((a, b) => b[1] - a[1]).slice(0, 6);
  const kinds = latest.flatMap((r) => r.response.results).reduce<Record<string, number>>((m, r) => { const k = kindOf(r); m[k] = (m[k] ?? 0) + 1; return m; }, {});

  const banner = openBy("High") > 0
    ? { cls: "bad", text: `Attention needed: ${openBy("High")} High-risk finding(s) are open across ${perApp.filter((a) => a.High > 0).length} of ${perApp.length} application(s).` }
    : openBy("Medium") > 0 ? { cls: "warn", text: `No High-risk findings are open. ${openBy("Medium")} Medium finding(s) need to be planned.` }
    : { cls: "ok", text: "No High or Medium findings are open in the latest assessments." };

  const actions: string[] = [];
  if (openBy("High")) actions.push(`Fix, or formally accept with a written reason, the ${openBy("High")} open High finding(s) first.${topHigh[0] ? ` The oldest has been open ${topHigh[0].days} day(s).` : ""}`);
  if (byCat[0]) actions.push(`Most open High and Medium findings are in "${byCat[0][0]}" (${byCat[0][1]}). Start there for the biggest reduction.`);
  if (unjustified) actions.push(`${unjustified} accepted risk(s) have no written justification. Add one, and who approved it.`);
  if (unscanned.length) actions.push(`${unscanned.length} application(s) have never been scanned: ${unscanned.slice(0, 4).map((a) => a.name).join(", ")}${unscanned.length > 4 ? "…" : ""}.`);
  actions.push("Run the release gate before anything is promoted to production, and schedule recurring scans so this picture stays current.");

  const th = (s: string) => `<th>${s}</th>`;
  const appRows = perApp.map((a) => `<tr><td>${esc(a.name)}</td><td>${esc(new Date(a.rec.createdAt).toLocaleDateString())}</td><td class="${a.worst}">${a.worst}</td>
<td>${a.rec.response.results.length}</td><td class="High">${a.High}</td><td class="Medium">${a.Medium}</td><td class="Low">${a.Low}</td>
<td>${a.change === null ? "first scan" : a.change === 0 ? "no change" : a.change < 0 ? `${-a.change} fewer` : `${a.change} more`}</td></tr>`).join("");
  const highRows = topHigh.map(({ r, days }) => `<tr><td>${esc(r.rec.appName ?? "Ad hoc")}</td><td>${esc(r.sink)}</td><td>${esc(r.type)}<br><small>${esc(r.ruleId)} · ${esc(r.source)}</small></td><td>${days} d</td><td>${esc(r.status)}</td></tr>`).join("");

  return `<!doctype html><html><head><meta charset="utf-8"><title>Executive security summary</title><style>
body{font:13px/1.5 Segoe UI,Arial,sans-serif;color:#1b2333;margin:28px;max-width:1000px}h1{font-size:23px;margin:0;color:#06142a}h2{font-size:15px;margin:20px 0 6px;color:#06142a;border-bottom:2px solid #19b8f2;padding-bottom:3px;break-after:avoid}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #c9cfdd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#eef3fb}tr{break-inside:avoid}
.kpi{display:flex;gap:10px;margin:10px 0;flex-wrap:wrap}.kpi div{border:1px solid #c9cfdd;padding:8px 14px;border-radius:4px;min-width:96px}.kpi b{font-size:21px;display:block}
td.High,.High{color:#b42318;font-weight:700}td.Medium,.Medium{color:#b54708;font-weight:700}td.Low,.Low{color:#067647;font-weight:700}small{color:#667}
.banner{padding:10px 14px;border-radius:4px;border:1px solid;margin:10px 0;font-weight:600}.banner.bad{background:#fef3f2;border-color:#fda29b}.banner.warn{background:#fffaeb;border-color:#fec84b}.banner.ok{background:#ecfdf3;border-color:#75e0a7}
.cover{display:flex;align-items:center;gap:14px}.note{color:#555}ol{margin:4px 0;padding-left:20px}@page{margin:14mm}@media print{body{margin:0}}</style></head><body>
<div class="cover"><img src="${logoSrc()}" height="60" alt=""><div><h1>Executive security summary</h1><div class="note">Falcon Scan: Automation &amp; AI Security Analyzer</div></div></div>
<p>${esc(meta.system || "All applications")}${meta.organization ? ` · ${esc(meta.organization)}` : ""} · ${esc(new Date().toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }))}${meta.assessor ? ` · prepared by ${esc(meta.assessor)}` : ""}</p>
<div class="banner ${banner.cls}">${esc(banner.text)}</div>
<div class="kpi"><div><b>${perApp.length}</b>Applications assessed</div><div><b>${latest.reduce((n, r) => n + r.response.results.length, 0)}</b>Files and flows</div><div class="High"><b>${openBy("High")}</b>Open High</div>
<div class="Medium"><b>${openBy("Medium")}</b>Open Medium</div><div class="Low"><b>${openBy("Low")}</b>Open Low</div><div><b>${fixed}</b>Fixed</div><div><b>${accepted.length}</b>Accepted risk</div></div>
${meta.purpose.trim() ? `<p>${esc(meta.purpose)}</p>` : ""}
<h2>Applications at a glance</h2><table><tr>${["Application", "Last assessed", "Risk", "Files", "High", "Medium", "Low", "Change since previous"].map(th).join("")}</tr>${appRows || '<tr><td colspan="8">No assessments yet.</td></tr>'}</table>
<h2>What needs attention first</h2>${highRows ? `<table><tr>${["Application", "File", "Issue", "Open for", "Status"].map(th).join("")}</tr>${highRows}</table>` : "<p>No High findings are open.</p>"}
<h2>Where the risk is concentrated</h2>${byCat.length ? `<table><tr>${th("Category")}${th("Open High and Medium")}</tr>${byCat.map(([c, n]) => `<tr><td>${esc(c)}</td><td>${n}</td></tr>`).join("")}</table>` : "<p>Nothing open at High or Medium.</p>"}
<h2>Progress and accepted risk</h2><p>${fixed} finding(s) marked fixed, ${noise} marked as noise, ${accepted.length} accepted as a known risk${unjustified ? ` (${unjustified} without a written justification)` : ""}.</p>
<h2>What was assessed</h2><table><tr>${th("Kind")}${th("Files")}</tr>${Object.entries(kinds).map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n}</td></tr>`).join("") || '<tr><td colspan="2">Nothing yet.</td></tr>'}</table>
<h2>Recommended next steps</h2><ol>${actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol>
<p class="note"><small>Based on automated static analysis of exported definitions and the triage decisions recorded in Falcon Scan. It does not cover runtime behaviour, and some AI-agent checks are heuristics. It supports, and does not replace, a security assessment by people.</small></p>
</body></html>`;
}

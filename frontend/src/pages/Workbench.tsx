import "./Workbench.css";
import "../components/workbench/FindingsPanel.css";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Application, Rule, TicketConfig } from "../types";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useApps } from "../context/ApplicationContext";
import { useAuth } from "../context/AuthContext";
import { usePolicy } from "../context/PolicyContext";
import { useIssues } from "../context/IssueContext";
import { useScan } from "../context/ScanContext";
import { SAMPLE_FLOWS } from "../data/sampleFlows";
import { toRows, type FindingRow } from "../lib/findingRows";
import Logo from "../components/Logo";
import { BRAND } from "../brand";
import ScanRunner from "../components/ScanRunner";
import MenuBar, { type Menu } from "../components/workbench/MenuBar";
import Explorer, { type ExplorerTarget } from "../components/workbench/Explorer";
import ContextMenu, { type CtxItem } from "../components/workbench/ContextMenu";
import JsonViewer from "../components/JsonViewer";
import AssessmentsTable from "../components/workbench/AssessmentsTable";
import FindingsPanel, { type BottomTab, type FindCmd } from "../components/workbench/FindingsPanel";
import Dashboard from "../components/workbench/Dashboard";
import ScanConfigDialog from "../components/workbench/ScanConfigDialog";
import { diff as diffRecords, previousOf } from "../lib/compare";
import { download, downloadBlob, openPrintable, toCsv, toHtml } from "../lib/report";
import { toPoamCsv, toSaaHtml, type SaaMeta } from "../lib/saaReport";
import { logoReady } from "../lib/logoData";
import SaaReportDialog from "../components/workbench/SaaReportDialog";
import NewApplicationWizard from "../components/workbench/NewApplicationWizard";
import WelcomeTab from "../components/workbench/WelcomeTab";
import PropertiesTab from "../components/workbench/PropertiesTab";
import PlatformsTab from "../components/workbench/PlatformsTab";
import Splitter from "../components/workbench/Splitter";
import RuleLibraryTab from "../components/workbench/RuleLibraryTab";
import { readFolder } from "../lib/folderImport";
import AdminPanel from "../components/workbench/AdminPanel";
import SchedulesPanel from "../components/workbench/SchedulesPanel";
import AccountMenu from "../components/workbench/AccountMenu";
import { toExecHtml } from "../lib/execReport";
import { useSession } from "../context/SessionContext";
import { useServerData } from "../context/ServerDataContext";

type Perspective = "configuration" | "triage" | "analysis" | "dashboard";
type CenterTab = "welcome" | "properties" | "assessments" | "platforms" | "rules" | "schedules" | "admin";

const stamp = () => new Date().toLocaleTimeString();

export default function Workbench() {
  const nav = useNavigate();
  const { signedIn } = useAuth();
  const { apps, addApp, addFlows, removeFlow, removeApp, renameApp } = useApps();
  const { history, addScan, markCompleted, removeScan, clearHistory } = useScan();
  const { policy, setPolicy } = usePolicy();
  const issues = useIssues();
  const { can, authEnabled } = useSession();
  const { serverMode, tickets, addTicket, reload } = useServerData();
  const canAssess = can("assessor");                 // viewers read; assessors and administrators change things
  const isAdmin = authEnabled && can("admin");

  const [perspective, setPerspective] = useState<Perspective>("configuration");
  const since0 = localStorage.getItem("falconscan.dashSince");
  const fresh0 = history.filter((r) => !since0 || r.createdAt > since0);
  const [centerTab, setCenterTab] = useState<CenterTab>(fresh0.length ? "assessments" : "welcome");
  const [bottomTab, setBottomTab] = useState<BottomTab>("findings");
  const [appId, setAppId] = useState<string | null>(null);
  const [assessmentId, setAssessmentId] = useState<string | null>(fresh0[0]?.id ?? null);
  const [finding, setFinding] = useState<FindingRow | null>(null);
  const [wizard, setWizard] = useState(false);
  const [batch, setBatch] = useState(false);
  const [rulesList, setRulesList] = useState<Rule[]>([]);
  const [ruleCategory, setRuleCategory] = useState("");
  const [findCmd, setFindCmd] = useState<FindCmd>({ id: 0, kind: "all" });
  const folderInput = useRef<HTMLInputElement>(null);
  const abort = useRef<AbortController | null>(null);
  const cancelled = useRef(false);
  useEffect(() => { api.rules().then(setRulesList).catch(() => setRulesList([])); }, []);
  const [cfgOpen, setCfgOpen] = useState(false);
  const [saaOpen, setSaaOpen] = useState(false);
  const [execOpen, setExecOpen] = useState(false);
  const [ticketCfg, setTicketCfg] = useState<TicketConfig | null>(null);
  useEffect(() => { if (serverMode) api.ticketConfig().then(setTicketCfg).catch(() => setTicketCfg(null)); }, [serverMode]);
  // Data this browser saved before the shared database was switched on can be moved across once.
  const localBundle = () => {
    const get = (k: string, d: string) => { try { return JSON.parse(localStorage.getItem(k) ?? d); } catch { return JSON.parse(d); } };
    return { applications: get("murphygan.apps", "[]"), assessments: get("murphygan.scans", "[]"), issues: get("murphygan.issues", "{}"), policy: get("murphygan.policy", "{}") };
  };
  const [importAsk, setImportAsk] = useState(() => {
    if (!serverMode || !can("assessor") || localStorage.getItem("falconscan.importAsked")) return false;
    const b = localBundle();
    return b.applications.length + b.assessments.length > 0;
  });
  // The dashboard only counts assessments made after the last "New scan"; saved ones are not deleted.
  const [dashSince, setDashSince] = useState<string | null>(() => localStorage.getItem("falconscan.dashSince"));
  const setSince = (v: string | null) => {
    setDashSince(v);
    try { v ? localStorage.setItem("falconscan.dashSince", v) : localStorage.removeItem("falconscan.dashSince"); } catch { /* ignore */ }
  };
  const [ctx, setCtx] = useState<(ExplorerTarget & { x: number; y: number }) | null>(null);
  const [viewJson, setViewJson] = useState<unknown>(null);
  const [filterAppId, setFilterAppId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([`[${stamp()}] Falcon Scan ready.`]);
  const note = (m: string) => setLog((l) => [...l, `[${stamp()}] ${m}`]);

  const app = apps.find((a) => a.id === appId);
  const record = history.find((r) => r.id === assessmentId);
  const previous = useMemo(() => previousOf(history, record), [history, record]);
  const rows = useMemo(() => toRows(record, previous), [record, previous]);
  const diffData = useMemo(() => (record && previous ? diffRecords(record, previous) : null), [record, previous]);
  const issueOf = (r: FindingRow) => issues.get(r.issueKey);

  const dashHistory = dashSince ? history.filter((r) => r.createdAt > dashSince) : history;
  const latestFor = (id: string) => history.find((r) => r.appId === id);
  const shownRecords = filterAppId ? dashHistory.filter((r) => r.appId === filterAppId) : dashHistory;
  const filterApp = apps.find((a) => a.id === filterAppId);

  const doImport = async () => {
    try {
      const c = await api.importBundle(localBundle());
      localStorage.setItem("falconscan.importAsked", "1"); setImportAsk(false);
      note(`Imported from this browser: ${c.applications} application(s), ${c.assessments} assessment(s), ${c.issues} triage decision(s).`);
      await reload();
    } catch (e) { note(`ERROR: ${(e as Error).message}`); setBottomTab("console"); }
  };
  const skipImport = () => { localStorage.setItem("falconscan.importAsked", "1"); setImportAsk(false); };

  const makeTicket = async (r: FindingRow) => {
    if (!ticketCfg?.configured) return;
    if (!confirm(`Create a ${ticketCfg.system === "jira" ? "Jira" : "Azure DevOps"} ticket in ${ticketCfg.target}?\n\nOnly the title, rule, location, explanation and fix steps are sent. No file contents or secret values.`)) return;
    try {
      const t = await api.createTicket({ issueKey: r.issueKey, title: r.type, severity: r.severity, ruleId: r.ruleId, cwe: r.cwe, owasp: r.owasp,
        flow: r.sink, location: r.source, detail: r.detail, fix: r.fix, appName: record?.appName ?? "" });
      addTicket(r.issueKey, t);
      note(`Ticket ${t.id} created: ${t.url}`);
    } catch (e) { note(`ERROR: ${(e as Error).message}`); setBottomTab("console"); alert((e as Error).message); }
  };

  const removeAppConfirmed = (a: { id: string; name: string }) => {
    if (!confirm(`Remove application "${a.name}"?

Its saved assessments stay in My Assessments.`)) return;
    removeApp(a.id);
    if (appId === a.id) setAppId(null);
    if (filterAppId === a.id) setFilterAppId(null);
    note(`Application "${a.name}" removed.`);
  };

  const ctxItems = (t: ExplorerTarget): CtxItem[] => {
    const a = apps.find((x) => x.id === t.appId);
    if (!a) return [];
    if (t.flow) {
      return [
        { label: "View flow JSON", onClick: () => setViewJson(a.flows.find((f) => f.filename === t.flow)?.content) },
        { label: "Generate fixed copy…", disabled: busy || !canAssess, onClick: () => fixOne(a, t.flow!) },
        { separator: true },
        { label: "Remove flow from application", danger: true, disabled: !canAssess, onClick: () => { removeFlow(a.id, t.flow!); note(`Flow "${t.flow}" removed from "${a.name}".`); } },
      ];
    }
    const mine = history.filter((r) => r.appId === a.id);
    const last = latestFor(a.id);
    return [
      { label: "Run scan", shortcut: "F5", disabled: a.flows.length === 0 || busy || !canAssess, onClick: () => { setAppId(a.id); scanApp(a); } },
      { separator: true },
      { label: "Properties", onClick: () => { setAppId(a.id); setCenterTab("properties"); setPerspective("configuration"); } },
      { label: `View assessments (${mine.length})`, disabled: mine.length === 0,
        onClick: () => { setFilterAppId(a.id); setCenterTab("assessments"); setPerspective("configuration"); if (last) setAssessmentId(last.id); } },
      { label: "View findings", disabled: !last,
        onClick: () => { if (last) { setAssessmentId(last.id); setFinding(null); setBottomTab("findings"); setPerspective("triage"); } } },
      { label: "Add flow files…", disabled: !canAssess, onClick: () => { setAppId(a.id); setCenterTab("properties"); setPerspective("configuration"); } },
      { separator: true },
      { label: "Remove application", danger: true, disabled: !canAssess, onClick: () => removeAppConfirmed(a) },
    ];
  };

  const fixOne = async (a: Application, filename: string) => {
    const f = a.flows.find((x) => x.filename === filename);
    if (!f) return;
    note(`Generating a fixed copy of "${filename}"…`);
    setBottomTab("console");
    try {
      const r = await api.fixFlow(f.filename, f.content, policy);
      r.applied.forEach((x) => note(`  fixed ${x.ruleId} at ${x.location}: ${x.change}`));
      r.skipped.forEach((x) => note(`  not changed ${x.ruleId} (${x.count}): ${x.reason}`));
      note(`Findings ${r.before.total} -> ${r.after.total} (High ${r.before.High} -> ${r.after.High}).`);
      if (r.applied.length) {
        download(`${filename.replace(/\.json$/i, "")}.fixed.json`, JSON.stringify(r.content, null, 2), "application/json");
        note("Fixed copy downloaded. Review it, then re-import it. The flow saved in this application was not changed.");
      } else note("No automatic fix applies to this flow. See How to fix on each finding.");
    } catch (e) { note(`ERROR: ${(e as Error).message}`); }
  };

  const gateCheck = () => {
    if (!record) return;
    const blocking = rows.filter((r) => r.severity === "High" && !["Fixed", "Accepted risk", "Noise"].includes(issueOf(r).status));
    note(`Release gate for "${record.appName ?? "assessment"}": ${blocking.length ? "FAILED" : "PASSED"}. Rule: no High finding may be open or in progress; Fixed, Accepted risk and Noise do not block.`);
    blocking.slice(0, 15).forEach((r) => note(`  High ${r.ruleId} ${r.sink} [${r.source}] ${r.type}`));
    if (blocking.length > 15) note(`  ...and ${blocking.length - 15} more.`);
    note("For a pipeline gate with expiring waivers, use the command line: python falconscan.py <files> --policy gate.json");
    setBottomTab("console");
  };

  const selectApp = (id: string | null) => { setAppId(id); if (id) setCenterTab("properties"); };

  const scanApp = async (target?: Application) => {
    const app = target ?? apps.find((a) => a.id === appId);
    if (!app || app.flows.length === 0 || busy) return;
    setBusy(true);
    note(`Scanning "${app.name}" (${app.flows.length} flow file(s)) with configuration "${policy.name}"...`);
    try {
      abort.current = new AbortController();
      const resp = await api.scanUpload(app.flows, policy, abort.current.signal);
      const id = addScan(resp, "upload", { appId: app.id, appName: app.name, config: policy.name, disabled: policy.disabled });
      const n = resp.results.reduce((s, r) => s + r.findings.length, 0);
      note(`Scan finished: ${n} finding(s) in ${resp.results.length} flow(s).`);
      setAssessmentId(id); setFinding(null); setPerspective("analysis");
    } catch (e) {
      if ((e as Error).name === "AbortError") note(`Scan of "${app.name}" cancelled. No assessment was saved.`);
      else { note(`ERROR: ${(e as Error).message}`); setBottomTab("console"); }
    } finally { abort.current = null; setBusy(false); }
  };

  const finishWizard: React.ComponentProps<typeof NewApplicationWizard>["onFinish"] = (name, desc, dir, flows) => {
    const id = addApp(name, desc, dir, flows);
    note(`Application "${name}" created with ${flows.length} flow(s).`);
    setWizard(false); setAppId(id); setCenterTab("properties"); setPerspective("configuration");
  };

  const loadSample = () => {
    const id = addApp("Sample Flows", "", "", SAMPLE_FLOWS);
    note("Sample application loaded."); setAppId(id); setCenterTab("properties");
  };

  const exportAssessment = () => {
    if (!record) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(record.response, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = `assessment-${record.id}.json`; a.click(); URL.revokeObjectURL(url);
    note("Assessment exported.");
  };

  const exportCsv = () => {
    if (!record) return;
    download(`falconscan-${record.appName ?? "scan"}-${record.id}.csv`, toCsv(rows, issueOf), "text/csv;charset=utf-8");
    note("CSV report exported.");
  };
  const exportHtml = () => {
    if (!record) return;
    openPrintable(toHtml(record, rows, issueOf, diffData));
    note("HTML report opened: use Print ▸ Save as PDF for a PDF copy.");
  };

  // Start fresh: leave the assessment, findings and console. Saved assessments stay in My Assessments.
  const newScan = () => {
    setAssessmentId(null); setFinding(null); setFilterAppId(null); setViewJson(null); setSince(new Date().toISOString());
    setPerspective("configuration"); setCenterTab(appId ? "properties" : "welcome"); setBottomTab("findings");
    setLog([`[${stamp()}] Ready for a new scan. Select an application and choose Scan > Scan Application. Earlier assessments are still under My Assessments.`]);
  };
  const deleteAssessment = () => {
    if (!record || !confirm(`Delete this assessment of "${record.appName ?? "ad hoc scan"}" (${new Date(record.createdAt).toLocaleString()})?\n\nExport the SA&A report first if you need it. Triage statuses and comments belong to the application and are kept.`)) return;
    removeScan(record.id);
    setAssessmentId(history.find((r) => r.id !== record.id)?.id ?? null); setFinding(null);
    note("Assessment deleted.");
  };
  const deleteAll = () => {
    if (history.length === 0 || !confirm(`Delete all ${history.length} saved assessment(s)?\n\nThis cannot be undone. Export any reports you need first.`)) return;
    clearHistory(); setAssessmentId(null); setFinding(null); setFilterAppId(null); setSince(null);
    note("All assessments deleted.");
  };

  const saaFilename = (ext: string) => `falconscan-saa-${(record?.appName ?? "assessment").replace(/[^\w.-]+/g, "_")}-${record?.id}.${ext}`;
  const saaHtml = (m: SaaMeta) => toSaaHtml(record!, rows, issueOf, diffData, m);
  const saaOpenReport = (m: SaaMeta) => { openPrintable(saaHtml(m)); note("SA&A report opened: use Print > Save as PDF for a PDF copy."); };
  const saaDownload = (m: SaaMeta) => { download(saaFilename("html"), saaHtml(m), "text/html;charset=utf-8"); note("SA&A report downloaded."); };
  const saaPdf = async (m: SaaMeta) => {
    note("Creating the PDF…");
    setBottomTab("console");
    try {
      await logoReady;
      downloadBlob(saaFilename("pdf"), await api.reportPdf(saaHtml(m)));
      note("SA&A report saved as PDF. Attach the downloaded file to your email.");
    } catch (e) {
      note(`Could not create the PDF automatically: ${(e as Error).message}`);
      openPrintable(saaHtml(m));
      note("The report was opened instead: use Print > Save as PDF.");
    }
  };
  const execHtml = (m: SaaMeta) => toExecHtml(history, apps, (k) => issues.get(k), m);
  const execPdf = async (m: SaaMeta) => {
    note("Creating the executive summary PDF…");
    setBottomTab("console");
    try {
      await logoReady;
      downloadBlob("falconscan-executive-summary.pdf", await api.reportPdf(execHtml(m)));
      note("Executive summary saved as PDF.");
    } catch (e) {
      note(`Could not create the PDF automatically: ${(e as Error).message}`);
      openPrintable(execHtml(m));
      note("The summary was opened instead: use Print > Save as PDF.");
    }
  };
  const exportPoam = () => {
    if (!record) return;
    download(saaFilename("poam.csv"), toPoamCsv(record, rows, issueOf), "text/csv;charset=utf-8");
    note("POA&M exported (open findings only).");
  };

  // ---- actions behind the menus ----
  const goTab = (t: CenterTab) => { setPerspective("configuration"); setCenterTab(t); };
  const showBottom = (t: BottomTab) => { setBottomTab(t); if (perspective === "analysis" || perspective === "dashboard") setPerspective("triage"); };
  const scanAll = async () => {
    const list = apps.filter((a) => a.flows.length > 0);
    if (list.length === 0) { note("No application has files to scan."); return; }
    setBatch(true); cancelled.current = false;
    try {
      for (const a of list) { if (cancelled.current) break; await scanApp(a); }
      if (!cancelled.current) note(`Scan of ${list.length} application(s) finished.`);
    } finally { setBatch(false); }
  };
  const cancelScan = () => { cancelled.current = true; abort.current?.abort(); };
  const addFolder = async (list: FileList | null) => {
    const files = Array.from(list ?? []);
    if (folderInput.current) folderInput.current.value = "";
    if (files.length === 0) return;
    note(`Reading folder "${(files[0].webkitRelativePath || files[0].name).split("/")[0]}"…`);
    try {
      const got = await readFolder(files);
      got.notes.forEach(note);
      if (got.flows.length === 0) { note("No automation files were found in that folder."); setBottomTab("console"); return; }
      const id = addApp(got.name, "", got.name, got.flows);
      note(`Application "${got.name}" created from the folder with ${got.flows.length} file(s).`);
      setAppId(id); goTab("properties");
    } catch (e) { note(`ERROR: ${(e as Error).message}`); setBottomTab("console"); }
  };
  const duplicateApp = () => {
    if (!app) return;
    const id = addApp(`${app.name} (copy)`, app.description, app.workingDir, app.flows);
    note(`Application duplicated as "${app.name} (copy)".`); setAppId(id); goTab("properties");
  };
  const command = (kind: FindCmd["kind"]) => { showBottom("findings"); setFindCmd((c) => ({ id: c.id + 1, kind })); };
  const saveLibraryPolicy = (p: typeof policy) => { setPolicy(p); note(`Custom rules saved (${(p.custom ?? []).length}). They apply to the next scan.`); };
  const scanAgain = () => { const a = apps.find((x) => x.id === record?.appId); if (a) scanApp(a); };
  const renameSelected = () => {
    if (!app) return;
    const n = prompt("New name for the application:", app.name)?.trim();
    if (n && n !== app.name) { renameApp(app.id, n); note(`Application renamed to "${n}".`); }
  };
  const copyFinding = async () => {
    if (!finding) return;
    const text = `${finding.severity}: ${finding.type} (${finding.ruleId})\nFile: ${finding.sink}\nLocation: ${finding.source}\n${finding.detail}${finding.fix ? `\nFix: ${finding.fix}` : ""}`;
    try { await navigator.clipboard.writeText(text); note("Finding copied to the clipboard."); } catch { note("ERROR: the browser did not allow copying."); setBottomTab("console"); }
  };
  const openAssessment = (id: string) => { setAssessmentId(id); setFinding(null); setPerspective("analysis"); };
  const working = busy || batch;
  const canScan = !!app && app.flows.length > 0 && !working && canAssess;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "F4" && canScan) { e.preventDefault(); scanApp(); } };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const menus: Menu[] = [
    { label: "File", items: [
      { icon: "＋", label: "Add Application", disabled: !canAssess, items: [
        { label: "Create a new application…", onClick: () => setWizard(true) },
        { label: "Open an existing application", disabled: apps.length === 0,
          items: apps.map((a) => ({ label: a.name, onClick: () => { setAppId(a.id); goTab("properties"); } })) },
        { label: "Import a solution package (.zip)…", onClick: () => setWizard(true), hint: "Opens the new application wizard, which accepts solution .zip files" },
        { label: "Import from Power Platform…", onClick: () => nav(signedIn ? "/scanner" : "/connect") },
        { label: "Load sample application", onClick: loadSample },
      ] },
      { icon: "📁", label: "Add Folder…", disabled: !canAssess, onClick: () => folderInput.current?.click(), hint: "Creates an application from every automation file in a folder and its sub-folders" },
      { label: "Add Files to Application…", disabled: !app || !canAssess, onClick: () => goTab("properties"), hint: "Adds flow, agent or RPA files to the selected application" },
      { icon: "✕", label: "Remove Application", disabled: !app || !canAssess, onClick: () => app && removeAppConfirmed(app) },
      { separator: true },
      { icon: "📂", label: "Open Assessment", disabled: history.length === 0,
        items: history.slice(0, 15).map((r) => ({ label: `${r.appName ?? "Ad hoc scan"} · ${new Date(r.createdAt).toLocaleString()}`, onClick: () => openAssessment(r.id) })) },
      { icon: "▫", label: "Close Assessment", disabled: !record, onClick: () => { setAssessmentId(null); setFinding(null); goTab("assessments"); } },
      { icon: "💾", label: "Save Assessment As… (JSON)", disabled: !record, onClick: exportAssessment, hint: "Assessments are saved automatically. This downloads a copy." },
      { separator: true },
      { icon: "📄", label: "Reports", disabled: history.length === 0, items: [
        { label: "SA&A Assessment Report…", disabled: !record, onClick: () => setSaaOpen(true) },
        { label: "Executive Summary (PDF)…", onClick: () => setExecOpen(true) },
        { label: "Export POA&M (CSV)…", disabled: !record, onClick: exportPoam },
        { label: "Export Report (CSV)…", disabled: !record, onClick: exportCsv },
        { label: "Export Report (HTML / PDF)…", disabled: !record, onClick: exportHtml },
      ] },
      { separator: true },
      { label: "Exit", onClick: () => nav("/") },
    ] },
    { label: "Edit", items: [
      { icon: "⎘", label: "Copy Finding", disabled: !finding, onClick: copyFinding, hint: "Copies the selected finding as text" },
      { label: "Duplicate Application", disabled: !app || !canAssess, onClick: duplicateApp, hint: "Makes a copy of the selected application and its files" },
      { label: "Rename Application…", disabled: !app || !canAssess, onClick: renameSelected },
      { label: "Remove Application", disabled: !app || !canAssess, onClick: () => app && removeAppConfirmed(app) },
      { icon: "⟳", label: "Refresh", disabled: !serverMode, onClick: () => { reload(); note("Refreshed from the shared database."); }, hint: "Reloads the shared data" },
      { separator: true },
      { icon: "⌕", label: "Find…", onClick: () => command("find"), hint: "Searches the findings list" },
      { label: "Find Next", onClick: () => command("next"), hint: "Selects the next finding in the list" },
      { separator: true },
      { label: "New scan (clear view)", onClick: newScan },
      { label: "Clear console", onClick: () => setLog([]) },
      { separator: true },
      { label: "Delete this assessment…", disabled: !record || !canAssess, onClick: deleteAssessment },
      { label: "Delete all assessments…", disabled: history.length === 0 || !can("admin"), onClick: deleteAll },
      { separator: true },
      { icon: "⚙", label: "Preferences (Scan Configuration)…", disabled: !canAssess, onClick: () => setCfgOpen(true) },
    ] },
    { label: "Scan", items: [
      { icon: "▶", label: working ? "Scanning…" : "Scan All Applications", disabled: !canAssess || working || !apps.some((a) => a.flows.length > 0), onClick: scanAll },
      { icon: "▶", label: "Scan Selection", shortcut: "F4", disabled: !canScan, onClick: () => scanApp(), hint: "Scans the selected application" },
      { icon: "↻", label: "Scan Again", disabled: !canAssess || working || !apps.some((a) => a.id === record?.appId && a.flows.length > 0), onClick: scanAgain, hint: "Scans the application of the open assessment again" },
      { icon: "■", label: "Cancel Scan", disabled: !working, onClick: cancelScan, hint: "Stops waiting for the scan. The server finishes its work but nothing is saved." },
      { separator: true },
      { label: "Release gate check", disabled: !record, onClick: gateCheck },
      { separator: true },
      { icon: "⚙", label: "Build Configuration", items: [
        { label: `Scan Configuration… (${policy.name})`, disabled: !canAssess, onClick: () => setCfgOpen(true) },
      ] },
    ] },
    { label: "Tools", items: [
      { label: `Scan Configuration… (${policy.name})`, disabled: !canAssess, onClick: () => setCfgOpen(true) },
      { label: "Release gate check", disabled: !record, onClick: gateCheck },
      { separator: true },
      { label: "Load sample application", disabled: !canAssess, onClick: loadSample },
    ] },
    { label: "View", items: [
      { label: "Explorer", onClick: () => setPerspective("configuration") },
      { label: "Properties", onClick: () => goTab("properties") },
      { label: "Pattern Rule Library", onClick: () => { setRuleCategory(""); goTab("rules"); } },
      { label: "Custom Rules", onClick: () => { setRuleCategory(""); goTab("rules"); document.getElementById("custom-rules")?.scrollIntoView(); } },
      { label: "Bundles", disabled: rulesList.length === 0,
        items: [...new Set(rulesList.map((r) => r.category))].sort().map((c) => ({ label: `${c} (${rulesList.filter((r) => r.category === c).length})`, onClick: () => { setRuleCategory(c); goTab("rules"); } })) },
      { label: "Scan Configuration…", disabled: !canAssess, onClick: () => setCfgOpen(true) },
      { label: "Report Editor (SA&A report)…", disabled: !record, onClick: () => setSaaOpen(true) },
      { separator: true },
      { label: "Console", onClick: () => showBottom("console") },
      { label: "Metrics (Dashboard)", onClick: () => setPerspective("dashboard") },
      { label: "My Assessments", onClick: () => goTab("assessments") },
      { separator: true },
      { label: "Findings", onClick: () => command("all") },
      { label: "Excluded Findings (noise or accepted)", onClick: () => command("excluded") },
      { label: "Finding Detail and How to Fix", onClick: () => showBottom("findings"), hint: "Select a finding to see its detail, fix and example" },
      { label: "Assessment Diff (new and fixed findings)", disabled: !previous, onClick: () => showBottom("changes"), hint: "Needs an earlier assessment of the same application" },
      { label: "Analysis (steps and data flow)", disabled: !record, onClick: () => setPerspective("analysis") },
      { separator: true },
      { label: "Platform Integrations", onClick: () => goTab("platforms") },
      ...(serverMode ? [{ label: "Scheduled scans", onClick: () => goTab("schedules") }] : []),
      ...(isAdmin ? [{ label: "Administration (users and audit log)", onClick: () => goTab("admin") }] : []),
    ] },
    { label: "Perspective", items: [
      { label: "Configuration", onClick: () => setPerspective("configuration") },
      { label: "Triage", onClick: () => setPerspective("triage") },
      { label: "Analysis", onClick: () => setPerspective("analysis") },
      { label: "Dashboard", onClick: () => setPerspective("dashboard") },
      { separator: true },
      { label: "Reset layout", onClick: () => { setPerspective("configuration"); setCenterTab("assessments"); } },
    ] },
    { label: "Help", items: [{ label: `About ${BRAND.name}`, onClick: () => alert(`${BRAND.name}: ${BRAND.tagline}\n\n${BRAND.statement}\n\nScans Power Automate flows, UiPath projects, MCP configurations and AI agent definitions by static analysis.`) }] },
  ];

  const tab = (id: CenterTab, label: string) => (
    <button className={centerTab === id ? "on" : ""} onClick={() => setCenterTab(id)}>{label}</button>
  );
  const persp = (id: Perspective, label: string) => (
    <button className={perspective === id ? "on" : ""} onClick={() => setPerspective(id)}>{label}</button>
  );

  return (
    <div className={`wb ${perspective}`}>
      <div className="wb-title">
        <Link to="/"><Logo size={26} /> {BRAND.name} <small>{BRAND.tagline}</small></Link>
        <span className="grow" />
        <AccountMenu />
        {canAssess && (signedIn ? <span className="muted">Signed in to Power Platform</span> : <Link className="btn ghost" to="/connect">Connect</Link>)}
      </div>
      <MenuBar menus={menus} />
      <input ref={folderInput} type="file" hidden multiple onChange={(e) => addFolder(e.target.files)}
        {...({ webkitdirectory: "", directory: "" } as Record<string, string>)} />
      <div className="perspectives">
        {persp("configuration", "Configuration")}{persp("triage", "Triage")}{persp("analysis", "Analysis")}{persp("dashboard", "Dashboard")}
        <span className="sep" />
        <button onClick={newScan} title="Clear the current results and start a new scan. Saved assessments are kept.">⟲ New scan</button>
        <button onClick={() => setSaaOpen(true)} disabled={!record} title="Security assessment report with POA&M for the selected assessment">SA&amp;A report</button>
        <span className="sep" />
        <button className="on" onClick={() => scanApp()} disabled={!app || app.flows.length === 0 || busy || !canAssess}
          title="Scan the selected application">▶ Scan</button>
      </div>

      {importAsk && (
        <div className="filter-chip">
          This browser holds applications and assessments saved before the shared database was turned on.
          <span><button onClick={doImport}>Import them</button> <button onClick={skipImport}>Not now</button></span>
        </div>
      )}
      <div className="wb-body">
        <Explorer apps={apps} selectedId={appId} onSelect={selectApp} onNew={() => canAssess && setWizard(true)}
          onContextMenu={(x, y, t) => { setAppId(t.appId); setCtx({ x, y, ...t }); }} />
        <Splitter axis="x" cssVar="--explorer-w" grows="prev" min={140} collapsed={0} label="the Explorer" />
        <div className="wb-right">
          <div className="center">
            {perspective === "dashboard" ? (
              <div className="center-body">
                <Dashboard history={dashHistory} apps={apps} issueOf={(k) => issues.get(k)} since={dashSince}
                  hidden={history.length - dashHistory.length} onShowAll={() => setSince(null)} />
              </div>
            ) : perspective === "analysis" ? (
              <div className="center-body analysis-pane">
                {record
                  ? <ScanRunner key={record.id} results={record.response.results} startCompleted={record.completed}
                      onComplete={() => markCompleted(record.id)} />
                  : <p className="muted">Select an application and choose Scan ▸ Scan Application to start an analysis.</p>}
              </div>
            ) : (
              <>
                <div className="tabstrip">
                  {tab("welcome", "Welcome")}{tab("properties", "Properties")}{tab("assessments", "My Assessments")}{centerTab === "platforms" && tab("platforms", "Platform Integrations")}{centerTab === "rules" && tab("rules", "Rule Library")}{serverMode && tab("schedules", "Schedules")}{isAdmin && tab("admin", "Administration")}
                </div>
                <div className="center-body">
                  {centerTab === "welcome" && <WelcomeTab onNewApp={() => setWizard(true)} onSample={loadSample} readOnly={!canAssess} />}
                  {centerTab === "properties" && <PropertiesTab app={app} onAddFlows={(id, f) => { addFlows(id, f); note(`${f.length} flow file(s) added.`); }}
                    onRemoveFlow={removeFlow} readOnly={!canAssess} onError={(m) => { note(`ERROR: ${m}`); setBottomTab("console"); }} />}
                  {centerTab === "platforms" && <PlatformsTab />}
                  {centerTab === "rules" && <RuleLibraryTab rules={rulesList} policy={policy} canEdit={canAssess} category={ruleCategory} onCategory={setRuleCategory} onSavePolicy={saveLibraryPolicy} />}
                  {centerTab === "schedules" && serverMode && <SchedulesPanel apps={apps} canEdit={canAssess} onChanged={reload} />}
                  {centerTab === "admin" && isAdmin && <AdminPanel />}
                  {centerTab === "assessments" && (
                    <>
                    {dashSince && (
                      <div className="filter-chip">
                        Showing {dashHistory.length} assessment(s) since the last New scan.
                        {history.length > dashHistory.length &&
                          <button onClick={() => setSince(null)} title="Show every saved assessment again">Show all {history.length} saved assessments</button>}
                      </div>
                    )}
                    {filterApp && (
                      <div className="filter-chip">
                        Showing assessments for <b>{filterApp.name}</b>
                        <button onClick={() => setFilterAppId(null)} title="Show all assessments">✕ Show all</button>
                      </div>
                    )}
                    <AssessmentsTable records={shownRecords} history={history} selectedId={assessmentId}
                      onSelect={(id) => { setAssessmentId(id); setFinding(null); }}
                      onOpen={(id) => { setAssessmentId(id); setPerspective("analysis"); }} />
                    </>
                  )}
                </div>
              </>
            )}
          </div>
          <Splitter axis="y" cssVar="--bottom-h" grows="next" min={90} collapsed={27} label="the findings panel" />
          <FindingsPanel tab={bottomTab} onTab={setBottomTab} rows={rows} selected={finding} onSelect={setFinding}
            log={log} label={record ? `${record.appName ?? "Ad hoc"}` : "No assessment selected"}
            issueOf={issueOf} onIssue={(r, patch) => issues.set(r.issueKey, patch)}
            diff={diffData} previousLabel={previous ? new Date(previous.createdAt).toLocaleString() : null}
            readOnly={!canAssess} cmd={findCmd} ticketCfg={ticketCfg} ticketOf={(r) => tickets[r.issueKey]} onTicket={makeTicket} />
        </div>
      </div>
      <div className="statusbar"><span>{busy ? "Scanning…" : "Ready"}</span><span>{apps.length} application(s) · {history.length} assessment(s)</span></div>
      {ctx && (
        <ContextMenu x={ctx.x} y={ctx.y} onClose={() => setCtx(null)} items={ctxItems(ctx)}
          title={ctx.flow ?? apps.find((a) => a.id === ctx.appId)?.name} />
      )}
      {viewJson !== null && <JsonViewer data={viewJson} onClose={() => setViewJson(null)} />}
      {cfgOpen && <ScanConfigDialog policy={policy} onClose={() => setCfgOpen(false)}
        onSave={(p) => { setPolicy(p); setCfgOpen(false); note(`Scan configuration "${p.name}" saved (${p.disabled.length} rule(s) off, ${Object.keys(p.severity).length} override(s)).`); }} />}
      {saaOpen && record && <SaaReportDialog defaultSystem={record.appName ?? ""} onClose={() => setSaaOpen(false)}
        onOpen={saaOpenReport} onDownload={saaDownload} onPdf={saaPdf} />}
      {execOpen && <SaaReportDialog title="Executive summary" systemLabel="Scope" defaultSystem="All applications" onClose={() => setExecOpen(false)}
        onOpen={(m) => openPrintable(execHtml(m))} onDownload={(m) => download("falconscan-executive-summary.html", execHtml(m), "text/html;charset=utf-8")} onPdf={execPdf} />}
      {wizard && <NewApplicationWizard onCancel={() => setWizard(false)} onFinish={finishWizard} />}
    </div>
  );
}

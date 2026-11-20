import type {
  AccountState, AdminUser, AuditEntry, AuditVerify, Bootstrap, Env, Flow, FixResult, IssueState, LoginInfo, Policy, Role, Rule, ScanRecord,
  ScanResponse, Schedule, SchedulesResponse, SessionUser, SolutionFlows, TicketConfig, TicketLink,
} from "../types";

const wire = (p?: Policy) => (p ? { disabled: p.disabled, severity: p.severity, custom: p.custom ?? [] } : undefined);
const JSON_HEADERS = { "Content-Type": "application/json" };
const json = (body: unknown) => ({ headers: JSON_HEADERS, body: JSON.stringify(body) });

/** Anything that changes something carries this header; the server refuses such requests without it (CSRF protection). */
function withCsrf(init?: RequestInit): RequestInit {
  const method = (init?.method ?? "GET").toUpperCase();
  if (method === "GET" || method === "HEAD") return { ...init, credentials: "same-origin" };
  return { ...init, credentials: "same-origin", headers: { ...(init?.headers as Record<string, string> | undefined), "X-Falcon-CSRF": "1" } };
}

async function failure(r: Response): Promise<Error> {
  const body = await r.json().catch(() => null);
  // A non-JSON 500 from the dev proxy means the backend is not running.
  if (!body && r.status >= 500) return new Error("Cannot reach the backend. Start it with: uvicorn main:app --reload (in the backend folder).");
  return new Error(typeof body?.detail === "string" ? body.detail : r.statusText);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api${path}`, withCsrf(init));
  if (r.status === 401) window.dispatchEvent(new Event("falcon:unauthorized"));
  if (!r.ok) throw await failure(r);
  return r.json();
}

export const api = {
  // ---- Power Platform sign-in (Microsoft), unchanged ----
  login: () => request<LoginInfo>("/auth/login", { method: "POST" }),
  status: () => request<{ status: string; user?: string; error?: string }>("/auth/status"),
  logout: () => request<unknown>("/auth/logout", { method: "POST" }),
  environments: () => request<Env[]>("/environments"),
  flows: (env: string, admin: boolean) => request<Flow[]>(`/environments/${env}/flows?admin=${admin}`),
  flow: (env: string, id: string, admin: boolean) => request<unknown>(`/environments/${env}/flows/${id}?admin=${admin}`),
  rules: () => request<Rule[]>("/rules"),
  scanUpload: (files: { filename: string; content: unknown }[], policy?: Policy, signal?: AbortSignal) =>
    request<ScanResponse>("/scan/upload", { method: "POST", signal, ...json({ files, policy: wire(policy) }) }),
  /** Print report HTML to a PDF on the backend (uses the Edge or Chrome installed there). */
  reportPdf: async (html: string): Promise<Blob> => {
    const r = await fetch("/api/report/pdf", withCsrf({ method: "POST", ...json({ html }) }));
    if (r.status === 401) window.dispatchEvent(new Event("falcon:unauthorized"));
    if (!r.ok) throw await failure(r);
    return r.blob();
  },
  extractSolution: (filename: string, contentBase64: string) =>
    request<SolutionFlows>("/solution/extract", { method: "POST", ...json({ filename, contentBase64 }) }),
  fixFlow: (filename: string, content: unknown, policy?: Policy) =>
    request<FixResult>("/fix", { method: "POST", ...json({ filename, content, policy: wire(policy) }) }),
  scan: (environmentId: string, flowIds: string[], admin: boolean, policy?: Policy) =>
    request<ScanResponse>("/scan", { method: "POST", ...json({ environmentId, flowIds, admin, policy: wire(policy) }) }),

  // ---- application accounts and roles ----
  accountState: () => request<AccountState>("/account/state"),
  accountLogin: (username: string, password: string) => request<{ user: SessionUser }>("/account/login", { method: "POST", ...json({ username, password }) }),
  accountSetup: (username: string, password: string, displayName: string, setupToken: string) =>
    request<{ user: SessionUser }>("/account/setup", { method: "POST", ...json({ username, password, displayName, setupToken }) }),
  accountLogout: () => request<unknown>("/account/logout", { method: "POST" }),
  accountPassword: (current: string, next: string) => request<unknown>("/account/password", { method: "POST", ...json({ current, new: next }) }),

  // ---- administration ----
  adminUsers: () => request<AdminUser[]>("/admin/users"),
  adminCreateUser: (u: { username: string; password: string; role: Role; displayName: string }) => request<AdminUser>("/admin/users", { method: "POST", ...json(u) }),
  adminUpdateUser: (id: number, patch: Partial<{ role: Role; active: boolean; password: string; displayName: string; unlock: boolean }>) =>
    request<AdminUser>(`/admin/users/${id}`, { method: "PATCH", ...json(patch) }),
  adminAudit: (action = "", before?: number) =>
    request<{ entries: AuditEntry[]; verify: AuditVerify }>(`/admin/audit?limit=100&action=${encodeURIComponent(action)}${before ? `&before=${before}` : ""}`),

  // ---- shared data ----
  bootstrap: () => request<Bootstrap>("/data/bootstrap"),
  saveApp: (app: unknown) => request<unknown>("/data/applications", { method: "POST", ...json(app) }),
  deleteApp: (id: string) => request<unknown>(`/data/applications/${encodeURIComponent(id)}`, { method: "DELETE" }),
  addAssessment: (rec: ScanRecord) => request<ScanRecord>("/data/assessments", { method: "POST", ...json(rec) }),
  completeAssessment: (id: string) => request<unknown>(`/data/assessments/${encodeURIComponent(id)}`, { method: "PATCH" }),
  deleteAssessment: (id: string) => request<unknown>(`/data/assessments/${encodeURIComponent(id)}`, { method: "DELETE" }),
  deleteAllAssessments: () => request<{ deleted: number }>("/data/assessments", { method: "DELETE" }),
  setIssue: (key: string, patch: Partial<Pick<IssueState, "status" | "comment">>) => request<IssueState>("/data/issues", { method: "PUT", ...json({ key, ...patch }) }),
  setPolicy: (p: Policy) => request<Policy>("/data/policy", { method: "PUT", ...json(p) }),
  importBundle: (bundle: unknown) => request<Record<string, number>>("/data/import", { method: "POST", ...json(bundle) }),

  // ---- schedules and tickets ----
  schedules: () => request<SchedulesResponse>("/schedules"),
  createSchedule: (s: { name: string; sourceType: string; sourceRef: string; intervalMinutes: number; failOn: string }) =>
    request<Schedule>("/schedules", { method: "POST", ...json(s) }),
  updateSchedule: (id: number, patch: Partial<{ name: string; intervalMinutes: number; failOn: string; enabled: boolean }>) =>
    request<Schedule>(`/schedules/${id}`, { method: "PATCH", ...json(patch) }),
  deleteSchedule: (id: number) => request<unknown>(`/schedules/${id}`, { method: "DELETE" }),
  runSchedule: (id: number) => request<Schedule>(`/schedules/${id}/run`, { method: "POST" }),
  ticketConfig: () => request<TicketConfig>("/tickets/config"),
  createTicket: (finding: unknown) => request<TicketLink>("/tickets", { method: "POST", ...json(finding) }),
};

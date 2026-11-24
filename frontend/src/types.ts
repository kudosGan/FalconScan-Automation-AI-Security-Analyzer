export type Severity = "High" | "Medium" | "Low";
export type Risk = Severity | "Unknown";

export type Env = { id: string; displayName: string; type: string; isDefault: boolean };
export type Flow = { id: string; displayName: string; state: string; lastModifiedTime: string; creator: string };
export type LoginInfo = { user_code: string; verification_uri: string };

export type Finding = {
  severity: Severity; ruleId: string; title: string; detail: string; location: string; jsonPath?: string[]; fix?: string[];
  cwe?: string | null; owasp?: string | null; lcnc?: string | null; category?: string; fingerprint?: string;
  alternative?: { title: string; steps: string[] } | null;
  example?: { before: string; after: string } | null;
};
export type Connection = {
  connector: string; name: string; publisher: string; category: string; thirdParty: boolean;
  destination: string; direction: string; sensitivity: "High" | "Medium" | "Low"; dataTypes: string[];
  ai: { provider: string; microsoft: boolean } | null; target: string | null; why: string;
};
export type DataFlow = {
  from: string; to: string; fromConnector: string; toConnector: string;
  sensitivity: string; thirdParty: boolean; ai: boolean; via: string;
};
export type Step = {
  connection?: Connection | null;
  id: string; kind: "trigger" | "action" | "flow"; name: string; type: string; path: string;
  depth: number; connector: string | null; json: unknown; findings: Finding[];
};
export type FlowResult = {
  steps?: Step[];
  dataFlows?: DataFlow[];
  connections?: (Pick<Connection, "connector" | "name" | "publisher" | "thirdParty" | "sensitivity" | "ai"> & { usedBy: string[] })[];
  metadata?: Record<string, string | number | null>;
  flowId: string; name: string; state?: string; connectors: string[];
  triggerCount?: number; actionCount?: number; findings: Finding[];
  risk: Risk; score: number; error?: string;
};
export type ScanResponse = { environmentId: string; results: FlowResult[] };

export type ScanRecord = {
  id: string; createdAt: string; source: "upload" | "live" | "scheduled"; response: ScanResponse; completed: boolean; createdBy?: string;
  appId?: string; appName?: string; config?: string; disabled?: string[];
};

export type FlowFile = { filename: string; content: unknown };
export type Application = {
  id: string; name: string; description: string; workingDir: string; createdAt: string; flows: FlowFile[];
};

export type Rule = {
  id: string; title: string; severity: Severity; category: string;
  cwe: string | null; owasp: string | null; description: string;
  /** OWASP Low-Code/No-Code Top 10 category, e.g. LCNC-SEC-08, and its name. */
  lcnc?: string; lcncTitle?: string;
};
/** A named scan configuration: which rules run and any severity overrides. */
/** A word or phrase that must not appear in an automation file. Plain text, matched without regard to capitals. */
export type CustomRule = { id: string; title: string; severity: Severity; text: string; fix: string; enabled: boolean };
export type Policy = { name: string; disabled: string[]; severity: Record<string, Severity>; custom?: CustomRule[] };

export type IssueStatus = "Open" | "In progress" | "Fixed" | "Accepted risk" | "Noise";
export const ISSUE_STATUSES: IssueStatus[] = ["Open", "In progress", "Fixed", "Accepted risk", "Noise"];
export type IssueState = { status: IssueStatus; comment: string; updatedAt: string };

export type SolutionFlows = { flows: { filename: string; content: unknown }[]; skipped: { file: string; reason: string }[] };

type Counts = { total: number; High: number; Medium: number; Low: number };
export type FixResult = {
  content: unknown;
  applied: { ruleId: string; title: string; location: string; change: string }[];
  skipped: { ruleId: string; title: string; reason: string; count: number }[];
  before: Counts; after: Counts;
};

// ---- accounts, shared data, schedules and tickets ----
export type Role = "viewer" | "assessor" | "admin";
export type SessionUser = { id: number; username: string; displayName: string; role: Role };
export type AccountState = { authEnabled: boolean; setupRequired: boolean; github?: boolean; user: SessionUser | null };
export type AdminUser = SessionUser & { active: boolean; createdAt: string | null; lastLogin: string | null; locked: boolean };
export type AuditEntry = { id: number; ts: string; actor: string; role: string; action: string; target: string; detail: Record<string, unknown>; ip: string; hash: string };
export type AuditVerify = { ok: boolean; checked: number; brokenAt: number | null; head: string };
export type Schedule = {
  id: number; name: string; sourceType: "application" | "folder"; sourceRef: string; intervalMinutes: number; failOn: string; enabled: boolean;
  nextRun: number; lastRun: number | null; lastStatus: string; lastAssessmentId: string | null; createdBy: string; createdAt: string;
};
export type SchedulesResponse = { schedules: Schedule[]; folderSchedules: boolean; scanRootName: string | null; minIntervalMinutes: number };
export type TicketLink = { system: string; id: string; url: string; createdAt: string; createdBy: string };
export type TicketConfig = { configured: boolean; system: string | null; target: string | null; problem: string | null };
export type Bootstrap = {
  applications: Application[]; assessments: ScanRecord[]; issues: Record<string, IssueState & { updatedBy?: string }>;
  policy: Policy; tickets: Record<string, TicketLink>;
};

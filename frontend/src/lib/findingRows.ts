import type { Finding, ScanRecord, Severity } from "../types";

export type FindingRow = {
  key: string; trace: number; severity: Severity; classification: string; type: string;
  api: string; source: string; sink: string; directory: string;
  ruleId: string; detail: string; stepJson: unknown;
  cwe: string; owasp: string;
  /** Guidance from the scanner; empty for scans saved before it was recorded. */
  fix: string[]; example: Finding["example"]; alternative: Finding["alternative"];
  /** Identifies the same issue across rescans of one application. */
  fingerprint: string;
  /** Key for triage state: application + fingerprint. */
  issueKey: string;
  /** True when an earlier assessment of this application did not have this finding. */
  isNew: boolean;
};

const CLASS: Record<string, string> = {
  TRG: "Trigger exposure", ACT: "Action configuration", SEC: "Secret handling",
  CFG: "Configuration", GOV: "Governance", CON: "Connections", AI: "Data exposure",
};
export const classify = (ruleId: string) => CLASS[ruleId.split("-")[1]] ?? "General";

/** Fingerprint of a finding; older saved scans lack the server-made one, so rebuild it the same way. */
export const fingerprintOf = (flowId: string, f: Finding) =>
  f.fingerprint ?? [flowId, f.ruleId, f.location, (f.jsonPath ?? []).join(".")].join("|");

export const fingerprintsOf = (record: ScanRecord | undefined): Set<string> =>
  new Set(record?.response.results.flatMap((r) => r.findings.map((f) => fingerprintOf(r.flowId, f))) ?? []);

// One row per finding: Source = where in the flow, Sink = which flow, API = connector or action type.
export function toRows(record: ScanRecord | undefined, previous?: ScanRecord): FindingRow[] {
  if (!record) return [];
  const before = previous ? fingerprintsOf(previous) : null;
  const wasOff = new Set(previous?.disabled ?? []);   // a rule that did not run before cannot be "new" now
  const app = record.appId ?? `adhoc-${record.id}`;
  return record.response.results.flatMap((r) =>
    (r.steps ?? []).flatMap((s, i) =>
      s.findings.map((f, j) => {
        const fp = fingerprintOf(r.flowId, f);
        return {
          key: `${r.flowId}-${s.id}-${f.ruleId}-${j}`,
          trace: i + 1,
          severity: f.severity,
          classification: f.category ?? classify(f.ruleId),
          type: f.title,
          api: s.connector ?? s.type,
          source: s.path,
          sink: r.name,
          directory: record.appName ?? "Uploaded files",
          ruleId: f.ruleId,
          detail: f.detail,
          stepJson: s.json,
          cwe: f.cwe ?? "—",
          owasp: f.owasp ?? "—",
          fix: f.fix ?? [], example: f.example ?? null, alternative: f.alternative ?? null,
          fingerprint: fp,
          issueKey: `${app}|${fp}`,
          isNew: before ? !before.has(fp) && !wasOff.has(f.ruleId) : false,
        };
      }),
    ),
  );
}

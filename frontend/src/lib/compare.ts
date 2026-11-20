import type { Finding, ScanRecord } from "../types";
import { fingerprintOf, fingerprintsOf } from "./findingRows";

/** The next-older assessment of the same application, if any (history is newest first). */
export function previousOf(history: ScanRecord[], record: ScanRecord | undefined): ScanRecord | undefined {
  if (!record?.appId) return undefined;
  return history.find((r) => r.appId === record.appId && r.createdAt < record.createdAt);
}

export type FixedItem = { flow: string; finding: Finding };
export type Diff = { added: number; fixed: FixedItem[]; unchanged: number };

/** Findings that appeared, disappeared or stayed between two assessments.
 *  Rules switched off in either scan configuration are left out: not running a rule is not the same as fixing it. */
export function diff(current: ScanRecord, previous: ScanRecord): Diff {
  const off = new Set([...(current.disabled ?? []), ...(previous.disabled ?? [])]);
  const ruleOf = (fp: string) => fp.split("|")[1];
  const now = new Set([...fingerprintsOf(current)].filter((fp) => !off.has(ruleOf(fp))));
  const before = new Set([...fingerprintsOf(previous)].filter((fp) => !off.has(ruleOf(fp))));
  const fixed: FixedItem[] = previous.response.results.flatMap((r) =>
    r.findings.filter((f) => !off.has(f.ruleId) && !now.has(fingerprintOf(r.flowId, f))).map((finding) => ({ flow: r.name, finding })));
  let added = 0, unchanged = 0;
  now.forEach((fp) => (before.has(fp) ? unchanged++ : added++));
  return { added, fixed, unchanged };
}

export const countBySeverity = (r: ScanRecord) => {
  const all = r.response.results.flatMap((x) => x.findings);
  return { High: all.filter((f) => f.severity === "High").length, Medium: all.filter((f) => f.severity === "Medium").length,
           Low: all.filter((f) => f.severity === "Low").length };
};

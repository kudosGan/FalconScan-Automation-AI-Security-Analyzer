import type { Step } from "../types";

const SECRET = /(pass(word|wd)?|secret|api[-_]?key|token|authorization|credential|pwd)/i;
const isExpr = (v: string) => { const t = v.trim().replace(/^"|"$/g, ""); return t.startsWith("@") || t.includes("@{"); };

/** Plain-English note about what the scanner is checking on one JSON line. */
export function annotateLine(raw: string, step: Step): string {
  const line = raw.trim();
  if (!line || /^[\]\[{},]+$/.test(line)) return "Structure: moving to the next property";
  const m = line.match(/^"([^"]+)":\s*(.*?),?$/);
  if (!m) return `Reading value ${line.slice(0, 60)}`;
  const [, key, rawVal] = m;
  const val = rawVal.replace(/^"|"$/g, "");
  const c = step.connection;

  if (key === "type") return `Step type is ${val}: choosing which rules apply`;
  if (key === "kind") return `Trigger kind ${val}: checking how this flow can be started`;
  if (key === "triggerAuthenticationType") return `Who may call this trigger: "${val}". Checking it is not open to anyone`;
  if (key === "apiId" || key === "connectionName") {
    return c ? `Identifying connector: ${c.name}, run by ${c.publisher}. ${c.thirdParty ? "Data leaves Microsoft 365 here" : "Stays inside Microsoft services"}`
             : `Connector reference ${val}`;
  }
  if (key === "operationId") return c ? `Operation ${val}: this step ${c.direction} ${c.name} data` : `Operation ${val}`;
  if (key === "uri" || key === "url") {
    let host = val;
    try { host = new URL(val).hostname; } catch { /* expression or partial URL */ }
    const scheme = val.startsWith("http://") ? " Unencrypted (http), a risk." : "";
    return `Destination ${host}: ${c ? c.destination : "resolving where data goes"}.${scheme}`;
  }
  if (key === "method") return `HTTP method ${val}: ${val.toUpperCase() === "GET" ? "reads data" : "sends data to the destination"}`;
  if (key === "authentication") return rawVal === "{" ? "Authentication block: checking type and credentials" : `Authentication ${val}`;
  if (SECRET.test(key) && !/^[{[]$/.test(rawVal)) {
    return isExpr(rawVal) ? `"${key}" uses an expression: no hard-coded secret here`
                          : `"${key}" holds a literal value: checking for a hard-coded credential`;
  }
  if (key === "dataset") return `Data source (SharePoint site / database): ${val}. ${c ? `Sensitivity ${c.sensitivity}` : ""}`;
  if (key === "table") return `List or table "${val}": ${c ? c.dataTypes.join(", ") : "records are read or written here"}`;
  if (/emailMessage\/To|^to$|recipient/i.test(key)) return `Recipient "${val}": checking for personal or external addresses`;
  if (key === "parameters") return "Operation inputs: checking what data is passed in";
  if (key === "inputs") return "Action inputs: reading what this step sends and receives";
  if (key === "runtimeConfiguration" || key === "secureData") return "Run-history protection: checking Secure Inputs/Outputs";
  if (key === "runAfter") return "Run order: this step waits for the steps listed here";
  if (key === "host") return "Connection details: checking which service this step talks to";
  if (isExpr(rawVal)) return `"${key}" uses an expression: tracing which earlier step its data comes from`;
  return `Reading "${key}"`;
}

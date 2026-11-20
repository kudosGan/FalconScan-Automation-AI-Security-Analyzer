"""Generate a corrected copy of a flow for the findings whose fix is mechanical and safe.

Only a few rules qualify. Everything else needs a decision (which secret store, which authentication,
who may call the trigger), so those findings are reported as skipped with the reason, never guessed at.
The corrected flow is returned for a person to review and re-import; nothing is changed in any environment.
"""
import copy
import re

import agentscan
import dispatch
import rpascan
import scanner
from flowio import locate_definition, normalize


def _action(defn: dict, name: str) -> dict | None:
    return next((a for n, a in scanner._walk_actions(defn.get("actions")) if n == name), None)


def _http_to_https(a: dict):
    inputs = a.get("inputs")
    uri = inputs.get("uri") if isinstance(inputs, dict) else None
    if not (isinstance(uri, str) and uri.lower().startswith("http://")):
        return None, "the address is built by an expression, so it cannot be rewritten safely"
    inputs["uri"] = "https://" + uri[7:]
    return f"uri {uri} -> {inputs['uri']} (check the destination accepts HTTPS)", None


def _secure_data(a: dict):
    rc = a.setdefault("runtimeConfiguration", {})
    if not isinstance(rc, dict):
        return None, "runtimeConfiguration has an unexpected shape"
    rc["secureData"] = {"properties": ["inputs", "outputs"]}
    return "secure inputs and outputs turned on", None


def _terminate(a: dict):
    after = a.get("runAfter") or {}
    if not any(s in ("Failed", "TimedOut", "Skipped") for st in after.values() for s in (st or [])):
        return None, "it ends the run as Succeeded on the normal path, which may be intended"
    inputs = a.setdefault("inputs", {})
    inputs["runStatus"] = "Failed"
    inputs.setdefault("runError", {"code": "FlowFailed", "message": "The flow ended in its error-handling path."})
    return "runStatus Succeeded -> Failed (review the error message)", None


HANDLERS = {"PA-ACT-001": _http_to_https, "PA-CFG-001": _secure_data, "PA-CFG-002": _terminate}


def _counts(result: dict) -> dict:
    c = {"total": len(result["findings"]), "High": 0, "Medium": 0, "Low": 0}
    for f in result["findings"]:
        c[f["severity"]] += 1
    return c


def _fix_agent(filename: str, content: dict, policy: dict | None, kind: str) -> dict:
    """Safe, mechanical fixes for MCP and agent files: https for remote URLs, and removing settings that weaken security."""
    before = agentscan.scan_agent(filename, copy.deepcopy(content), policy)
    fixed = copy.deepcopy(content)
    root = agentscan._agent_root(fixed) if kind == "agent" else fixed
    comps = agentscan.components(root, kind)
    applied, skipped, drops = [], {}, []
    for f in before["findings"]:
        comp = comps.get(f["location"].split(":", 1)[1]) if f["location"].startswith("action:") else None
        path, rule, why, change = f["jsonPath"], f["ruleId"], "this fix needs a decision from you; see How to fix", None
        try:
            if comp is not None and rule == "AG-MCP-001" and path:
                if path[0] in agentscan.URL_KEYS:
                    old = comp[path[0]]
                    comp[path[0]] = "https://" + old[7:]
                else:
                    old = comp["args"][int(path[1])]
                    comp["args"][int(path[1])] = "https://" + old[7:]
                change = f"{old} -> https://{old[7:]} (check the server accepts HTTPS)"
            elif comp is not None and rule == "AG-MCP-007" and path[0] == "env":
                del comp["env"][path[1]]
                change = f"removed env {path[1]}, so certificates are checked again"
            elif comp is not None and rule == "AG-MCP-007" and path[0] == "args":
                drops.append((comp, comp["args"][int(path[1])]))
                change = f"removed the argument {comp['args'][int(path[1])]}"
            elif comp is not None and rule == "AG-MCP-008":
                del comp[path[0]]
                change = f"removed {path[0]}, so tool calls need approval again"
            elif comp is not None and rule == "AG-AGT-002" and f["severity"] == "Medium" and path:
                holder = comp["function"] if path[0] == "function" else comp
                key = path[-1]
                holder[key] = "always" if holder[key] == "never" else True
                change = f"{key} set to {holder[key]!r}"
        except (KeyError, IndexError, TypeError, ValueError):
            change, why = None, "the setting was not where the scan expected"
        if change:
            applied.append({"ruleId": rule, "title": f["title"], "location": f["location"], "change": change})
        else:
            s = skipped.setdefault((rule, why), {"ruleId": rule, "title": f["title"], "reason": why, "count": 0})
            s["count"] += 1
    for comp, value in drops:
        if value in comp.get("args", []):
            comp["args"].remove(value)
    after = agentscan.scan_agent(filename, copy.deepcopy(fixed), policy)
    return {"content": fixed, "applied": applied, "skipped": list(skipped.values()), "before": _counts(before), "after": _counts(after)}


def _fix_rpa(filename: str, content: dict, policy: dict | None, kind: str) -> dict:
    """RPA files: plain-HTTP addresses become https, and UiPath dependency minimums become exact [versions]. Nothing else is guessed."""
    before = dispatch.scan_any(filename, copy.deepcopy(content), policy)
    fixed = copy.deepcopy(content)
    applied = []
    if kind == "uipath-project":
        for pkg, ver in list((fixed.get("dependencies") or {}).items()):
            if re.fullmatch(r"\d+(\.\d+){1,3}([-+][\w.]+)?", str(ver).strip()):
                fixed["dependencies"][pkg] = f"[{str(ver).strip()}]"
                applied.append({"ruleId": "UIP-PRJ-001", "title": "Project dependencies not pinned to an exact version",
                                "location": "flow", "change": f"{pkg}: {ver} -> [{str(ver).strip()}]"})
    else:
        fixed["text"], changed = rpascan.autofix_http(fixed["text"])
        applied += [{"ruleId": "RPA-NET-001", "title": "Unencrypted HTTP address", "location": "flow",
                     "change": f"{u} -> https://{u[7:]} (check the service accepts HTTPS)"} for u in changed]
    skipped: dict = {}
    fixed_rules = {a["ruleId"] for a in applied}
    for f in before["findings"]:
        if f["ruleId"] in fixed_rules and f["ruleId"] in ("RPA-NET-001",):
            continue
        why = "this fix needs a decision from you; see How to fix"
        sk = skipped.setdefault((f["ruleId"], why), {"ruleId": f["ruleId"], "title": f["title"], "reason": why, "count": 0})
        sk["count"] += 1
    after = dispatch.scan_any(filename, copy.deepcopy(fixed), policy)
    return {"content": fixed, "applied": applied, "skipped": list(skipped.values()), "before": _counts(before), "after": _counts(after)}


def fix_flow(filename: str, content: dict, policy: dict | None = None) -> dict:
    kind = agentscan.kind_of(content)
    if kind:
        return _fix_agent(filename, content, policy, kind)
    rkind = rpascan.kind_of(content)
    if rkind:
        return _fix_rpa(filename, content, policy, rkind)
    before = scanner.scan_flow(normalize(filename, copy.deepcopy(content)), policy)
    fixed = copy.deepcopy(content)
    defn = locate_definition(fixed)
    applied, skipped = [], {}
    for f in before["findings"]:
        loc = f["location"]
        action = _action(defn, loc.split(":", 1)[1]) if loc.startswith("action:") else None
        handler = HANDLERS.get(f["ruleId"])
        if handler and action is not None:
            change, why = handler(action)
            if change:
                applied.append({"ruleId": f["ruleId"], "title": f["title"], "location": loc, "change": change})
                continue
        else:
            why = "this fix needs a decision from you; see How to fix" if not handler else "the action was not found"
        s = skipped.setdefault((f["ruleId"], why), {"ruleId": f["ruleId"], "title": f["title"], "reason": why, "count": 0})
        s["count"] += 1
    after = scanner.scan_flow(normalize(filename, copy.deepcopy(fixed)), policy)
    return {"content": fixed, "applied": applied, "skipped": list(skipped.values()),
            "before": _counts(before), "after": _counts(after)}

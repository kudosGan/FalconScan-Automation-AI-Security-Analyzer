"""Custom rules: words or phrases a person decides must not appear in an automation file (for example an internal server name).

They are plain text matches, not patterns, so a rule can never make the server hang. The matched text is never copied into the
finding, because it may be a secret: the finding only says how many times it was found.
"""
import re

import scanner

SEVERITIES = ("High", "Medium", "Low")
MAX_RULES = 50
MAX_TEXT = 200
_ID = re.compile(r"CUS-\d{3}")


def clean(rules) -> list[dict]:
    """Return at most 50 valid rules. A rule keeps its id so triage decisions stay attached when others are added or removed."""
    out: list[dict] = []
    used: set[str] = set()
    pending: list[dict] = []
    for r in (rules or [])[: MAX_RULES * 2]:
        if not isinstance(r, dict):
            continue
        text = str(r.get("text") or "").strip()[:MAX_TEXT]
        if not text:
            continue
        item = {"id": "", "title": str(r.get("title") or "").strip()[:120] or "Custom rule",
                "severity": r.get("severity") if r.get("severity") in SEVERITIES else "Medium",
                "text": text, "fix": str(r.get("fix") or "").strip()[:500], "enabled": r.get("enabled", True) is not False}
        rid = str(r.get("id") or "")
        if _ID.fullmatch(rid) and rid not in used:
            item["id"] = rid
            used.add(rid)
        pending.append(item)
    n = 0
    for item in pending[:MAX_RULES]:
        if not item["id"]:
            while f"CUS-{n:03d}" in used or n == 0:
                n += 1
            item["id"] = f"CUS-{n:03d}"
            used.add(item["id"])
        out.append(item)
    return out


def _strings(o, depth: int = 0):
    if depth > 60:
        return
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v, depth + 1)


def apply(result: dict, content, rules) -> dict:
    """Add a finding for every enabled rule whose text appears in the file, and update the risk and score."""
    active = [r for r in clean(rules) if r["enabled"]]
    if not active or result.get("error"):
        return result
    haystack = "\n".join(_strings(content)).lower()
    base = str(result.get("flowId", ""))
    added = []
    for r in active:
        n = haystack.count(r["text"].lower())
        if not n:
            continue
        added.append({
            "severity": r["severity"], "ruleId": r["id"], "title": r["title"],
            "detail": f"Custom rule {r['id']}: the text you listed was found {n} time(s) in this file. The text itself is not repeated here.",
            "location": "flow", "jsonPath": [], "fix": [r["fix"]] if r["fix"] else [], "alternative": None, "example": None,
            "cwe": None, "owasp": None, "category": "Custom rules", "fingerprint": "|".join([base, r["id"], "flow", ""])})
    if not added:
        return result
    result["findings"] = [*result.get("findings", []), *added]
    for s in result.get("steps", []):
        if s.get("id") == "flow:config":
            s["findings"] = [*s.get("findings", []), *added]
            break
    score = sum(scanner.SEV_WEIGHT[f["severity"]] for f in result["findings"])
    result["score"] = score
    result["risk"] = "High" if any(f["severity"] == "High" for f in result["findings"]) or score >= 12 else "Medium" if score >= 4 else "Low"
    return result

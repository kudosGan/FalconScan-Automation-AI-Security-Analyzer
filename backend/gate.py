"""Release gate: decide whether a set of scanned flows may move on to production.

The gate fails when any finding at or above `failOn` is not covered by a valid waiver.
A waiver needs a rule, a reason and an expiry date. Expired or incomplete waivers do not apply.
"""
from datetime import date

import dispatch

RANK = {"Low": 1, "Medium": 2, "High": 3}
GATE_KEYS = {"failOn", "waivers"}


def failon_rank(level: str | None) -> int:
    """Rank a failOn setting. 'none' (or null) never fails the gate."""
    if level in (None, "", "none", "None"):
        return 99
    if level not in RANK:
        raise ValueError(f"failOn must be High, Medium, Low or none (got {level!r})")
    return RANK[level]


def scan_items(items: list[dict], policy: dict | None) -> list[dict]:
    """Scan [{file, content}] with the scan part of the policy. A file that is not a flow becomes an error result."""
    scan_policy = {k: v for k, v in (policy or {}).items() if k not in GATE_KEYS}
    out = []
    for it in items:
        try:
            r = dispatch.scan_any(it["file"], it["content"], scan_policy)
        except Exception as e:   # one bad file must not hide the rest
            r = {"flowId": it["file"], "name": it["file"], "error": str(e), "findings": [],
                 "connectors": [], "risk": "Unknown", "score": 0}
        r["file"] = it["file"]
        out.append(r)
    return out


def _check_waiver(w: dict, today: date) -> tuple[str, str | None]:
    """Return ('ok'|'expired'|'invalid', problem)."""
    if not isinstance(w, dict) or not w.get("ruleId"):
        return "invalid", "a waiver needs a ruleId"
    if not str(w.get("reason", "")).strip():
        return "invalid", "a waiver needs a reason"
    try:
        exp = date.fromisoformat(str(w.get("expires", "")))
    except ValueError:
        return "invalid", "a waiver needs an expiry date as YYYY-MM-DD"
    if exp < today:
        return "expired", f"expired on {exp.isoformat()}"
    return "ok", None


def _matches(w: dict, r: dict, f: dict) -> bool:
    if w["ruleId"] != f["ruleId"]:
        return False
    if w.get("flow") and w["flow"] not in (r.get("name"), r.get("flowId"), r.get("file")):
        return False
    if w.get("location") and w["location"] != f["location"]:
        return False
    return True


def evaluate(results: list[dict], gate: dict | None, today: date | None = None) -> dict:
    gate = gate or {}
    today = today or date.today()
    threshold = failon_rank(gate.get("failOn", "High"))
    waivers, expired, invalid = [], [], []
    for w in gate.get("waivers") or []:
        status, why = _check_waiver(w, today)
        if status == "ok":
            waivers.append(w)
        elif status == "expired":
            expired.append({"waiver": w, "problem": why})
        else:
            invalid.append({"waiver": w, "problem": why})

    blocking, waived, counts = [], [], {"High": 0, "Medium": 0, "Low": 0}
    for r in results:
        for f in r.get("findings", []):
            counts[f["severity"]] += 1
            if RANK[f["severity"]] < threshold:
                continue
            item = {"file": r.get("file"), "flow": r.get("name"), "ruleId": f["ruleId"], "severity": f["severity"],
                    "title": f["title"], "location": f["location"], "detail": f["detail"], "fingerprint": f.get("fingerprint")}
            w = next((w for w in waivers if _matches(w, r, f)), None)
            (waived if w else blocking).append({**item, "waiver": w} if w else item)
    errors = [{"file": r.get("file"), "error": r["error"]} for r in results if r.get("error")]
    return {"passed": not blocking, "failOn": gate.get("failOn", "High"), "counts": counts,
            "blocking": blocking, "waived": waived, "expiredWaivers": expired, "invalidWaivers": invalid, "errors": errors}

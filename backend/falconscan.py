"""Falcon Scan command line: scan flows in a pipeline and fail the build when they are not fit for production.

  python falconscan.py flows/ release.zip --policy gate.json --format sarif --output falcon.sarif
  python falconscan.py flows/ --fail-on Medium --fix-dir fixed/

Exit codes: 0 gate passed, 1 gate failed, 2 bad input (nothing to scan, unreadable policy, unreadable named file).
Policy file (JSON), all keys optional:
  {"failOn": "High", "disabled": ["PA-TRG-002"], "severity": {"PA-GOV-003": "Medium"},
   "dlp": {"business": [], "nonBusiness": [], "blocked": [], "defaultGroup": "nonBusiness"},
   "waivers": [{"ruleId": "PA-ACT-002", "flow": "Nightly export", "location": "action:Call_partner",
                "reason": "Approved partner API", "owner": "j.doe", "expires": "2027-03-31"}]}
"""
import argparse
import json
import pathlib
import sys
from datetime import date

import dispatch
import fixer
import gate
from flowio import extract_solution, locate_definition

RPA_SUFFIXES = tuple(dispatch.RPA_TEXT_EXTENSIONS)
ARCHIVE_SUFFIXES = (".zip", ".nupkg")
from sarif import to_sarif


def collect(paths: list[str]) -> tuple[list[dict], list[str], list[str]]:
    """Return (items, notes, errors). Files found inside a folder that are not flows are skipped with a note."""
    items, notes, errors = [], [], []

    def add_file(p: pathlib.Path, named: bool):
        try:
            if p.suffix.lower() in ARCHIVE_SUFFIXES:
                got = extract_solution(p.read_bytes())
                items.extend({"file": f"{p.name}:{f['filename']}", "content": f["content"]} for f in got["flows"])
                notes.extend(f"{p.name}: skipped {s['file']} ({s['reason']})" for s in got["skipped"])
                if not got["flows"]:
                    (errors if named else notes).append(f"{p}: no cloud flows found in this archive")
            else:
                if p.suffix.lower() in RPA_SUFFIXES:
                    content = dispatch.wrap_text(p.name, p.read_text(encoding="utf-8-sig"))
                else:
                    content = json.loads(p.read_text(encoding="utf-8-sig"))
                if not isinstance(content, dict):
                    raise ValueError("not a flow definition")
                if not dispatch.kind_of(content):
                    locate_definition(content)   # raises ValueError when this is not a flow, MCP, agent or RPA file
                items.append({"file": str(p), "content": content})
        except (OSError, ValueError) as e:
            (errors if named else notes).append(f"{p}: {e}")

    for raw in paths:
        p = pathlib.Path(raw)
        if p.is_dir():
            for q in sorted(p.rglob("*")):
                if q.is_file() and q.suffix.lower() in (".json", ".zip", ".nupkg") + RPA_SUFFIXES:
                    add_file(q, named=False)
        elif p.is_file():
            add_file(p, named=True)
        else:
            errors.append(f"{raw}: not found")
    return items, notes, errors


def text_report(results: list[dict], verdict: dict) -> str:
    lines = []
    for r in results:
        n = len(r.get("findings", []))
        status = "ERROR " + r["error"] if r.get("error") else f"{r['risk']} risk, {n} finding(s)"
        lines.append(f"{r['file']}: {status}")
    lines.append("")
    for b in verdict["blocking"]:
        lines.append(f"  BLOCKING {b['severity']:<6} {b['ruleId']}  {b['flow']}  [{b['location']}]  {b['title']}")
    for w in verdict["waived"]:
        lines.append(f"  waived   {w['severity']:<6} {w['ruleId']}  {w['flow']}  until {w['waiver']['expires']}: {w['waiver']['reason']}")
    for x in verdict["expiredWaivers"] + verdict["invalidWaivers"]:
        lines.append(f"  waiver not applied ({x['problem']}): {json.dumps(x['waiver'])}")
    c = verdict["counts"]
    lines.append(f"\nFindings: {c['High']} High, {c['Medium']} Medium, {c['Low']} Low. Gate fails on {verdict['failOn']} or worse.")
    lines.append("GATE PASSED" if verdict["passed"] else f"GATE FAILED: {len(verdict['blocking'])} blocking finding(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="falconscan", description="Scan Power Automate flows and gate a release.")
    ap.add_argument("paths", nargs="+", help="flow .json files, solution .zip files, or folders")
    ap.add_argument("--policy", help="gate / scan policy JSON file")
    ap.add_argument("--fail-on", choices=["High", "Medium", "Low", "none"], help="overrides failOn in the policy")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", help="write the report here instead of the screen")
    ap.add_argument("--fix-dir", help="write corrected copies of flows that have safe automatic fixes into this folder")
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD), for testing waiver expiry")
    a = ap.parse_args(argv)

    policy: dict = {}
    if a.policy:
        try:
            policy = json.loads(pathlib.Path(a.policy).read_text(encoding="utf-8-sig"))
            if not isinstance(policy, dict):
                raise ValueError("policy must be a JSON object")
        except (OSError, ValueError) as e:
            print(f"falconscan: cannot read policy: {e}", file=sys.stderr)
            return 2
    if a.fail_on:
        policy["failOn"] = a.fail_on
    try:
        today = date.fromisoformat(a.today) if a.today else None
        gate.failon_rank(policy.get("failOn", "High"))
    except ValueError as e:
        print(f"falconscan: {e}", file=sys.stderr)
        return 2

    items, notes, errors = collect(a.paths)
    for m in notes:
        print(f"note: {m}", file=sys.stderr)
    for m in errors:
        print(f"error: {m}", file=sys.stderr)
    if errors or not items:
        if not items and not errors:
            print("error: no flow files found", file=sys.stderr)
        return 2

    results = gate.scan_items(items, policy)
    verdict = gate.evaluate(results, policy, today)

    if a.fix_dir:
        out = pathlib.Path(a.fix_dir)
        out.mkdir(parents=True, exist_ok=True)
        for it in items:
            fx = fixer.fix_flow(it["file"], it["content"], {k: v for k, v in policy.items() if k not in gate.GATE_KEYS})
            if fx["applied"]:
                name = "".join(ch if ch.isalnum() or ch in " ._-()" else "_" for ch in pathlib.Path(it["file"].split(":")[-1]).stem)
                (out / f"{name}.fixed.json").write_text(json.dumps(fx["content"], indent=2), encoding="utf-8")
                print(f"note: wrote {name}.fixed.json ({len(fx['applied'])} fix(es) applied)", file=sys.stderr)

    if a.format == "json":
        body = json.dumps({"gate": verdict, "results": results}, indent=2)
    elif a.format == "sarif":
        body = json.dumps(to_sarif(results, {w["fingerprint"]: w["waiver"]["reason"] for w in verdict["waived"] if w.get("fingerprint")}), indent=2)
    else:
        body = text_report(results, verdict)
    if a.output:
        pathlib.Path(a.output).write_text(body, encoding="utf-8")
        print(f"report written to {a.output}", file=sys.stderr)
        if a.format != "text":
            print("GATE PASSED" if verdict["passed"] else f"GATE FAILED: {len(verdict['blocking'])} blocking finding(s)", file=sys.stderr)
    else:
        print(body)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

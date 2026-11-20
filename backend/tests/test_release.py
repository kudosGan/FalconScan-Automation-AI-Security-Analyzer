import copy
import io
import json
import pathlib
import sys
import zipfile
from datetime import date

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
import falconscan
import fixer
import gate
import scanner
from flowio import extract_solution, normalize
from sarif import to_sarif

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def risky_results():
    return gate.scan_items([{"file": "risky-flow.json", "content": load("risky-flow.json")}], None)


# ---- solution zip -------------------------------------------------------------------------------

def make_zip(xml_override: bytes | None = None) -> bytes:
    wf = {"properties": {"connectionReferences": {}, "definition": load("risky-flow.json")["properties"]["definition"]},
          "schemaVersion": "1.0.0.0"}
    xml = ('<ImportExportXml><Workflows><Workflow WorkflowId="{1}" Name="Nightly export"><JsonFileName>/Workflows/Nightly-1234.json</JsonFileName>'
           '<StateCode>1</StateCode></Workflow></Workflows></ImportExportXml>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("customizations.xml", xml_override if xml_override is not None else xml)
        z.writestr("Workflows/Nightly-1234.json", json.dumps(wf))
        z.writestr("Workflows/notes.json", json.dumps({"hello": "world"}))
        z.writestr("Workflows/broken.json", "{not json")
    return buf.getvalue()


def test_solution_zip_yields_named_flows_and_skips_the_rest():
    got = extract_solution(make_zip())
    assert [f["filename"] for f in got["flows"]] == ["Nightly export.json"]
    props = got["flows"][0]["content"]["properties"]
    assert props["displayName"] == "Nightly export" and props["state"] == "Started"
    assert {s["file"] for s in got["skipped"]} == {"Workflows/notes.json", "Workflows/broken.json"}
    r = scanner.scan_flow(normalize("Nightly export.json", got["flows"][0]["content"]))
    assert {"PA-ACT-001", "PA-SEC-001"} <= {f["ruleId"] for f in r["findings"]}


def test_solution_zip_rejects_garbage_and_entity_xml():
    with pytest.raises(ValueError):
        extract_solution(b"not a zip")
    evil = make_zip(b'<!DOCTYPE x [<!ENTITY a "aaaa">]><ImportExportXml><Workflows><Workflow Name="Hijacked"><JsonFileName>/Workflows/Nightly-1234.json</JsonFileName></Workflow></Workflows></ImportExportXml>')
    flows = extract_solution(evil)["flows"]
    assert [f["filename"] for f in flows] == ["Nightly-1234.json"]   # unsafe xml is ignored, the flow is still read


# ---- auto fix -----------------------------------------------------------------------------------

def test_fix_applies_only_safe_fixes_and_rescan_improves():
    original = load("risky-flow.json")
    snapshot = copy.deepcopy(original)
    out = fixer.fix_flow("risky-flow.json", original)
    assert original == snapshot                                   # the input is never changed
    rules = {a["ruleId"] for a in out["applied"]}
    assert "PA-ACT-001" in rules and "PA-CFG-001" in rules
    assert out["after"]["total"] < out["before"]["total"] and out["after"]["High"] < out["before"]["High"]
    assert any(s["ruleId"] == "PA-SEC-001" for s in out["skipped"])   # secrets need a decision, never guessed
    assert "http://" not in json.dumps(out["content"]["properties"]["definition"]["actions"]).lower().replace("https://", "")


def _terminate_flow(run_after: dict) -> dict:
    return {"properties": {"displayName": "t", "definition": {"triggers": {}, "actions": {
        "Stop": {"type": "Terminate", "runAfter": run_after, "inputs": {"runStatus": "Succeeded"}}}}}}


def test_terminate_is_only_fixed_on_an_error_path():
    err = fixer.fix_flow("t.json", _terminate_flow({"Step": ["Failed"]}))
    assert [a["ruleId"] for a in err["applied"]] == ["PA-CFG-002"]
    assert err["content"]["properties"]["definition"]["actions"]["Stop"]["inputs"]["runStatus"] == "Failed"
    ok = fixer.fix_flow("t.json", _terminate_flow({"Step": ["Succeeded"]}))
    assert ok["applied"] == [] and ok["skipped"][0]["ruleId"] == "PA-CFG-002"


# ---- gate ---------------------------------------------------------------------------------------

def test_gate_fails_on_high_and_waivers_need_reason_and_unexpired_date():
    results = risky_results()
    today = date(2026, 11, 20)
    v = gate.evaluate(results, {"failOn": "High"}, today)
    assert not v["passed"] and v["blocking"]
    assert gate.evaluate(results, {"failOn": "none"}, today)["passed"]

    waivers = [{"ruleId": b["ruleId"], "reason": "accepted by security", "owner": "x", "expires": "2027-01-01"} for b in v["blocking"]]
    ok = gate.evaluate(results, {"failOn": "High", "waivers": waivers}, today)
    assert ok["passed"] and len(ok["waived"]) == len(v["blocking"])

    late = gate.evaluate(results, {"failOn": "High", "waivers": waivers}, date(2027, 6, 1))
    assert not late["passed"] and len(late["expiredWaivers"]) == len(waivers)

    bad = [{"ruleId": "PA-SEC-001", "expires": "2027-01-01"}, {"ruleId": "PA-SEC-001", "reason": "x"}]
    v2 = gate.evaluate(results, {"failOn": "High", "waivers": bad}, today)
    assert not v2["passed"] and len(v2["invalidWaivers"]) == 2


def test_waiver_can_be_limited_to_one_flow_and_location():
    results = risky_results()
    first = gate.evaluate(results, {"failOn": "High"}, date(2026, 11, 20))["blocking"][0]
    w = {"ruleId": first["ruleId"], "flow": "some other flow", "reason": "r", "expires": "2027-01-01"}
    assert not gate.evaluate(results, {"waivers": [w]}, date(2026, 11, 20))["waived"]
    w["flow"] = first["flow"]
    w["location"] = first["location"]
    assert gate.evaluate(results, {"waivers": [w]}, date(2026, 11, 20))["waived"]


def test_failon_value_is_validated():
    with pytest.raises(ValueError):
        gate.evaluate([], {"failOn": "Critical"})


# ---- sarif --------------------------------------------------------------------------------------

def test_sarif_has_rules_results_and_suppressions():
    results = risky_results()
    fp = results[0]["findings"][0]["fingerprint"]
    s = to_sarif(results, {fp: "approved"})
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "Falcon Scan"
    assert len(run["results"]) == len(results[0]["findings"])
    assert {r["ruleId"] for r in run["results"]} <= {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert any("suppressions" in r for r in run["results"]) and all(r["level"] in ("error", "warning", "note") for r in run["results"])


# ---- DLP ----------------------------------------------------------------------------------------

def test_dlp_policy_is_optional_and_checks_blocked_and_mixed_groups():
    flow = normalize("d.json", load("data-exposure-flow.json"))
    plain = scanner.scan_flow(copy.deepcopy(flow))
    assert not [f for f in plain["findings"] if f["ruleId"].startswith("PA-DLP")]
    names = plain["connectors"]
    assert len(names) >= 2

    blocked = scanner.scan_flow(copy.deepcopy(flow), {"dlp": {"blocked": [names[0]]}})
    assert any(f["ruleId"] == "PA-DLP-001" and names[0] in f["detail"] for f in blocked["findings"])

    mixed = scanner.scan_flow(copy.deepcopy(flow), {"dlp": {"business": [names[0]], "nonBusiness": [names[1]]}})
    assert any(f["ruleId"] == "PA-DLP-002" for f in mixed["findings"])

    off = scanner.scan_flow(copy.deepcopy(flow), {"dlp": {"business": [names[0]], "nonBusiness": [names[1]]}, "disabled": ["PA-DLP-002"]})
    assert not any(f["ruleId"] == "PA-DLP-002" for f in off["findings"])


# ---- command line -------------------------------------------------------------------------------

def test_cli_exit_codes_and_outputs(tmp_path, capsys):
    risky, clean = str(SAMPLES / "risky-flow.json"), str(SAMPLES / "clean-flow.json")
    assert falconscan.main([risky]) == 1
    assert "GATE FAILED" in capsys.readouterr().out
    assert falconscan.main([clean]) == 0
    assert falconscan.main([risky, "--fail-on", "none"]) == 0
    assert falconscan.main([str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "policy.json"
    bad.write_text("[1,2]")
    assert falconscan.main([clean, "--policy", str(bad)]) == 2
    capsys.readouterr()

    out = tmp_path / "r.sarif"
    fixed = tmp_path / "fixed"
    assert falconscan.main([risky, "--format", "sarif", "--output", str(out), "--fix-dir", str(fixed)]) == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert (fixed / "risky-flow.fixed.json").exists()


def test_cli_reads_solution_zip_and_skips_non_flows_in_folders(tmp_path, capsys):
    (tmp_path / "solution.zip").write_bytes(make_zip())
    (tmp_path / "package.json").write_text('{"name": "not a flow"}')
    assert falconscan.main([str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "solution.zip:Nightly export.json" in captured.out
    assert "package.json" in captured.err      # skipped with a note, not an error

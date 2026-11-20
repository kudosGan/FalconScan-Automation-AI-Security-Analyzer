import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
import scanner
from main import _normalize

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def scan(name: str) -> dict:
    return scanner.scan_flow(_normalize(name, load(name)))


def rules(result: dict) -> list[str]:
    return sorted(f["ruleId"] for f in result["findings"])


def test_risky_flow_is_high():
    r = scan("risky-flow.json")
    assert r["risk"] == "High"
    assert {"PA-ACT-001", "PA-ACT-003", "PA-SEC-001", "PA-TRG-001"} <= set(rules(r))


def test_clean_flow_only_schedule_note():
    assert rules(scan("clean-flow.json")) == ["PA-TRG-002"]


def test_real_format_flow_detects_each_rule():
    r = scan("real-format-flow.json")
    ids = rules(r)
    assert "PA-TRG-003" in ids          # triggerAuthenticationType: All
    assert "PA-ACT-004" in ids          # personal gmail recipient
    assert "PA-SEC-001" in ids          # literal Basic-auth password
    assert "PA-GOV-003" in ids          # premium SQL connection reference
    assert r["risk"] == "High"


def test_expressions_are_not_flagged_as_secrets():
    r = scan("real-format-flow.json")
    secret_locs = [f["location"] for f in r["findings"] if f["ruleId"] == "PA-SEC-001"]
    assert secret_locs == ["action:Post_to_erp"]   # Safe_call uses @parameters(...)


def test_connectors_come_from_connection_references_and_hosts():
    r = scan("real-format-flow.json")
    assert {"shared_sharepointonline", "shared_office365", "shared_sql"} <= set(r["connectors"])


def test_steps_follow_run_after_order():
    r = scan("real-format-flow.json")
    names = [s["name"] for s in r["steps"]]
    assert names == ["manual", "Get_item", "Notify_accountant", "Post_to_erp", "Safe_call", "Flow configuration"]


def test_every_finding_attached_to_a_step():
    for sample in ("risky-flow.json", "real-format-flow.json", "procurement-approval.json"):
        r = scan(sample)
        assert sum(len(s["findings"]) for s in r["steps"]) == len(r["findings"]), sample


def test_logic_apps_template_is_accepted():
    flow = _normalize("t.json", load("logic-apps-template.json"))
    assert flow["properties"]["definition"]["triggers"]


def test_unknown_shape_is_rejected():
    with pytest.raises(ValueError):
        _normalize("x.json", {"hello": "world"})


def test_metadata_fields():
    m = scan("real-format-flow.json")["metadata"]
    assert m["Flow name"] == "Invoice Intake (real export format)"
    assert m["Type"] == "Instant"
    assert m["Actions"] == 4 and m["Connectors"] == 3
    assert m["Premium connectors"] == "shared_sql"
    assert scan("daily-report.json")["metadata"]["Type"] == "Scheduled"


def test_every_finding_has_fix_guidance():
    for sample in ("risky-flow.json", "real-format-flow.json", "procurement-approval.json",
                   "employee-onboarding.json", "daily-report.json"):
        for f in scan(sample)["findings"]:
            assert f["fix"], f"{f['ruleId']} has no fix text"
    assert all(r in scanner.FIXES for r in ("PA-TRG-001", "PA-ACT-001", "PA-SEC-001", "PA-CFG-001"))


def test_every_rule_has_an_alternative_and_high_rules_are_detailed():
    for rule in scanner.FIXES:
        alt = scanner.ALTERNATIVES.get(rule)
        assert alt and alt["title"] and alt["steps"], f"{rule} has no alternative fix"
    for rule in ("PA-ACT-001", "PA-SEC-001"):          # High rules that are a concrete edit
        ex = scanner.EXAMPLES[rule]
        assert ex["before"] != ex["after"]
    f = next(x for x in scan("risky-flow.json")["findings"] if x["ruleId"] == "PA-ACT-001")
    assert f["alternative"]["steps"] and f["example"]["after"].startswith('"uri": "https://')


def test_connection_analysis_classifies_publisher_and_ai():
    r = scan("data-exposure-flow.json")
    by = {s["name"]: s["connection"] for s in r["steps"] if s.get("connection")}
    assert by["Get_case_record"]["publisher"] == "Microsoft" and by["Get_case_record"]["sensitivity"] == "High"
    assert "Item metadata" in " ".join(by["Get_case_record"]["dataTypes"])
    assert by["Post_to_Slack"]["thirdParty"] and not by["Post_to_Slack"]["ai"]
    assert by["Ask_OpenAI"]["ai"]["provider"] == "OpenAI" and not by["Ask_OpenAI"]["ai"]["microsoft"]
    assert by["Call_summariser_api"]["ai"]["provider"] == "OpenAI"       # plain HTTP to an AI host
    assert by["Run_AI_Builder_prompt"]["ai"]["microsoft"]
    assert by["When_a_new_email_arrives"]["name"] == "Office 365 Outlook"


def test_data_flow_traced_through_compose_and_expressions():
    r = scan("data-exposure-flow.json")
    flows = {(f["from"], f["to"]) for f in r["dataFlows"]}
    assert ("Get_case_record", "Post_to_Slack") in flows             # direct reference
    assert ("Get_case_record", "Ask_OpenAI") in flows                # via the Compose step
    assert ("When_a_new_email_arrives", "Ask_OpenAI") in flows       # via triggerBody()
    ids = rules(r)
    assert "PA-CON-001" in ids and "PA-AI-001" in ids
    ai_high = [f for f in r["findings"] if f["ruleId"] == "PA-AI-001" and f["severity"] == "High"]
    assert ai_high and r["risk"] == "High"


def test_no_data_flow_without_a_reference():
    r = scan("clean-flow.json")
    assert r["dataFlows"] == [] and "PA-CON-001" not in rules(r)


def test_metadata_reports_third_party_and_ai():
    m = scan("data-exposure-flow.json")["metadata"]
    assert "Slack" in m["Third-party connectors"] and "OpenAI" in m["AI services"]
    assert m["Highest data sensitivity"] == "High"
    assert m["Owner"] == "maker@contoso.com"


ALL_SAMPLES = ("risky-flow.json", "employee-onboarding.json", "procurement-approval.json", "daily-report.json",
               "real-format-flow.json", "data-exposure-flow.json", "clean-flow.json")


def test_every_emitted_rule_is_in_the_catalog_with_standards():
    from rules import BY_ID
    for sample in ALL_SAMPLES:
        for f in scan(sample)["findings"]:
            assert f["ruleId"] in BY_ID, f["ruleId"]
            assert f["category"] and f["fingerprint"].count("|") == 3
    sec = next(f for f in scan("risky-flow.json")["findings"] if f["ruleId"] == "PA-SEC-001")
    assert sec["cwe"] == "CWE-798" and sec["owasp"].startswith("A07")


def test_policy_disables_rules_and_overrides_severity():
    flow = _normalize("risky-flow.json", load("risky-flow.json"))
    base = scanner.scan_flow(flow)
    off = scanner.scan_flow(flow, {"disabled": ["PA-SEC-001", "PA-ACT-001"]})
    assert "PA-SEC-001" not in rules(off) and len(off["findings"]) < len(base["findings"])
    assert sum(len(s["findings"]) for s in off["steps"]) == len(off["findings"])      # steps stay consistent
    low = scanner.scan_flow(flow, {"severity": {r: "Low" for r in ("PA-SEC-001", "PA-ACT-001", "PA-TRG-001",
                                   "PA-ACT-002", "PA-ACT-003", "PA-CFG-001", "PA-TRG-003")}})
    assert all(f["severity"] == "Low" for f in low["findings"])                       # overrides applied
    assert low["risk"] != "High"                                                       # no High finding left
    junk = scanner.scan_flow(flow, {"disabled": ["NOPE"], "severity": {"PA-SEC-001": "Banana"}})
    assert len(junk["findings"]) == len(base["findings"])                              # bad policy input ignored


def test_fingerprint_is_stable_between_scans():
    a = {f["fingerprint"] for f in scan("risky-flow.json")["findings"]}
    b = {f["fingerprint"] for f in scan("risky-flow.json")["findings"]}
    assert a == b and len(a) == len(scan("risky-flow.json")["findings"])


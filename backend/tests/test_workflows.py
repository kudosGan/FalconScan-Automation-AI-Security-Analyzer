import json
import pathlib

import pytest

import dispatch
import rules
import workflowscan

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def ids(res):
    return {f["ruleId"] for f in res["findings"]}


def test_files_are_recognised_and_routed():
    assert dispatch.kind_of(load("n8n-risky.json")) == "n8n"
    assert dispatch.kind_of(load("make-risky.json")) == "Make"
    for other in ("risky-flow.json", "ai-agent-risky.json", "mcp-config-risky.json", "uipath-project.json"):
        assert workflowscan.kind_of(load(other)) is None, other
    assert dispatch.scan_any("n8n-risky.json", load("n8n-risky.json"))["metadata"]["Platform"] == "n8n"


def test_n8n_risky_workflow_findings():
    res = workflowscan.scan_workflow("n8n-risky.json", load("n8n-risky.json"))
    assert ids(res) >= {"WF-TRG-001", "WF-SEC-001", "WF-NET-001", "WF-NET-002", "WF-INJ-001", "WF-AI-001", "WF-CODE-001", "WF-CFG-001",
                        "WF-CFG-002", "WF-CFG-003"}
    assert res["risk"] == "High" and res["triggerCount"] == 1
    assert "8f3a91c27d4e45b0a6c1d2e3f4a5b6c7" not in json.dumps(res)          # the secret never reaches the result


def test_make_risky_scenario_findings():
    res = workflowscan.scan_workflow("make-risky.json", load("make-risky.json"))
    assert ids(res) >= {"WF-TRG-002", "WF-SEC-001", "WF-NET-001", "WF-NET-002", "WF-INJ-001", "WF-AI-001", "WF-CFG-001"}
    assert "k9Zp2QvT7mRw4XbN8cLd" not in json.dumps(res)
    assert any(s["id"].startswith("module:6") for s in res["steps"])           # a module inside a router route is scanned too


def test_clean_n8n_workflow_has_no_findings():
    res = workflowscan.scan_workflow("n8n-clean.json", load("n8n-clean.json"))
    assert res["findings"] == [] and res["risk"] == "Low"


def test_webhook_with_authentication_is_not_flagged():
    wf = load("n8n-risky.json")
    wf["nodes"][0]["parameters"]["authentication"] = "headerAuth"
    assert "WF-TRG-001" not in ids(workflowscan.scan_workflow("x.json", wf))


def test_policy_can_switch_a_rule_off():
    res = workflowscan.scan_workflow("n8n-risky.json", load("n8n-risky.json"), {"disabled": ["WF-AI-001"]})
    assert "WF-AI-001" not in ids(res)


def test_every_workflow_rule_is_in_the_catalog_with_a_category():
    used = {f["ruleId"] for n in ("n8n-risky.json", "make-risky.json") for f in workflowscan.scan_workflow(n, load(n))["findings"]}
    for rid in used:
        assert rid in rules.BY_ID and rules.BY_ID[rid]["lcnc"].startswith("LCNC-SEC-")


def test_unrecognised_input_is_refused():
    with pytest.raises(ValueError):
        workflowscan.scan_workflow("x.json", {"hello": "world"})

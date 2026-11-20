import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import customrules
import dispatch
import gate
import main
import store
from sarif import to_sarif

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
AGENT = json.loads((SAMPLES / "ai-agent-clean.json").read_text(encoding="utf-8"))


def rule(text="corp-sql-01", **kw):
    return {"title": "Internal server name", "severity": "High", "text": text, "fix": "Use the environment variable instead.", **kw}


def scan(rules, content=None):
    return dispatch.scan_any("agent.json", content or AGENT, {"custom": rules})


def test_a_listed_text_that_is_in_the_file_becomes_a_finding():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "connects to CORP-SQL-01 nightly"
    r = scan([rule()], content)
    f = [x for x in r["findings"] if x["ruleId"].startswith("CUS-")]
    assert len(f) == 1 and f[0]["severity"] == "High" and f[0]["title"] == "Internal server name"
    assert f[0]["fix"] == ["Use the environment variable instead."]
    assert r["risk"] == "High"


def test_the_finding_never_repeats_the_matched_text():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "password is hunter2-secret"
    r = scan([rule("hunter2-secret")], content)
    assert "hunter2-secret" not in json.dumps([x for x in r["findings"] if x["ruleId"].startswith("CUS-")])


def test_a_file_without_the_text_gets_no_custom_finding():
    assert not [x for x in scan([rule("not-in-this-file-xyz")])["findings"] if x["ruleId"].startswith("CUS-")]


def test_the_rule_is_plain_text_not_a_pattern():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "abc"
    assert not [x for x in scan([rule(".*")], content)["findings"] if x["ruleId"].startswith("CUS-")]
    content["notes"] = "a literal .* here"
    assert [x for x in scan([rule(".*")], content)["findings"] if x["ruleId"].startswith("CUS-")]


def test_the_finding_is_attached_to_a_step_so_the_screen_can_list_it():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "corp-sql-01"
    r = scan([rule()], content)
    step = next(s for s in r["steps"] if s["id"] == "flow:config")
    assert any(x["ruleId"].startswith("CUS-") for x in step["findings"])


def test_a_switched_off_rule_does_nothing():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "corp-sql-01"
    assert not [x for x in scan([rule(enabled=False)], content)["findings"] if x["ruleId"].startswith("CUS-")]


def test_bad_rules_are_dropped_and_the_list_is_capped():
    cleaned = customrules.clean([{"text": ""}, "nope", {"text": "x" * 500}, *[{"text": f"t{i}"} for i in range(80)]])
    assert len(cleaned) == customrules.MAX_RULES
    assert len(cleaned[0]["text"]) == customrules.MAX_TEXT
    assert len({c["id"] for c in cleaned}) == len(cleaned)


def test_ids_stay_with_their_rule_when_another_is_removed():
    first = customrules.clean([rule("a"), rule("b"), rule("c")])
    kept = customrules.clean([first[0], first[2]])
    assert [k["id"] for k in kept] == [first[0]["id"], first[2]["id"]]
    again = customrules.clean([first[0], first[2], rule("d")])
    assert again[2]["id"] not in {first[0]["id"], first[2]["id"]}


def test_a_flow_file_is_covered_too():
    flow = {"properties": {"displayName": "Demo", "definition": {"triggers": {}, "actions": {"a": {"type": "Compose", "inputs": "corp-sql-01"}}}}}
    r = dispatch.scan_any("demo.json", flow, {"custom": [rule()]})
    assert any(x["ruleId"].startswith("CUS-") for x in r["findings"])


def test_the_policy_is_saved_with_its_custom_rules(isolated_db):
    saved = store.set_policy({"name": "X", "custom": [rule()]})
    assert saved["custom"][0]["text"] == "corp-sql-01"
    assert store.get_policy()["custom"][0]["id"] == saved["custom"][0]["id"]


def test_the_release_gate_and_sarif_accept_custom_rules():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "corp-sql-01"
    results = gate.scan_items([{"file": "agent.json", "content": content}], {"custom": [rule()], "failOn": "High"})
    verdict = gate.evaluate(results, {"failOn": "High"})
    assert verdict["passed"] is False
    assert "CUS-001" in json.dumps(to_sarif(results, verdict))


def test_the_upload_endpoint_applies_custom_rules():
    content = json.loads(json.dumps(AGENT))
    content["notes"] = "corp-sql-01"
    body = {"files": [{"filename": "a.json", "content": content}], "policy": {"custom": [rule()]}}
    r = TestClient(main.app).post("/scan/upload", json=body).json()["results"][0]
    assert any(x["ruleId"] == "CUS-001" for x in r["findings"])

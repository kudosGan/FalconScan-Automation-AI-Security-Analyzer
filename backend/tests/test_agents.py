import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

import agentscan
import falconscan
import fixer
import gate
import main
from rules import RULES
from sarif import to_sarif

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def load(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def rules_of(result: dict) -> set[str]:
    return {f["ruleId"] for f in result["findings"]}


def mcp(**server) -> dict:
    return {"mcpServers": {"s": server}}


# ---- recognising the file ------------------------------------------------------------------------

def test_files_are_recognised_without_confusing_flows_and_agents():
    assert agentscan.kind_of(load("mcp-config-risky.json")) == "mcp"
    assert agentscan.kind_of(load("ai-agent-risky.json")) == "agent"
    assert agentscan.kind_of({"servers": {"x": {"type": "http", "url": "https://a.example.com/mcp"}}}) == "mcp"      # VS Code
    assert agentscan.kind_of({"mcp": {"servers": {"x": {"command": "node", "args": ["a.js"]}}}}) == "mcp"
    for flow in ("risky-flow.json", "logic-apps-template.json", "manifest.json"):
        assert agentscan.kind_of(load(flow)) is None
    assert agentscan.kind_of({"hello": "world"}) is None
    with pytest.raises(ValueError, match="MCP"):
        agentscan.scan_any("x.json", {"hello": "world"})


# ---- what the samples should raise ---------------------------------------------------------------

def test_risky_mcp_config_raises_the_expected_rules_and_hides_the_secret():
    r = agentscan.scan_any("mcp-config-risky.json", load("mcp-config-risky.json"))
    assert {"AG-SEC-001", "AG-MCP-001", "AG-MCP-002", "AG-MCP-003", "AG-MCP-004", "AG-MCP-005", "AG-MCP-006", "AG-MCP-007", "AG-MCP-008"} <= rules_of(r)
    assert r["risk"] == "High"
    blob = json.dumps(r)
    assert "ghp_EXAMPLE" not in blob                      # not in steps, details or anywhere else in the result
    assert any(s["name"] == "github" and s["findings"] for s in r["steps"])
    pinned = next(f for f in r["findings"] if f["ruleId"] == "AG-MCP-005")
    assert pinned["location"] == "action:files"           # the pinned filesystem server is still flagged for its path


def test_risky_agent_raises_the_expected_rules_and_hides_the_secret():
    r = agentscan.scan_any("ai-agent-risky.json", load("ai-agent-risky.json"))
    assert {"AG-SEC-001", "AG-LLM-002", "AG-LLM-001", "AG-AGT-001", "AG-AGT-002", "AG-AGT-003", "AG-AGT-004",
            "AG-AGT-005", "AG-AGT-006", "AG-A2A-001", "AG-MCP-002"} <= rules_of(r)
    assert "sk-live-EXAMPLE" not in json.dumps(r)
    injection = next(f for f in r["findings"] if f["ruleId"] == "AG-AGT-004")
    assert injection["severity"] == "High"                # untrusted content plus code execution


def test_clean_agent_has_no_findings():
    r = agentscan.scan_any("ai-agent-clean.json", load("ai-agent-clean.json"))
    assert r["findings"] == [] and r["risk"] == "Low"


# ---- things that must NOT be flagged -------------------------------------------------------------

@pytest.mark.parametrize("cfg", [
    {"command": "node", "args": ["server.js"], "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}},
    {"command": "node", "args": ["server.js"], "env": {"API_KEY": "<your-api-key>"}},
    {"command": "node", "args": ["server.js"], "env": {"API_KEY": "your-key-here"}},
    {"url": "https://tools.example.com/mcp", "headers": {"Authorization": "Bearer ${input:token}"}},
    {"url": "https://tools.example.com/mcp?key=${KEY}", "headers": {"x-api-key": "${env:KEY}"}},
    {"command": "node", "args": ["server.js"], "env": {"token_url": "https://login.example.com/oauth/token"}},
    {"command": "docker", "args": ["run", "-i", "--rm", "-e", "API_TOKEN", "example/mcp:1.2.3"]},
])
def test_references_and_placeholders_are_not_secrets(cfg):
    assert "AG-SEC-001" not in rules_of(agentscan.scan_any("c.json", mcp(**cfg)))


def test_local_servers_and_authenticated_remote_servers_are_not_flagged():
    local = rules_of(agentscan.scan_any("c.json", mcp(url="http://localhost:8080/mcp")))
    assert not local & {"AG-MCP-001", "AG-MCP-002"}
    authed = rules_of(agentscan.scan_any("c.json", mcp(url="https://tools.example.com/mcp", headers={"Authorization": "Bearer ${env:T}"})))
    assert not authed & {"AG-MCP-001", "AG-MCP-002"}


# ---- details of individual checks ----------------------------------------------------------------

@pytest.mark.parametrize("base,spec,pinned", [
    ("npx", "@scope/pkg@1.2.3", True), ("npx", "@scope/pkg", False), ("npx", "pkg@latest", False), ("npx", "pkg", False),
    ("npx", "pkg@^1.2.3", False), ("uvx", "pkg==1.2.3", True), ("uvx", "pkg", False), ("uvx", "pkg@1.2.3", True),
    ("docker", "img:1.2", True), ("docker", "img:latest", False), ("docker", "img", False), ("docker", "reg.io/a/img@sha256:abc", True),
])
def test_version_pinning(base, spec, pinned):
    assert agentscan._pinned(base, spec) is pinned


def test_secret_passed_as_a_command_line_argument_is_found_and_hidden():
    r = agentscan.scan_any("c.json", mcp(command="node", args=["s.js", "--api-key", "abcdef123456XYZ"]))
    assert "AG-SEC-001" in rules_of(r) and "abcdef123456XYZ" not in json.dumps(r)
    r = agentscan.scan_any("c.json", mcp(command="docker", args=["run", "-e", "GITHUB_TOKEN=abcdef123456XYZ", "img:1.0"]))
    assert "AG-SEC-001" in rules_of(r) and "abcdef123456XYZ" not in json.dumps(r)


def test_unconstrained_input_only_when_no_limits_are_given():
    def agent(props):
        return {"name": "a", "model": "m", "instructions": "x", "tools": [{"type": "function", "function": {
            "name": "t", "description": "d", "parameters": {"type": "object", "properties": props}}}]}
    assert "AG-AGT-003" in rules_of(agentscan.scan_any("a.json", agent({"command": {"type": "string"}})))
    assert "AG-AGT-003" not in rules_of(agentscan.scan_any("a.json", agent({"command": {"type": "string", "enum": ["a", "b"]}})))
    assert "AG-AGT-003" not in rules_of(agentscan.scan_any("a.json", agent({"title": {"type": "string"}})))


def test_policy_can_switch_agent_rules_off_and_change_severity():
    c = load("mcp-config-risky.json")
    r = agentscan.scan_any("c.json", c, {"disabled": ["AG-MCP-003"], "severity": {"AG-MCP-008": "High"}})
    assert "AG-MCP-003" not in rules_of(r)
    assert next(f for f in r["findings"] if f["ruleId"] == "AG-MCP-008")["severity"] == "High"


def test_every_ai_rule_has_guidance_and_is_in_the_catalog():
    ids = {r["id"] for r in RULES if r["id"].startswith("AG-")}
    assert ids == set(agentscan.FIXES) == set(agentscan.ALTERNATIVES)
    for r in agentscan.scan_any("a.json", load("ai-agent-risky.json"))["findings"] + agentscan.scan_any("m.json", load("mcp-config-risky.json"))["findings"]:
        assert r["ruleId"] in ids | {x["id"] for x in RULES} and r["fix"] and r["cwe"] and r["owasp"]


# ---- fixes ---------------------------------------------------------------------------------------

def test_fixer_applies_only_safe_changes_to_mcp_config():
    original = load("mcp-config-risky.json")
    snapshot = copy.deepcopy(original)
    out = fixer.fix_flow("mcp-config-risky.json", original)
    assert original == snapshot
    assert {"AG-MCP-001", "AG-MCP-007", "AG-MCP-008"} <= {a["ruleId"] for a in out["applied"]}
    servers = out["content"]["mcpServers"]
    assert servers["partner-tools"]["url"].startswith("https://")
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in servers["helper"].get("env", {}) and "autoApprove" not in servers["db"]
    assert out["after"]["total"] < out["before"]["total"]
    assert any(s["ruleId"] == "AG-SEC-001" for s in out["skipped"])        # secrets still need a person


def test_fixer_tightens_agent_approval_and_urls():
    out = fixer.fix_flow("ai-agent-risky.json", load("ai-agent-risky.json"))
    crm = next(t for t in out["content"]["tools"] if t.get("server_label") == "crm")
    assert crm["require_approval"] == "always"
    assert out["after"]["High"] <= out["before"]["High"] and out["after"]["total"] < out["before"]["total"]


# ---- through the rest of the app -----------------------------------------------------------------

def test_gate_handles_a_mix_of_flows_and_ai_files():
    items = [{"file": n, "content": load(n)} for n in ("risky-flow.json", "mcp-config-risky.json", "ai-agent-clean.json")]
    results = gate.scan_items(items, None)
    assert [bool(r["findings"]) for r in results] == [True, True, False] and not any(r.get("error") for r in results)
    verdict = gate.evaluate(results, {"failOn": "High"})
    assert not verdict["passed"] and {b["file"] for b in verdict["blocking"]} == {"risky-flow.json", "mcp-config-risky.json"}
    assert gate.evaluate(results[2:], {"failOn": "Low"})["passed"]


def test_upload_endpoint_accepts_ai_files_and_catalog_lists_them():
    client = TestClient(main.app)
    files = [{"filename": n, "content": load(n)} for n in ("mcp-config-risky.json", "ai-agent-risky.json", "risky-flow.json")]
    body = client.post("/scan/upload", json={"files": files}).json()
    assert [r["name"] for r in body["results"]] == ["mcp-config-risky", "Support Assistant", "Risky Demo Flow"]
    assert all(r["steps"] and r["findings"] for r in body["results"])
    assert {r["id"] for r in client.get("/rules").json()} >= {"AG-SEC-001", "AG-AGT-004", "AG-A2A-001"}
    assert next(p for p in client.get("/platforms").json() if p["id"] == "ai-agents")["status"] == "active"
    assert client.post("/fix", json={"filename": "m.json", "content": load("mcp-config-risky.json")}).json()["applied"]


def test_sarif_and_cli_cover_ai_files(tmp_path, capsys):
    results = gate.scan_items([{"file": "a.json", "content": load("ai-agent-risky.json")}], None)
    sarif = to_sarif(results)
    ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"AG-SEC-001", "AG-AGT-004"} <= ids and any(r["ruleId"] == "AG-AGT-004" for r in sarif["runs"][0]["results"])
    assert falconscan.main([str(SAMPLES / "mcp-config-risky.json")]) == 1
    assert falconscan.main([str(SAMPLES / "ai-agent-clean.json")]) == 0
    fixed = tmp_path / "fixed"
    assert falconscan.main([str(SAMPLES / "ai-agent-risky.json"), "--fix-dir", str(fixed)]) == 1
    assert (fixed / "ai-agent-risky.fixed.json").exists()

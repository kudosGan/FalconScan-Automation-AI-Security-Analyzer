import copy
import io
import json
import pathlib
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

import dispatch
import falconscan
import fixer
import gate
import main
import rpascan
from flowio import extract_solution
from rules import RULES
from sarif import to_sarif

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
XAML_HEAD = ('<Activity x:Class="T" xmlns="http://schemas.microsoft.com/netfx/2009/xaml/activities" '
             'xmlns:ui="http://schemas.uipath.com/workflow/activities" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">')


def sample_text(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def xaml(body: str, name: str = "T.xaml") -> dict:
    return dispatch.wrap_text(name, f'{XAML_HEAD}<Sequence DisplayName="S">{body}</Sequence></Activity>')


def project() -> dict:
    return json.loads(sample_text("uipath-project.json"))


def rules_of(r: dict) -> set[str]:
    return {f["ruleId"] for f in r["findings"]}


# ---- recognising files -----------------------------------------------------------------------------

def test_files_are_recognised_by_what_they_are():
    assert dispatch.kind_of(project()) == "uipath-project"
    assert dispatch.kind_of(dispatch.wrap_text("Main.xaml", "<Activity/>")) == "uipath-xaml"
    assert dispatch.kind_of(dispatch.wrap_text("a.bot", "{}")) == "automation-anywhere"
    assert dispatch.kind_of(dispatch.wrap_text("a.atmx", "<x/>")) == "automation-anywhere"
    assert dispatch.kind_of(dispatch.wrap_text("r.bprelease", "<x/>")) == "blue-prism"
    assert dispatch.kind_of(dispatch.wrap_text("e.xml", "<r xmlns='http://www.blueprism.co.uk/product/release'/>")) == "blue-prism"
    assert dispatch.kind_of(dispatch.wrap_text("e.xml", "<r/>")) is None
    # an ordinary package.json must not be mistaken for a UiPath project
    assert dispatch.kind_of({"name": "x", "main": "index.js", "dependencies": {"left-pad": "1.0.0"}}) is None
    for other in ("risky-flow.json", "mcp-config-risky.json", "ai-agent-risky.json"):
        assert rpascan.kind_of(json.loads(sample_text(other))) is None
    with pytest.raises(ValueError, match="RPA"):
        dispatch.scan_any("x.json", {"hello": "world"})


def test_dispatch_still_scans_flows_and_agents():
    assert dispatch.scan_any("risky-flow.json", json.loads(sample_text("risky-flow.json")))["findings"]
    assert dispatch.scan_any("a.json", json.loads(sample_text("ai-agent-risky.json")))["metadata"]["Type"] == "AI agent"


# ---- UiPath workflow --------------------------------------------------------------------------------

def test_risky_workflow_raises_the_expected_rules_and_hides_secrets():
    r = dispatch.scan_any("uipath-Main.xaml", dispatch.wrap_text("uipath-Main.xaml", sample_text("uipath-Main.xaml")))
    assert rules_of(r) == {"RPA-SEC-001", "RPA-NET-001", "RPA-CODE-001", "RPA-CODE-002", "UIP-DB-001", "UIP-LOG-001"}
    assert sum(f["ruleId"] == "RPA-SEC-001" for f in r["findings"]) == 3         # variable, assignment, connection string
    assert r["risk"] == "High" and r["metadata"]["Platform"] == "UiPath"
    blob = json.dumps(r)
    assert not any(x in blob for x in ("Summer2024", "Winter2024", "sk-live-EXAMPLE"))
    assert {"Call partner API", "Connect to HR database", "Find user"} <= {s["name"] for s in r["steps"]}


def test_clean_workflow_has_no_findings():
    r = dispatch.scan_any("uipath-clean.xaml", dispatch.wrap_text("uipath-clean.xaml", sample_text("uipath-clean.xaml")))
    assert r["findings"] == [] and r["risk"] == "Low"


@pytest.mark.parametrize("body", [
    '<Variable x:TypeArguments="x:String" Name="adminPassword" />',                                           # no default
    '<Variable x:TypeArguments="x:String" Default="[strDefault]" Name="adminPassword" />',                    # expression
    '<ui:SendMail DisplayName="m" Password="[strPassword]" />',                                              # variable reference
    '<ui:SendMail DisplayName="m" Password="{x:Null}" />',                                                   # markup extension
    '<ui:HttpClient DisplayName="h" EndPoint="http://localhost:8080/api" />',                                # local address
    '<ui:HttpClient DisplayName="h" EndPoint="https://api.example.com/v1" />',                               # https
    '<ui:DatabaseConnect DisplayName="d" ConnectionString="[&quot;Server=a;Password=&quot; &amp; pw]" />',   # built from a variable
    '<ui:LogMessage DisplayName="l" Level="Info" Message="[&quot;Enter the password in the portal&quot;]" />',   # word only inside text
    '<ui:ExecuteQuery DisplayName="q" Sql="[&quot;SELECT 1&quot;]" />',                                      # no concatenation
    '<ui:LogMessage DisplayName="l" Message="[&quot;Select the user &quot; &amp; name]" />',                 # not a SQL attribute
])
def test_references_and_look_alikes_are_not_flagged(body):
    assert dispatch.scan_any("T.xaml", xaml(body))["findings"] == []


def test_xml_with_entities_or_garbage_is_refused():
    with pytest.raises(ValueError, match="DTD"):
        dispatch.scan_any("T.xaml", dispatch.wrap_text("T.xaml", '<!DOCTYPE a [<!ENTITY x "y">]><Activity/>'))
    with pytest.raises(ValueError, match="valid XML"):
        dispatch.scan_any("T.xaml", dispatch.wrap_text("T.xaml", "<Activity>"))


def test_policy_can_switch_rpa_rules_off():
    c = dispatch.wrap_text("uipath-Main.xaml", sample_text("uipath-Main.xaml"))
    r = dispatch.scan_any("uipath-Main.xaml", c, {"disabled": ["UIP-LOG-001", "RPA-CODE-002"], "severity": {"UIP-DB-001": "High"}})
    assert not rules_of(r) & {"UIP-LOG-001", "RPA-CODE-002"}
    assert next(f for f in r["findings"] if f["ruleId"] == "UIP-DB-001")["severity"] == "High"


# ---- UiPath project.json ----------------------------------------------------------------------------

def test_project_findings_and_clean_project():
    r = dispatch.scan_any("project.json", project())
    assert rules_of(r) == {"UIP-PRJ-001", "UIP-PRJ-002", "UIP-PRJ-003"}
    assert next(f for f in r["findings"] if f["ruleId"] == "UIP-PRJ-001")["severity"] == "Medium"       # a "*" floating version
    good = project()
    good["dependencies"] = {"UiPath.System.Activities": "[24.10.5]"}
    good["targetFramework"] = "Windows"
    good["runtimeOptions"]["excludedLoggedData"] = ["Private:*", "*password*"]
    assert dispatch.scan_any("project.json", good)["findings"] == []


def test_minimum_versions_are_low_and_floating_versions_are_medium():
    p = project()
    p["dependencies"] = {"A": "1.2.3"}
    found = [f for f in dispatch.scan_any("project.json", p)["findings"] if f["ruleId"] == "UIP-PRJ-001"]
    assert len(found) == 1 and found[0]["severity"] == "Low"
    p["dependencies"] = {"A": "1.2.3", "B": "*"}
    found = [f for f in dispatch.scan_any("project.json", p)["findings"] if f["ruleId"] == "UIP-PRJ-001"]
    assert len(found) == 1 and found[0]["severity"] == "Medium"


# ---- Automation Anywhere and Blue Prism: basic, schema-free ----------------------------------------------

def test_automation_anywhere_style_json_is_checked_without_a_schema():
    bot = {"nodes": [{"commands": [{"commandName": "restCall", "attributes": [
        {"name": "password", "value": {"type": "STRING", "string": "Hunter2hunter2"}},
        {"name": "uri", "value": {"type": "STRING", "string": "http://api.example.com/x"}},
        {"name": "note", "value": {"type": "STRING", "string": "hello"}}]}]}]}
    r = dispatch.scan_any("a.bot", dispatch.wrap_text("a.bot", json.dumps(bot)))
    assert {"RPA-SEC-001", "RPA-NET-001"} <= rules_of(r) and r["metadata"]["Platform"] == "Automation Anywhere"
    assert "Hunter2hunter2" not in json.dumps(r)
    assert "not been verified" in r["steps"][0]["json"]["note"]


def test_blue_prism_style_xml_is_checked_without_a_schema():
    xml = ('<process name="P"><stage name="Secret" type="Data"><datatype>password</datatype><initialvalue>Winter2024Winter</initialvalue></stage>'
           '<stage name="Run" type="Code"><code>x</code></stage><stage name="Go" type="Action" url="http://svc.example.com/a"/></process>')
    r = dispatch.scan_any("p.bprelease", dispatch.wrap_text("p.bprelease", xml))
    assert {"RPA-SEC-001", "RPA-CODE-002", "RPA-NET-001"} <= rules_of(r) and r["metadata"]["Platform"] == "Blue Prism"
    assert "Winter2024Winter" not in json.dumps(r)


def test_plain_text_export_with_a_token_and_a_shell_command():
    r = dispatch.scan_any("a.atmx", dispatch.wrap_text("a.atmx", "run: cmd.exe /c del x\nkey ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE123456\n"))
    assert {"RPA-SEC-001", "RPA-CODE-001"} <= rules_of(r) and "ghp_EXAMPLE" not in json.dumps(r)


# ---- fixes -------------------------------------------------------------------------------------------

def test_fixer_upgrades_http_and_pins_minimum_versions_only():
    src = dispatch.wrap_text("uipath-Main.xaml", sample_text("uipath-Main.xaml"))
    snap = copy.deepcopy(src)
    out = fixer.fix_flow("uipath-Main.xaml", src)
    assert src == snap and "https://api.partner.example.com" in out["content"]["text"] and "http://api.partner" not in out["content"]["text"]
    assert out["after"]["total"] == out["before"]["total"] - 1
    assert any(s["ruleId"] == "RPA-SEC-001" for s in out["skipped"])
    pj = fixer.fix_flow("project.json", project())
    assert pj["content"]["dependencies"]["UiPath.UIAutomation.Activities"] == "[24.10.7]"
    assert pj["content"]["dependencies"]["UiPath.Mail.Activities"] == "*"           # a floating version needs a human choice


# ---- archives, API, gate, CLI --------------------------------------------------------------------------

def make_package() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("content/Main.xaml", sample_text("uipath-Main.xaml"))
        z.writestr("content/Sub/Main.xaml", sample_text("uipath-clean.xaml"))
        z.writestr("content/project.json", sample_text("uipath-project.json"))
        z.writestr("lib/net45/x.dll", b"MZ\x00\x01binary")
        z.writestr("package.json", '{"name": "not uipath", "main": "i.js", "dependencies": {"a": "1"}}')
    return buf.getvalue()


def test_uipath_package_is_unpacked_into_files():
    got = extract_solution(make_package())
    names = [f["filename"] for f in got["flows"]]
    assert names == ["Main.xaml", "Main (2).xaml", "project.json"]
    assert [dispatch.kind_of(f["content"]) for f in got["flows"]] == ["uipath-xaml", "uipath-xaml", "uipath-project"]


def test_api_gate_sarif_and_catalog_cover_rpa_files():
    client = TestClient(main.app)
    files = [{"filename": "uipath-Main.xaml", "content": dispatch.wrap_text("uipath-Main.xaml", sample_text("uipath-Main.xaml"))},
             {"filename": "project.json", "content": project()}]
    body = client.post("/scan/upload", json={"files": files}).json()
    assert [r["metadata"]["Type"] for r in body["results"]] == ["UiPath workflow", "UiPath project"]
    ids = {r["id"] for r in client.get("/rules").json()}
    assert {"RPA-SEC-001", "UIP-DB-001", "UIP-PRJ-001"} <= ids
    plat = {p["id"]: p["status"] for p in client.get("/platforms").json()}
    assert plat["uipath"] == "active" and plat["other-rpa"] == "limited"
    results = gate.scan_items([{"file": f["filename"], "content": f["content"]} for f in files], None)
    assert not gate.evaluate(results, {"failOn": "High"})["passed"]
    assert any(r["ruleId"] == "RPA-NET-001" for r in to_sarif(results)["runs"][0]["results"])
    assert client.post("/fix", json={"filename": "uipath-Main.xaml", "content": files[0]["content"]}).json()["applied"]


def test_every_rpa_rule_has_guidance_and_is_in_the_catalog():
    ids = {r["id"] for r in RULES if r["id"].startswith(("RPA-", "UIP-"))}
    assert ids == set(rpascan.FIXES) == set(rpascan.ALTERNATIVES)


def test_cli_reads_xaml_projects_and_packages(tmp_path, capsys):
    (tmp_path / "Main.xaml").write_text(sample_text("uipath-Main.xaml"), encoding="utf-8")
    (tmp_path / "project.json").write_text(sample_text("uipath-project.json"), encoding="utf-8")
    assert falconscan.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "Main.xaml" in out and "project.json" in out
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "Clean.xaml").write_text(sample_text("uipath-clean.xaml"), encoding="utf-8")
    assert falconscan.main([str(clean)]) == 0
    pkg = tmp_path / "InvoiceBot.nupkg"
    pkg.write_bytes(make_package())
    assert falconscan.main([str(pkg), "--fail-on", "none"]) == 0
    assert "Main.xaml" in capsys.readouterr().out
    fixed = tmp_path / "fixed"
    assert falconscan.main([str(tmp_path / "Main.xaml"), "--fix-dir", str(fixed)]) == 1
    assert list(fixed.glob("*.fixed.json"))


def test_every_finding_is_attached_to_a_step_for_every_kind_of_file():
    """The workbench lists findings through steps, so a finding without a step would never be shown."""
    files = {n: json.loads(sample_text(n)) for n in ("risky-flow.json", "mcp-config-risky.json", "ai-agent-risky.json", "uipath-project.json")}
    files["uipath-Main.xaml"] = dispatch.wrap_text("uipath-Main.xaml", sample_text("uipath-Main.xaml"))
    files["a.bot"] = dispatch.wrap_text("a.bot", json.dumps({"attributes": [{"name": "password", "value": {"string": "Hunter2hunter2"}}]}))
    files["p.bprelease"] = dispatch.wrap_text("p.bprelease", '<process><stage name="c" type="Code"/><stage name="a" url="http://svc.example.com/x"/></process>')
    for name, content in files.items():
        r = dispatch.scan_any(name, content)
        in_steps = sorted(f["fingerprint"] for s in r["steps"] for f in s["findings"])
        assert r["findings"], name
        assert in_steps == sorted(f["fingerprint"] for f in r["findings"]), name

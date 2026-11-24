import json
import pathlib

import rules
import scanner

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


def test_every_rule_maps_to_one_owasp_low_code_category():
    assert len(rules.LCNC) == 10
    for r in rules.RULES:
        assert r["lcnc"] in rules.LCNC and r["lcncTitle"] == rules.LCNC[r["lcnc"]], r["id"]
    assert set(rules._L) == {r["id"] for r in rules.RULES}      # no mapping left over for a rule that no longer exists


def test_findings_carry_the_low_code_category():
    flow = json.loads((SAMPLES / "risky-flow.json").read_text(encoding="utf-8"))
    res = scanner.scan_flow(flow) if hasattr(scanner, "scan_flow") else None
    assert rules.meta("PA-SEC-001")["lcnc"] == "LCNC-SEC-08"
    if res:
        assert all(f.get("lcnc", "").startswith("LCNC-SEC-") for f in res["findings"])

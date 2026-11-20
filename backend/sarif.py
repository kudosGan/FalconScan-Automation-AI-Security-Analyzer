"""SARIF 2.1.0 output so pipelines and code-scanning dashboards can read Falcon Scan findings."""
import agentscan  # noqa: F401  (registers the AI rule guidance)
import rpascan  # noqa: F401  (registers the RPA rule guidance)
import scanner
from rules import RULES

LEVEL = {"High": "error", "Medium": "warning", "Low": "note"}


def to_sarif(results: list[dict], waived: dict[str, str] | None = None) -> dict:
    """`waived` maps a finding fingerprint to the waiver reason; those results carry a suppression."""
    waived = waived or {}
    rules = [{
        "id": r["id"], "name": r["id"].replace("-", ""),
        "shortDescription": {"text": r["title"]}, "fullDescription": {"text": r["description"] or r["title"]},
        "help": {"text": " ".join(f"{i}. {t}" for i, t in enumerate(scanner.FIXES.get(r["id"], []), 1)) or r["title"]},
        "defaultConfiguration": {"level": LEVEL[r["severity"]]},
        "properties": {"tags": [x for x in (r["category"], r["cwe"], r["owasp"]) if x]},
    } for r in RULES]
    out = []
    for res in results:
        for f in res.get("findings", []):
            item = {
                "ruleId": f["ruleId"], "level": LEVEL[f["severity"]],
                "message": {"text": f"{f['title']}: {f['detail']}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": res.get("file") or res.get("name") or "flow"}},
                               "logicalLocations": [{"name": f["location"], "kind": "member"}]}],
                "partialFingerprints": {"falconScan/v1": f.get("fingerprint", "")},
            }
            if f.get("fingerprint") in waived:
                item["suppressions"] = [{"kind": "external", "justification": waived[f["fingerprint"]]}]
            out.append(item)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Falcon Scan", "rules": rules}},
                      "results": out}]}

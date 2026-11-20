"""Create a Jira or Azure DevOps ticket from a finding.

Everything sensitive comes from environment variables on the server, never from the database or the browser:
  FALCON_TICKETS=jira
    FALCON_JIRA_URL      https://yourcompany.atlassian.net
    FALCON_JIRA_EMAIL    the account the API token belongs to
    FALCON_JIRA_TOKEN    an Atlassian API token
    FALCON_JIRA_PROJECT  project key, for example SEC
    FALCON_JIRA_ISSUETYPE (default Bug)
  FALCON_TICKETS=azuredevops
    FALCON_ADO_ORG_URL   https://dev.azure.com/yourorg
    FALCON_ADO_PROJECT   project name
    FALCON_ADO_PAT       a personal access token with Work Items (read and write)
    FALCON_ADO_TYPE      (default Bug)
Only the finding's title, rule, location, explanation and fix steps are sent. Never the file contents or any secret values.
"""
import html
import os
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

import db

TIMEOUT = 20


class TicketError(Exception):
    pass


def _system() -> str | None:
    s = (os.environ.get("FALCON_TICKETS") or "").strip().lower()
    return s if s in ("jira", "azuredevops") else None


def _base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    ok = url.startswith("https://") or url.startswith(("http://127.0.0.1", "http://localhost"))
    if not ok:
        raise TicketError("The ticket system address must start with https://.")
    return url


def _missing(system: str) -> list[str]:
    need = {"jira": ["FALCON_JIRA_URL", "FALCON_JIRA_EMAIL", "FALCON_JIRA_TOKEN", "FALCON_JIRA_PROJECT"],
            "azuredevops": ["FALCON_ADO_ORG_URL", "FALCON_ADO_PROJECT", "FALCON_ADO_PAT"]}[system]
    return [n for n in need if not os.environ.get(n)]


def config() -> dict:
    """What the browser may know: whether tickets are set up and where they go. No credentials."""
    system = _system()
    if not system:
        return {"configured": False, "system": None, "target": None, "problem": "No ticket system is set up on the server (FALCON_TICKETS)."}
    missing = _missing(system)
    if missing:
        return {"configured": False, "system": system, "target": None, "problem": "Missing server settings: " + ", ".join(missing)}
    target = (os.environ["FALCON_JIRA_PROJECT"] + " at " + os.environ["FALCON_JIRA_URL"]) if system == "jira" \
        else (os.environ["FALCON_ADO_PROJECT"] + " at " + os.environ["FALCON_ADO_ORG_URL"])
    return {"configured": True, "system": system, "target": target, "problem": None}


def _clean(finding: dict) -> dict:
    t = lambda k, n: str(finding.get(k) or "")[:n]
    fix = [str(x)[:600] for x in (finding.get("fix") or []) if isinstance(x, str)][:8]
    sev = t("severity", 10)
    return {"issueKey": t("issueKey", 600), "title": t("title", 200), "severity": sev if sev in ("High", "Medium", "Low") else "Medium",
            "ruleId": t("ruleId", 40), "cwe": t("cwe", 40), "owasp": t("owasp", 80), "flow": t("flow", 200), "location": t("location", 300),
            "detail": t("detail", 1500), "app": t("appName", 200), "fix": fix}


def _summary(f: dict) -> str:
    return f"[Falcon Scan] {f['severity']}: {f['title']} in {f['flow'] or f['app']}"[:240]


def _paragraphs(f: dict) -> list[str]:
    lines = [f"Severity: {f['severity']}", f"Rule: {f['ruleId']}" + (f" ({f['cwe']}, {f['owasp']})" if f["cwe"] and f["cwe"] != "—" else ""),
             f"Application: {f['app']}" if f["app"] else "", f"File: {f['flow']}", f"Where: {f['location']}", "", f['detail']]
    return [x for x in lines if x is not None]


def _jira(f: dict) -> dict:
    base = _base(os.environ["FALCON_JIRA_URL"])
    text = lambda s: {"type": "paragraph", "content": [{"type": "text", "text": s}] if s else []}
    content = [text(p) for p in _paragraphs(f) if p != ""]
    if f["fix"]:
        content.append(text("How to fix:"))
        content.append({"type": "orderedList", "content": [{"type": "listItem", "content": [text(s)]} for s in f["fix"]]})
    body = {"fields": {"project": {"key": os.environ["FALCON_JIRA_PROJECT"]},
                       "issuetype": {"name": os.environ.get("FALCON_JIRA_ISSUETYPE") or "Bug"},
                       "summary": _summary(f), "description": {"type": "doc", "version": 1, "content": content},
                       "labels": ["falcon-scan", f"severity-{f['severity'].lower()}"]}}
    r = httpx.post(f"{base}/rest/api/3/issue", json=body, auth=(os.environ["FALCON_JIRA_EMAIL"], os.environ["FALCON_JIRA_TOKEN"]),
                   headers={"Accept": "application/json"}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        raise TicketError(f"Jira refused the request (HTTP {r.status_code}). Check the project key, issue type and permissions.")
    key = r.json()["key"]
    return {"system": "jira", "id": key, "url": f"{base}/browse/{key}"}


def _ado(f: dict) -> dict:
    base = _base(os.environ["FALCON_ADO_ORG_URL"])
    project, wtype = os.environ["FALCON_ADO_PROJECT"], os.environ.get("FALCON_ADO_TYPE") or "Bug"
    esc = html.escape
    desc = "".join(f"<p>{esc(p)}</p>" for p in _paragraphs(f) if p != "")
    if f["fix"]:
        desc += "<p><b>How to fix:</b></p><ol>" + "".join(f"<li>{esc(s)}</li>" for s in f["fix"]) + "</ol>"
    ops = [{"op": "add", "path": "/fields/System.Title", "value": _summary(f)},
           {"op": "add", "path": "/fields/System.Description", "value": desc},
           {"op": "add", "path": "/fields/System.Tags", "value": f"falcon-scan; severity-{f['severity'].lower()}"}]
    r = httpx.post(f"{base}/{quote(project)}/_apis/wit/workitems/${quote(wtype)}?api-version=7.1", json=ops, auth=("", os.environ["FALCON_ADO_PAT"]),
                   headers={"Content-Type": "application/json-patch+json", "Accept": "application/json"}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        raise TicketError(f"Azure DevOps refused the request (HTTP {r.status_code}). Check the project, work item type and token permissions.")
    data = r.json()
    url = (data.get("_links") or {}).get("html", {}).get("href") or f"{base}/{quote(project)}/_workitems/edit/{data['id']}"
    return {"system": "azuredevops", "id": str(data["id"]), "url": url}


def existing(issue_key: str) -> dict | None:
    r = db.conn().execute("SELECT * FROM tickets WHERE issue_key=?", (issue_key,)).fetchone()
    return {"system": r["system"], "id": r["external_id"], "url": r["url"], "createdAt": r["created_at"], "createdBy": r["created_by"]} if r else None


def create(finding: dict, user: str) -> dict:
    cfg = config()
    if not cfg["configured"]:
        raise TicketError(cfg["problem"])
    f = _clean(finding)
    if not f["issueKey"] or not f["title"]:
        raise TicketError("The finding needs a key and a title.")
    if existing(f["issueKey"]):
        raise TicketError("This finding already has a ticket.")
    try:
        made = _jira(f) if cfg["system"] == "jira" else _ado(f)
    except httpx.HTTPError as e:
        raise TicketError(f"Could not reach the ticket system: {type(e).__name__}.")
    with db.tx() as c:
        c.execute("INSERT OR REPLACE INTO tickets(issue_key, system, external_id, url, created_at, created_by) VALUES (?,?,?,?,?,?)",
                  (f["issueKey"], made["system"], made["id"], made["url"], datetime.now(timezone.utc).isoformat(), user))
    return existing(f["issueKey"]) | {"ruleId": f["ruleId"]}

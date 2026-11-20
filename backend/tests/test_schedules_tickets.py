import base64
import json
import pathlib
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

import accounts
import audit
import db
import main
import scheduler
import store
import tickets

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
RISKY = json.loads((SAMPLES / "risky-flow.json").read_text(encoding="utf-8"))
CLEAN = json.loads((SAMPLES / "clean-flow.json").read_text(encoding="utf-8"))
PW = "correct horse battery"


def save_app(app_id="a1", flows=None, name="HR flows"):
    return store.save_application({"id": app_id, "name": name, "flows": flows if flows is not None else [{"filename": "risky-flow.json", "content": RISKY}]}, "alan")


# ---- schedules ------------------------------------------------------------------------------------------------

def test_application_schedule_runs_stores_an_assessment_and_reports_the_gate():
    save_app()
    s = scheduler.create("Nightly HR", "application", "a1", 60, "High", "alan")
    assert s["enabled"] and s["lastStatus"] == ""
    done = scheduler.run(s["id"], "alan")
    assert done["lastStatus"].startswith("Gate failed") and done["lastAssessmentId"]
    rec = store.list_assessments()[0]
    assert rec["id"] == done["lastAssessmentId"] and rec["source"] == "scheduled" and rec["appId"] == "a1" and rec["completed"]
    assert rec["response"]["results"][0]["findings"] and rec["createdBy"] == "schedule:Nightly HR"
    assert audit.entries(action="schedule.run")[0]["detail"]["status"].startswith("Gate failed")


def test_findings_marked_closed_do_not_block_the_scheduled_gate():
    save_app()
    s = scheduler.create("n", "application", "a1", 60, "High", "alan")
    scheduler.run(s["id"])
    for f in store.list_assessments()[0]["response"]["results"][0]["findings"]:
        store.set_issue("a1|" + f["fingerprint"], "alan", "Accepted risk" if f["severity"] == "High" else "Open", "approved")
    assert scheduler.run(s["id"])["lastStatus"] == "Gate passed"
    clean = scheduler.create("c", "application", "a1", 60, "none", "alan")
    assert scheduler.run(clean["id"])["lastStatus"] == "Scanned"


def test_schedule_validation():
    save_app()
    for args in [("", "application", "a1", 60, "High"), ("n", "bogus", "a1", 60, "High"), ("n", "application", "a1", 5, "High"),
                 ("n", "application", "a1", 60, "Critical"), ("n", "application", "missing", 60, "High"), ("n", "folder", ".", 60, "High")]:
        with pytest.raises(ValueError):
            scheduler.create(*args, "alan")


def test_due_schedules_run_once_and_disabled_ones_do_not():
    save_app()
    a = scheduler.create("a", "application", "a1", 15, "High", "alan")
    b = scheduler.create("b", "application", "a1", 15, "High", "alan")
    scheduler.update(b["id"], enabled=False)
    assert scheduler.run_due(time.time()) == []                                       # nothing is due yet
    later = time.time() + 16 * 60
    assert scheduler.run_due(later) == [a["id"]]
    assert scheduler.run_due(later) == []                                              # already claimed and rescheduled
    assert scheduler.list_schedules()[0]["lastStatus"] and not scheduler.list_schedules()[1]["lastStatus"]


def test_a_schedule_cannot_run_twice_at_once_and_a_vanished_application_is_reported():
    save_app()
    s = scheduler.create("a", "application", "a1", 60, "High", "alan")
    lock = scheduler._run_locks.setdefault(s["id"], threading.Lock())
    lock.acquire()
    try:
        with pytest.raises(ValueError, match="already running"):
            scheduler.run(s["id"])
    finally:
        lock.release()
    store.delete_application("a1")
    assert scheduler.run(s["id"])["lastStatus"].startswith("Error: The application no longer exists")


def test_folder_schedules_stay_inside_the_scan_root(tmp_path, monkeypatch):
    root = tmp_path / "exports"
    (root / "team").mkdir(parents=True)
    (root / "team" / "risky-flow.json").write_text(json.dumps(RISKY))
    (root / "team" / "notes.txt").write_text("ignored")
    outside = tmp_path / "secret"
    outside.mkdir()
    with pytest.raises(ValueError, match="FALCON_SCAN_ROOT"):
        scheduler.create("f", "folder", "team", 60, "High", "alan")
    monkeypatch.setenv("FALCON_SCAN_ROOT", str(root))
    for bad in ("../secret", str(outside), "team/../../secret", "missing"):
        with pytest.raises(ValueError):
            scheduler.create("f", "folder", bad, 60, "High", "alan")
    s = scheduler.create("Team exports", "folder", "team", 60, "High", "alan")
    done = scheduler.run(s["id"])
    assert done["lastStatus"].startswith("Gate failed")
    app = next(a for a in store.list_applications() if a["id"] == f"sched-{s['id']}")
    assert [f["filename"] for f in app["flows"]] == ["risky-flow.json"] and store.list_assessments()[0]["appId"] == app["id"]


def test_schedule_api_roles_and_audit(monkeypatch):
    monkeypatch.setenv("FALCON_AUTH", "on")
    save_app()
    accounts.create_user("alan", PW, "assessor"); accounts.create_user("vera", PW, "viewer")

    def client(name):
        c = TestClient(main.app); c.headers["X-Falcon-CSRF"] = "1"
        assert c.post("/account/login", json={"username": name, "password": PW}).status_code == 200
        return c
    alan, vera = client("alan"), client("vera")
    body = {"name": "Nightly", "sourceType": "application", "sourceRef": "a1", "intervalMinutes": 60, "failOn": "High"}
    assert vera.post("/schedules", json=body).status_code == 403 and vera.get("/schedules").status_code == 200
    made = alan.post("/schedules", json=body)
    assert made.status_code == 200
    sid = made.json()["id"]
    assert alan.post("/schedules", json={**body, "intervalMinutes": 1}).status_code == 400
    assert alan.patch(f"/schedules/{sid}", json={"enabled": False}).json()["enabled"] is False
    assert vera.post(f"/schedules/{sid}/run").status_code == 403
    assert alan.post(f"/schedules/{sid}/run").json()["lastStatus"].startswith("Gate failed")
    listing = vera.get("/schedules").json()
    assert listing["folderSchedules"] is False and listing["schedules"][0]["name"] == "Nightly"
    assert alan.delete(f"/schedules/{sid}").status_code == 200 and alan.delete(f"/schedules/{sid}").status_code == 404
    assert {"schedule.create", "schedule.update", "schedule.run", "schedule.delete"} <= {e["action"] for e in audit.entries(limit=100)}


# ---- tickets: a fake Jira and a fake Azure DevOps on localhost ---------------------------------------------------------

class Fake(BaseHTTPRequestHandler):
    seen: list = []
    status = 201

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Fake.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "ctype": self.headers.get("Content-Type"), "body": json.loads(body)})
        if Fake.status >= 400:
            self.send_response(Fake.status); self.end_headers(); self.wfile.write(b'{"errorMessages":["nope"]}'); return
        port = self.server.server_address[1]
        out = {"id": "10001", "key": "SEC-7"} if "/rest/api/3/issue" in self.path else {"id": 42, "_links": {"html": {"href": f"http://127.0.0.1:{port}/P/_workitems/edit/42"}}}
        self.send_response(201); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(json.dumps(out).encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def fake():
    Fake.seen, Fake.status = [], 201
    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


FINDING = {"issueKey": "a1|risky|action:Call|uri", "title": "Unencrypted HTTP call", "severity": "High", "ruleId": "PA-ACT-001", "cwe": "CWE-319",
           "owasp": "A02:2021 Cryptographic Failures", "flow": "risky-flow.json", "location": "action:Call_Partner_API", "appName": "HR flows",
           "detail": "Action calls http://partner.example.com over plain HTTP.", "fix": ["Change the address to https://."]}


def jira_env(monkeypatch, url):
    for k, v in {"FALCON_TICKETS": "jira", "FALCON_JIRA_URL": url, "FALCON_JIRA_EMAIL": "bot@example.com", "FALCON_JIRA_TOKEN": "jira-secret-token",
                 "FALCON_JIRA_PROJECT": "SEC"}.items():
        monkeypatch.setenv(k, v)


def test_jira_ticket_has_the_documented_request_shape(fake, monkeypatch):
    jira_env(monkeypatch, fake)
    t = tickets.create(FINDING, "alan")
    assert t["id"] == "SEC-7" and t["url"] == f"{fake}/browse/SEC-7" and t["system"] == "jira"
    req = Fake.seen[0]
    assert req["path"] == "/rest/api/3/issue"
    assert req["auth"] == "Basic " + base64.b64encode(b"bot@example.com:jira-secret-token").decode()
    f = req["body"]["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Bug"} and f["summary"].startswith("[Falcon Scan] High:")
    assert f["description"]["type"] == "doc" and f["description"]["version"] == 1
    flat = json.dumps(f["description"])
    assert "PA-ACT-001" in flat and "Change the address to https://." in flat and "orderedList" in flat
    assert set(f["labels"]) == {"falcon-scan", "severity-high"}
    assert tickets.existing(FINDING["issueKey"])["id"] == "SEC-7"


def test_azure_devops_ticket_has_the_documented_request_shape(fake, monkeypatch):
    for k, v in {"FALCON_TICKETS": "azuredevops", "FALCON_ADO_ORG_URL": fake, "FALCON_ADO_PROJECT": "My Project", "FALCON_ADO_PAT": "ado-secret-pat"}.items():
        monkeypatch.setenv(k, v)
    t = tickets.create({**FINDING, "detail": "<script>alert(1)</script>"}, "alan")
    assert t["id"] == "42" and t["system"] == "azuredevops" and t["url"].endswith("/P/_workitems/edit/42")
    req = Fake.seen[0]
    assert req["path"] == "/My%20Project/_apis/wit/workitems/$Bug?api-version=7.1"
    assert req["ctype"] == "application/json-patch+json"
    assert req["auth"] == "Basic " + base64.b64encode(b":ado-secret-pat").decode()
    ops = {o["path"]: o["value"] for o in req["body"]}
    assert all(o["op"] == "add" for o in req["body"]) and ops["/fields/System.Title"].startswith("[Falcon Scan] High:")
    assert "<script>" not in ops["/fields/System.Description"] and "&lt;script&gt;" in ops["/fields/System.Description"]
    assert "<ol><li>Change the address to https://.</li></ol>" in ops["/fields/System.Description"]


def test_duplicate_tickets_errors_and_what_is_never_sent_or_shown(fake, monkeypatch):
    with pytest.raises(tickets.TicketError, match="No ticket system"):
        tickets.create(FINDING, "alan")
    jira_env(monkeypatch, fake)
    cfg = tickets.config()
    assert cfg["configured"] and cfg["system"] == "jira" and "jira-secret-token" not in json.dumps(cfg) and "bot@example.com" not in json.dumps(cfg)
    tickets.create(FINDING, "alan")
    with pytest.raises(tickets.TicketError, match="already has a ticket"):
        tickets.create(FINDING, "alan")
    sent = json.dumps(Fake.seen)
    assert "jira-secret-token" not in sent                                             # only in the Authorization header, which is not in the body
    Fake.status = 401
    with pytest.raises(tickets.TicketError, match="refused") as e:
        tickets.create({**FINDING, "issueKey": "other"}, "alan")
    assert "jira-secret-token" not in str(e.value) and tickets.existing("other") is None
    monkeypatch.setenv("FALCON_JIRA_URL", "http://evil.example.com")
    with pytest.raises(tickets.TicketError, match="https"):
        tickets.create({**FINDING, "issueKey": "third"}, "alan")
    monkeypatch.delenv("FALCON_JIRA_TOKEN")
    assert "FALCON_JIRA_TOKEN" in tickets.config()["problem"] and not tickets.config()["configured"]


def test_ticket_api_roles_audit_and_no_secrets_in_the_log(fake, monkeypatch):
    monkeypatch.setenv("FALCON_AUTH", "on")
    jira_env(monkeypatch, fake)
    accounts.create_user("alan", PW, "assessor"); accounts.create_user("vera", PW, "viewer")

    def client(name):
        c = TestClient(main.app); c.headers["X-Falcon-CSRF"] = "1"
        c.post("/account/login", json={"username": name, "password": PW})
        return c
    alan, vera = client("alan"), client("vera")
    assert vera.get("/tickets/config").json()["configured"] and vera.post("/tickets", json=FINDING).status_code == 403
    r = alan.post("/tickets", json=FINDING)
    assert r.status_code == 200 and r.json()["id"] == "SEC-7"
    assert alan.post("/tickets", json=FINDING).status_code == 409
    assert store.bootstrap()["tickets"][FINDING["issueKey"]]["id"] == "SEC-7" and vera.get("/data/bootstrap").json()["tickets"]
    logged = json.dumps(audit.entries(limit=100))
    assert "ticket.create" in logged and "jira-secret-token" not in logged

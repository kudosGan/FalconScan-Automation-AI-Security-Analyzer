import json
import pathlib

import pytest
from fastapi.testclient import TestClient

import accounts
import audit
import main
import pdf
import store

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
PW = "correct horse battery"
RISKY = json.loads((SAMPLES / "risky-flow.json").read_text(encoding="utf-8"))


@pytest.fixture
def secure(monkeypatch):
    monkeypatch.setenv("FALCON_AUTH", "on")
    monkeypatch.setenv("FALCON_SETUP_TOKEN", "setup-secret-token")


def new_client() -> TestClient:
    c = TestClient(main.app)
    c.headers["X-Falcon-CSRF"] = "1"
    return c


def signin(name: str, role: str) -> TestClient:
    """A client signed in as a fresh user with the given role (its own cookie jar)."""
    accounts.create_user(name, PW, role, name.title())
    c = new_client()
    r = c.post("/account/login", json={"username": name, "password": PW})
    assert r.status_code == 200, r.text
    return c


# ---- first run and signing in ---------------------------------------------------------------------------

def test_first_run_needs_the_setup_token_off_the_server_and_only_works_once(secure):
    c = new_client()
    s = c.get("/account/state").json()
    assert s == {"authEnabled": True, "setupRequired": True, "user": None}
    assert c.get("/rules").status_code == 401 and c.post("/scan/upload", json={"files": []}).status_code == 401
    body = {"username": "root", "password": PW, "displayName": "Root"}
    assert c.post("/account/setup", json={**body, "setupToken": "wrong"}).status_code == 403
    r = c.post("/account/setup", json={**body, "setupToken": "setup-secret-token"})
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/account/state").json()["setupRequired"] is False and c.get("/rules").status_code == 200
    assert new_client().post("/account/setup", json={**body, "username": "second", "setupToken": "setup-secret-token"}).status_code == 409


def test_state_changing_requests_need_the_csrf_header(secure):
    accounts.create_user("alice", PW, "assessor")
    c = TestClient(main.app)                                                       # no header
    assert c.post("/account/login", json={"username": "alice", "password": PW}).status_code == 403
    c.headers["X-Falcon-CSRF"] = "1"
    assert c.post("/account/login", json={"username": "alice", "password": PW}).status_code == 200
    del c.headers["X-Falcon-CSRF"]
    assert c.post("/data/policy", json={"name": "x"}).status_code == 403
    assert c.get("/data/bootstrap").status_code == 200                              # reading needs no header


def test_failed_logins_are_audited_lock_the_account_and_admins_can_unlock(secure):
    admin = signin("root", "admin")
    u = accounts.create_user("bob", PW, "viewer")
    c = new_client()
    for _ in range(accounts.MAX_FAILS):
        assert c.post("/account/login", json={"username": "bob", "password": "wrong wrong wrong"}).status_code == 401
    assert c.post("/account/login", json={"username": "bob", "password": PW}).status_code == 401       # locked, even with the right password
    actions = [e["action"] for e in audit.entries()]
    assert actions.count("login.fail") == accounts.MAX_FAILS and "account.locked" in actions and "login.blocked" in actions
    assert admin.patch(f"/admin/users/{u['id']}", json={"unlock": True}).status_code == 200
    assert c.post("/account/login", json={"username": "bob", "password": PW}).status_code == 200


def test_logout_ends_the_session_and_stale_cookies_stop_working(secure):
    c = signin("alice", "assessor")
    stale = c.cookies.get("falcon_session")
    assert c.post("/account/logout").status_code == 200
    other = new_client()
    other.cookies.set("falcon_session", stale)
    assert other.get("/rules").status_code == 401


# ---- roles -------------------------------------------------------------------------------------------------

def test_role_matrix(secure, monkeypatch):
    monkeypatch.setattr(pdf, "html_to_pdf", lambda html: b"%PDF-fake")
    viewer, assessor, admin = signin("vera", "viewer"), signin("alan", "assessor"), signin("ada", "admin")
    files = {"files": [{"filename": "risky-flow.json", "content": RISKY}]}

    assert viewer.get("/rules").status_code == 200 and viewer.get("/data/bootstrap").status_code == 200
    assert viewer.post("/report/pdf", json={"html": "<p>x</p>"}).status_code == 200            # a viewer may produce reports
    for method, path, body in [("post", "/scan/upload", files), ("post", "/gate", files), ("post", "/fix", {"filename": "a.json", "content": RISKY}),
                               ("put", "/data/policy", {"name": "x"}), ("put", "/data/issues", {"key": "k", "status": "Fixed"}),
                               ("post", "/schedules", {"name": "n", "sourceType": "folder", "sourceRef": ".", "intervalMinutes": 60}),
                               ("get", "/environments", None)]:
        assert getattr(viewer, method)(path, **({"json": body} if body is not None else {})).status_code == 403, path
    assert viewer.get("/admin/users").status_code == 403 and viewer.get("/admin/audit").status_code == 403

    assert assessor.post("/scan/upload", json=files).status_code == 200
    assert assessor.put("/data/issues", json={"key": "k", "status": "Fixed", "comment": "done"}).status_code == 200
    assert assessor.delete("/data/assessments").status_code == 403                          # wiping everything is admin only
    assert assessor.get("/admin/audit").status_code == 403 and assessor.post("/admin/users", json={"username": "x" * 5, "password": PW}).status_code == 403

    assert admin.get("/admin/users").status_code == 200 and admin.get("/admin/audit").status_code == 200
    assert admin.delete("/data/assessments").status_code == 200
    denied = [e for e in audit.entries(action="access.denied")]
    assert len(denied) >= 10 and all(e["actor"] in ("vera", "alan") for e in denied)


def test_user_management_and_immediate_effect_of_role_changes(secure):
    admin = signin("root", "admin")
    r = admin.post("/admin/users", json={"username": "newbie", "password": PW, "role": "assessor", "displayName": "New B"})
    assert r.status_code == 200 and r.json()["role"] == "assessor"
    assert admin.post("/admin/users", json={"username": "newbie", "password": PW}).status_code == 400            # duplicate
    assert admin.post("/admin/users", json={"username": "weak", "password": "short"}).status_code == 400
    c = new_client()
    assert c.post("/account/login", json={"username": "newbie", "password": PW}).status_code == 200
    assert c.post("/scan/upload", json={"files": []}).status_code == 200
    admin.patch(f"/admin/users/{r.json()['id']}", json={"role": "viewer"})
    assert c.get("/rules").status_code == 401                                         # the old session was ended
    assert new_client().post("/account/login", json={"username": "newbie", "password": PW}).status_code == 200
    me = admin.get("/account/state").json()["user"]
    assert admin.patch(f"/admin/users/{me['id']}", json={"role": "viewer"}).status_code == 400                   # last administrator
    logged = json.dumps(audit.entries(limit=500))
    assert "user.create" in logged and PW not in logged


def test_changing_your_own_password(secure):
    c = signin("alice", "viewer")
    assert c.post("/account/password", json={"current": "nope", "new": "another long passphrase"}).status_code == 400
    assert c.post("/account/password", json={"current": PW, "new": "another long passphrase"}).status_code == 200
    assert new_client().post("/account/login", json={"username": "alice", "password": PW}).status_code == 401
    assert new_client().post("/account/login", json={"username": "alice", "password": "another long passphrase"}).status_code == 200


# ---- shared data -------------------------------------------------------------------------------------------

def test_data_written_by_one_user_is_seen_by_another_and_audited(secure):
    alan, vera = signin("alan", "assessor"), signin("vera", "viewer")
    app = {"id": "a1", "name": "HR flows", "description": "", "workingDir": "", "createdAt": "2026-01-01T00:00:00Z",
           "flows": [{"filename": "risky-flow.json", "content": RISKY}]}
    assert alan.post("/data/applications", json=app).status_code == 200
    scan = alan.post("/scan/upload", json={"files": [{"filename": "risky-flow.json", "content": RISKY}]}).json()
    rec = {"id": "r1", "createdAt": "2026-01-02T00:00:00Z", "source": "upload", "appId": "a1", "appName": "HR flows", "config": "Normal scan",
           "disabled": [], "completed": False, "response": scan}
    assert alan.post("/data/assessments", json=rec).status_code == 200
    key = "a1|" + scan["results"][0]["findings"][0]["fingerprint"]
    assert alan.put("/data/issues", json={"key": key, "status": "Accepted risk", "comment": "approved"}).status_code == 200
    seen = vera.get("/data/bootstrap").json()
    assert [a["name"] for a in seen["applications"]] == ["HR flows"] and seen["assessments"][0]["createdBy"] == "alan"
    assert seen["issues"][key]["status"] == "Accepted risk" and seen["issues"][key]["updatedBy"] == "alan"
    assert vera.put("/data/applications/a1", json=app).status_code == 403
    assert alan.put("/data/applications/a1", json={**app, "name": "Renamed"}).json()["name"] == "Renamed"
    assert alan.patch("/data/assessments/r1").status_code == 200 and alan.patch("/data/assessments/nope").status_code == 404
    assert alan.put("/data/issues", json={"key": key, "status": "Banana"}).status_code == 400
    actions = [e["action"] for e in audit.entries(limit=100)]
    for a in ("app.save", "assessment.add", "issue.update", "scan.run"):
        assert a in actions
    assert alan.delete("/data/applications/a1").status_code == 200 and alan.delete("/data/applications/a1").status_code == 404


def test_browser_data_can_be_imported_once(secure):
    c = signin("alan", "assessor")
    bundle = {"applications": [{"id": "a1", "name": "From browser", "flows": []}], "issues": {"k": {"status": "Noise", "comment": ""}}}
    assert c.post("/data/import", json=bundle).json() == {"applications": 1, "assessments": 0, "issues": 1, "policy": 0}
    assert c.post("/data/import", json=bundle).json() == {"applications": 0, "assessments": 0, "issues": 0, "policy": 0}


def test_audit_endpoints_for_admins(secure):
    admin = signin("root", "admin")
    admin.get("/admin/users")
    out = admin.get("/admin/audit").json()
    assert out["verify"]["ok"] and any(e["action"] == "login.success" for e in out["entries"])
    assert admin.get("/admin/audit?action=login").json()["entries"] and admin.get("/admin/audit/verify").json()["ok"]
    csv = admin.get("/admin/audit.csv")
    assert csv.status_code == 200 and "login.success" in csv.text and "attachment" in csv.headers["content-disposition"]
    assert audit.entries(action="audit.export")


# ---- single-user mode -----------------------------------------------------------------------------------------

def test_with_sign_in_switched_off_everything_works_as_before(monkeypatch):
    monkeypatch.setenv("FALCON_AUTH", "off")
    c = TestClient(main.app)                                                         # no cookie, no header
    assert c.get("/account/state").json()["authEnabled"] is False
    assert c.post("/scan/upload", json={"files": [{"filename": "r.json", "content": RISKY}]}).status_code == 200
    assert c.get("/admin/users").status_code == 200

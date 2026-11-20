import json

import pytest

import accounts
import audit
import db
import store

PW = "correct horse battery"


def user(name="alice", role="viewer", pw=PW):
    return accounts.create_user(name, pw, role, name.title())


# ---- passwords and accounts ---------------------------------------------------------------------

def test_password_hashing_is_salted_and_verifies():
    a, b = accounts.hash_password(PW), accounts.hash_password(PW)
    assert a != b and accounts.verify_password(PW, a) and not accounts.verify_password("wrong password!!", a)
    assert not accounts.verify_password(PW, "garbage") and PW not in a


@pytest.mark.parametrize("pw", ["short", "alice-alice-alice", "password1234", "aaaaaaaaaaaaaaaa"])
def test_weak_passwords_are_refused(pw):
    with pytest.raises(ValueError):
        accounts.create_user("alice", pw, "viewer")


def test_usernames_roles_and_duplicates_are_validated():
    for bad in ("ab", "has space", "UPPER!", "-start"):
        with pytest.raises(ValueError):
            accounts.create_user(bad, PW)
    with pytest.raises(ValueError, match="Role"):
        accounts.create_user("bob", PW, "superuser")
    user("bob")
    with pytest.raises(ValueError, match="taken"):
        accounts.create_user("BOB", PW)


def test_login_success_and_failure_messages_do_not_reveal_which_part_was_wrong():
    user()
    assert accounts.authenticate("Alice", PW)["username"] == "alice"
    for who, pw in (("alice", "wrong wrong wrong"), ("nobody", PW)):
        with pytest.raises(accounts.AuthError) as e:
            accounts.authenticate(who, pw)
        assert str(e.value) == "Incorrect username or password."


def test_account_locks_after_five_failures_and_unlocks_with_time_or_an_admin(monkeypatch):
    u = user()
    clock = [1000.0]
    monkeypatch.setattr(accounts, "_now", lambda: clock[0])
    for _ in range(accounts.MAX_FAILS):
        with pytest.raises(accounts.AuthError):
            accounts.authenticate("alice", "nope nope nope")
    with pytest.raises(accounts.AuthError) as e:
        accounts.authenticate("alice", PW)                      # even the right password is refused while locked
    assert e.value.reason == "locked"
    clock[0] += accounts.LOCK_SECONDS + 1
    assert accounts.authenticate("alice", PW)["username"] == "alice"
    for _ in range(accounts.MAX_FAILS):
        with pytest.raises(accounts.AuthError):
            accounts.authenticate("alice", "nope nope nope")
    accounts.update_user(u["id"], unlock=True)
    assert accounts.authenticate("alice", PW)


def test_inactive_users_cannot_sign_in():
    u = user("bob", "admin")
    user("alice", "admin")
    accounts.update_user(u["id"], active=False)
    with pytest.raises(accounts.AuthError):
        accounts.authenticate("bob", PW)


def test_the_last_active_admin_cannot_be_removed():
    a = user("root", "admin")
    with pytest.raises(ValueError, match="administrator"):
        accounts.update_user(a["id"], role="viewer")
    with pytest.raises(ValueError, match="administrator"):
        accounts.update_user(a["id"], active=False)
    b = user("second", "admin")
    assert accounts.update_user(a["id"], role="viewer")["role"] == "viewer"
    with pytest.raises(ValueError):
        accounts.update_user(b["id"], role="assessor")


# ---- sessions ----------------------------------------------------------------------------------------

def test_sessions_work_expire_and_are_stored_hashed(monkeypatch):
    u = user()
    clock = [5000.0]
    monkeypatch.setattr(accounts, "_now", lambda: clock[0])
    token = accounts.create_session(u["id"], "10.0.0.1", "agent")
    assert accounts.session_user(token)["username"] == "alice" and accounts.session_user("wrong") is None and accounts.session_user(None) is None
    assert token not in json.dumps([dict(r) for r in db.conn().execute("SELECT * FROM sessions")])
    clock[0] += accounts.SESSION_IDLE - 10
    assert accounts.session_user(token)                          # activity keeps it alive
    clock[0] += accounts.SESSION_IDLE + 10
    assert accounts.session_user(token) is None                  # idle too long
    t2 = accounts.create_session(u["id"])
    for _ in range(12):                                          # active every hour: alive right up to the 12 hour limit
        clock[0] += 3600
        assert accounts.session_user(t2)
    clock[0] += 1
    assert accounts.session_user(t2) is None                     # but the absolute limit still ends it


def test_role_changes_password_resets_and_logout_end_sessions():
    u = user("carol", "assessor")
    user("root", "admin")
    t = accounts.create_session(u["id"])
    accounts.update_user(u["id"], role="viewer")
    assert accounts.session_user(t) is None
    t = accounts.create_session(u["id"])
    accounts.update_user(u["id"], password="a brand new passphrase")
    assert accounts.session_user(t) is None and accounts.authenticate("carol", "a brand new passphrase")
    t = accounts.create_session(u["id"])
    accounts.end_session(t)
    assert accounts.session_user(t) is None


def test_changing_your_own_password_needs_the_current_one_and_keeps_only_this_session():
    u = user()
    t1, t2 = accounts.create_session(u["id"]), accounts.create_session(u["id"])
    with pytest.raises(ValueError, match="current"):
        accounts.change_own_password(u["id"], "wrong", "another long passphrase", t1)
    accounts.change_own_password(u["id"], PW, "another long passphrase", t1)
    assert accounts.session_user(t1) and accounts.session_user(t2) is None


# ---- audit log -------------------------------------------------------------------------------------------

def test_audit_chain_verifies_and_detects_edits_and_deletions():
    for i in range(5):
        audit.log("alice", "scan.run", f"app{i}", {"flows": i}, "10.0.0.1", "assessor")
    assert audit.verify()["ok"] and audit.verify()["checked"] == 5
    with db.tx() as c:
        c.execute("UPDATE audit SET actor='mallory' WHERE id=3")
    bad = audit.verify()
    assert not bad["ok"] and bad["brokenAt"] == 3
    with db.tx() as c:
        c.execute("UPDATE audit SET actor='alice' WHERE id=3")
    assert audit.verify()["ok"]
    with db.tx() as c:
        c.execute("DELETE FROM audit WHERE id=2")
    assert not audit.verify()["ok"]


def test_audit_never_stores_credentials_and_filters_and_exports():
    audit.log("bob", "user.create", "carol", {"password": "hunter2hunter2", "api_token": "abc", "path": "C:/x", "role": "viewer"})
    audit.log("bob", "login.fail", "bob")
    e = audit.entries(action="user.")[0]
    assert e["detail"] == {"path": "C:/x", "role": "viewer"}
    assert "hunter2" not in json.dumps(audit.entries()) and len(audit.entries(actor="bob")) == 2
    assert audit.entries(limit=1)[0]["action"] == "login.fail" and audit.entries(before_id=2)[0]["id"] == 1
    csv = audit.to_csv()
    assert "user.create" in csv and audit.verify()["head"] in csv and "hunter2" not in csv


# ---- shared data -------------------------------------------------------------------------------------------

def test_applications_round_trip_and_are_validated():
    app = {"id": "a1", "name": "HR flows", "description": "d", "workingDir": "", "createdAt": "2026-01-01T00:00:00Z",
           "flows": [{"filename": "f.json", "content": {"x": 1}}]}
    saved = store.save_application(app, "alice")
    assert saved["flows"] == app["flows"] and saved["updatedBy"] == "alice" and saved["createdAt"] == app["createdAt"]
    app["name"] = "Renamed"
    assert store.save_application(app, "bob")["name"] == "Renamed" and len(store.list_applications()) == 1
    with pytest.raises(ValueError):
        store.save_application({"id": "", "name": "x"}, "a")
    with pytest.raises(ValueError):
        store.save_application({"id": "b", "name": "x", "flows": [{"nofilename": 1}]}, "a")
    assert store.delete_application("a1") and not store.delete_application("a1")


def test_assessments_issues_and_policy():
    rec = {"id": "r1", "createdAt": "2026-01-02T00:00:00Z", "source": "upload", "appId": "a1", "appName": "HR", "config": "Normal scan",
           "disabled": ["PA-TRG-002"], "completed": False, "response": {"environmentId": "uploaded", "results": []}}
    out = store.add_assessment(rec, "alice")
    assert out["appName"] == "HR" and out["disabled"] == ["PA-TRG-002"] and out["createdBy"] == "alice"
    store.add_assessment({**rec, "id": "r2", "createdAt": "2026-01-03T00:00:00Z"}, "alice")
    assert [r["id"] for r in store.list_assessments()] == ["r2", "r1"]
    assert store.set_completed("r1") and store.list_assessments()[1]["completed"]
    assert store.delete_assessment("r2") and store.delete_all_assessments() == 1
    with pytest.raises(ValueError):
        store.add_assessment({"id": "x"}, "a")

    assert store.set_issue("k", "alice", "Accepted risk", "approved by CISO")["status"] == "Accepted risk"
    assert store.set_issue("k", "bob", comment="updated")["status"] == "Accepted risk"          # a partial update keeps the status
    with pytest.raises(ValueError):
        store.set_issue("k", "alice", "Banana")
    assert store.get_policy()["name"] == "Normal scan"
    assert store.set_policy({"name": "Strict", "disabled": ["PA-TRG-002"], "severity": {"PA-ACT-002": "High", "X": "Banana"}})["severity"] == {"PA-ACT-002": "High"}


def test_import_never_overwrites_and_reports_counts():
    store.save_application({"id": "a1", "name": "Server copy", "flows": []}, "root")
    store.set_issue("k1", "root", "Fixed", "server")
    bundle = {"applications": [{"id": "a1", "name": "Browser copy", "flows": []}, {"id": "a2", "name": "New", "flows": []}],
              "assessments": [{"id": "r1", "response": {"results": []}}],
              "issues": {"k1": {"status": "Noise", "comment": "browser"}, "k2": {"status": "Open", "comment": ""}},
              "policy": {"name": "Browser policy"}}
    assert store.import_bundle(bundle, "alice") == {"applications": 1, "assessments": 1, "issues": 1, "policy": 1}
    boot = store.bootstrap()
    assert {a["id"]: a["name"] for a in boot["applications"]} == {"a1": "Server copy", "a2": "New"}
    assert boot["issues"]["k1"]["comment"] == "server" and boot["policy"]["name"] == "Browser policy"
    assert store.import_bundle(bundle, "alice") == {"applications": 0, "assessments": 0, "issues": 0, "policy": 0}

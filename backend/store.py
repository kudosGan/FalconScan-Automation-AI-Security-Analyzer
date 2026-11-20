"""Shared application data: applications, assessments, triage state and the active scan policy.

The shapes match what the browser app already uses, so the same screens work on top of the shared database.
"""
import json
from datetime import datetime, timezone

import customrules
import db

ISSUE_STATUSES = ("Open", "In progress", "Fixed", "Accepted risk", "Noise")
MAX_ASSESSMENTS_RETURNED = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(v, limit: int) -> str:
    return str(v if v is not None else "")[:limit]


def _app_row(r) -> dict:
    return {"id": r["id"], "name": r["name"], "description": r["description"], "workingDir": r["working_dir"],
            "createdAt": r["created_at"], "updatedAt": r["updated_at"], "updatedBy": r["updated_by"], "flows": json.loads(r["flows_json"])}


def list_applications() -> list[dict]:
    return [_app_row(r) for r in db.conn().execute("SELECT * FROM applications ORDER BY created_at")]


def save_application(app: dict, user: str) -> dict:
    """Create or replace an application (including its files)."""
    aid = _text(app.get("id"), 64)
    if not aid or not _text(app.get("name"), 200).strip():
        raise ValueError("An application needs an id and a name.")
    flows = app.get("flows") if isinstance(app.get("flows"), list) else []
    if not all(isinstance(f, dict) and isinstance(f.get("filename"), str) and "content" in f for f in flows):
        raise ValueError("Each file needs a filename and content.")
    created = _text(app.get("createdAt"), 40) or _now()
    with db.tx() as c:
        c.execute("""INSERT INTO applications(id, name, description, working_dir, created_at, updated_at, updated_by, flows_json)
                     VALUES (?,?,?,?,?,?,?,?)
                     ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, working_dir=excluded.working_dir,
                       updated_at=excluded.updated_at, updated_by=excluded.updated_by, flows_json=excluded.flows_json""",
                  (aid, _text(app["name"], 200), _text(app.get("description"), 2000), _text(app.get("workingDir"), 500),
                   created, _now(), user, json.dumps(flows)))
        return _app_row(c.execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone())


def delete_application(app_id: str) -> bool:
    with db.tx() as c:
        return c.execute("DELETE FROM applications WHERE id=?", (app_id,)).rowcount > 0


def _assessment_row(r) -> dict:
    out = {"id": r["id"], "createdAt": r["created_at"], "createdBy": r["created_by"], "source": r["source"],
           "response": json.loads(r["response_json"]), "completed": bool(r["completed"])}
    if r["app_id"]:
        out["appId"] = r["app_id"]
    if r["app_name"]:
        out["appName"] = r["app_name"]
    if r["config"]:
        out["config"] = r["config"]
    out["disabled"] = json.loads(r["disabled_json"])
    return out


def list_assessments(limit: int = MAX_ASSESSMENTS_RETURNED) -> list[dict]:
    rows = db.conn().execute("SELECT * FROM assessments ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 1000)),))
    return [_assessment_row(r) for r in rows]


def add_assessment(rec: dict, user: str) -> dict:
    rid = _text(rec.get("id"), 64)
    if not rid or not isinstance(rec.get("response"), dict):
        raise ValueError("An assessment needs an id and a response.")
    with db.tx() as c:
        c.execute("""INSERT OR REPLACE INTO assessments(id, app_id, app_name, created_at, created_by, source, config, disabled_json, completed, response_json)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (rid, _text(rec.get("appId"), 64) or None, _text(rec.get("appName"), 200) or None, _text(rec.get("createdAt"), 40) or _now(),
                   user, _text(rec.get("source"), 20) or "upload", _text(rec.get("config"), 200) or None,
                   json.dumps(rec.get("disabled") if isinstance(rec.get("disabled"), list) else []), int(bool(rec.get("completed"))),
                   json.dumps(rec["response"])))
        return _assessment_row(c.execute("SELECT * FROM assessments WHERE id=?", (rid,)).fetchone())


def set_completed(rec_id: str) -> bool:
    with db.tx() as c:
        return c.execute("UPDATE assessments SET completed=1 WHERE id=?", (rec_id,)).rowcount > 0


def delete_assessment(rec_id: str) -> bool:
    with db.tx() as c:
        return c.execute("DELETE FROM assessments WHERE id=?", (rec_id,)).rowcount > 0


def delete_all_assessments() -> int:
    with db.tx() as c:
        return c.execute("DELETE FROM assessments").rowcount


def all_issues() -> dict:
    return {r["key"]: {"status": r["status"], "comment": r["comment"], "updatedAt": r["updated_at"], "updatedBy": r["updated_by"]}
            for r in db.conn().execute("SELECT * FROM issues")}


def set_issue(key: str, user: str, status: str | None = None, comment: str | None = None) -> dict:
    key = _text(key, 600)
    if not key:
        raise ValueError("Missing issue key.")
    if status is not None and status not in ISSUE_STATUSES:
        raise ValueError("Unknown status.")
    with db.tx() as c:
        cur = c.execute("SELECT * FROM issues WHERE key=?", (key,)).fetchone()
        st = status if status is not None else (cur["status"] if cur else "Open")
        cm = _text(comment, 4000) if comment is not None else (cur["comment"] if cur else "")
        c.execute("INSERT INTO issues(key, status, comment, updated_at, updated_by) VALUES (?,?,?,?,?) "
                  "ON CONFLICT(key) DO UPDATE SET status=excluded.status, comment=excluded.comment, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                  (key, st, cm, _now(), user))
    return all_issues()[key]


def get_setting(key: str, default=None):
    r = db.conn().execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r["value_json"]) if r else default


def set_setting(key: str, value) -> None:
    with db.tx() as c:
        c.execute("INSERT INTO settings(key, value_json) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                  (key, json.dumps(value)))


DEFAULT_POLICY = {"name": "Normal scan", "disabled": [], "severity": {}, "custom": []}


def get_policy() -> dict:
    return {**DEFAULT_POLICY, **(get_setting("policy", {}) or {})}


def set_policy(p: dict) -> dict:
    sev = {k: v for k, v in (p.get("severity") or {}).items() if v in ("High", "Medium", "Low")}
    clean = {"name": _text(p.get("name"), 100) or DEFAULT_POLICY["name"],
             "disabled": [str(x)[:40] for x in (p.get("disabled") or [])][:200], "severity": sev,
             "custom": customrules.clean(p.get("custom"))}
    set_setting("policy", clean)
    return clean


def tickets_by_key() -> dict:
    return {r["issue_key"]: {"system": r["system"], "id": r["external_id"], "url": r["url"], "createdAt": r["created_at"], "createdBy": r["created_by"]}
            for r in db.conn().execute("SELECT * FROM tickets")}


def bootstrap() -> dict:
    return {"applications": list_applications(), "assessments": list_assessments(), "issues": all_issues(),
            "policy": get_policy(), "tickets": tickets_by_key()}


def import_bundle(bundle: dict, user: str) -> dict:
    """One-time move of browser-saved data into the shared database. Existing records are never overwritten."""
    counts = {"applications": 0, "assessments": 0, "issues": 0, "policy": 0}
    have_apps = {a["id"] for a in list_applications()}
    for a in bundle.get("applications") or []:
        if isinstance(a, dict) and a.get("id") and a["id"] not in have_apps:
            save_application(a, user); counts["applications"] += 1
    have_rec = {r["id"] for r in db.conn().execute("SELECT id FROM assessments")}
    for r in bundle.get("assessments") or []:
        if isinstance(r, dict) and r.get("id") and r["id"] not in have_rec and isinstance(r.get("response"), dict):
            add_assessment(r, user); counts["assessments"] += 1
    have_issues = set(all_issues())
    for k, v in (bundle.get("issues") or {}).items():
        if k not in have_issues and isinstance(v, dict) and v.get("status") in ISSUE_STATUSES:
            set_issue(k, user, v["status"], v.get("comment", "")); counts["issues"] += 1
    if isinstance(bundle.get("policy"), dict) and get_setting("policy") is None:
        set_policy(bundle["policy"]); counts["policy"] = 1
    return counts

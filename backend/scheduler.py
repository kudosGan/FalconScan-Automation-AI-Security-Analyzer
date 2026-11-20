"""Scheduled scans.

A schedule re-scans either a saved application or a folder on the server, on a fixed interval, stores the result as an assessment and
records whether the release gate would pass (no open finding at or above the schedule's level, ignoring findings you have marked
Fixed, Accepted risk or Noise). Folder schedules only read inside FALCON_SCAN_ROOT, so a schedule cannot be pointed at arbitrary files.
Run the backend as a single process: several workers would each run the schedules.
"""
import os
import pathlib
import secrets
import threading
import time
from datetime import datetime, timezone

import audit
import db
import dispatch
import gate
import store

MIN_INTERVAL = 15
MAX_FILES = 300
MAX_BYTES = 150 * 1024 * 1024
_run_locks: dict[int, threading.Lock] = {}
_thread: threading.Thread | None = None
_stop = threading.Event()
LEVELS = ("High", "Medium", "Low", "none")


def scan_root() -> pathlib.Path | None:
    r = os.environ.get("FALCON_SCAN_ROOT")
    return pathlib.Path(r).resolve() if r and pathlib.Path(r).is_dir() else None


def _row(r) -> dict:
    return {"id": r["id"], "name": r["name"], "sourceType": r["source_type"], "sourceRef": r["source_ref"], "intervalMinutes": r["interval_minutes"],
            "failOn": r["fail_on"], "enabled": bool(r["enabled"]), "nextRun": r["next_run_ts"], "lastRun": r["last_run_ts"],
            "lastStatus": r["last_status"], "lastAssessmentId": r["last_assessment_id"], "createdBy": r["created_by"], "createdAt": r["created_at"]}


def list_schedules() -> list[dict]:
    return [_row(r) for r in db.conn().execute("SELECT * FROM schedules ORDER BY id")]


def _validate(name, source_type, source_ref, interval, fail_on) -> None:
    if not str(name).strip():
        raise ValueError("A schedule needs a name.")
    if source_type not in ("application", "folder"):
        raise ValueError("The source must be an application or a folder.")
    if not isinstance(interval, int) or interval < MIN_INTERVAL or interval > 60 * 24 * 90:
        raise ValueError(f"The interval must be between {MIN_INTERVAL} minutes and 90 days.")
    if fail_on not in LEVELS:
        raise ValueError("The gate level must be High, Medium, Low or none.")
    if source_type == "application":
        if not db.conn().execute("SELECT 1 FROM applications WHERE id=?", (source_ref,)).fetchone():
            raise ValueError("That application does not exist.")
    else:
        root = scan_root()
        if root is None:
            raise ValueError("Folder schedules are off: the server has no FALCON_SCAN_ROOT folder.")
        _inside(root, source_ref)


def _inside(root: pathlib.Path, ref: str) -> pathlib.Path:
    p = (root / ref).resolve()
    if not (p == root or root in p.parents):
        raise ValueError("That folder is outside the allowed scan folder.")
    if not p.exists():
        raise ValueError("That folder does not exist.")
    return p


def create(name: str, source_type: str, source_ref: str, interval_minutes: int, fail_on: str, user: str) -> dict:
    _validate(name, source_type, source_ref, interval_minutes, fail_on)
    now = time.time()
    with db.tx() as c:
        cur = c.execute("INSERT INTO schedules(name, source_type, source_ref, interval_minutes, fail_on, next_run_ts, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (name.strip()[:100], source_type, source_ref.strip()[:500], interval_minutes, fail_on, now + interval_minutes * 60, user,
                         datetime.now(timezone.utc).isoformat()))
        return _row(c.execute("SELECT * FROM schedules WHERE id=?", (cur.lastrowid,)).fetchone())


def update(sid: int, **changes) -> dict:
    row = db.conn().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    if not row:
        raise ValueError("No such schedule.")
    cur = _row(row)
    new = {**cur, **{k: v for k, v in changes.items() if v is not None}}
    _validate(new["name"], new["sourceType"], new["sourceRef"], new["intervalMinutes"], new["failOn"])
    with db.tx() as c:
        c.execute("UPDATE schedules SET name=?, interval_minutes=?, fail_on=?, enabled=?, next_run_ts=? WHERE id=?",
                  (new["name"].strip()[:100], new["intervalMinutes"], new["failOn"], int(bool(new["enabled"])),
                   time.time() + new["intervalMinutes"] * 60 if new["intervalMinutes"] != cur["intervalMinutes"] else cur["nextRun"], sid))
    return _row(db.conn().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone())


def delete(sid: int) -> bool:
    with db.tx() as c:
        return c.execute("DELETE FROM schedules WHERE id=?", (sid,)).rowcount > 0


def _new_id() -> str:
    return format(int(time.time() * 1000), "x") + secrets.token_hex(2)


def _collect_folder(sched: dict) -> list[dict]:
    import falconscan                                # imported here: it pulls in the whole scanner stack
    root = scan_root()
    if root is None:
        raise ValueError("The server has no FALCON_SCAN_ROOT folder.")
    p = _inside(root, sched["sourceRef"])
    items, _notes, errors = falconscan.collect([str(p)])
    if errors:
        raise ValueError("; ".join(errors)[:300])
    if not items:
        raise ValueError("No flow, agent or RPA files were found in that folder.")
    if len(items) > MAX_FILES or sum(len(str(i["content"])) for i in items) > MAX_BYTES:
        raise ValueError(f"The folder has too many or too large files (limit {MAX_FILES} files).")
    out = []
    for i in items:
        try:
            name = str(pathlib.Path(i["file"]).relative_to(p))     # a file inside the folder: keep its path below the folder
        except ValueError:
            name = pathlib.Path(i["file"]).name if pathlib.Path(i["file"]).is_file() else i["file"]    # an archive entry keeps its "pack.zip:Main.xaml" label
        out.append({"filename": name, "content": i["content"]})
    return out


def _verdict(results: list[dict], app_id: str, fail_on: str) -> tuple[bool, int, dict]:
    """(passed, blocking count, counts). Findings marked Fixed, Accepted risk or Noise do not block, as in the workbench."""
    v = gate.evaluate(results, {"failOn": fail_on})
    issues = store.all_issues()
    blocking = [b for b in v["blocking"] if issues.get(f"{app_id}|{b['fingerprint']}", {}).get("status", "Open") not in ("Fixed", "Accepted risk", "Noise")]
    return not blocking, len(blocking), v["counts"]


def run(sid: int, actor: str = "scheduler", now: float | None = None) -> dict:
    """Run one schedule now. Returns the updated schedule. `now` lets the caller keep one clock for the whole cycle."""
    lock = _run_locks.setdefault(sid, threading.Lock())
    if not lock.acquire(blocking=False):
        raise ValueError("That schedule is already running.")
    try:
        row = db.conn().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
        if not row:
            raise ValueError("No such schedule.")
        s = _row(row)
        status, rec_id = "", None
        try:
            if s["sourceType"] == "application":
                app = next((a for a in store.list_applications() if a["id"] == s["sourceRef"]), None)
                if app is None:
                    raise ValueError("The application no longer exists.")
                app_id, app_name, files = app["id"], app["name"], app["flows"]
            else:
                app_id, app_name, files = f"sched-{sid}", f"Schedule: {s['name']}", _collect_folder(s)
                store.save_application({"id": app_id, "name": app_name, "description": f"Files read from {s['sourceRef']}", "flows": files}, "scheduler")
            if not files:
                raise ValueError("The application has no files to scan.")
            pol = store.get_policy()
            results = gate.scan_items([{"file": f["filename"], "content": f["content"]} for f in files],
                                      {"disabled": pol["disabled"], "severity": pol["severity"]})
            rec_id = _new_id()
            store.add_assessment({"id": rec_id, "createdAt": datetime.now(timezone.utc).isoformat(), "source": "scheduled", "appId": app_id, "appName": app_name,
                                  "config": pol["name"], "disabled": pol["disabled"], "completed": True,
                                  "response": {"environmentId": "uploaded", "results": results}}, f"schedule:{s['name']}")
            if s["failOn"] == "none":
                status = "Scanned"
            else:
                ok, n, _ = _verdict(results, app_id, s["failOn"])
                status = "Gate passed" if ok else f"Gate failed: {n} blocking finding(s)"
            errs = sum(1 for r in results if r.get("error"))
            if errs:
                status += f" ({errs} file(s) could not be read)"
        except Exception as e:
            status = f"Error: {str(e)[:200]}"
        now = time.time() if now is None else now
        with db.tx() as c:
            c.execute("UPDATE schedules SET last_run_ts=?, last_status=?, last_assessment_id=?, next_run_ts=? WHERE id=?",
                      (now, status, rec_id, now + s["intervalMinutes"] * 60, sid))
        audit.log(actor, "schedule.run", s["name"], {"status": status, "assessment": rec_id or ""}, role="system" if actor == "scheduler" else "")
        return _row(db.conn().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone())
    finally:
        lock.release()


def run_due(now: float | None = None) -> list[int]:
    """Run every enabled schedule that is due. Each is claimed first, so two processes cannot run the same one."""
    now = time.time() if now is None else now
    ran = []
    for r in db.conn().execute("SELECT id, next_run_ts FROM schedules WHERE enabled=1 AND next_run_ts<=?", (now,)).fetchall():
        with db.tx() as c:
            claimed = c.execute("UPDATE schedules SET next_run_ts=? WHERE id=? AND next_run_ts=?", (now + 3600, r["id"], r["next_run_ts"])).rowcount
        if claimed:
            try:
                run(r["id"], now=now)
            except ValueError:
                pass
            ran.append(r["id"])
    return ran


def _loop() -> None:
    while not _stop.wait(30):
        try:
            run_due()
        except Exception:
            pass                                        # never let one bad cycle stop the scheduler


def start() -> None:
    global _thread
    if os.environ.get("FALCON_SCHEDULER", "on").lower() in ("off", "0", "false") or (_thread and _thread.is_alive()):
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="falcon-scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()

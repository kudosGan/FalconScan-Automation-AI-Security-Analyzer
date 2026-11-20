"""Append-only audit log with a hash chain.

Every entry stores the hash of the one before it, so editing or removing an entry in the middle breaks the chain and verify()
reports where. Truncating the newest entries cannot be detected from inside the database; export the log (with its head hash)
and keep a copy elsewhere if you need that guarantee.
"""
import hashlib
import json
import threading
from datetime import datetime, timezone

import db

_lock = threading.Lock()
GENESIS = "0" * 64
SECRET_WORDS = ("password", "passwd", "token", "secret", "api_key", "apikey", "authorization", "cookie")


def _scrub(detail: dict | None) -> dict:
    """Never write credentials into the log, whatever the caller passes."""
    out = {}
    for k, v in (detail or {}).items():
        if str(k).lower() == "pat" or any(w in str(k).lower() for w in SECRET_WORDS):
            continue
        out[str(k)] = v if isinstance(v, (int, float, bool, type(None))) else str(v)[:500]
    return out


def _digest(prev: str, ts, actor, role, action, target, detail, ip) -> str:
    body = json.dumps([prev, ts, actor, role, action, target, detail, ip], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def log(actor: str, action: str, target: str = "", detail: dict | None = None, ip: str = "", role: str = "") -> int:
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    d = json.dumps(_scrub(detail), sort_keys=True, ensure_ascii=True)
    with _lock, db.tx() as c:
        last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else GENESIS
        h = _digest(prev, ts, actor, role, action, target, d, ip)
        cur = c.execute("INSERT INTO audit(ts, actor, role, action, target, detail, ip, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                        (ts, actor, role, action, target, d, ip, prev, h))
        return cur.lastrowid


def entries(limit: int = 200, before_id: int | None = None, actor: str = "", action: str = "") -> list[dict]:
    q, args = "SELECT id, ts, actor, role, action, target, detail, ip, hash FROM audit WHERE 1=1", []
    if before_id:
        q += " AND id < ?"; args.append(before_id)
    if actor:
        q += " AND actor = ?"; args.append(actor)
    if action:
        q += " AND action LIKE ?"; args.append(action + "%")
    q += " ORDER BY id DESC LIMIT ?"; args.append(max(1, min(limit, 1000)))
    return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in db.conn().execute(q, args)]


def verify() -> dict:
    prev, n = GENESIS, 0
    for r in db.conn().execute("SELECT * FROM audit ORDER BY id"):
        n += 1
        if r["prev_hash"] != prev or r["hash"] != _digest(r["prev_hash"], r["ts"], r["actor"], r["role"], r["action"], r["target"], r["detail"], r["ip"]):
            return {"ok": False, "checked": n, "brokenAt": r["id"], "head": prev}
        prev = r["hash"]
    return {"ok": True, "checked": n, "brokenAt": None, "head": prev}


def to_csv() -> str:
    q = lambda v: '"' + str(v if v is not None else "").replace('"', '""') + '"'
    rows = ["id,time,actor,role,action,target,detail,ip,hash"]
    for e in reversed(entries(limit=1000)):
        rows.append(",".join(q(e[k]) if k != "detail" else q(json.dumps(e[k], sort_keys=True)) for k in
                            ("id", "ts", "actor", "role", "action", "target", "detail", "ip", "hash")))
    return "﻿" + "\r\n".join(rows) + f"\r\n# head hash: {verify()['head']}\r\n"

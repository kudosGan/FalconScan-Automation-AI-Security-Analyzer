"""Local user accounts, roles and sessions.

Passwords are hashed with scrypt and a per-user salt. Session tokens are random, only their SHA-256 hash is stored, and they expire
(12 hours in all, 2 hours idle). Five wrong passwords lock the account for 15 minutes. Roles:
  viewer   read everything, change nothing
  assessor run scans, manage applications, triage, tickets, schedules
  admin    everything, plus users and the audit log
"""
import base64
import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timezone

import db

ROLES = {"viewer": 1, "assessor": 2, "admin": 3}
MIN_PASSWORD = 12
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60
SESSION_ABSOLUTE = 12 * 3600
SESSION_IDLE = 2 * 3600
TOUCH_EVERY = 60
_now = time.time                      # tests replace this to move the clock
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@\-]{2,63}$")
COMMON = {"password1234", "passw0rd1234", "123456789012", "qwertyuiop12", "administrator", "letmein12345", "welcome12345"}
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


class AuthError(Exception):
    def __init__(self, message: str, reason: str = "denied"):
        super().__init__(message)
        self.reason = reason


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, h = stored.split("$")
        if scheme != "scrypt":
            return False
        want = base64.b64decode(h)
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), **_SCRYPT)
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False


_DUMMY = hash_password("not-a-real-password")          # checked when the user does not exist, so timing does not reveal it


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"The password must be at least {MIN_PASSWORD} characters.")
    if password.lower() in COMMON or (username and username.lower() in password.lower()):
        raise ValueError("That password is too easy to guess. Use a longer phrase that does not contain the username.")
    if len(set(password)) < 5:
        raise ValueError("The password needs more variety.")


def public(row) -> dict:
    return {"id": row["id"], "username": row["username"], "displayName": row["display_name"] or row["username"], "role": row["role"],
            "active": bool(row["active"]), "createdAt": row["created_at"], "lastLogin": row["last_login"],
            "locked": row["locked_until"] > _now()}


def count_users() -> int:
    return db.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_user(user_id: int):
    return db.conn().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def list_users() -> list[dict]:
    return [public(r) for r in db.conn().execute("SELECT * FROM users ORDER BY username")]


def create_user(username: str, password: str, role: str = "viewer", display_name: str = "", only_if_empty: bool = False) -> dict:
    username = username.strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError("Usernames are 3 to 64 characters: letters, digits and . _ @ -")
    if role not in ROLES:
        raise ValueError("Role must be viewer, assessor or admin.")
    check_password_policy(password, username)
    try:
        with db.tx() as c:
            if only_if_empty and c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                raise ValueError("Setup is already done: an account exists.")
            cur = c.execute("INSERT INTO users(username, display_name, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                            (username, display_name.strip()[:100], hash_password(password), role, datetime.now(timezone.utc).isoformat()))
            return public(c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ValueError("That username is already taken.")
        raise


def _active_admins(c) -> int:
    return c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]


def update_user(user_id: int, role: str | None = None, active: bool | None = None, password: str | None = None,
                display_name: str | None = None, unlock: bool = False) -> dict:
    with db.tx() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise ValueError("No such user.")
        new_role = role if role is not None else row["role"]
        new_active = int(active) if active is not None else row["active"]
        if new_role not in ROLES:
            raise ValueError("Role must be viewer, assessor or admin.")
        if row["role"] == "admin" and row["active"] and (new_role != "admin" or not new_active) and _active_admins(c) <= 1:
            raise ValueError("There must always be at least one active administrator.")
        sets, args = ["role=?", "active=?"], [new_role, new_active]
        if display_name is not None:
            sets.append("display_name=?"); args.append(display_name.strip()[:100])
        if password is not None:
            check_password_policy(password, row["username"])
            sets.append("password_hash=?"); args.append(hash_password(password))
        if unlock:
            sets += ["failed_count=0", "locked_until=0"]
        c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", (*args, user_id))
        if password is not None or new_role != row["role"] or not new_active:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))      # take effect immediately
        return public(c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def change_own_password(user_id: int, current: str, new: str, keep_token: str | None = None) -> None:
    row = get_user(user_id)
    if not row or not verify_password(current, row["password_hash"]):
        raise ValueError("The current password is not correct.")
    check_password_policy(new, row["username"])
    with db.tx() as c:
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), user_id))
        keep = hashlib.sha256(keep_token.encode()).hexdigest() if keep_token else ""
        c.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, keep))


def authenticate(username: str, password: str) -> dict:
    username = username.strip().lower()
    row = db.conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    msg = "Incorrect username or password."
    if row is None:
        verify_password(password, _DUMMY)
        raise AuthError(msg, "unknown_user")
    if row["locked_until"] > _now():
        verify_password(password, _DUMMY)
        raise AuthError("Too many failed attempts. Try again in a few minutes, or ask an administrator to unlock the account.", "locked")
    ok = verify_password(password, row["password_hash"])
    if not ok or not row["active"]:
        if not ok:
            fails = row["failed_count"] + 1
            with db.tx() as c:
                if fails >= MAX_FAILS:
                    c.execute("UPDATE users SET failed_count=0, locked_until=? WHERE id=?", (_now() + LOCK_SECONDS, row["id"]))
                else:
                    c.execute("UPDATE users SET failed_count=? WHERE id=?", (fails, row["id"]))
            raise AuthError(msg, "locked_now" if fails >= MAX_FAILS else "bad_password")
        raise AuthError(msg, "inactive")
    with db.tx() as c:
        c.execute("UPDATE users SET failed_count=0, locked_until=0, last_login=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), row["id"]))
    return public(get_user(row["id"]))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: int, ip: str = "", user_agent: str = "") -> str:
    token = secrets.token_urlsafe(32)
    t = _now()
    with db.tx() as c:
        c.execute("DELETE FROM sessions WHERE expires_ts < ?", (t,))
        c.execute("INSERT INTO sessions(token_hash, user_id, created_ts, last_seen_ts, expires_ts, ip, user_agent) VALUES (?,?,?,?,?,?,?)",
                  (_hash_token(token), user_id, t, t, t + SESSION_ABSOLUTE, ip[:64], user_agent[:200]))
    return token


def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    h, t = _hash_token(token), _now()
    s = db.conn().execute("SELECT * FROM sessions WHERE token_hash=?", (h,)).fetchone()
    if not s:
        return None
    if t > s["expires_ts"] or t - s["last_seen_ts"] > SESSION_IDLE:
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
        return None
    user = get_user(s["user_id"])
    if not user or not user["active"]:
        return None
    if t - s["last_seen_ts"] > TOUCH_EVERY:
        with db.tx() as c:
            c.execute("UPDATE sessions SET last_seen_ts=? WHERE token_hash=?", (t, h))
    return public(user)


def end_session(token: str | None) -> None:
    if token:
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_hash_token(token),))

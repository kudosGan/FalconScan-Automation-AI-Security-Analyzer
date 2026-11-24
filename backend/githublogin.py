"""Sign in with GitHub (OAuth web flow), limited to a list of GitHub usernames.

Environment:
  FALCON_GITHUB_CLIENT_ID / FALCON_GITHUB_CLIENT_SECRET   from the GitHub OAuth app
  FALCON_GITHUB_USERS     allowed accounts, "alice:admin,bob:assessor,carol" (the role defaults to assessor)
  FALCON_PUBLIC_URL       the address people use, e.g. https://example.onrender.com (needed behind a proxy)
The GitHub OAuth app's callback URL is <public url>/api/account/github/callback.
"""
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

import accounts
import audit
import db

STATE_COOKIE = "falcon_gh_state"
AUTHORIZE = "https://github.com/login/oauth/authorize"
TOKEN = "https://github.com/login/oauth/access_token"
USER_API = "https://api.github.com/user"
router = APIRouter(tags=["account"])


def configured() -> bool:
    return bool(os.environ.get("FALCON_GITHUB_CLIENT_ID") and os.environ.get("FALCON_GITHUB_CLIENT_SECRET"))


def allowed_users() -> dict[str, str]:
    out: dict[str, str] = {}
    for item in (os.environ.get("FALCON_GITHUB_USERS") or "").split(","):
        name, _, role = item.strip().partition(":")
        name, role = name.strip().lower(), (role.strip().lower() or "assessor")
        if name and role in accounts.ROLES:
            out[name] = role
    return out


def _site(request: Request) -> str:
    return (os.environ.get("FALCON_PUBLIC_URL") or "").rstrip("/")


def _callback(request: Request) -> str:
    root = (request.scope.get("root_path") or "").rstrip("/")          # "/api" when the API is mounted under the website
    base = _site(request) + root if _site(request) else str(request.base_url).rstrip("/")
    return base + "/account/github/callback"


def _fail(request: Request, message: str) -> RedirectResponse:
    r = RedirectResponse(f"{_site(request)}/login?{urlencode({'error': message})}", status_code=302)
    r.delete_cookie(STATE_COOKIE, path="/")
    return r


def _upsert(login: str, name: str, role: str) -> dict:
    username = "gh-" + login.lower()
    now = datetime.now(timezone.utc).isoformat()
    with db.tx() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            # Nobody can sign in with this password: it is random and never shown.
            c.execute("INSERT INTO users(username, display_name, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                      (username, (name or login)[:100], accounts.hash_password(secrets.token_urlsafe(32)), role, now))
        else:
            if row["role"] != role:                              # the list in the environment is the authority
                c.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
            c.execute("UPDATE users SET role=?, last_login=? WHERE id=?", (role, now, row["id"]))
        uid = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
    return accounts.public(accounts.get_user(uid))


@router.get("/account/github/start")
def github_start(request: Request):
    if not configured():
        return _fail(request, "Sign in with GitHub is not set up on this server.")
    state = secrets.token_urlsafe(24)
    url = AUTHORIZE + "?" + urlencode({"client_id": os.environ["FALCON_GITHUB_CLIENT_ID"], "redirect_uri": _callback(request),
                                       "scope": "", "state": state, "allow_signup": "false"})
    r = RedirectResponse(url, status_code=302)
    secure = request.url.scheme == "https" or os.environ.get("FALCON_COOKIE_SECURE") == "1"
    r.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax", secure=secure, max_age=600, path="/")   # Lax: it must come back from github.com
    return r


@router.get("/account/github/callback")
def github_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    from enterprise import _set_cookie, client_ip              # imported here: enterprise imports this module
    ip = client_ip(request)
    want = request.cookies.get(STATE_COOKIE) or ""
    if not configured():
        return _fail(request, "Sign in with GitHub is not set up on this server.")
    if error or not code or not want or not secrets.compare_digest(want, state):
        return _fail(request, "The GitHub sign-in was cancelled or expired. Please try again.")
    try:
        with httpx.Client(timeout=15, headers={"Accept": "application/json"}) as h:
            t = h.post(TOKEN, data={"client_id": os.environ["FALCON_GITHUB_CLIENT_ID"], "client_secret": os.environ["FALCON_GITHUB_CLIENT_SECRET"],
                                    "code": code, "redirect_uri": _callback(request)}).json()
            access = t.get("access_token")
            if not access:
                return _fail(request, "GitHub did not accept the sign-in. Please try again.")
            u = h.get(USER_API, headers={"Authorization": f"Bearer {access}", "X-GitHub-Api-Version": "2022-11-28"}).json()
    except (httpx.HTTPError, ValueError):
        return _fail(request, "Could not reach GitHub. Please try again.")
    login = str(u.get("login") or "").lower()
    role = allowed_users().get(login)
    if not login or role is None:
        audit.log("gh-" + (login or "?")[:60], "login.fail", "", {"reason": "github_not_allowed"}, ip)
        return _fail(request, "That GitHub account is not allowed to use this app.")
    user = _upsert(login, str(u.get("name") or ""), role)
    r = RedirectResponse(_site(request) + "/workbench", status_code=302)
    r.delete_cookie(STATE_COOKIE, path="/")
    _set_cookie(r, request, accounts.create_session(user["id"], ip, request.headers.get("user-agent", "")))
    audit.log(user["username"], "login.success", "", {"via": "github"}, ip, user["role"])
    return r

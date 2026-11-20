"""HTTP layer for sign-in, roles, shared data, the audit log, schedules and tickets.

Install with enterprise.install(app). Sign-in is on unless FALCON_AUTH=off. When it is on:
  * every request except /account/state, /account/login and /account/setup needs a valid session cookie;
  * every request that changes something must also send the header X-Falcon-CSRF: 1 (the cookie is SameSite=Strict as well);
  * each route needs a minimum role (see needed_role) and a refused request is written to the audit log.
"""
import hmac
import os
from contextlib import asynccontextmanager

from fastapi import APIRouter, Body, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

import accounts
import audit
import db
import scheduler
import store
import tickets

COOKIE = "falcon_session"
CSRF_HEADER = "x-falcon-csrf"
SAFE = {"GET", "HEAD", "OPTIONS"}
LOCAL_USER = {"id": 0, "username": "local", "displayName": "Local user", "role": "admin", "active": True,
              "createdAt": None, "lastLogin": None, "locked": False}
PUBLIC = {("GET", "/account/state"), ("POST", "/account/login"), ("POST", "/account/setup")}
AUDITED = {("POST", "/scan/upload"): "scan.run", ("POST", "/scan"): "scan.run.live", ("POST", "/gate"): "gate.run",
           ("POST", "/fix"): "fix.generate", ("POST", "/report/pdf"): "report.pdf", ("POST", "/solution/extract"): "solution.import"}


def auth_enabled() -> bool:
    return os.environ.get("FALCON_AUTH", "on").strip().lower() not in ("off", "0", "false", "no")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def needed_role(method: str, path: str) -> str:
    if path.startswith("/admin/"):
        return "admin"
    if method == "DELETE" and path == "/data/assessments":
        return "admin"
    if path.startswith(("/auth/", "/environments")):
        return "assessor"                       # Power Platform sign-in and tenant listing
    if path.startswith("/account/") or (method, path) == ("POST", "/report/pdf"):
        return "viewer"
    return "viewer" if method in SAFE else "assessor"


async def gate_middleware(request: Request, call_next):
    method, path = request.method, request.url.path
    if not auth_enabled():
        request.state.user, request.state.token = LOCAL_USER, None
        return await call_next(request)
    if method == "OPTIONS":
        return await call_next(request)
    token = request.cookies.get(COOKIE)
    user = await run_in_threadpool(accounts.session_user, token)
    request.state.user, request.state.token = user, token
    if method not in SAFE and request.headers.get(CSRF_HEADER) != "1":
        return JSONResponse({"detail": "Missing request header."}, status_code=403)
    if (method, path) not in PUBLIC:
        if user is None:
            return JSONResponse({"detail": "Sign in required."}, status_code=401)
        need = needed_role(method, path)
        if accounts.ROLES[user["role"]] < accounts.ROLES[need]:
            await run_in_threadpool(audit.log, user["username"], "access.denied", f"{method} {path}"[:200], {"needed": need}, client_ip(request), user["role"])
            return JSONResponse({"detail": f"This needs the {need} role. You are signed in as {user['role']}."}, status_code=403)
    response = await call_next(request)
    act = AUDITED.get((method, path))
    if act and user and response.status_code < 400:
        await run_in_threadpool(audit.log, user["username"], act, path, {}, client_ip(request), user["role"])
    return response


def me(request: Request) -> dict:
    return request.state.user


def bad(e: Exception, code: int = 400) -> HTTPException:
    return HTTPException(code, str(e))


def _set_cookie(response: Response, request: Request, token: str) -> None:
    secure = request.url.scheme == "https" or os.environ.get("FALCON_COOKIE_SECURE") == "1"
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, max_age=accounts.SESSION_ABSOLUTE, path="/")


# ---- accounts ----------------------------------------------------------------------------------------------
account = APIRouter(tags=["account"])


class Creds(BaseModel):
    username: str
    password: str


class Setup(Creds):
    displayName: str = ""
    setupToken: str = ""


class PasswordChange(BaseModel):
    current: str
    new: str


@account.get("/account/state")
def account_state(request: Request):
    if not auth_enabled():
        return {"authEnabled": False, "setupRequired": False, "user": LOCAL_USER}
    return {"authEnabled": True, "setupRequired": accounts.count_users() == 0, "user": request.state.user}


@account.post("/account/setup")
def account_setup(body: Setup, request: Request, response: Response):
    ip = client_ip(request)
    token = os.environ.get("FALCON_SETUP_TOKEN") or ""
    if not (ip in ("127.0.0.1", "::1", "localhost") or (token and hmac.compare_digest(token, body.setupToken))):
        raise HTTPException(403, "The first administrator can only be created on the server itself, or with the setup token (FALCON_SETUP_TOKEN).")
    try:
        user = accounts.create_user(body.username, body.password, "admin", body.displayName, only_if_empty=True)
    except ValueError as e:
        raise bad(e, 409 if "already" in str(e) else 400)
    _set_cookie(response, request, accounts.create_session(user["id"], ip, request.headers.get("user-agent", "")))
    audit.log(user["username"], "setup.admin_created", user["username"], {}, ip, "admin")
    return {"user": user}


@account.post("/account/login")
def account_login(body: Creds, request: Request, response: Response):
    ip = client_ip(request)
    try:
        user = accounts.authenticate(body.username, body.password)
    except accounts.AuthError as e:
        who = body.username.strip().lower()[:64] or "?"
        audit.log(who, "login.blocked" if e.reason == "locked" else "login.fail", "", {"reason": e.reason}, ip)
        if e.reason == "locked_now":
            audit.log(who, "account.locked", who, {}, ip)
        raise HTTPException(401, str(e))
    _set_cookie(response, request, accounts.create_session(user["id"], ip, request.headers.get("user-agent", "")))
    audit.log(user["username"], "login.success", "", {}, ip, user["role"])
    return {"user": user}


@account.post("/account/logout")
def account_logout(request: Request, response: Response):
    u = me(request)
    accounts.end_session(request.state.token)
    response.delete_cookie(COOKIE, path="/")
    audit.log(u["username"], "logout", "", {}, client_ip(request), u["role"])
    return {"status": "signed_out"}


@account.post("/account/password")
def account_password(body: PasswordChange, request: Request):
    u = me(request)
    try:
        accounts.change_own_password(u["id"], body.current, body.new, request.state.token)
    except ValueError as e:
        raise bad(e)
    audit.log(u["username"], "password.change", u["username"], {}, client_ip(request), u["role"])
    return {"status": "changed"}


# ---- administration ----------------------------------------------------------------------------------------
admin = APIRouter(tags=["admin"])


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    displayName: str = ""


class UserPatch(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None
    displayName: str | None = None
    unlock: bool = False


@admin.get("/admin/users")
def admin_users():
    return accounts.list_users()


@admin.post("/admin/users")
def admin_create_user(body: NewUser, request: Request):
    try:
        u = accounts.create_user(body.username, body.password, body.role, body.displayName)
    except ValueError as e:
        raise bad(e)
    a = me(request)
    audit.log(a["username"], "user.create", u["username"], {"role": u["role"]}, client_ip(request), a["role"])
    return u


@admin.patch("/admin/users/{uid}")
def admin_update_user(uid: int, body: UserPatch, request: Request):
    a = me(request)
    try:
        target = accounts.get_user(uid)
        u = accounts.update_user(uid, body.role, body.active, body.password, body.displayName, body.unlock)
    except ValueError as e:
        raise bad(e)
    changed = {k: v for k, v in {"role": body.role, "active": body.active, "displayName": body.displayName}.items() if v is not None}
    if body.password:
        changed["passwordReset"] = True
    if body.unlock:
        changed["unlocked"] = True
    audit.log(a["username"], "user.update", target["username"] if target else str(uid), changed, client_ip(request), a["role"])
    return u


@admin.get("/admin/audit")
def admin_audit(limit: int = 200, before: int | None = None, actor: str = "", action: str = ""):
    return {"entries": audit.entries(limit, before, actor, action), "verify": audit.verify()}


@admin.get("/admin/audit/verify")
def admin_audit_verify():
    return audit.verify()


@admin.get("/admin/audit.csv")
def admin_audit_csv(request: Request):
    a = me(request)
    audit.log(a["username"], "audit.export", "", {}, client_ip(request), a["role"])
    return Response(audit.to_csv(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="falconscan-audit.csv"'})


# ---- shared data -------------------------------------------------------------------------------------------
data = APIRouter(tags=["data"])


def _log(request: Request, action: str, target: str = "", detail: dict | None = None) -> None:
    u = me(request)
    audit.log(u["username"], action, target[:200], detail, client_ip(request), u["role"])


@data.get("/data/bootstrap")
def data_bootstrap():
    return store.bootstrap()


@data.post("/data/applications")
def data_save_application(request: Request, body: dict = Body(...)):
    try:
        app = store.save_application(body, me(request)["username"])
    except ValueError as e:
        raise bad(e)
    _log(request, "app.save", app["name"], {"id": app["id"], "files": len(app["flows"])})
    return app


@data.put("/data/applications/{app_id}")
def data_put_application(app_id: str, request: Request, body: dict = Body(...)):
    return data_save_application(request, {**body, "id": app_id})


@data.delete("/data/applications/{app_id}")
def data_delete_application(app_id: str, request: Request):
    if not store.delete_application(app_id):
        raise HTTPException(404, "No such application.")
    _log(request, "app.delete", app_id)
    return {"status": "deleted"}


@data.post("/data/assessments")
def data_add_assessment(request: Request, body: dict = Body(...)):
    try:
        rec = store.add_assessment(body, me(request)["username"])
    except ValueError as e:
        raise bad(e)
    _log(request, "assessment.add", rec.get("appName", "") or rec["id"], {"id": rec["id"], "flows": len(rec["response"].get("results", []))})
    return rec


@data.patch("/data/assessments/{rec_id}")
def data_complete_assessment(rec_id: str):
    if not store.set_completed(rec_id):
        raise HTTPException(404, "No such assessment.")
    return {"status": "completed"}


@data.delete("/data/assessments/{rec_id}")
def data_delete_assessment(rec_id: str, request: Request):
    if not store.delete_assessment(rec_id):
        raise HTTPException(404, "No such assessment.")
    _log(request, "assessment.delete", rec_id)
    return {"status": "deleted"}


@data.delete("/data/assessments")
def data_delete_all_assessments(request: Request):
    n = store.delete_all_assessments()
    _log(request, "assessment.clear_all", "", {"count": n})
    return {"deleted": n}


@data.put("/data/issues")
def data_set_issue(request: Request, body: dict = Body(...)):
    try:
        out = store.set_issue(str(body.get("key", "")), me(request)["username"], body.get("status"), body.get("comment"))
    except ValueError as e:
        raise bad(e)
    _log(request, "issue.update", str(body.get("key", ""))[:120], {"status": out["status"]})
    return out


@data.put("/data/policy")
def data_set_policy(request: Request, body: dict = Body(...)):
    pol = store.set_policy(body)
    _log(request, "policy.update", pol["name"], {"disabledRules": len(pol["disabled"]), "overrides": len(pol["severity"])})
    return pol


@data.post("/data/import")
def data_import(request: Request, body: dict = Body(...)):
    counts = store.import_bundle(body, me(request)["username"])
    _log(request, "data.import", "", counts)
    return counts


# ---- schedules ---------------------------------------------------------------------------------------------
sched = APIRouter(tags=["schedules"])


class ScheduleIn(BaseModel):
    name: str
    sourceType: str
    sourceRef: str
    intervalMinutes: int
    failOn: str = "High"


class SchedulePatch(BaseModel):
    name: str | None = None
    intervalMinutes: int | None = None
    failOn: str | None = None
    enabled: bool | None = None


@sched.get("/schedules")
def schedules_list():
    root = scheduler.scan_root()
    return {"schedules": scheduler.list_schedules(), "folderSchedules": root is not None, "scanRootName": root.name if root else None,
            "minIntervalMinutes": scheduler.MIN_INTERVAL}


@sched.post("/schedules")
def schedules_create(body: ScheduleIn, request: Request):
    try:
        s = scheduler.create(body.name, body.sourceType, body.sourceRef, body.intervalMinutes, body.failOn, me(request)["username"])
    except ValueError as e:
        raise bad(e)
    _log(request, "schedule.create", s["name"], {"source": s["sourceType"], "everyMinutes": s["intervalMinutes"], "failOn": s["failOn"]})
    return s


@sched.patch("/schedules/{sid}")
def schedules_update(sid: int, body: SchedulePatch, request: Request):
    try:
        s = scheduler.update(sid, name=body.name, intervalMinutes=body.intervalMinutes, failOn=body.failOn, enabled=body.enabled)
    except ValueError as e:
        raise bad(e)
    _log(request, "schedule.update", s["name"], {k: v for k, v in body.model_dump().items() if v is not None})
    return s


@sched.delete("/schedules/{sid}")
def schedules_delete(sid: int, request: Request):
    if not scheduler.delete(sid):
        raise HTTPException(404, "No such schedule.")
    _log(request, "schedule.delete", str(sid))
    return {"status": "deleted"}


@sched.post("/schedules/{sid}/run")
def schedules_run(sid: int, request: Request):
    try:
        return scheduler.run(sid, actor=me(request)["username"])
    except ValueError as e:
        raise bad(e)


# ---- tickets -----------------------------------------------------------------------------------------------
tix = APIRouter(tags=["tickets"])


@tix.get("/tickets/config")
def tickets_config():
    return tickets.config()


@tix.post("/tickets")
def tickets_create(request: Request, body: dict = Body(...)):
    try:
        t = tickets.create(body, me(request)["username"])
    except tickets.TicketError as e:
        raise bad(e, 409 if "already has" in str(e) else 502 if "refused" in str(e) or "reach" in str(e) else 400)
    _log(request, "ticket.create", f"{t['system']}:{t['id']}", {"rule": t.get("ruleId", ""), "url": t["url"]})
    return t


def install(app) -> None:
    app.middleware("http")(gate_middleware)
    for r in (account, admin, data, sched, tix):
        app.include_router(r)
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a):
        db.conn()                         # create the database on start-up so the first request does not pay for it
        scheduler.start()
        try:
            async with inner(a) as state:
                yield state
        finally:
            scheduler.stop()
    app.router.lifespan_context = lifespan

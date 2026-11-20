import base64
import binascii
import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import auth
import pp_client
import agentscan  # noqa: F401  (registers the AI rule guidance)
import customrules
import dispatch
import enterprise
import fixer
import rpascan  # noqa: F401  (registers the RPA rule guidance)
import gate
import pdf
import scanner
from flowio import extract_solution, normalize as _normalize
from platforms import PLATFORMS
from rules import RULES

app = FastAPI(title="Falcon Scan - Automation & AI Security Analyzer")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["*"], allow_headers=["*"])
enterprise.install(app)    # sign-in, roles, shared data, audit log, schedules and tickets


def _guard(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, str(e))


@app.post("/auth/login")
def login():
    return _guard(auth.start_device_login)


@app.get("/auth/status")
def auth_status():
    return auth.status()


@app.post("/auth/logout")
def logout():
    auth.logout()
    return {"status": "signed_out"}


@app.get("/environments")
def environments():
    return _guard(pp_client.list_environments)


@app.get("/environments/{env_id}/flows")
def flows(env_id: str, admin: bool = False):
    return _guard(pp_client.list_flows, env_id, admin)


class Policy(BaseModel):
    disabled: list[str] = []
    severity: dict[str, str] = {}
    custom: list[dict] = []   # custom text rules, see customrules.py
    dlp: dict | None = None   # optional DLP connector policy: {business, nonBusiness, blocked, defaultGroup}


@app.get("/platforms")
def platforms():
    """Supported and planned automation platforms. Only status "active" can be scanned."""
    return PLATFORMS


@app.get("/rules")
def rules():
    """Rule catalog with default severities and CWE/OWASP references."""
    return RULES


class ScanRequest(BaseModel):
    policy: Policy | None = None
    environmentId: str
    flowIds: list[str]
    admin: bool = False


def _scan_live(flow: dict, policy: dict | None) -> dict:
    return customrules.apply(scanner.scan_flow(flow, policy), flow, (policy or {}).get("custom"))


@app.post("/scan")
def scan(req: ScanRequest):
    results = []
    for fid in req.flowIds:
        try:
            results.append(_scan_live(_guard(pp_client.get_flow, req.environmentId, fid, req.admin), req.policy.model_dump() if req.policy else None))
        except HTTPException as e:
            results.append({"flowId": fid, "name": fid, "error": e.detail, "findings": [],
                            "connectors": [], "risk": "Unknown", "score": 0})
    return {"environmentId": req.environmentId, "results": results}


class UploadedFile(BaseModel):
    filename: str
    content: dict


class UploadRequest(BaseModel):
    files: list[UploadedFile]
    policy: Policy | None = None


class SolutionRequest(BaseModel):
    filename: str
    contentBase64: str


@app.post("/solution/extract")
def solution_extract(req: SolutionRequest):
    """Read cloud flows out of a Power Platform solution .zip. The flows come back as ordinary uploads."""
    try:
        return extract_solution(base64.b64decode(req.contentBase64, validate=True))
    except (ValueError, binascii.Error) as e:
        raise HTTPException(400, str(e))


class FixRequest(BaseModel):
    filename: str
    content: dict
    policy: Policy | None = None


@app.post("/fix")
def fix(req: FixRequest):
    """A corrected copy of the flow for the findings with a safe automatic fix, plus what was and was not changed."""
    try:
        return fixer.fix_flow(req.filename, req.content, req.policy.model_dump() if req.policy else None)
    except ValueError as e:
        raise HTTPException(400, str(e))


class PdfRequest(BaseModel):
    html: str


@app.post("/report/pdf")
def report_pdf(req: PdfRequest):
    """Print a finished report (HTML) to PDF using the Edge or Chrome already installed on this machine."""
    try:
        return Response(pdf.html_to_pdf(req.html), media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="report.pdf"'})
    except ValueError as e:
        raise HTTPException(413, str(e))
    except RuntimeError as e:
        raise HTTPException(501, str(e))


class Waiver(BaseModel):
    ruleId: str
    reason: str = ""
    expires: str = ""
    flow: str | None = None
    location: str | None = None
    owner: str | None = None


class GateRequest(BaseModel):
    files: list[UploadedFile]
    failOn: str = "High"
    disabled: list[str] = []
    severity: dict[str, str] = {}
    dlp: dict | None = None
    waivers: list[Waiver] = []


@app.post("/gate")
def release_gate(req: GateRequest):
    """Scan the files and decide whether they may go to production under the given policy."""
    policy = req.model_dump(exclude={"files"})
    try:
        results = gate.scan_items([{"file": f.filename, "content": f.content} for f in req.files], policy)
        return {"gate": gate.evaluate(results, policy), "results": results}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/scan/upload")
def scan_upload(req: UploadRequest):
    """Scan flow JSON files supplied by the user. No Microsoft sign-in needed."""
    results = []
    for f in req.files:
        try:
            results.append(dispatch.scan_any(f.filename, f.content, req.policy.model_dump() if req.policy else None))
        except Exception as e:
            results.append({"flowId": f.filename, "name": f.filename, "error": str(e), "findings": [],
                            "connectors": [], "risk": "Unknown", "score": 0})
    return {"environmentId": "uploaded", "results": results}


@app.get("/environments/{env_id}/flows/{flow_id}")
def flow(env_id: str, flow_id: str, admin: bool = False):
    return _guard(pp_client.get_flow, env_id, flow_id, admin)

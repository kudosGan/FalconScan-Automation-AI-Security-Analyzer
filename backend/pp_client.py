"""Thin read-only client for Power Platform / Power Automate management APIs.

Only metadata + flow definitions are fetched; never run history or payloads.
"""
import httpx
from auth import get_token, SCOPE_BAP, SCOPE_FLOW

BAP = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform"
FLOW = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple"


def _get(url: str, scope: list[str], params: dict | None = None) -> dict:
    r = httpx.get(url, params=params, timeout=60,
                  headers={"Authorization": f"Bearer {get_token(scope)}"})
    if r.status_code >= 400:
        raise httpx.HTTPStatusError(f"{r.status_code}: {r.text[:500]}", request=r.request, response=r)
    return r.json()


def list_environments() -> list[dict]:
    data = _get(f"{BAP}/environments", SCOPE_BAP, {"api-version": "2020-10-01"})
    return [{
        "id": e["name"],
        "displayName": e["properties"].get("displayName"),
        "type": e["properties"].get("environmentSku"),
        "isDefault": e["properties"].get("isDefault", False),
        "location": e.get("location"),
    } for e in data.get("value", [])]


def list_flows(env_id: str, admin: bool = False) -> list[dict]:
    """admin=True lists ALL flows in the environment (needs Power Platform admin);
    otherwise only flows the signed-in user owns or can access."""
    if admin:
        url = f"{FLOW}/scopes/admin/environments/{env_id}/v2/flows"
    else:
        url = f"{FLOW}/environments/{env_id}/flows"
    params = {"api-version": "2016-11-01"}
    out = []
    while url:
        data = _get(url, SCOPE_FLOW, params)
        for f in data.get("value", []):
            p = f.get("properties", {})
            out.append({
                "id": f["name"],
                "displayName": p.get("displayName"),
                "state": p.get("state"),
                "createdTime": p.get("createdTime"),
                "lastModifiedTime": p.get("lastModifiedTime"),
                "creator": (p.get("creator") or {}).get("userId"),
            })
        url, params = data.get("nextLink"), None
    return out


def get_flow(env_id: str, flow_id: str, admin: bool = False) -> dict:
    """Full flow resource including properties.definition (the JSON to analyze)."""
    base = f"{FLOW}/scopes/admin/environments/{env_id}" if admin else f"{FLOW}/environments/{env_id}"
    return _get(f"{base}/flows/{flow_id}", SCOPE_FLOW, {"api-version": "2016-11-01"})

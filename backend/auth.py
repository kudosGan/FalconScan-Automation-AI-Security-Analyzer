"""Entra ID auth via MSAL device-code flow (delegated, read-only).

One sign-in; MSAL's token cache silently mints tokens for each Power Platform
resource (BAP for environments, Flow service for flows) via the refresh token.
"""
import os
import threading
import msal
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID", "organizations")
CLIENT_ID = os.getenv("CLIENT_ID", "")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

SCOPE_BAP = ["https://api.bap.microsoft.com/.default"]
SCOPE_FLOW = ["https://service.flow.microsoft.com/.default"]

_app: msal.PublicClientApplication | None = None
_state: dict = {"status": "signed_out", "error": None, "user": None}
_account: dict | None = None


def _msal() -> msal.PublicClientApplication:
    global _app
    if not CLIENT_ID:
        raise RuntimeError("CLIENT_ID is not set. Copy backend/.env.example to backend/.env.")
    if _app is None:
        _app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
    return _app


def start_device_login() -> dict:
    """Begin device-code flow; returns the code/URL for the user. Completion runs in background."""
    global _state
    flow = _msal().initiate_device_flow(scopes=SCOPE_BAP)
    if "user_code" not in flow:
        raise RuntimeError(flow.get("error_description", "Failed to start device flow"))
    _state = {"status": "pending", "error": None, "user": None}
    threading.Thread(target=_complete, args=(flow, _state), daemon=True).start()
    return {"user_code": flow["user_code"], "verification_uri": flow["verification_uri"],
            "message": flow["message"]}


def _complete(flow: dict, state: dict) -> None:
    global _account
    result = _msal().acquire_token_by_device_flow(flow)  # blocks until the user signs in
    if "access_token" in result:
        accounts = _msal().get_accounts()
        _account = accounts[0] if accounts else None
        state["user"] = result.get("id_token_claims", {}).get("preferred_username")
        state["status"] = "signed_in"
    else:
        state["status"] = "error"
        state["error"] = result.get("error_description", "Login failed")


def status() -> dict:
    return dict(_state)


def get_token(scopes: list[str]) -> str:
    if not _account:
        raise PermissionError("Not signed in")
    result = _msal().acquire_token_silent(scopes, account=_account)
    if not result or "access_token" not in result:
        raise PermissionError("Token request failed; check API permissions/consent, or sign in again")
    return result["access_token"]


def logout() -> None:
    global _account, _state
    if _account:
        _msal().remove_account(_account)
    _account = None
    _state = {"status": "signed_out", "error": None, "user": None}

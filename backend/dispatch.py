"""One entry point that decides what a file is and scans it with the right analyser.

Order: AI agent / MCP configuration, then RPA file (UiPath, Automation Anywhere, Blue Prism), then Power Automate flow.
"""
import agentscan
import customrules
import rpascan
import scanner
from flowio import normalize

# File extensions the app reads as text and wraps for scanning.
RPA_TEXT_EXTENSIONS = tuple(rpascan.EXT_PLATFORM) + (".xml",)


def kind_of(content) -> str | None:
    """'mcp' | 'agent' | 'uipath-project' | 'uipath-xaml' | 'automation-anywhere' | 'blue-prism' | None (None means not recognised here)."""
    return agentscan.kind_of(content) or rpascan.kind_of(content)


def scan_any(filename: str, content: dict, policy: dict | None = None) -> dict:
    result = _scan(filename, content, policy)
    return customrules.apply(result, content, (policy or {}).get("custom"))


def _scan(filename: str, content: dict, policy: dict | None) -> dict:
    if agentscan.kind_of(content):
        return agentscan.scan_agent(filename, content, policy)
    if rpascan.kind_of(content):
        return rpascan.scan_rpa(filename, content, policy)
    try:
        return scanner.scan_flow(normalize(filename, content), policy)
    except ValueError:
        raise ValueError("Not a Power Automate flow, MCP configuration, AI agent definition or RPA file (UiPath, Automation Anywhere, Blue Prism).")


def wrap_text(filename: str, text: str) -> dict:
    """The wrapper object an RPA text file travels in."""
    return {"format": "rpa-file", "name": filename, "text": text}

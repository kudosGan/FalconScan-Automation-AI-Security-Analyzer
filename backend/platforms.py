"""Registry of automation platforms Falcon Scan can assess.

Power Automate (scanner.scan_flow) and AI agent / MCP configuration files (agentscan.scan_agent) are implemented. Planned platforms are listed
so the UI and API can describe the roadmap; they have no adapter and no scanning.

A future adapter converts platform-specific input into the common model the
analysis engine consumes, then returns the standard findings shape that
`scanner.scan_flow` already produces.
"""

PLATFORMS = [
    {"id": "power-platform", "name": "Microsoft Power Platform", "phase": 1, "status": "active",
     "adapter": "scanner.scan_flow"},
    {"id": "uipath", "name": "UiPath", "phase": 2, "status": "active", "adapter": "rpascan.scan_rpa",
     "scope": "project.json and .xaml workflows (credentials, HTTP, code, SQL, logging, dependencies). Orchestrator and robot settings are planned."},
    {"id": "other-rpa", "name": "Other RPA platforms", "phase": 3, "status": "limited", "adapter": "rpascan.scan_rpa",
     "scope": "Automation Anywhere (.bot, .atmx) and Blue Prism (.bprelease, .bpobject, .bpprocess): basic schema-free checks only, not verified against real exports."},
    {"id": "ai-agents", "name": "AI and agentic automation", "phase": 4, "status": "active", "adapter": "agentscan.scan_agent",
     "scope": "MCP server configurations and agent definition JSON (heuristic static checks). Copilot Studio exports and runtime testing are planned."},
]

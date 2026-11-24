"""Rule catalog: every check the scanner can raise, with its default severity and standards references.

CWE / OWASP references are indicative mappings to help triage and reporting. They are not a certification.
"""

OWASP_A01 = "A01:2021 Broken Access Control"
OWASP_A02 = "A02:2021 Cryptographic Failures"
OWASP_A03 = "A03:2021 Injection"
OWASP_A04 = "A04:2021 Insecure Design"
OWASP_A06 = "A06:2021 Vulnerable and Outdated Components"
OWASP_A07 = "A07:2021 Identification and Authentication Failures"
OWASP_A09 = "A09:2021 Security Logging and Monitoring Failures"
OWASP_LLM01 = "LLM01:2025 Prompt Injection"
OWASP_LLM02 = "LLM02:2025 Sensitive Information Disclosure"
OWASP_LLM03 = "LLM03:2025 Supply Chain"
OWASP_LLM05 = "LLM05:2025 Improper Output Handling"
OWASP_LLM06 = "LLM06:2025 Excessive Agency"

# OWASP Low-Code/No-Code Top 10. The same ten risks the platform security strategy lists; every rule below maps to exactly one.
LCNC = {
    "LCNC-SEC-01": "Account Impersonation",
    "LCNC-SEC-02": "Authorization Misuse",
    "LCNC-SEC-03": "Data Leakage and Unexpected Consequences",
    "LCNC-SEC-04": "Authentication and Secure Communication Failures",
    "LCNC-SEC-05": "Security Misconfiguration",
    "LCNC-SEC-06": "Injection Handling Failures",
    "LCNC-SEC-07": "Vulnerable and Untrusted Components",
    "LCNC-SEC-08": "Data and Secret Handling Failures",
    "LCNC-SEC-09": "Asset Management Failures",
    "LCNC-SEC-10": "Security Logging and Monitoring Failures",
}
_L = {
    "PA-TRG-001": "02", "PA-TRG-002": "09", "PA-TRG-003": "04", "PA-ACT-001": "04", "PA-ACT-002": "03", "PA-ACT-003": "04",
    "PA-ACT-004": "03", "PA-SEC-001": "08", "PA-CFG-001": "08", "PA-CFG-002": "10", "PA-GOV-001": "09", "PA-GOV-002": "02",
    "PA-GOV-003": "09", "PA-CON-001": "03", "PA-CON-002": "07", "PA-CON-003": "07", "PA-AI-001": "03", "PA-DLP-001": "05",
    "PA-DLP-002": "03",
    "AG-SEC-001": "08", "AG-MCP-001": "04", "AG-MCP-002": "04", "AG-MCP-003": "07", "AG-MCP-004": "06", "AG-MCP-005": "02",
    "AG-MCP-006": "05", "AG-MCP-007": "04", "AG-MCP-008": "02", "AG-AGT-001": "02", "AG-AGT-002": "02", "AG-AGT-003": "06",
    "AG-AGT-004": "06", "AG-AGT-005": "03", "AG-AGT-006": "02", "AG-LLM-001": "03", "AG-LLM-002": "04", "AG-A2A-001": "02",
    "RPA-SEC-001": "08", "RPA-NET-001": "04", "RPA-CODE-001": "06", "RPA-CODE-002": "06", "UIP-DB-001": "06", "UIP-LOG-001": "08",
    "UIP-PRJ-001": "07", "UIP-PRJ-002": "08", "UIP-PRJ-003": "07",
    "WF-TRG-001": "04", "WF-TRG-002": "04", "WF-SEC-001": "08", "WF-NET-001": "04", "WF-NET-002": "04", "WF-CODE-001": "06",
    "WF-CODE-002": "06", "WF-INJ-001": "06", "WF-AI-001": "03", "WF-CFG-001": "10", "WF-CFG-002": "03", "WF-CFG-003": "10",
    "WF-GOV-001": "09",
}


def _r(rule_id, title, severity, category, cwe=None, owasp=None, description=""):
    return {"id": rule_id, "title": title, "severity": severity, "category": category,
            "cwe": cwe, "owasp": owasp, "description": description}


RULES: list[dict] = [
    _r("PA-TRG-001", "HTTP request trigger", "Medium", "Trigger exposure", "CWE-284", OWASP_A01,
       "Anyone holding the callback URL can start the flow."),
    _r("PA-TRG-002", "Scheduled trigger", "Low", "Governance", None, None,
       "Runs unattended; needs an owner and a business need."),
    _r("PA-TRG-003", "HTTP trigger open to anyone", "High", "Trigger exposure", "CWE-306", OWASP_A07,
       "triggerAuthenticationType allows any caller."),
    _r("PA-ACT-001", "Unencrypted HTTP call", "High", "Action configuration", "CWE-319", OWASP_A02,
       "Data sent over plain http://."),
    _r("PA-ACT-002", "External HTTP call", "Medium", "Action configuration", "CWE-200", OWASP_A01,
       "Data may leave the tenant."),
    _r("PA-ACT-003", "HTTP action without authentication", "Medium", "Action configuration", "CWE-306", OWASP_A07,
       "No authentication block on an HTTP action."),
    _r("PA-ACT-004", "Email sent to a personal mailbox", "Medium", "Data exposure", "CWE-201", OWASP_A04,
       "Recipients are consumer mail domains."),
    _r("PA-SEC-001", "Hard-coded secret", "High", "Secret handling", "CWE-798", OWASP_A07,
       "A credential is typed into the flow definition."),
    _r("PA-CFG-001", "Secure inputs/outputs not enabled", "Low", "Configuration", "CWE-532", OWASP_A09,
       "Values appear in run history."),
    _r("PA-CFG-002", "Terminate forces success", "Low", "Configuration", "CWE-703", OWASP_A04,
       "Failures may be masked."),
    _r("PA-GOV-001", "Flow is not running", "Low", "Governance", None, None,
       "Stopped or suspended flows should be reviewed or removed."),
    _r("PA-GOV-002", "High connector count", "Low", "Governance", "CWE-250", OWASP_A04,
       "Many connectors widen the access the flow holds."),
    _r("PA-GOV-003", "Premium connector", "Low", "Governance", None, None,
       "Needs a premium licence and approval."),
    _r("PA-CON-001", "Sensitive data flows to a third party", "Medium", "Data exposure", "CWE-200", OWASP_A04,
       "Data read from Microsoft 365 reaches a third-party service."),
    _r("PA-CON-002", "Third-party connector", "Low", "Connections", "CWE-1357", OWASP_A06,
       "Data leaves Microsoft 365 to a third-party service."),
    _r("PA-CON-003", "Custom or unlisted connector", "Low", "Connections", "CWE-1357", OWASP_A06,
       "Destination is defined by the connector's author."),
    _r("PA-AI-001", "Data exposed to an AI service", "Medium", "Data exposure", "CWE-200", OWASP_LLM02,
       "Content is sent to an AI service."),
    _r("PA-DLP-001", "Connector blocked by DLP policy", "High", "DLP policy", "CWE-284", OWASP_A01,
       "The flow uses a connector your data loss prevention policy blocks. Only checked when a DLP policy is supplied."),
    _r("PA-DLP-002", "Business and non-business connectors mixed", "High", "DLP policy", "CWE-668", OWASP_A04,
       "The flow connects a business-data connector to a non-business one, which a DLP policy forbids. Only checked when a DLP policy is supplied."),
    # ---- AI agents and MCP servers (agentscan.py): heuristic static checks of configuration files ----
    _r("AG-SEC-001", "Hard-coded secret in AI configuration", "High", "Secret handling", "CWE-798", OWASP_LLM02,
       "A key, token or password is typed into an agent or MCP configuration."),
    _r("AG-MCP-001", "Remote MCP server over plain HTTP", "High", "MCP server", "CWE-319", OWASP_A02,
       "Tool calls and results travel unencrypted to a non-local server."),
    _r("AG-MCP-002", "Remote MCP server with no credential configured", "Medium", "MCP server", "CWE-306", OWASP_LLM06,
       "No key, token or sign-in is configured; anyone who can reach the server may be able to use its tools."),
    _r("AG-MCP-003", "MCP server runs an unpinned package or image", "Medium", "MCP server", "CWE-829", OWASP_LLM03,
       "The code that runs can change without review (latest version, no version, or an untagged image)."),
    _r("AG-MCP-004", "MCP server started through a shell or inline code", "High", "MCP server", "CWE-78", OWASP_A03,
       "The server is launched with a shell command or interpreter code string."),
    _r("AG-MCP-005", "MCP server with broad file access", "High", "MCP server", "CWE-732", OWASP_LLM06,
       "A file server is allowed to read a drive root or a whole home folder."),
    _r("AG-MCP-006", "MCP container with host-level access", "High", "MCP server", "CWE-250", OWASP_LLM06,
       "A container runs privileged or mounts sensitive host paths."),
    _r("AG-MCP-007", "TLS certificate checking disabled", "High", "MCP server", "CWE-295", OWASP_A02,
       "Connections accept any certificate, so they can be intercepted."),
    _r("AG-MCP-008", "Tool calls approved automatically", "Medium", "MCP server", "CWE-862", OWASP_LLM06,
       "Tools run without asking a person first."),
    _r("AG-AGT-001", "Code execution or computer-control tool", "Medium", "Agent permissions", "CWE-94", OWASP_LLM06,
       "The agent can run code, shell commands or control a computer."),
    _r("AG-AGT-002", "Powerful tool without a human approval step", "Medium", "Agent permissions", "CWE-862", OWASP_LLM06,
       "A tool that sends, changes or deletes things has no approval requirement."),
    _r("AG-AGT-003", "Tool accepts unconstrained free-form input", "Medium", "Tool calling", "CWE-20", OWASP_LLM05,
       "A parameter such as a command, query or path takes any text, so model output reaches it unchecked."),
    _r("AG-AGT-004", "Prompt-injection path to an action tool", "Medium", "Prompt injection", "CWE-1427", OWASP_LLM01,
       "Content from outside can reach the model, and the same agent can take actions."),
    _r("AG-AGT-005", "Private data can leave through a tool", "Medium", "Data exposure", "CWE-200", OWASP_LLM02,
       "The agent can read private data and also send data out."),
    _r("AG-AGT-006", "Excessive or wildcard permissions", "Medium", "Agent permissions", "CWE-250", OWASP_LLM06,
       "Permissions, scopes or allowed tools are set to everything or to an administrator level."),
    _r("AG-LLM-001", "Model endpoint outside your cloud tenant", "Low", "Data exposure", "CWE-200", OWASP_LLM02,
       "Prompts and data go to a third-party model provider."),
    _r("AG-LLM-002", "Model endpoint over plain HTTP", "High", "Data exposure", "CWE-319", OWASP_A02,
       "Prompts and responses travel unencrypted."),
    _r("AG-A2A-001", "Agent delegates to other agents", "Low", "Agent-to-agent", "CWE-441", OWASP_LLM06,
       "Instructions injected into one agent can drive the agents it hands work to."),
    # ---- RPA platforms (rpascan.py): UiPath projects and workflows, plus basic checks for other RPA exports ----
    _r("RPA-SEC-001", "Hard-coded credential in an automation file", "High", "Secret handling", "CWE-798", OWASP_A07,
       "A password, key or token is typed into the workflow, variable, script or connection string."),
    _r("RPA-NET-001", "Unencrypted HTTP address", "High", "Action configuration", "CWE-319", OWASP_A02,
       "The automation talks to a non-local address over plain http://."),
    _r("RPA-CODE-001", "Shell or system command started", "Medium", "Action configuration", "CWE-78", OWASP_A03,
       "The automation starts a command shell, PowerShell or a script host."),
    _r("RPA-CODE-002", "Embedded code or script step", "Low", "Governance", "CWE-94", OWASP_A03,
       "Custom code or a script runs inside the automation and needs its own review."),
    _r("UIP-DB-001", "SQL built by string concatenation", "Medium", "Action configuration", "CWE-89", OWASP_A03,
       "A SQL statement is assembled from text and variables, so values can change the query."),
    _r("UIP-LOG-001", "Possible secret written to the log", "Medium", "Data exposure", "CWE-532", OWASP_A09,
       "A log message includes a variable that looks like a password, key or token."),
    _r("UIP-PRJ-001", "Project dependencies not pinned to an exact version", "Low", "Governance", "CWE-829", OWASP_A06,
       "Package versions can change between builds without review."),
    _r("UIP-PRJ-002", "Sensitive values not excluded from logs", "Low", "Configuration", "CWE-532", OWASP_A09,
       "The project does not list password or private data keywords in its excluded-from-logging setting."),
    # ---- Workflow automation exports (workflowscan.py): n8n workflows and Make scenario blueprints ----
    _r("WF-TRG-001", "Webhook trigger open to anyone", "High", "Trigger exposure", "CWE-306", OWASP_A07,
       "A webhook with no authentication starts the workflow for anyone who learns its address."),
    _r("WF-TRG-002", "Webhook trigger: caller not restricted in the export", "Medium", "Trigger exposure", "CWE-306", OWASP_A07,
       "The scenario starts from a public address and the export shows no IP restriction or secret check."),
    _r("WF-SEC-001", "Hard-coded secret in a workflow", "High", "Secret handling", "CWE-798", OWASP_A07,
       "A key, password or token is typed into a node, module, header or code step."),
    _r("WF-NET-001", "Unencrypted HTTP address", "High", "Action configuration", "CWE-319", OWASP_A02,
       "The workflow talks to a non-local address over plain http://."),
    _r("WF-NET-002", "TLS certificate checking disabled", "High", "Action configuration", "CWE-295", OWASP_A02,
       "The step accepts any certificate, so the connection can be intercepted."),
    _r("WF-CODE-001", "Shell or system command started", "Medium", "Action configuration", "CWE-78", OWASP_A03,
       "A step runs an operating-system command or a shell."),
    _r("WF-CODE-002", "Embedded code or script step", "Low", "Governance", "CWE-94", OWASP_A03,
       "Custom code runs inside the workflow and needs its own review."),
    _r("WF-INJ-001", "SQL built from workflow data", "Medium", "Action configuration", "CWE-89", OWASP_A03,
       "Values from earlier steps are placed directly in a SQL statement."),
    _r("WF-AI-001", "Data sent to an AI service", "Medium", "Data exposure", "CWE-200", OWASP_LLM02,
       "Workflow content is sent to an AI model provider."),
    _r("WF-CFG-001", "Errors ignored", "Low", "Configuration", "CWE-703", OWASP_A09,
       "A step continues after a failure, so problems can pass unnoticed."),
    _r("WF-CFG-002", "Test data pinned in the workflow", "Medium", "Data exposure", "CWE-200", OWASP_A04,
       "Pinned sample data is saved inside the export and may hold real records."),
    _r("WF-CFG-003", "No error workflow", "Low", "Configuration", "CWE-391", OWASP_A09,
       "Failed runs may not alert anyone."),
    _r("WF-GOV-001", "Workflow is not active", "Low", "Governance", None, None,
       "A switched-off workflow should be reviewed or removed."),
    _r("UIP-PRJ-003", "Project uses the legacy framework", "Low", "Governance", "CWE-1104", OWASP_A06,
       "Legacy projects run on an older runtime that gets fewer updates."),
]


for _rule in RULES:
    _rule["lcnc"] = f"LCNC-SEC-{_L[_rule['id']]}"          # a KeyError here means a new rule was added without choosing its category
    _rule["lcncTitle"] = LCNC[_rule["lcnc"]]

BY_ID = {r["id"]: r for r in RULES}
SEVERITIES = ("High", "Medium", "Low")


def meta(rule_id: str) -> dict:
    r = BY_ID.get(rule_id, {})
    return {"cwe": r.get("cwe"), "owasp": r.get("owasp"), "lcnc": r.get("lcnc"), "category": r.get("category", "General")}


def clean_policy(policy: dict | None) -> tuple[set, dict]:
    """Return (disabled rule ids, severity overrides) with unknown ids and bad severities dropped."""
    policy = policy or {}
    disabled = {x for x in policy.get("disabled", []) if x in BY_ID}
    override = {k: v for k, v in (policy.get("severity") or {}).items() if k in BY_ID and v in SEVERITIES}
    return disabled, override

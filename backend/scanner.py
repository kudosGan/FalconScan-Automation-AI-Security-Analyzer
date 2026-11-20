"""Minimal static analyzer for Power Automate flow definitions.

Static configuration analysis only: no network probing and no run data.
"""
import json
import re

from connectors import RANK, classify
from rules import clean_policy, meta

SEV_WEIGHT = {"High": 10, "Medium": 4, "Low": 1}
SECRET_KEYS = re.compile(r"(pass(word|wd)?|secret|api[-_]?key|token|authorization|credential|pwd)", re.I)
PERSONAL_MAIL = re.compile(r"[\w.+-]+@(gmail|outlook|hotmail|live|yahoo|icloud|proton(mail)?|aol)\.[a-z.]+", re.I)
SEND_OPS = re.compile(r"(sendemail|sendmail|forward|reply)", re.I)
BENIGN_VALUES = {"anonymous", "none", "true", "false", "null"}

# Remediation guidance per rule: shown under "How to fix" in the UI.
FIXES: dict[str, list[str]] = {
    "PA-TRG-001": [
        "Open the flow, select the trigger and set \"Who can trigger the flow?\" to \"Specific users in my tenant\" (or \"Any user in my tenant\") instead of \"Anyone\".",
        "Treat the callback URL as a secret: keep it out of emails, wikis and source code.",
        "If the URL was ever exposed, delete the trigger and add a new one so a new URL (signature) is generated.",
    ],
    "PA-TRG-002": [
        "Confirm the flow still has an active owner and a business need.",
        "Add a co-owner or move the flow into a solution owned by a service account so it survives staff changes.",
        "Turn the flow off or delete it if the schedule is no longer needed.",
    ],
    "PA-TRG-003": [
        "Open the trigger and change \"Who can trigger the flow?\" from \"Anyone\" to \"Any user in my tenant\" or \"Specific users in my tenant\".",
        "In code view this is inputs.triggerAuthenticationType; it should no longer be All/Anonymous.",
        "If external systems must call the flow, put it behind API Management or validate a token inside the flow.",
    ],
    "PA-ACT-001": [
        "Change the URI from http:// to https:// in the HTTP action.",
        "Confirm the target server supports TLS. If it does not, do not send data to it until it does.",
        "Add a DLP policy so unencrypted endpoints cannot be used in new flows.",
    ],
    "PA-ACT-002": [
        "Confirm the destination is an approved partner or internal service.",
        "Prefer a custom connector for approved APIs so it can be governed and reviewed.",
        "In the Power Platform admin center, put the HTTP connector in a restricted DLP group or block it where it is not needed.",
    ],
    "PA-ACT-003": [
        "In the HTTP action, set Authentication to Active Directory OAuth, Managed Identity or Basic, not none.",
        "Store any secret in an environment variable (secret type) or Azure Key Vault, and reference it as an expression.",
        "Avoid the Raw authentication type unless the receiving API requires it.",
    ],
    "PA-ACT-004": [
        "Replace the personal address with a company shared mailbox or distribution list.",
        "If external recipients are required, confirm with the data owner and document the exception.",
        "Use an Exchange transport rule or DLP policy to block automatic sending to consumer mail domains.",
    ],
    "PA-SEC-001": [
        "Rotate the exposed secret now: assume it has been seen by everyone who can open or export the flow.",
        "Move the value to Azure Key Vault (Get secret action) or a secret-type environment variable in a solution.",
        "Reference it with an expression such as @parameters('MySecret') or the Key Vault output instead of typing it into the action.",
        "Turn on Secure Inputs and Secure Outputs for the actions that handle it.",
    ],
    "PA-CFG-001": [
        "Open the action's ⋯ menu ▸ Settings and turn on Secure Inputs and Secure Outputs.",
        "In code view this adds runtimeConfiguration.secureData.properties = [\"inputs\", \"outputs\"].",
        "Do this for every action that sends or receives sensitive data, so values stay out of run history.",
    ],
    "PA-CFG-002": [
        "Replace the Terminate (Succeeded) with a status that matches what happened: Failed or Cancelled when an error occurred.",
        "Use Scope actions with Run after settings as try/catch so real failures are reported.",
        "Alert the owner when a branch ends in an error.",
    ],
    "PA-GOV-001": [
        "Delete the flow if it is no longer used, or turn it on if it should be running.",
        "Check who owns it and note why it was stopped.",
    ],
    "PA-GOV-002": [
        "Split the flow into smaller child flows, each using only the connectors it needs.",
        "Remove connectors and connections that are no longer used.",
        "Review each connection's account: use service accounts with the least privilege required.",
    ],
    "PA-CON-001": [
        "Confirm the data owner has approved sending this data to the third party, and that a contract or data-processing agreement covers it.",
        "Send only the fields the receiver needs: build a small object with Select/Compose instead of passing the whole item or email.",
        "Remove personal or confidential columns (names, emails, IDs) before the third-party action.",
        "In the Power Platform admin center, put the third-party connector in the Non-business or Blocked DLP group so it cannot be combined with SharePoint, Outlook or Dataverse.",
    ],
    "PA-CON-002": [
        "Confirm the third-party service is approved by your organisation and note who owns the vendor relationship.",
        "Check the connection runs under a service account and not a person's identity.",
        "Review the connector's DLP group in the Power Platform admin center.",
    ],
    "PA-CON-003": [
        "Open the custom connector and review where its host points, which operations it exposes and how it authenticates.",
        "Make sure the connector is owned by a team, documented, and covered by a DLP policy.",
        "If it is an unknown marketplace connector, confirm the publisher before the flow uses it.",
    ],
    "PA-AI-001": [
        "Check exactly which fields are placed in the prompt or request, and remove personal, confidential or customer data that is not essential.",
        "Prefer an AI service inside your tenant (Azure OpenAI, AI Builder) and confirm its data-retention and training settings.",
        "For third-party AI, get approval first and confirm the provider does not train on your data.",
        "Turn on Secure Inputs and Secure Outputs for the AI action so prompts and answers stay out of run history.",
    ],
    "PA-GOV-003": [
        "Confirm the premium licence is assigned and approved for this flow's users.",
        "Document why the premium connector is needed, or switch to a standard connector.",
    ],
}

# "If you cannot do the recommended fix": a second, different way to remove the same risk.
ALTERNATIVES: dict[str, dict] = {
    "PA-TRG-003": {"title": "Keep the HTTP trigger but make callers prove who they are", "steps": [
        "Put the flow behind Azure API Management (or another gateway) that requires an Entra ID token or subscription key before it forwards the call.",
        "Or check a secret inside the flow: add a Condition on the incoming header (for example x-api-token) compared with a value read from Azure Key Vault.",
        "When the check fails, use a Response action with status 401 and a Terminate (Failed) so nothing else runs.",
        "Or avoid the public trigger altogether: use a connector trigger (SharePoint, Dataverse, Teams) or call the flow from Power Apps.",
    ]},
    "PA-ACT-001": {"title": "The target cannot do HTTPS yet", "steps": [
        "Put a TLS-terminating front end (API Management, Azure Front Door or Application Gateway) in front of the target and call that over https://.",
        "Or reach the system through an on-premises data gateway with a custom connector so traffic stays on your network.",
        "Until one of these is in place, send only non-sensitive identifiers (IDs, not names, emails or document contents).",
    ]},
    "PA-SEC-001": {"title": "Remove the need for a secret in the flow", "steps": [
        "Use identity-based authentication: Managed Identity or Active Directory OAuth on the HTTP action, so there is no password to store.",
        "Or create a custom connector or connection that holds the credential: the secret then lives in the connection, not in the flow definition.",
        "Or use a secret-type environment variable inside a solution and reference it with @parameters('YourVariable').",
        "Whichever you choose: rotate the old value first, then turn on Secure Inputs/Outputs on the actions that read it.",
    ]},
    "PA-TRG-001": {"title": "Use a trigger that does not expose a public URL", "steps": [
        "Replace the HTTP trigger with a connector trigger (SharePoint, Dataverse, Forms) or a Power Apps / Teams trigger.",
        "If a URL is unavoidable, front it with API Management and restrict by IP or token.",
    ]},
    "PA-TRG-002": {"title": "Make the schedule accountable instead of removing it", "steps": [
        "Add a recurring review date for the flow in your governance register with a named owner and a backup owner.",
        "Or move it to a solution with a service account as owner and set up alerts for failed runs.",
    ]},
    "PA-ACT-002": {"title": "Replace the raw HTTP call with a governed connector", "steps": [
        "Build a custom connector for the approved API so the endpoint, authentication and allowed operations are fixed and reviewable.",
        "Or use the vendor's certified connector if one exists, and block the generic HTTP connector for makers.",
    ]},
    "PA-ACT-003": {"title": "Use a connector that handles sign-in for you", "steps": [
        "Replace the HTTP action with a custom connector that has OAuth 2.0 or API-key authentication configured once, centrally.",
        "Or call an Azure-hosted API with Managed Identity authentication, which needs no secret at all.",
    ]},
    "PA-ACT-004": {"title": "Send through a managed route instead of editing the address", "steps": [
        "Use \"Send an email from a shared mailbox (V2)\" with an internal shared mailbox that forwards under policy.",
        "Or post the message to a Teams channel and let the recipient pick it up there.",
    ]},
    "PA-CFG-001": {"title": "Keep sensitive data out of the action", "steps": [
        "Pass reference IDs instead of the data itself, and let the next step look the record up.",
        "Restrict who can see run history: share the flow with people as run-only users instead of co-owners.",
    ]},
    "PA-CFG-002": {"title": "Report failures through a try/catch pattern", "steps": [
        "Wrap the work in a Scope, add a second Scope with Configure run after = has failed, and send an alert from it.",
        "End the failure branch with Terminate set to Failed so the run is shown correctly.",
    ]},
    "PA-GOV-001": {"title": "Archive before deleting", "steps": [
        "Export the flow as a package, store it with the owner's records, then delete the live copy.",
        "Or move it into a solution marked as archived, with the owner and reason recorded.",
    ]},
    "PA-GOV-002": {"title": "Accept the size, but record the approval", "steps": [
        "If the connectors are all required, keep the flow and record the review and approver in your governance register.",
        "Move the premium or sensitive connectors into a child flow with its own owner and permissions.",
    ]},
    "PA-CON-001": {"title": "Keep the data inside your tenant", "steps": [
        "Do the processing with a Microsoft service instead (for example Azure Functions or Logic Apps in your own subscription) and send the third party only the result.",
        "Or anonymise first: replace names and IDs with reference numbers and look them up again on the way back.",
        "Or use a gateway or private endpoint so the third party only receives what an API policy allows.",
    ]},
    "PA-CON-002": {"title": "Use a Microsoft equivalent", "steps": [
        "Check whether a Microsoft connector gives the same result (for example Teams instead of Slack, or SharePoint instead of Dropbox).",
        "If the third-party service must stay, record the approval and review it each year.",
    ]},
    "PA-CON-003": {"title": "Replace it with a known connector", "steps": [
        "Use a certified connector or the generic HTTP action with an approved destination, authentication and DLP coverage.",
        "Or take ownership of the custom connector, publish it in a solution and review it like any other code.",
    ]},
    "PA-AI-001": {"title": "Keep AI processing under your control", "steps": [
        "Run the AI step through a tenant-hosted service (Azure OpenAI in your subscription) with content filtering and no data retention.",
        "Or pass the AI service only a summary or redacted version of the data.",
        "Or make a person review and approve the content before it is sent (an Approval step) for sensitive sources.",
    ]},
    "PA-GOV-003": {"title": "Check whether a standard connector can do the same job", "steps": [
        "Look for a standard connector or built-in action that covers the need.",
        "Or license the flow itself (per-flow plan) instead of every user, and record the approval.",
    ]},
}

EXAMPLES_EXTRA = {
    "PA-CON-001": {"before": "\"body\": \"@body('Get_item')\"",
                   "after": "\"body\": { \"ref\": \"@body('Get_item')?['ID']\" }"},
    "PA-AI-001": {"before": "\"prompt\": \"@body('Get_email')?['body']\"",
                  "after": "\"prompt\": \"@outputs('Summarise_without_names')\""},
}

# Before / after snippets for the fixes where the change is a concrete edit.
EXAMPLES: dict[str, dict] = {
    "PA-ACT-001": {"before": '"uri": "http://partner.example.com/api/orders"',
                   "after": '"uri": "https://partner.example.com/api/orders"'},
    "PA-SEC-001": {"before": '"password": "Welcome123!"',
                   "after": "\"password\": \"@parameters('HrApiPassword')\""},
    "PA-CFG-001": {"before": '"runtimeConfiguration": {}',
                   "after": '"runtimeConfiguration": { "secureData": { "properties": ["inputs", "outputs"] } }'},
    "PA-ACT-003": {"before": '"inputs": { "method": "GET", "uri": "https://api.example.com/x" }',
                   "after": '"inputs": { "method": "GET", "uri": "https://api.example.com/x", "authentication": { "type": "ManagedServiceIdentity" } }'},
    "PA-CFG-002": {"before": '"inputs": { "runStatus": "Succeeded" }',
                   "after": '"inputs": { "runStatus": "Failed", "runError": { "message": "Processing failed" } }'},
}

EXAMPLES.update(EXAMPLES_EXTRA)


FIXES["PA-DLP-001"] = [
    "Remove the blocked connector from the flow, or ask the environment admin whether an exception is justified.",
    "If the work is needed, replace the connector with an approved one that does the same job.",
]
FIXES["PA-DLP-002"] = [
    "Split the flow so business and non-business connectors are in separate flows, and pass only the data that must cross between them.",
    "Or replace the non-business connector with an approved business-group connector.",
    "Check the DLP policy with the environment admin; do not move connectors between groups just to make the flow pass.",
]

ALTERNATIVES["PA-DLP-001"] = {"title": "Use an approved way to reach the same system", "steps": [
    "Ask the platform team which connector or custom connector is approved for this service, and switch to it.",
    "Or call the service from an approved Azure Function or API Management endpoint instead of the blocked connector.",
]}
ALTERNATIVES["PA-DLP-002"] = {"title": "Keep the groups apart with a controlled hand-off", "steps": [
    "Have the business-side flow write only the needed fields to an approved store, and let a second flow in the other group read from there.",
    "Or ask for a reviewed DLP exception for this one flow, with an owner and an expiry date.",
]}


def _dlp_findings(add, connectors: set, dlp: dict) -> None:
    """Compare the flow's connectors with a DLP policy: {business, nonBusiness, blocked: [names], defaultGroup}."""
    key = lambda x: str(x).lower().removeprefix("shared_")
    groups = {g: {key(c) for c in (dlp.get(g) or [])} for g in ("business", "nonBusiness", "blocked")}
    default = "business" if str(dlp.get("defaultGroup", "")).lower() == "business" else "nonBusiness"
    placed: dict[str, str] = {}
    for c in sorted(connectors):
        k = key(c)
        placed[c] = ("blocked" if k in groups["blocked"] else "business" if k in groups["business"]
                     else "nonBusiness" if k in groups["nonBusiness"] else default)
    for c, g in placed.items():
        if g == "blocked":
            add("High", "PA-DLP-001", "Connector blocked by DLP policy", f"'{c}' is in the blocked group of the DLP policy.", "flow", ["connectors"])
    biz = [c for c, g in placed.items() if g == "business"]
    non = [c for c, g in placed.items() if g == "nonBusiness"]
    if biz and non:
        add("High", "PA-DLP-002", "Business and non-business connectors mixed",
            f"Business: {', '.join(biz)}. Non-business: {', '.join(non)}. A DLP policy does not allow both in one flow.",
            "flow", ["connectors"])


def _walk_actions(actions: dict | None):
    """Yield (name, action) for every action, descending into Scope/If/Foreach/Switch/Until."""
    for name, a in (actions or {}).items():
        yield name, a
        yield from _walk_actions(a.get("actions"))
        yield from _walk_actions((a.get("else") or {}).get("actions"))
        for case in (a.get("cases") or {}).values():
            yield from _walk_actions(case.get("actions"))
        yield from _walk_actions((a.get("default") or {}).get("actions"))


def _inputs(item: dict) -> dict:
    """An item's inputs as a dict. Compose, Variable and similar actions store plain text or lists instead."""
    v = item.get("inputs") if isinstance(item, dict) else None
    return v if isinstance(v, dict) else {}


def _connector(item: dict) -> str | None:
    """Connector name from host.apiId, falling back to host.connectionName (real exports use both)."""
    host = _inputs(item).get("host") or {}
    api = host.get("apiId") or ""
    if api:
        return api.rsplit("/", 1)[-1]
    name = host.get("connectionName")
    return name if isinstance(name, str) and not name.startswith("@") else None


def _is_expression(v: str) -> bool:
    """Power Automate expressions start with '@' or embed '@{...}'; a lone '@' inside text is literal."""
    v = v.strip()
    return v.startswith("@") or "@{" in v


def _literal_secrets(obj, path: str = "", keys: tuple = ()):
    """Yield (path, key) for secret-looking keys whose value is a hard-coded string.

    Expressions (@parameters(...), @{...}, @body(...)) are not literals and are ignored.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else k
            if isinstance(v, str):
                if (SECRET_KEYS.search(k) and len(v.strip()) >= 4 and not _is_expression(v)
                        and v.strip().lower() not in BENIGN_VALUES):
                    yield here, list(keys) + [k]
            else:
                yield from _literal_secrets(v, here, keys + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _literal_secrets(v, f"{path}[{i}]", keys + (str(i),))


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _ordered(actions: dict) -> list[str]:
    """Order sibling actions by runAfter dependencies so steps follow execution order."""
    remaining, done = list(actions), []
    while remaining:
        ready = [n for n in remaining
                 if all(d not in actions or d in done for d in (actions[n].get("runAfter") or {}))]
        if not ready:
            ready = remaining[:1]  # cycle / odd data: don't loop forever
        for n in ready:
            done.append(n)
            remaining.remove(n)
    return done


def _iter_steps(actions: dict | None, parent: str = "", depth: int = 0):
    """Yield (name, action, path, depth) in execution order, descending into branches."""
    actions = actions or {}
    for name in _ordered(actions):
        a = actions[name]
        path = f"{parent} > {name}" if parent else name
        yield name, a, path, depth
        yield from _iter_steps(a.get("actions"), path, depth + 1)
        yield from _iter_steps((a.get("else") or {}).get("actions"), f"{path} (else)", depth + 1)
        for cn, case in (a.get("cases") or {}).items():
            yield from _iter_steps(case.get("actions"), f"{path} [{cn}]", depth + 1)
        yield from _iter_steps((a.get("default") or {}).get("actions"), f"{path} (default)", depth + 1)


def _strip_children(a: dict) -> dict:
    """Show only this step's own JSON; nested actions get their own steps."""
    out = {k: v for k, v in a.items() if k not in ("actions", "else", "cases", "default")}
    kids = len(list(_walk_actions(a.get("actions")))) if a.get("actions") else 0
    if kids or a.get("else") or a.get("cases"):
        out["(nested)"] = "child actions are inspected in their own steps"
    return out


def _build_steps(d: dict, props: dict, connectors: set, findings: list[dict], conns: dict) -> list[dict]:
    by_loc: dict[str, list[dict]] = {}
    for f in findings:
        by_loc.setdefault(f["location"], []).append(f)
    steps = []
    for name, t in (d.get("triggers") or {}).items():
        steps.append({"id": f"trigger:{name}", "kind": "trigger", "name": name, "type": t.get("type", "Trigger"),
                      "path": name, "depth": 0, "connector": _connector(t), "json": t,
                      "connection": conns.get(f"trigger:{name}"),
                      "findings": by_loc.get(f"trigger:{name}", [])})
    for name, a, path, depth in _iter_steps(d.get("actions")):
        steps.append({"id": f"action:{path}", "kind": "action", "name": name, "type": a.get("type", "Action"),
                      "path": path, "depth": depth, "connector": _connector(a), "json": _strip_children(a),
                      "connection": conns.get(f"action:{name}"),
                      "findings": by_loc.get(f"action:{name}", [])})
    steps.append({"id": "flow:config", "kind": "flow", "name": "Flow configuration", "type": "Metadata",
                  "path": "flow", "depth": 0, "connector": None, "connection": None,
                  "json": {"displayName": props.get("displayName"), "state": props.get("state"),
                           "connectors": sorted(connectors),
                           "triggers": len(d.get("triggers") or {}),
                           "actions": len(list(_walk_actions(d.get("actions"))))},
                  "findings": by_loc.get("flow", [])})
    return steps


def _flow_type(triggers: dict) -> str:
    """Power Automate's three flow kinds, derived from the trigger."""
    kinds = {(t.get("type"), t.get("kind")) for t in triggers.values()}
    if any(t == "Recurrence" for t, _ in kinds):
        return "Scheduled"
    if any(t == "Request" for t, _ in kinds):
        return "Instant"
    return "Automated" if kinds else "Unknown"


def _metadata(flow: dict, props: dict, d: dict, triggers: dict, n_actions: int,
              connectors: set, premium: list[str]) -> dict:
    creator = props.get("creator") or {}
    env = props.get("environment") or {}
    return {
        "Flow name": props.get("displayName"),
        "Flow ID": flow.get("name"),
        "State": props.get("state"),
        "Type": _flow_type(triggers),
        "Trigger": ", ".join(f"{n} ({t.get('type')})" for n, t in triggers.items()) or None,
        "Owner": creator.get("userPrincipalName") or creator.get("userId") or creator.get("objectId"),
        "Created": props.get("createdTime"),
        "Last modified": props.get("lastModifiedTime"),
        "Environment": env.get("displayName") or env.get("name"),
        "Triggers": len(triggers),
        "Actions": n_actions,
        "Connectors": len(connectors),
        "Premium connectors": ", ".join(sorted(premium)) or "None",
        "Schema version": d.get("contentVersion"),
    }


def scan_flow(flow: dict, policy: dict | None = None) -> dict:
    props = flow.get("properties", {})
    d = props.get("definition") or {}
    triggers = d.get("triggers") or {}
    actions = list(_walk_actions(d.get("actions")))
    findings: list[dict] = []

    def add(sev, rule, title, detail, where, jpath=None):
        """jpath = key path inside the step's own JSON that the finding points at (drives line highlighting)."""
        findings.append({"severity": sev, "ruleId": rule, "title": title, "detail": detail,
                         "location": where, "jsonPath": jpath or [], "fix": FIXES.get(rule, []),
                         "alternative": ALTERNATIVES.get(rule), "example": EXAMPLES.get(rule)})

    connectors = set()
    premium: list[str] = []
    for name, t in triggers.items():
        if c := _connector(t):
            connectors.add(c)
        if t.get("type") == "Request":
            kind = t.get("kind", "")
            auth = str(_inputs(t).get("triggerAuthenticationType", ""))
            if auth.lower() in ("all", "anonymous") and kind == "Http":
                add("High", "PA-TRG-003", "HTTP trigger open to anyone",
                    f"triggerAuthenticationType is '{auth}': any caller with the URL can run this flow. "
                    "Restrict \"Who can trigger\" to users in your tenant.", f"trigger:{name}",
                    ["inputs", "triggerAuthenticationType"])
            add("Medium" if kind == "Http" else "Low", "PA-TRG-001", "HTTP request trigger",
                "Anyone holding the callback URL can start this flow. Confirm access is restricted "
                "(\"Who can trigger\" setting) and the URL is not shared.", f"trigger:{name}",
                ["kind"] if "kind" in t else ["type"])
        if t.get("type") == "Recurrence":
            add("Low", "PA-TRG-002", "Scheduled trigger", "Runs unattended; verify it still has an owner and a business need.", f"trigger:{name}",
                ["recurrence"] if "recurrence" in t else ["type"])

    for ref_name, ref in (props.get("connectionReferences") or {}).items():
        api_name = ((ref.get("api") or {}).get("name")) or str(ref.get("id", "")).rsplit("/", 1)[-1] or ref_name
        connectors.add(api_name)
        if str(ref.get("tier", "")).lower() == "premium":
            premium.append(api_name)
            add("Low", "PA-GOV-003", "Premium connector",
                f"'{api_name}' needs a premium licence; confirm it is approved.", "flow", ["connectors"])

    for name, a in actions:
        if c := _connector(a):
            connectors.add(c)
        inputs = _inputs(a)
        if a.get("type") == "Http":
            uri = str(inputs.get("uri", ""))
            if uri.lower().startswith("http://"):
                add("High", "PA-ACT-001", "Unencrypted HTTP call", f"Action calls {uri} over plain HTTP.", f"action:{name}", ["inputs", "uri"])
            else:
                add("Medium", "PA-ACT-002", "External HTTP call", "Data may leave the tenant; verify the destination is approved.", f"action:{name}", ["inputs", "uri"])
            if not inputs.get("authentication"):
                add("Medium", "PA-ACT-003", "HTTP action without authentication", "No authentication block configured.", f"action:{name}", ["inputs", "method"])
        auth_in = inputs.get("authentication")
        if isinstance(auth_in, dict) and str(auth_in.get("type", "")).lower() == "raw"                 and isinstance(auth_in.get("value"), str) and not _is_expression(auth_in["value"]):
            add("High", "PA-SEC-001", "Hard-coded secret in authentication",
                "authentication.value is a literal string. Use a secure parameter or Key Vault.", f"action:{name}",
                ["inputs", "authentication", "value"])
        for where, kpath in _literal_secrets(inputs):
            add("High", "PA-SEC-001", "Hard-coded secret",
                f"'{where}' holds a literal value. Use a secure input, environment variable or Key Vault.", f"action:{name}",
                ["inputs"] + kpath)
        op = str((inputs.get("host") or {}).get("operationId", ""))
        if SEND_OPS.search(op) or SEND_OPS.search(str(a.get("type", ""))):
            params = inputs.get("parameters") or {}
            hits = {m.group(0) for s_ in _strings(params) for m in PERSONAL_MAIL.finditer(s_)}
            bad_key = next((k for k, v in params.items() if any(PERSONAL_MAIL.search(x) for x in _strings(v))), None)
            if hits:
                add("Medium", "PA-ACT-004", "Email sent to a personal mailbox",
                    f"Recipient(s) {', '.join(sorted(hits))} are consumer addresses; company data may leave managed mail.",
                    f"action:{name}", ["inputs", "parameters", bad_key] if bad_key else ["inputs", "parameters"])
        if (a.get("runtimeConfiguration") or {}).get("secureData") is None and a.get("type") == "Http":
            add("Low", "PA-CFG-001", "Secure inputs/outputs not enabled", "HTTP action values appear in run history.", f"action:{name}", ["runtimeConfiguration"])
        if a.get("type") in ("Terminate",) and (inputs.get("runStatus") == "Succeeded"):
            add("Low", "PA-CFG-002", "Terminate forces success", "Failures may be masked.", f"action:{name}", ["inputs", "runStatus"])


    # ---- connection analysis: who runs it, where data goes, how sensitive, AI exposure ----
    items = {f"trigger:{n}": t for n, t in triggers.items()}
    items.update({f"action:{n}": a for n, a in actions})
    conns: dict[str, dict] = {}
    for loc, it in items.items():
        c = classify(it, _connector(it))
        if c:
            conns[loc] = c

    # which steps feed which: an expression such as body('Get_item') or triggerBody() is a reference
    names = {loc.split(":", 1)[1]: loc for loc in items}
    deps: dict[str, set] = {}
    for loc, it in items.items():
        blob = json.dumps({"i": it.get("inputs"), "e": it.get("expression"), "f": it.get("foreach")})
        refs = {names[n] for n in names if names[n] != loc and re.search(r"['\"]" + re.escape(n) + r"['\"]", blob)}
        if re.search(r"trigger(Body|Outputs|FormData\w*|MultipartBody)\(", blob):
            refs |= {k for k in items if k.startswith("trigger:")}
        deps[loc] = refs

    def ancestors(loc: str) -> set:
        seen, stack = set(), list(deps.get(loc, ()))
        while stack:
            x = stack.pop()
            if x not in seen:
                seen.add(x)
                stack.extend(deps.get(x, ()))
        return seen

    def jp(c: dict) -> list[str]:
        return ["inputs", "uri"] if c["connector"] == "http" else ["inputs", "host"]

    def src_text(locs: list[str]) -> str:
        return "; ".join(f"{l.split(':', 1)[1]} ({conns[l]['name']}: {', '.join(conns[l]['dataTypes'][:2])})" for l in locs)

    sources = {loc: c for loc, c in conns.items() if RANK[c["sensitivity"]] >= 2 and not c["ai"]
               and (loc.startswith("trigger:") or c["direction"] == "reads")}
    data_flows: list[dict] = []
    for loc, c in conns.items():
        if not (c["thirdParty"] or c["ai"]) or loc.startswith("trigger:"):
            continue
        sname = loc.split(":", 1)[1]
        feeding = [s_ for s_ in sources if s_ != loc and s_ in ancestors(loc)]
        top = max((RANK[sources[x]["sensitivity"]] for x in feeding), default=0)
        for x in feeding:
            data_flows.append({"from": x.split(":", 1)[1], "to": sname, "fromConnector": sources[x]["name"],
                               "toConnector": c["name"], "sensitivity": sources[x]["sensitivity"],
                               "thirdParty": c["thirdParty"], "ai": bool(c["ai"]), "via": "expression reference"})
        if c["ai"]:
            third_ai = not c["ai"]["microsoft"]
            if feeding:
                sev = "High" if third_ai else "Medium"  # AI inside your tenant is lower risk than a third-party AI
                detail = (f"{src_text(feeding)} feed this step, which sends content to {c['ai']['provider']}"
                          f"{' (a third-party AI service outside your tenant)' if third_ai else ''}.")
            else:
                sev = "Medium" if third_ai else "Low"
                detail = (f"This step uses {c['ai']['provider']}. No sensitive source was traced into it, "
                          "but check what the prompt or request contains.")
            add(sev, "PA-AI-001", "Data exposed to an AI service", detail, loc, jp(c))
        elif feeding:
            add("High" if top == 3 else "Medium", "PA-CON-001", "Sensitive data flows to a third party",
                f"{src_text(feeding)} feed this step, which sends data to {c['destination']}.", loc, jp(c))
        if c["publisher"].startswith("Custom"):
            add("Low", "PA-CON-003", "Custom or unlisted connector", c["why"], loc, jp(c))
        elif c["thirdParty"] and not c["ai"] and c["connector"] != "http":
            add("Low", "PA-CON-002", "Third-party connector", f"{c['destination']}. {c['why']}", loc, jp(c))

    summary: dict[str, dict] = {}
    for loc, c in conns.items():
        e = summary.setdefault(c["connector"], {"connector": c["connector"], "name": c["name"],
                               "publisher": c["publisher"], "thirdParty": c["thirdParty"],
                               "sensitivity": c["sensitivity"], "ai": c["ai"], "usedBy": []})
        e["usedBy"].append(loc.split(":", 1)[1])

    if isinstance((policy or {}).get("dlp"), dict):
        _dlp_findings(add, connectors | ({"http"} if any(a.get("type") == "Http" for _, a in actions) else set()), policy["dlp"])

    if props.get("state") == "Stopped" or props.get("state") == "Suspended":
        add("Low", "PA-GOV-001", "Flow is not running", f"State: {props.get('state')}. Consider removing unused flows.", "flow", ["state"])
    if len(connectors) >= 6:
        add("Low", "PA-GOV-002", "High connector count", f"{len(connectors)} connectors used; review least privilege.", "flow", ["connectors"])

    # Scan policy: drop disabled rules, apply severity overrides, attach CWE/OWASP and a stable fingerprint.
    disabled, override = clean_policy(policy)
    flow_key = str(flow.get("name") or props.get("displayName") or "")
    findings = [
        {**f, **meta(f["ruleId"]), "severity": override.get(f["ruleId"], f["severity"]),
         "fingerprint": "|".join([flow_key, f["ruleId"], f["location"], ".".join(f.get("jsonPath") or [])])}
        for f in findings if f["ruleId"] not in disabled
    ]

    score = sum(SEV_WEIGHT[f["severity"]] for f in findings)
    risk = "High" if any(f["severity"] == "High" for f in findings) or score >= 12 else \
           "Medium" if score >= 4 else "Low"
    return {
        "flowId": flow.get("name"),
        "name": props.get("displayName"),
        "state": props.get("state"),
        "connectors": sorted(connectors),
        "triggerCount": len(triggers),
        "actionCount": len(actions),
        "findings": findings,
        "risk": risk,
        "score": score,
        "metadata": {**_metadata(flow, props, d, triggers, len(actions), connectors, premium), **{
            "Third-party connectors": ", ".join(sorted(e["name"] for e in summary.values() if e["thirdParty"])) or "None",
            "AI services": ", ".join(sorted({e["ai"]["provider"] for e in summary.values() if e["ai"]})) or "None",
            "Highest data sensitivity": max((e["sensitivity"] for e in summary.values()), key=lambda x: RANK[x], default="None"),
        }},
        "connections": list(summary.values()),
        "dataFlows": data_flows,
        "steps": _build_steps(d, props, connectors, findings, conns),
    }

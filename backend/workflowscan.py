"""Static analysis of workflow-automation exports: n8n workflows and Make (Integromat) scenario blueprints.

Both are plain JSON.
  * n8n: {"nodes": [{"type": "n8n-nodes-base.webhook", "parameters": {...}, ...}], "connections": {...}, "active": bool, "pinData": {...}}
  * Make: {"name": ..., "flow": [{"id": 1, "module": "http:ActionSendData", "parameters": {...}, "mapper": {...}}, ...], "metadata": {...}};
    routers hold more modules under "routes": [{"flow": [...]}].

Only configuration is read. Nothing is run and no service is contacted. The module and node names used here are the ones the
products document; a check that depends on a field the export does not contain simply does not fire, so an empty result is not proof
that a scenario is safe. Results use the same shape as scanner.scan_flow, so the workbench, gate, SARIF and reports need no changes.
"""
import re

import scanner
from agentscan import REDACTED, SECRET_KEY, _literal, _secret_paths
from rpascan import CODE_SECRET, _finish, value_issues

N8N, MAKE = "n8n", "Make"
MAX_NODES = 5000

N8N_TRIGGER = re.compile(r"(trigger|webhook|cron|start)$", re.I)
N8N_SHELL = re.compile(r"\.(executeCommand|ssh)$", re.I)
N8N_CODE = re.compile(r"\.(code|function|functionItem)$", re.I)
N8N_SQL = re.compile(r"\.(postgres|mySql|microsoftSql|oracleDatabase|snowflake|questDb|timescaleDb|cockroachDb)(Tool)?$", re.I)
AI_NAME = re.compile(r"(openai|anthropic|gemini|googlepalm|mistral|cohere|groq|deepseek|huggingface|perplexity|lmchat|xai|azureopenai)", re.I)
MAKE_SHELL = re.compile(r"^(ssh|sftp|shell|powershell|command)\b|executecommand", re.I)
MAKE_SQL = re.compile(r"^(mysql|postgres|postgresql|mssql|oracle|snowflake|sql)\b", re.I)
MAKE_AI = re.compile(r"^(openai|anthropic|google-gemini|gemini|mistral|perplexity|deepseek|groq|cohere|huggingface|xai|azure-openai)", re.I)
MAKE_WEBHOOK = re.compile(r"^gateway:(CustomWebHook|CustomMailhook)$")
HEADER_SECRET = re.compile(r"^(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie)$", re.I)

FIXES: dict[str, list[str]] = {
    "WF-TRG-001": [
        "Set the Webhook node's Authentication to Basic Auth, Header Auth or JWT Auth and give the caller the credential.",
        "Where the caller is another service, also restrict who can reach the n8n webhook path (reverse proxy, allow-list of source addresses).",
        "Use the 'Production' URL only, and remove test webhooks from workflows that are active.",
    ],
    "WF-TRG-002": [
        "Open the webhook in Make and set an IP restriction, or have the scenario check a shared secret in a header as its first module and stop when it does not match.",
        "Treat the webhook address as a password: do not put it in documents, tickets or chat.",
    ],
    "WF-SEC-001": [
        "Remove the value from the workflow. In n8n create a Credential and select it in the node; in Make use a Connection or a data store, not a typed value.",
        "Reading a secret from an environment variable or a secrets manager is better than saving it in the export.",
        "Treat the exposed value as compromised: change it, and remove it from every copy of the export and from version control history.",
    ],
    "WF-NET-001": [
        "Change the address to https:// and confirm the service supports TLS.",
        "If the service only speaks HTTP, reach it through a gateway that adds TLS, or keep it on a private network and document the exception.",
    ],
    "WF-NET-002": [
        "Turn certificate checking back on (n8n: switch off 'Ignore SSL Issues'; Make: switch on 'Reject connections that are using unverified certificates').",
        "If the service uses a private certificate authority, install that authority instead of disabling the check.",
    ],
    "WF-CODE-001": [
        "Replace the command with a node or module that does the job through an API.",
        "If a command is unavoidable, run a fixed, reviewed script and never build the command text from data the workflow receives (webhook bodies, emails, files).",
    ],
    "WF-CODE-002": [
        "Review the embedded code like any other code: who wrote it, what it reads, what it can send out.",
        "Keep code steps small, and keep credentials out of them.",
    ],
    "WF-INJ-001": [
        "Use the database node's query parameters (n8n: 'Query Parameters' with $1, $2; Make: use the module's structured fields) instead of putting values into the SQL text.",
        "Never place data that arrives from a webhook, email or form directly into a query.",
    ],
    "WF-AI-001": [
        "Check what is sent to the AI service: remove personal, financial and confidential fields before the step.",
        "Confirm the provider is approved and that its data-use terms (training, retention) match your policy.",
    ],
    "WF-CFG-001": [
        "Remove 'continue on fail' / the Ignore error handler, or route failures to an error branch that alerts someone.",
    ],
    "WF-CFG-002": [
        "Clear the pinned data before exporting or sharing the workflow (n8n: unpin data on each node).",
        "Do not pin real customer or employee records; use made-up test values.",
    ],
    "WF-CFG-003": [
        "Set an error workflow in the workflow settings that notifies an owner when a run fails.",
    ],
    "WF-GOV-001": [
        "Delete workflows that are no longer used, or record who owns them and why they are kept.",
    ],
}
ALTERNATIVES: dict[str, dict] = {
    "WF-TRG-001": {"title": "Put the webhook behind a gateway", "steps": [
        "Receive requests in an API gateway or reverse proxy that checks a key or token, and let only the gateway reach the webhook."]},
    "WF-TRG-002": {"title": "Verify the sender in the first step", "steps": [
        "Make the first module compare a signature or shared secret from the request header and stop the scenario when it does not match."]},
    "WF-SEC-001": {"title": "Use short-lived access", "steps": [
        "Use a service account with the least access needed, rotate it on a schedule, and keep it in the platform's credential store."]},
    "WF-NET-001": {"title": "Use a private connection", "steps": [
        "Connect over a VPN or private endpoint and keep the address inside your network."]},
    "WF-NET-002": {"title": "Trust your own certificate authority", "steps": [
        "Install the internal certificate authority on the host that runs the workflow instead of switching verification off."]},
    "WF-CODE-001": {"title": "Call an approved service instead", "steps": [
        "Wrap the task in a small internal service or approved tool and call it with fixed arguments."]},
    "WF-CODE-002": {"title": "Use a reviewed library", "steps": [
        "Move the logic into a versioned service or package that goes through code review, and call it from the workflow."]},
    "WF-INJ-001": {"title": "Use a stored procedure", "steps": [
        "Call a stored procedure or view that takes typed parameters, so the workflow never builds SQL text."]},
    "WF-AI-001": {"title": "Use an approved or private model", "steps": [
        "Send content only to an approved provider under your own agreement, or run a model inside your network."]},
    "WF-CFG-001": {"title": "Branch on failure", "steps": [
        "Send failures to an error branch that logs the problem and alerts an owner, then stops or retries on purpose."]},
    "WF-CFG-002": {"title": "Use synthetic test data", "steps": [
        "Keep a small set of made-up records for testing and pin only those."]},
    "WF-CFG-003": {"title": "Alert from a shared monitor", "steps": [
        "Send run failures from every workflow to one monitoring channel that an owner watches."]},
    "WF-GOV-001": {"title": "Archive instead of leaving it switched off", "steps": [
        "Export the workflow to version control with a note on why it was retired, then delete it from the live instance."]},
}
EXAMPLES: dict[str, dict] = {
    "WF-NET-001": {"before": '"url": "http://api.partner.example.com/orders"', "after": '"url": "https://api.partner.example.com/orders"'},
}
scanner.FIXES.update(FIXES)
scanner.ALTERNATIVES.update(ALTERNATIVES)
scanner.EXAMPLES.update(EXAMPLES)


def kind_of(content) -> str | None:
    """'n8n' | 'Make' | None."""
    if not isinstance(content, dict):
        return None
    nodes, flow = content.get("nodes"), content.get("flow")
    if isinstance(nodes, list) and nodes and isinstance(content.get("connections"), dict) \
            and all(isinstance(n, dict) and isinstance(n.get("type"), str) for n in nodes[:50]) \
            and any("n8n" in n["type"] or "parameters" in n for n in nodes[:50]):
        return N8N
    if isinstance(flow, list) and flow and all(isinstance(m, dict) and isinstance(m.get("module"), str) for m in flow[:50]) \
            and not content.get("properties"):
        return MAKE
    return None


def _leaves(obj, base=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, base + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, base + (i,))
    else:
        yield base, obj


def _pair_secrets(obj, base=()) -> list[tuple]:
    """{"name": "Authorization", "value": "Bearer abc..."} pairs, which the key-name check cannot see."""
    out: list[tuple] = []
    if isinstance(obj, dict):
        name, val = obj.get("name") or obj.get("key"), obj.get("value")
        if isinstance(name, str) and isinstance(val, str) and (HEADER_SECRET.match(name.strip()) or SECRET_KEY.search(name)) \
                and not val.startswith("=") and _literal(re.sub(r"^(bearer|basic|token)\s+", "", val.strip(), flags=re.I)):
            out.append(base + ("value",))
        for k, v in obj.items():
            out.extend(_pair_secrets(v, base + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_pair_secrets(v, base + (i,)))
    return out


def _short(t: str) -> str:
    return t.rsplit(".", 1)[-1] if "." in t else t


def scan_workflow(filename: str, content: dict, policy: dict | None = None) -> dict:
    kind = kind_of(content)
    if kind is None:
        raise ValueError("Not a recognised workflow export (n8n workflow JSON or Make scenario blueprint).")
    base = filename.rsplit(".", 1)[0]
    findings: list[dict] = []

    def add(sev, rule, title, detail, where, jpath):
        findings.append({"severity": sev, "ruleId": rule, "title": title, "detail": detail, "location": where,
                         "jsonPath": [str(p) for p in jpath], "fix": scanner.FIXES.get(rule, []),
                         "alternative": scanner.ALTERNATIVES.get(rule), "example": scanner.EXAMPLES.get(rule)})

    steps: list[dict] = []
    if kind == N8N:
        name, md = _n8n(base, content, add, steps)
    else:
        name, md = _make(base, content, add, steps)
    steps.insert(0, {"id": "flow:config", "kind": "flow", "name": name, "type": "Metadata", "path": "flow", "depth": 0, "connector": None,
                     "connection": None, "json": {k: v for k, v in content.items() if k not in ("nodes", "flow", "pinData", "connections")}})
    typ = "n8n workflow" if kind == N8N else "Make scenario"
    res = _finish(base, name, kind, typ, steps, md, findings, policy)
    res["connectors"] = sorted({s["connector"] for s in steps if s.get("connector")})
    res["triggerCount"] = sum(1 for s in steps if s["kind"] == "trigger")
    return res


def _inspect(where, label, obj, add, base_path):
    """Secrets, plain-HTTP addresses, shell strings and embedded-code credentials anywhere inside one node or module."""
    flagged = set(_secret_paths(obj)) | set(_pair_secrets(obj))
    for p in sorted(flagged, key=str):
        add("High", "WF-SEC-001", "Hard-coded secret in a workflow", f"'{label}: {'.'.join(str(x) for x in p)}' holds a literal credential. The value is hidden in this report.",
            where, list(base_path) + list(p))
    seen = set()
    for path, val in _leaves(obj):
        if not isinstance(val, str) or path in flagged:
            continue
        key = str(path[-1]) if path else ""
        for rule, sev, title, detail, _secret in value_issues(key, val):
            if rule == "RPA-SEC-001":
                continue                                    # already reported through the path check above
            new = {"RPA-NET-001": "WF-NET-001", "RPA-CODE-001": "WF-CODE-001"}.get(rule)
            if new and (new, detail) not in seen:
                seen.add((new, detail))
                add(sev, new, title, detail.replace("'" + key + "'", f"'{label}: {'.'.join(str(x) for x in path)}'"), where, list(base_path) + list(path))
        if CODE_SECRET.search(val) and ("code" in key.lower() or "script" in key.lower()):
            add("High", "WF-SEC-001", "Hard-coded secret in a workflow", f"'{label}: {'.'.join(str(x) for x in path)}' assigns a literal secret in code. The value is hidden in this report.",
                where, list(base_path) + list(path))
            flagged.add(path)
    return flagged


def _hide(obj, flagged, base=()):
    if isinstance(obj, dict):
        return {k: (REDACTED if base + (k,) in flagged else _hide(v, flagged, base + (k,))) for k, v in obj.items()}
    if isinstance(obj, list):
        return [REDACTED if base + (i,) in flagged else _hide(v, flagged, base + (i,)) for i, v in enumerate(obj)]
    return obj


# ---- n8n ----------------------------------------------------------------------------------------------------------------
def _n8n(base, wf, add, steps):
    name = str(wf.get("name") or base)
    nodes = [n for n in wf["nodes"][:MAX_NODES] if isinstance(n, dict)]
    active = wf.get("active")
    triggers = 0
    for i, n in enumerate(nodes):
        t = str(n.get("type", ""))
        label = str(n.get("name") or _short(t))
        sid = f"node:{i}:{label}"
        params = n.get("parameters") if isinstance(n.get("parameters"), dict) else {}
        is_trigger = bool(N8N_TRIGGER.search(_short(t))) and not t.endswith("respondToWebhook")
        triggers += is_trigger
        jp = ["nodes", i, "parameters"]

        if t.endswith(".webhook") and str(params.get("authentication", "none")).lower() == "none":
            add("High", "WF-TRG-001", "Webhook trigger open to anyone",
                f"'{label}' has Authentication set to None, so anyone who learns the URL can start the workflow.", sid, jp + ["authentication"])
        opts = params.get("options") if isinstance(params.get("options"), dict) else {}
        if opts.get("allowUnauthorizedCerts") is True:
            add("High", "WF-NET-002", "TLS certificate checking disabled", f"'{label}' ignores SSL certificate errors, so the connection can be intercepted.",
                sid, jp + ["options", "allowUnauthorizedCerts"])
        if N8N_SHELL.search(t):
            add("High", "WF-CODE-001", "Shell or system command started", f"'{label}' runs an operating-system command.", sid, jp + ["command"])
        elif N8N_CODE.search(t):
            add("Low", "WF-CODE-002", "Embedded code or script step", f"'{label}' runs custom code inside the workflow.", sid, jp)
        if N8N_SQL.search(t):
            q = params.get("query")
            if isinstance(q, str) and "{{" in q:
                add("Medium", "WF-INJ-001", "SQL built from workflow data",
                    f"'{label}' puts expression values straight into the SQL text, so incoming data can change the query.", sid, jp + ["query"])
        if AI_NAME.search(t):
            add("Medium", "WF-AI-001", "Data sent to an AI service", f"'{label}' ({_short(t)}) sends content to an AI model.", sid, ["nodes", i, "type"])
        if n.get("continueOnFail") is True or str(n.get("onError", "")).startswith("continue"):
            add("Low", "WF-CFG-001", "Errors ignored", f"'{label}' carries on after a failure, so problems can pass unnoticed.", sid, ["nodes", i])

        flagged = _inspect(sid, label, params, add, jp)
        steps.append({"id": sid, "kind": "trigger" if is_trigger else "action", "name": label, "type": _short(t), "path": f"nodes[{i}] {label}",
                      "depth": 0, "connector": _short(t), "connection": None, "json": {**{k: v for k, v in n.items() if k != "parameters"},
                                                                                         "parameters": _hide(params, flagged)}})

    pin = wf.get("pinData")
    if isinstance(pin, dict) and pin:
        add("Medium", "WF-CFG-002", "Test data pinned in the workflow",
            f"{len(pin)} node(s) carry pinned sample data that is saved inside the export and may hold real records.", "flow", ["pinData"])
    if active is False:
        add("Low", "WF-GOV-001", "Workflow is not active", "The workflow is switched off. Review it or remove it.", "flow", ["active"])
    settings = wf.get("settings") if isinstance(wf.get("settings"), dict) else {}
    if active is not False and triggers and not settings.get("errorWorkflow"):
        add("Low", "WF-CFG-003", "No error workflow", "No error workflow is set, so failed runs may not alert anyone.", "flow", ["settings"])
    md = {"Nodes": len(nodes), "Triggers": triggers, "Active": None if active is None else ("Yes" if active else "No"),
          "Pinned data nodes": len(pin) if isinstance(pin, dict) else 0}
    md["State"] = "Inactive" if active is False else "Active" if active else "Defined"
    return name, md


# ---- Make ---------------------------------------------------------------------------------------------------------------
def _make_modules(flow, trail=()):
    for i, m in enumerate(flow):
        if not isinstance(m, dict):
            continue
        yield trail + (i,), m
        for r, route in enumerate(m.get("routes") or []):
            if isinstance(route, dict) and isinstance(route.get("flow"), list):
                yield from _make_modules(route["flow"], trail + (i, "routes", r, "flow"))


def _make(base, bp, add, steps):
    name = str(bp.get("name") or base)
    count = 0
    triggers = 0
    for trail, m in _make_modules(bp["flow"]):
        count += 1
        if count > MAX_NODES:
            break
        mod = str(m.get("module", ""))
        mid = m.get("id", count)
        sid = f"module:{mid}:{mod}"
        label = f"{mod} (#{mid})"
        jp = ["flow"] + list(trail)
        is_trigger = bool(MAKE_WEBHOOK.match(mod)) or ":watch" in mod.lower()
        triggers += is_trigger
        mapper = m.get("mapper") if isinstance(m.get("mapper"), dict) else {}
        params = m.get("parameters") if isinstance(m.get("parameters"), dict) else {}

        if MAKE_WEBHOOK.match(mod):
            add("Medium", "WF-TRG-002", "Webhook trigger: caller not restricted in the export",
                f"{label} starts the scenario from an address anyone who learns it can call. The export does not show an IP restriction or a secret check.",
                sid, jp)
        if mapper.get("rejectUnauthorized") is False or params.get("rejectUnauthorized") is False:
            add("High", "WF-NET-002", "TLS certificate checking disabled", f"{label} accepts unverified certificates, so the connection can be intercepted.",
                sid, jp + ["mapper", "rejectUnauthorized"])
        if MAKE_SHELL.search(mod):
            add("High", "WF-CODE-001", "Shell or system command started", f"{label} runs a command on a remote or local system.", sid, jp)
        elif mod.lower().startswith("code:"):
            add("Low", "WF-CODE-002", "Embedded code or script step", f"{label} runs custom code inside the scenario.", sid, jp)
        if MAKE_SQL.match(mod):
            for key in ("query", "statement", "sql"):
                q = mapper.get(key)
                if isinstance(q, str) and "{{" in q:
                    add("Medium", "WF-INJ-001", "SQL built from workflow data",
                        f"{label} puts mapped values straight into the SQL text, so incoming data can change the query.", sid, jp + ["mapper", key])
        if MAKE_AI.match(mod):
            add("Medium", "WF-AI-001", "Data sent to an AI service", f"{label} sends content to an AI model.", sid, jp)
        if mod in ("builtin:Ignore", "builtin:Resume"):
            add("Low", "WF-CFG-001", "Errors ignored", f"{label} swallows errors, so failures can pass unnoticed.", sid, jp)

        flagged = _inspect(sid, label, {"parameters": params, "mapper": mapper}, add, jp)
        shown = _hide({"parameters": params, "mapper": mapper}, flagged)
        steps.append({"id": sid, "kind": "trigger" if is_trigger else "action", "name": label, "type": mod.split(":")[0], "path": f"flow {'/'.join(str(x) for x in trail)} {mod}",
                      "depth": max(0, (len(trail) - 1) // 3), "connector": mod.split(":")[0], "connection": None,
                      "json": {**{k: v for k, v in m.items() if k not in ("parameters", "mapper", "routes")}, **shown}})
    md = {"Modules": count, "Triggers": triggers, "State": "Defined"}
    return name, md

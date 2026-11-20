"""Static analysis of AI agent definitions and MCP server configurations.

Two kinds of JSON are recognised:
  * MCP configuration: {"mcpServers": {...}} (desktop AI clients, editors), {"servers": {...}} (VS Code) or {"mcp": {"servers": {...}}}
  * Agent definition: instructions + a `tools` list and/or a model (OpenAI / Azure style assistants, and similar)

Checks are about configuration only. Nothing is run, no server is contacted, and no prompt is sent to a model. Some checks are
heuristics based on tool names and descriptions (marked "may" in their messages); they point a reviewer at a combination worth
a decision, they do not prove an exploit. Results use the same shape as scanner.scan_flow, so the workbench, gate, SARIF and
reports need no changes.
"""
import copy
import os
import re
from urllib.parse import urlparse

import scanner
from flowio import normalize
from rules import clean_policy, meta

FLOW_KEYS = {"properties", "definition", "triggers", "actions", "resources"}
INSTR_KEYS = ("instructions", "system_prompt", "systemPrompt", "system", "prompt")
URL_KEYS = ("url", "serverUrl", "server_url")
BASE_URL_KEYS = ("base_url", "baseUrl", "endpoint", "api_base", "apiBase", "openai_api_base", "api_url", "apiUrl")
APPROVAL_KEYS = ("require_approval", "requires_approval", "needs_approval", "human_approval", "human_in_the_loop", "confirmation", "approval")
AUTOAPPROVE_KEYS = ("autoApprove", "alwaysAllow", "auto_approve", "trust")
DELEGATE_KEYS = ("handoffs", "sub_agents", "subAgents", "agents", "connected_agents", "connectedAgents", "delegates")
PERM_KEYS = ("permissions", "scopes", "roles", "allowed_tools", "allowedTools", "capabilities", "allow")
THIRD_PARTY_PROVIDERS = {"openai", "anthropic", "google", "gemini", "mistral", "cohere", "groq", "deepseek", "together", "xai", "perplexity", "huggingface"}
TENANT_HOSTS = re.compile(r"(\.openai\.azure\.com|\.cognitiveservices\.azure\.com|\.services\.ai\.azure\.com|bedrock-runtime\.[\w-]+\.amazonaws\.com|-aiplatform\.googleapis\.com)$", re.I)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
REDACTED = "***redacted***"

TOKEN_RES = [re.compile(p) for p in (
    r"sk-[A-Za-z0-9_\-]{20,}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{30,}", r"xox[abprs]-[A-Za-z0-9\-]{10,}",
    r"AKIA[0-9A-Z]{16}", r"AIza[0-9A-Za-z_\-]{35}", r"glpat-[A-Za-z0-9_\-]{20,}", r"hf_[A-Za-z0-9]{30,}",
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
SECRET_KEY = re.compile(r"(^|[_\-.])(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|authorization|credential|private[_-]?key|client[_-]?secret)s?($|[_\-.])", re.I)
SECRET_FLAG = re.compile(r"^--?[\w-]*(token|api-?key|secret|password|passwd|pwd)[\w-]*$", re.I)
PLACEHOLDER = re.compile(r"^\s*($|\$\{[^}]*\}|\$[A-Za-z_]\w*|%[^%]+%|<[^>]*>|\{\{.*\}\}|\*+|x{3,}|your[-_ ].*|changeme|placeholder|example.*|todo|null|none|true|false)\s*$", re.I)
BENIGN = {"bearer", "basic", "oauth", "oauth2", "none", "anonymous", "api_key", "apikey", "header", "query", "token", "password", "secret"}
URL_SECRET = re.compile(r"([?&](api[_-]?key|access[_-]?token|token|key|secret)=([^&\s]+))|(://[^/\s:@]+:[^/\s@]+@)", re.I)
ROOTISH = re.compile(r"^(/|[A-Za-z]:[\\/]*|~[\\/]*|\$\{?HOME\}?[\\/]*|%USERPROFILE%[\\/]*|/home[\\/]*|/Users[\\/]*|[A-Za-z]:[\\/]+Users[\\/]*)$", re.I)
BROAD_PERM = re.compile(r"^\*$|^all$|:\*$|\.\*$|\(\*\)$|(^|[.:/_-])(admin|owner|superuser|root|fullcontrol|full_?access)($|[.:/_-])|\.(readwrite|fullcontrol|manage)\.all$", re.I)
RISKY_PARAM = re.compile(r"(^|_)(command|cmd|sql|query|statement|code|script|path|file|filename|url|uri|expression|expr|shell)($|_)", re.I)
SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"}
INTERPRETERS = {"python", "python3", "py", "node", "deno", "bun", "ruby", "perl", "php"}
INLINE_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc", "-e", "--eval", "-p", "--print"}
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir", "-u", "--user", "--env-file", "--entrypoint", "--platform", "--cap-add", "--pid"}
INSECURE_FLAGS = {"--insecure", "--no-check-certificate", "--disable-ssl-verification", "--ignore-certificate-errors", "--tls-skip-verify", "--skip-tls-verify", "--insecure-skip-tls-verify"}

CAP_WORDS = {
    "exec": r"\b(bash|shell|terminal|powershell|exec|execute|run (code|command|script|shell)|eval|code (interpreter|execution)|computer|sandbox)\b",
    "untrusted": r"\b(browse|browser|web (search|fetch|browse)|search|scrape|crawl|fetch|download|puppeteer|playwright|read (email|inbox|mail|message|page|url|rss)|inbox|mailbox|rss|file search|retriev\w*|rag|knowledge)\b",
    "private": r"\b(database|sql|postgres|mysql|sqlite|mongo\w*|sharepoint|onedrive|drive|crm|salesforce|customer|employee|hr|payroll|email|mail|inbox|calendar|documents?|files?|filesystem|knowledge|vault|secrets?|patient|medical|github|repo(sitory)?)\b",
    "exfil": r"\b(send|post|publish|tweet|slack|teams|discord|webhook|email|mail|upload|share|http (post|request)|request|notify|sms)\b",
    "destructive": r"\b(delete|remove|drop|truncate|terminate|transfer|pay(ment)?|deploy|merge|push|commit|write|update|create|edit|modify|approve|revoke|disable)\b",
}
CAP_RES = {k: re.compile(v, re.I) for k, v in CAP_WORDS.items()}

# ---------------------------------------------------------------------------------------------------------------------
# Guidance. Registered with the flow scanner's tables so reports, SARIF and the UI treat every rule the same way.
FIXES: dict[str, list[str]] = {
    "AG-SEC-001": [
        "Remove the value from the file and read it from an environment variable or a secret store instead (for example ${env:NAME} or a secret input your client prompts for).",
        "Treat the exposed value as compromised: revoke it and issue a new one.",
        "Keep the file out of source control, or commit a version with placeholders only.",
    ],
    "AG-MCP-001": [
        "Change the address to https:// and confirm the server supports TLS.",
        "If the server only speaks HTTP, run it on the same machine (localhost) or put it behind a TLS-terminating gateway.",
    ],
    "AG-MCP-002": [
        "Configure a credential for the server (for example an Authorization header read from an environment variable, or OAuth sign-in) and confirm the server rejects anonymous callers.",
        "Limit which tools the agent may call on this server, so a missing credential exposes less.",
    ],
    "AG-MCP-003": [
        "Pin an exact version (for example package@1.4.2, or image:1.4.2 / image@sha256:...) instead of latest or no version.",
        "Review the package or image before first use and update it on purpose, not automatically.",
    ],
    "AG-MCP-004": [
        "Start the server directly (command plus fixed arguments) rather than through a shell or an inline code string.",
        "If a shell is unavoidable, use a fixed script file that has been reviewed, and pass no model-controlled text into it.",
    ],
    "AG-MCP-005": [
        "Give the file server only the folders it needs (for example one project folder), never a drive root or a whole home folder.",
        "Prefer read-only access where the server supports it.",
    ],
    "AG-MCP-006": [
        "Remove --privileged and any broad capability, and do not mount the Docker socket or the host root into the container.",
        "Mount only the specific folders the server needs, read-only where possible.",
    ],
    "AG-MCP-007": [
        "Remove the setting that turns certificate checking off, and trust the right certificate authority instead if a private one is in use.",
    ],
    "AG-MCP-008": [
        "Do not auto-approve tool calls. Require a person to approve tools that change or send data.",
        "If some read-only tools are safe, list only those by name instead of approving everything.",
    ],
    "AG-AGT-001": [
        "Remove the tool if the agent does not need it. If it does, run it in an isolated sandbox with no network and no access to secrets.",
        "Require a person to approve each command or run.",
    ],
    "AG-AGT-002": [
        "Require human approval before tools that send, change or delete things run (for example require_approval set to always).",
        "Give the agent the narrowest version of the tool, for example read-only instead of read-write.",
    ],
    "AG-AGT-003": [
        "Constrain the parameter: use an enum of allowed values, a pattern, a maximum length, or split the tool into specific safe operations.",
        "Validate and escape the value on the server side as well; do not rely on the model to do it.",
    ],
    "AG-AGT-004": [
        "Separate duties: do not give an agent that reads untrusted content (web pages, email, uploaded files) the tools to act, or require approval for those tools.",
        "Treat everything retrieved as data, not instructions, and keep sensitive tools in a different agent with no access to that content.",
    ],
    "AG-AGT-005": [
        "Do not let one agent both read private data and send data out. Remove one capability or require approval for sending.",
        "If both are needed, restrict where it can send (an allow-list of recipients or domains) and log every send.",
    ],
    "AG-AGT-006": [
        "Replace wildcard or administrator permissions with the specific permissions the agent needs.",
        "List allowed tools by name instead of allowing all tools.",
    ],
    "AG-LLM-001": [
        "Confirm this provider is approved for the data the agent handles, and that its retention and training terms suit you.",
        "Prefer a model endpoint inside your own cloud tenant for sensitive data.",
    ],
    "AG-LLM-002": [
        "Change the model endpoint to https://. Never send prompts or keys over plain HTTP.",
    ],
    "AG-A2A-001": [
        "List exactly which agents may receive work, pass only the information they need, and authenticate calls between agents.",
        "Give each delegate no more tools than its job needs, so a hijacked agent cannot reach the others' tools.",
    ],
}
ALTERNATIVES: dict[str, dict] = {
    "AG-SEC-001": {"title": "Use short-lived credentials", "steps": [
        "Use OAuth or a managed identity so there is no long-lived key to leak.",
        "Or fetch the secret at start-up from a vault and keep it in memory only."]},
    "AG-MCP-001": {"title": "Reach the server through a secure gateway", "steps": [
        "Publish the server through an API gateway that terminates TLS and requires sign-in.",
        "Or run it locally over stdio so no network connection is needed."]},
    "AG-MCP-002": {"title": "Run the server where only your agent can reach it", "steps": [
        "Bind it to localhost or a private network, and use a firewall rule or private endpoint so only trusted hosts connect."]},
    "AG-MCP-003": {"title": "Vendor the server", "steps": [
        "Copy the reviewed server into your own repository or registry and run it from there, so upstream changes cannot reach you silently."]},
    "AG-MCP-004": {"title": "Wrap the server in a reviewed launcher", "steps": [
        "Create a small reviewed script that starts the server with fixed arguments and call that script by path."]},
    "AG-MCP-005": {"title": "Use a scoped working folder", "steps": [
        "Create a dedicated folder for the agent, copy in only what it needs, and give the server that folder."]},
    "AG-MCP-006": {"title": "Use a rootless or sandboxed runtime", "steps": [
        "Run the container as a non-root user with a read-only filesystem and no extra capabilities."]},
    "AG-MCP-007": {"title": "Fix the certificate instead", "steps": [
        "Install the correct certificate chain on the server, or add your organization's root certificate to the trust store."]},
    "AG-MCP-008": {"title": "Approve by exception", "steps": [
        "Auto-approve only a short named list of read-only tools, and keep approval on for the rest."]},
    "AG-AGT-001": {"title": "Replace it with specific tools", "steps": [
        "Offer narrow tools that do one safe thing (for example 'convert file') instead of general code or shell execution."]},
    "AG-AGT-002": {"title": "Add a review step outside the model", "steps": [
        "Queue the action for a person or an approval workflow, and let the agent only propose it."]},
    "AG-AGT-003": {"title": "Offer fixed operations", "steps": [
        "Replace a free-form query or command with named operations that take typed, validated arguments."]},
    "AG-AGT-004": {"title": "Isolate the reading agent", "steps": [
        "Let one low-privilege agent read and summarize outside content, and pass only its plain-text summary to the agent that can act."]},
    "AG-AGT-005": {"title": "Remove the way out", "steps": [
        "Drop the send or upload tool, or limit it to an allow-listed destination and log each use."]},
    "AG-AGT-006": {"title": "Grant permissions per task", "steps": [
        "Issue short-lived, task-specific permissions rather than standing broad access."]},
    "AG-LLM-001": {"title": "Use a tenant-hosted model", "steps": [
        "Host the model in your own cloud account (for example Azure OpenAI, Bedrock or Vertex) with data retention off."]},
    "AG-LLM-002": {"title": "Use a secure proxy", "steps": [
        "Send model calls through an HTTPS gateway you control."]},
    "AG-A2A-001": {"title": "Use one orchestrator with fixed routes", "steps": [
        "Route work through a single orchestrator that decides which agent runs, instead of letting agents call each other freely."]},
}
EXAMPLES: dict[str, dict] = {
    "AG-SEC-001": {"before": '"env": { "GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }',
                   "after": '"env": { "GITHUB_TOKEN": "${env:GITHUB_TOKEN}" }'},
    "AG-MCP-001": {"before": '"url": "http://tools.example.com/mcp"', "after": '"url": "https://tools.example.com/mcp"'},
    "AG-MCP-003": {"before": '"args": ["-y", "@modelcontextprotocol/server-github"]',
                   "after": '"args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"]'},
    "AG-MCP-007": {"before": '"env": { "NODE_TLS_REJECT_UNAUTHORIZED": "0" }', "after": '"env": { }'},
    "AG-AGT-002": {"before": '"require_approval": "never"', "after": '"require_approval": "always"'},
}
scanner.FIXES.update(FIXES)
scanner.ALTERNATIVES.update(ALTERNATIVES)
scanner.EXAMPLES.update(EXAMPLES)


# ---------------------------------------------------------------------------------------------------------------------
def _instr_key(root: dict) -> str | None:
    return next((k for k in INSTR_KEYS if isinstance(root.get(k), str) and root[k].strip()), None)


def _servers_dict(root: dict) -> dict | None:
    for d in (root.get("mcpServers"), root.get("servers"), (root.get("mcp") or {}).get("servers") if isinstance(root.get("mcp"), dict) else None):
        if isinstance(d, dict) and d and all(isinstance(v, dict) for v in d.values()):
            return d
    return None


def _agent_root(content: dict) -> dict | None:
    for cand in (content, content.get("agent"), content.get("assistant")):
        if isinstance(cand, dict):
            tools = cand.get("tools")
            if _instr_key(cand) and (isinstance(tools, list) or cand.get("model") or _servers_dict(cand)):
                return cand
            if isinstance(tools, list) and tools and cand.get("model") and all(isinstance(t, (dict, str)) for t in tools):
                return cand
    return None


def kind_of(content) -> str | None:
    """'agent', 'mcp' or None. Anything that looks like a flow definition is never treated as an agent."""
    if not isinstance(content, dict) or FLOW_KEYS & content.keys():
        return None
    if _agent_root(content) is not None:
        return "agent"
    servers = _servers_dict(content)
    if servers and all(("command" in v or any(k in v for k in URL_KEYS) or "type" in v) for v in servers.values()):
        return "mcp"
    return None


def scan_any(filename: str, content: dict, policy: dict | None = None) -> dict:
    """Scan a Power Automate flow, an MCP configuration or an agent definition, whichever the JSON turns out to be."""
    if kind_of(content):
        return scan_agent(filename, content, policy)
    try:
        return scanner.scan_flow(normalize(filename, content), policy)
    except ValueError:
        raise ValueError("Not a Power Automate flow, an MCP server configuration or an AI agent definition.")


def _leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, path + (i,))
    else:
        yield path, obj


def _literal(v: str) -> bool:
    s = v.strip()
    return len(s) >= 8 and "${" not in s and "{{" not in s and not PLACEHOLDER.match(s) and s.lower() not in BENIGN


def _has_token(v: str) -> bool:
    return any(r.search(v) for r in TOKEN_RES)


def _url_secret(v: str) -> bool:
    """A literal key in a URL's query string, or a literal password in its user info."""
    for m in URL_SECRET.finditer(v):
        val = m.group(3) if m.group(3) is not None else (m.group(4) or "").split(":", 1)[-1].rstrip("@")
        if val and "${" not in val and "{{" not in val and not PLACEHOLDER.match(val):
            return True
    return False


def _secret_paths(obj, base=()) -> list[tuple]:
    """Paths of strings under obj that hold a literal credential: known token shapes, secret-named keys, or credentials in a URL."""
    out: list[tuple] = []
    for path, val in _leaves(obj, base):
        if not isinstance(val, str):
            continue
        key = path[-1] if path else None
        is_url = bool(re.match(r"^https?://", val.strip(), re.I))
        if _has_token(val) or _url_secret(val) or (isinstance(key, str) and SECRET_KEY.search(key) and not is_url and _literal(val)):
            out.append(path)
    return out


def _arg_secret_paths(args: list, base=()) -> list[tuple]:
    out = []
    for i, a in enumerate(args):
        if not isinstance(a, str):
            continue
        m = re.match(r"^--?[\w-]*(token|api-?key|secret|password|passwd|pwd)[\w-]*=(.+)$", a, re.I)
        env = re.match(r"^([A-Za-z_]\w*)=(.+)$", a)
        if m and _literal(m.group(2)):
            out.append(base + (i,))
        elif env and SECRET_KEY.search(env.group(1)) and _literal(env.group(2)):
            out.append(base + (i,))
        elif SECRET_FLAG.match(a) and i + 1 < len(args) and isinstance(args[i + 1], str) and not args[i + 1].startswith("-") and _literal(args[i + 1]):
            out.append(base + (i + 1,))
    return out


def _redact(obj, paths: set):
    obj = copy.deepcopy(obj)

    def walk(o, path=()):
        if isinstance(o, dict):
            return {k: (REDACTED if path + (k,) in paths and isinstance(v, str) else walk(v, path + (k,))) for k, v in o.items()}
        if isinstance(o, list):
            return [REDACTED if path + (i,) in paths and isinstance(v, str) else walk(v, path + (i,)) for i, v in enumerate(o)]
        if isinstance(o, str):
            for r in TOKEN_RES:
                o = r.sub(REDACTED, o)
            o = re.sub(r"([?&](?:api[_-]?key|access[_-]?token|token|key|secret)=)(?!\$\{)[^&\s]+", r"\1" + REDACTED, o, flags=re.I)
            return re.sub(r"(://[^/\s:@]+:)(?!\$\{)[^/\s@]+@", r"\1" + REDACTED + "@", o)
        return o
    return walk(obj)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _remote(url) -> bool:
    return isinstance(url, str) and url.lower().startswith(("http://", "https://")) and _host(url) not in LOCAL_HOSTS


def _remote_http(url) -> bool:
    return _remote(url) and url.lower().startswith("http://")


def _words(*parts: str) -> str:
    raw = " ".join(p for p in parts if p)
    raw = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
    return re.sub(r"[_\-./:\\]+", " ", raw).lower()


def _caps(label: str, type_: str, desc: str) -> set:
    text = _words(label, type_, desc[:200])
    caps = {k for k, r in CAP_RES.items() if r.search(text)}
    if re.match(r"(bash|computer|local_shell|shell|code_interpreter|code_execution|text_editor)", type_ or "", re.I):
        caps.add("exec")
    if re.match(r"(file_search|web_search)", type_ or "", re.I):
        caps.add("untrusted")
    if re.match(r"file_search", type_ or "", re.I):
        caps.add("private")
    return caps


def _dedupe(names: list[str]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for n in names:
        seen[n] = seen.get(n, 0) + 1
        out.append(n if seen[n] == 1 else f"{n} ({seen[n]})")
    return out


def _tool_dicts(root: dict) -> list[dict]:
    return [t if isinstance(t, dict) else {"name": str(t)} for t in (root.get("tools") if isinstance(root.get("tools"), list) else [])]


def _tool_name(t: dict, i: int) -> str:
    fn = t.get("function") if isinstance(t.get("function"), dict) else t
    return str(fn.get("name") or t.get("server_label") or t.get("type") or f"tool{i + 1}")


def _is_server(cfg: dict, servers: dict) -> bool:
    return any(cfg is s for s in servers.values())


def components(root: dict, kind: str) -> dict[str, dict]:
    """label -> the live dict of each MCP server and each tool, with names made unique. Used by the scanner and the fixer."""
    out: dict[str, dict] = {}
    servers = _servers_dict(root) or {}
    for label, cfg in zip(_dedupe(list(servers)), servers.values()):
        out[label] = cfg
    if kind == "agent":
        tools = _tool_dicts(root)
        for label, t in zip(_dedupe([_tool_name(t, i) for i, t in enumerate(tools)]), tools):
            out[label if label not in out else f"{label} (tool)"] = t
    return out


def _spec_of(base: str, args: list[str]) -> tuple[str | None, int | None]:
    """The package or image a launcher will fetch and run, and the index of that argument."""
    if base in ("npx", "bunx") or (base in ("pnpm", "yarn") and "dlx" in args) or (base == "npm" and "exec" in args):
        for i, a in enumerate(args):
            if a.startswith("--package="):
                return a.split("=", 1)[1], i
            if not a.startswith("-") and a not in ("dlx", "exec"):
                return a, i
    if base in ("uvx", "pipx"):
        for i, a in enumerate(args):
            if not a.startswith("-") and a != "run":
                return a, i
    if base in ("docker", "podman") and "run" in args:
        skip = False
        for i, a in enumerate(args[args.index("run") + 1:], args.index("run") + 1):
            if skip:
                skip = False
            elif a.startswith("-"):
                skip = a in DOCKER_VALUE_FLAGS
            else:
                return a, i
    return None, None


def _pinned(base: str, spec: str) -> bool:
    if base in ("docker", "podman"):
        last = spec.rsplit("/", 1)[-1]
        return "@sha256:" in spec or (":" in last and not last.endswith(":latest"))
    if "://" in spec or spec.startswith("git+"):
        return "#" in spec or re.search(r"@[0-9a-f]{7,40}$", spec) is not None
    if "==" in spec:
        return re.search(r"==\d", spec) is not None
    name, _, ver = spec.rpartition("@")
    return bool(name) and re.match(r"^\d+\.\d+\.\d+", ver) is not None


def scan_agent(filename: str, content: dict, policy: dict | None = None) -> dict:
    kind = kind_of(content)
    if kind is None:
        raise ValueError("Not an MCP configuration or AI agent definition.")
    root = _agent_root(content) if kind == "agent" else content
    base_name = filename.rsplit(".", 1)[0]
    name = str(root.get("name") or root.get("display_name") or base_name)
    comps = components(root, kind)
    findings: list[dict] = []
    flagged: dict[str, set] = {}      # location -> secret paths to hide in the step JSON

    def add(sev, rule, title, detail, where, jpath=None):
        findings.append({"severity": sev, "ruleId": rule, "title": title, "detail": detail, "location": where,
                         "jsonPath": [str(p) for p in (jpath or [])], "fix": scanner.FIXES.get(rule, []),
                         "alternative": scanner.ALTERNATIVES.get(rule), "example": scanner.EXAMPLES.get(rule)})

    def secrets(where: str, obj, base=(), extra: list[tuple] | None = None):
        paths = set(_secret_paths(obj, base)) | set(extra or [])
        for p in sorted(paths, key=str):
            flagged.setdefault(where, set()).add(tuple(p[len(base):]) if base else tuple(p))
            add("High", "AG-SEC-001", "Hard-coded secret in AI configuration",
                f"'{'.'.join(str(x) for x in p)}' holds a literal credential. The value is hidden in this report.", where, p)

    caps_by: dict[str, set] = {}
    spec_by: dict[str, str] = {}

    # ---- MCP servers (and OpenAI-style "mcp" tools) ----
    servers = _servers_dict(root) or {}
    for label, cfg in comps.items():
        where = f"action:{label}"
        is_server = _is_server(cfg, servers)
        is_mcp_tool = not is_server and str(cfg.get("type", "")).lower() == "mcp"
        if not (is_server or is_mcp_tool):
            continue
        cmd = str(cfg.get("command") or "")
        raw_args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        args = [str(a) for a in raw_args]
        base = re.sub(r"\.(exe|cmd|bat)$", "", os.path.basename(cmd.replace("\\", "/")).lower())
        url = next((cfg[k] for k in URL_KEYS if isinstance(cfg.get(k), str)), None)
        url_key = next((k for k in URL_KEYS if isinstance(cfg.get(k), str)), None)

        secrets(where, {k: cfg[k] for k in ("env", "headers", "url", "serverUrl", "server_url") if k in cfg},
                extra=_arg_secret_paths(args, ("args",)))

        if _remote_http(url):
            add("High", "AG-MCP-001", "Remote MCP server over plain HTTP", f"{url_key} '{_host(url)}' is reached over http://.", where, [url_key])
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        has_cred = (any(SECRET_KEY.search(str(k)) or str(k).lower() in ("authorization", "x-api-key") for k in headers)
                    or any(k in cfg for k in ("auth", "oauth", "authorization")) or bool(url and URL_SECRET.search(url)))
        if _remote(url) and not has_cred:
            add("Medium", "AG-MCP-002", "Remote MCP server with no credential configured",
                f"'{_host(url)}' has no Authorization header, key or sign-in in this configuration.", where, [url_key])
        if "mcp-remote" in " ".join(args):
            for i, a in enumerate(args):
                if _remote_http(a):
                    add("High", "AG-MCP-001", "Remote MCP server over plain HTTP", f"The proxy is pointed at http://{_host(a)}.", where, ["args", i])
                elif _remote(a) and "--header" not in args and not any(SECRET_KEY.search(str(k)) for k in (cfg.get("env") or {})):
                    add("Medium", "AG-MCP-002", "Remote MCP server with no credential configured",
                        f"'{_host(a)}' has no header or key passed through the proxy.", where, ["args", i])

        if (base in SHELLS or base in INTERPRETERS) and any(a.lower() in INLINE_FLAGS for a in args):
            add("High", "AG-MCP-004", "MCP server started through a shell or inline code",
                f"'{base}' is started with an inline command or code string.", where, ["command"])
        spec, idx = _spec_of(base, args)
        if spec:
            spec_by[label] = spec
            if not _pinned(base, spec):
                add("Medium", "AG-MCP-003", "MCP server runs an unpinned package or image",
                    f"'{spec}' has no fixed version, so what runs can change without review.", where, ["args", idx])
        if base in ("docker", "podman") and "run" in args:
            reasons, only_network = [], True
            for i, a in enumerate(args):
                nxt = args[i + 1] if i + 1 < len(args) else ""
                if a == "--privileged":
                    reasons.append("--privileged"); only_network = False
                elif a.startswith("--cap-add") and re.search(r"(ALL|SYS_ADMIN)", a + " " + (nxt if a == "--cap-add" else ""), re.I):
                    reasons.append("broad Linux capabilities"); only_network = False
                elif a in ("--pid=host", "--ipc=host") or (a in ("--pid", "--ipc") and nxt == "host"):
                    reasons.append("host process namespace"); only_network = False
                elif a in ("--network=host", "--net=host") or (a in ("--network", "--net") and nxt == "host"):
                    reasons.append("host network")
                elif a in ("-v", "--volume", "--mount") or a.startswith(("-v=", "--volume=", "--mount=")):
                    val = nxt if a in ("-v", "--volume", "--mount") else a.split("=", 1)[1]
                    if "docker.sock" in val or re.match(r"^(/|[A-Za-z]:[\\/]?):", val) or "source=/," in val or "src=/," in val:
                        reasons.append("a sensitive host path mounted"); only_network = False
            if reasons:
                add("Medium" if only_network else "High", "AG-MCP-006", "MCP container with host-level access",
                    f"The container is started with {', '.join(sorted(set(reasons)))}.", where, ["args"])
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        for k, v in env.items():
            if (str(k) in ("NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY") and str(v) == "0") or \
               (re.search(r"(SSL|TLS).*VERIFY|VERIFY.*(SSL|TLS)", str(k), re.I) and str(v).lower() in ("0", "false", "no", "off")):
                add("High", "AG-MCP-007", "TLS certificate checking disabled", f"env.{k} turns certificate checking off.", where, ["env", k])
        for i, a in enumerate(args):
            if a.lower() in INSECURE_FLAGS:
                add("High", "AG-MCP-007", "TLS certificate checking disabled", f"The argument '{a}' turns certificate checking off.", where, ["args", i])
        if "filesystem" in _words(cmd, " ".join(args)) or "server fs" in _words(" ".join(args)):
            for i, a in enumerate(args):
                if ROOTISH.match(a.strip()):
                    add("High", "AG-MCP-005", "MCP server with broad file access", f"The file server is allowed to use '{a}'.", where, ["args", i])
        for key in AUTOAPPROVE_KEYS:
            v = cfg.get(key)
            if v is True or (isinstance(v, list) and v):
                star = isinstance(v, list) and "*" in v
                add("Medium", "AG-MCP-008", "Tool calls approved automatically",
                    "All tools are approved without asking." if star or v is True else f"{len(v)} tool(s) are approved without asking.", where, [key])
        if is_mcp_tool:
            ra = cfg.get("require_approval")
            if ra == "never" or ra is False:
                add("Medium", "AG-AGT-002", "Powerful tool without a human approval step", "require_approval is set to never for this MCP tool.", where, ["require_approval"])
            if "allowed_tools" not in cfg:
                add("Low", "AG-AGT-006", "Excessive or wildcard permissions", "No allowed_tools list: every tool the server offers can be called.", where, ["server_label"] if "server_label" in cfg else ["type"])
        caps_by[label] = _caps(label, "", " ".join([spec_by.get(label, ""), _host(url or ""), str(cfg.get("description", ""))]))

    # ---- agent definition ----
    if kind == "agent":
        for label, t in comps.items():
            if _is_server(t, servers) or str(t.get("type", "")).lower() == "mcp":
                continue
            where = f"action:{label}"
            fn = t.get("function") if isinstance(t.get("function"), dict) else None
            ref = fn if fn is not None else t
            type_ = str(t.get("type") or "")
            desc = str(ref.get("description") or "")
            caps = _caps(label, type_, desc)
            caps_by[label] = caps
            secrets(where, t)
            name_path = (["function", "name"] if fn is not None and "name" in fn else ["name"] if "name" in t else ["type"])
            if re.match(r"(bash|computer|local_shell|shell|text_editor)", type_, re.I) or ("exec" in caps and re.search(r"\b(bash|shell|terminal|powershell)\b", _words(label), re.I)):
                add("High", "AG-AGT-001", "Code execution or computer-control tool", f"'{label}' lets the agent run shell commands or control a computer.", where, name_path)
            elif "exec" in caps:
                add("Medium", "AG-AGT-001", "Code execution or computer-control tool", f"'{label}' lets the agent run code.", where, name_path)
            approval_key = next((k for k in APPROVAL_KEYS if k in t or k in ref), None)
            if approval_key and (t.get(approval_key, ref.get(approval_key)) in ("never", False)):
                add("Medium", "AG-AGT-002", "Powerful tool without a human approval step", f"{approval_key} is turned off for '{label}'.", where,
                    ([approval_key] if approval_key in t else ["function", approval_key]))
            elif not approval_key and caps & {"exfil", "destructive"} and "exec" not in caps:
                add("Low", "AG-AGT-002", "Powerful tool without a human approval step",
                    f"'{label}' may send, change or delete things and has no approval setting.", where, name_path)
            pkey = next((k for k in ("parameters", "input_schema", "inputSchema") if isinstance(ref.get(k), dict)), None)
            props = (ref[pkey].get("properties") if pkey else None) or {}
            loose = [p for p, ps in props.items() if isinstance(ps, dict) and RISKY_PARAM.search(str(p))
                     and ps.get("type", "string") == "string" and not any(c in ps for c in ("enum", "pattern", "maxLength", "format", "const"))]
            if loose:
                add("Medium", "AG-AGT-003", "Tool accepts unconstrained free-form input",
                    f"'{label}' takes free text in {', '.join(repr(p) for p in loose[:4])} with no allowed values or limits.", where,
                    (["function"] if fn is not None else []) + [pkey, "properties", loose[0]])

        ikey = _instr_key(root)
        if ikey and _has_token(root[ikey]):
            flagged.setdefault("flow", set()).add((ikey,))
            add("High", "AG-SEC-001", "Hard-coded secret in AI configuration", f"The {ikey} text contains a credential. The value is hidden in this report.", "flow", [ikey])
        cfg_only = {k: v for k, v in root.items() if k not in ("tools", "mcpServers", "servers", "mcp")}
        for p in _secret_paths(cfg_only):
            if p[0] != ikey:
                flagged.setdefault("flow", set()).add(tuple(p))
                add("High", "AG-SEC-001", "Hard-coded secret in AI configuration", f"'{'.'.join(str(x) for x in p)}' holds a literal credential. The value is hidden in this report.", "flow", p)
        for key in BASE_URL_KEYS:
            u = root.get(key)
            if isinstance(u, str):
                if _remote_http(u):
                    add("High", "AG-LLM-002", "Model endpoint over plain HTTP", f"{key} '{_host(u)}' is reached over http://.", "flow", [key])
                elif _remote(u) and not TENANT_HOSTS.search(_host(u)):
                    add("Low", "AG-LLM-001", "Model endpoint outside your cloud tenant", f"{key} points to '{_host(u)}'.", "flow", [key])
        prov = str(root.get("provider") or "").lower()
        if prov in THIRD_PARTY_PROVIDERS:
            add("Low", "AG-LLM-001", "Model endpoint outside your cloud tenant", f"The model provider is '{prov}'.", "flow", ["provider"])
        for key in PERM_KEYS:
            val = root.get(key)
            strings = [x for _, x in _leaves(val) if isinstance(x, str)] if val is not None else []
            broad = [s for s in strings if BROAD_PERM.search(s.strip())]
            if broad or (key in ("allowed_tools", "allowedTools") and val in ("*", "all")):
                top = any(re.fullmatch(r"\*|(?i:.*(admin|owner|fullcontrol|full_?access).*)", s.strip()) for s in broad)
                add("High" if top else "Medium", "AG-AGT-006", "Excessive or wildcard permissions",
                    f"{key} includes {', '.join(repr(s) for s in broad[:4]) or repr(val)}.", "flow", [key])
        for key in DELEGATE_KEYS:
            val = root.get(key)
            if isinstance(val, (list, dict)) and val:
                items = val if isinstance(val, list) else list(val.values())
                http = any(isinstance(i, dict) and any(_remote_http(i.get(k)) for k in URL_KEYS + ("endpoint",)) for i in items)
                add("Medium" if http else "Low", "AG-A2A-001", "Agent delegates to other agents",
                    f"{len(items)} agent(s) can receive work from this one{' and at least one is reached over plain HTTP' if http else ''}.", "flow", [key])

    # ---- combinations (heuristic) ----
    def names(cap: str) -> list[str]:
        return [n for n, c in caps_by.items() if cap in c]
    untrusted, execs, exfil, private, destructive = (names(c) for c in ("untrusted", "exec", "exfil", "private", "destructive"))
    acting = sorted(set(execs) | set(exfil) | set(destructive))
    where_key = "tools" if kind == "agent" and _tool_dicts(root) else "mcpServers"
    if untrusted and acting:
        add("High" if execs else "Medium", "AG-AGT-004", "Prompt-injection path to an action tool",
            f"Content from {', '.join(untrusted[:3])} may reach the model, and this agent may also use {', '.join(acting[:3])}. "
            "A malicious page, file or message could steer those tools.", "flow", [where_key])
    if private and exfil:
        add("High" if untrusted else "Medium", "AG-AGT-005", "Private data can leave through a tool",
            f"The agent may read private data ({', '.join(private[:3])}) and send data out ({', '.join(exfil[:3])})"
            f"{' while also reading untrusted content' if untrusted else ''}.", "flow", [where_key])

    # ---- shape the result like a flow scan ----
    disabled, override = clean_policy(policy)
    findings = [{**f, **meta(f["ruleId"]), "severity": override.get(f["ruleId"], f["severity"]),
                 "fingerprint": "|".join([base_name, f["ruleId"], f["location"], ".".join(f["jsonPath"])])}
                for f in findings if f["ruleId"] not in disabled]
    by_loc: dict[str, list[dict]] = {}
    for f in findings:
        by_loc.setdefault(f["location"], []).append(f)

    cfg_json = {k: v for k, v in root.items() if k not in ("tools", "mcpServers", "servers", "mcp")}
    if kind == "agent":
        cfg_json["tools"] = [_tool_name(t, i) for i, t in enumerate(_tool_dicts(root))]
    if servers:
        cfg_json["mcpServers"] = list(servers)
    steps = [{"id": "flow:config", "kind": "flow", "name": "Agent configuration" if kind == "agent" else "MCP configuration",
              "type": "Metadata", "path": "flow", "depth": 0, "connector": None, "connection": None,
              "json": _redact(cfg_json, flagged.get("flow", set())), "findings": by_loc.get("flow", [])}]
    for label, comp in comps.items():
        where = f"action:{label}"
        steps.append({"id": where, "kind": "action", "name": label, "path": label, "depth": 0, "connection": None,
                      "type": "MCP server" if _is_server(comp, servers) else str(comp.get("type") or "Tool"),
                      "connector": spec_by.get(label) or comp.get("command") or None,
                      "json": _redact(comp, flagged.get(where, set())), "findings": by_loc.get(where, [])})

    score = sum(scanner.SEV_WEIGHT[f["severity"]] for f in findings)
    risk = "High" if any(f["severity"] == "High" for f in findings) or score >= 12 else "Medium" if score >= 4 else "Low"
    model = root.get("model")
    md = {"Flow name": name, "Type": "AI agent" if kind == "agent" else "MCP configuration", "State": "Defined",
          "Model": (model.get("name") if isinstance(model, dict) else model) or None,
          "Tools": len(_tool_dicts(root)) if kind == "agent" else None, "MCP servers": len(servers),
          "Remote servers": sum(1 for s in servers.values() if any(_remote(s.get(k)) for k in URL_KEYS)),
          "Instructions": f"{len(root[_instr_key(root)])} characters" if _instr_key(root) else None}
    if root.get("owner"):
        md["Owner"] = root["owner"]
    return {"flowId": base_name, "name": name, "state": "Defined", "connectors": sorted(comps), "triggerCount": 0,
            "actionCount": len(comps), "findings": findings, "risk": risk, "score": score,
            "metadata": {k: v for k, v in md.items() if v is not None}, "connections": [], "dataFlows": [], "steps": steps}

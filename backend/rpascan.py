"""Static analysis of RPA project files.

UiPath
  * project.json (dependencies, logging options, framework) and
  * .xaml workflows (variables, activity properties, code, SQL, logging).
Automation Anywhere (.bot, .atmx) and Blue Prism (.bprelease, .bpobject, .bpprocess)
  * BASIC checks only. They look at values (credential-looking names with literal values, token shapes, connection strings,
    plain-HTTP addresses, shell commands) without relying on a vendor schema, because that schema has not been verified
    against real exports. Treat results for these two as a first pass.

Files reach this module wrapped as {"format": "rpa-file", "name": "Main.xaml", "text": "..."}; project.json is read as plain JSON.
Nothing is executed or contacted. Results use the same shape as scanner.scan_flow.
"""
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import scanner
from agentscan import LOCAL_HOSTS, REDACTED, SECRET_KEY, TOKEN_RES, _has_token, _literal, _secret_paths
from rules import clean_policy, meta

UIPATH_KEYS = ("toolVersion", "runtimeOptions", "designOptions", "studioVersion", "expressionLanguage", "projectProfile", "targetFramework")
EXT_PLATFORM = {".xaml": "UiPath", ".bot": "Automation Anywhere", ".atmx": "Automation Anywhere",
                ".bprelease": "Blue Prism", ".bpobject": "Blue Prism", ".bpprocess": "Blue Prism"}
SCHEMA_HOSTS = ("schemas.microsoft.com", "schemas.uipath.com", "www.w3.org", "schemas.openxmlformats.org", "schemas.xmlsoap.org", "tempuri.org",
                "schemas.datacontract.org", "www.blueprism.co.uk", "bpdocs.blueprism.com", "docs.uipath.com", "www.uipath.com", "purl.org",
                "json-schema.org", "docs.automationanywhere.com")
IDENT_SECRET = re.compile(r"(password|passwd|pwd|secret|apikey|api_key|token|credential)", re.I)
URL_RE = re.compile(r"http://[^\s\"'<>\]\)]+", re.I)
CONNSTR_PW = re.compile(r"(?i)\b(password|pwd)\s*=\s*([^;\"'\s\]]+)")
CODE_SECRET = re.compile(r"(?i)\b\w*(password|pwd|secret|apikey|api_key|token)\w*\s*=\s*\"([^\"{][^\"]{3,})\"")
PS_PLAIN = re.compile(r"(?i)ConvertTo-SecureString[^\n]*-AsPlainText")
NET_CRED = re.compile(r"(?i)NetworkCredential\(\s*\"[^\"]*\"\s*,\s*\"[^\"]{3,}\"")
SHELL_RE = re.compile(r"(?i)\b(cmd(\.exe)?\s+/[ck]\b|powershell(\.exe)?\s+[-/]\w|pwsh(\.exe)?\s+-|cscript(\.exe)?\s|wscript(\.exe)?\s|mshta(\.exe)?\s|rundll32(\.exe)?\s|regsvr32(\.exe)?\s)")
SHELL_EXE = re.compile(r"(?i)^(.*[\\/])?(cmd|powershell|pwsh|cscript|wscript|mshta|rundll32|regsvr32)(\.exe)?$")
SHELL_ATTRS = {"filename", "command", "executable", "program"}
SQL_NAMES = re.compile(r"(?i)(sql|query|commandtext|statement)")
SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|drop|exec|execute)\b")
SQL_CONCAT = re.compile(r"\"\s*[&+]\s*[A-Za-z_(]|[A-Za-z_)\]]\s*[&+]\s*\"")
SKIP_ATTRS = {"displayname", "annotationtext", "class", "ignorable", "idref", "name", "key", "type", "typearguments"}
MAX_TEXT = 8 * 1024 * 1024
MAX_MATCHES = 200

FIXES: dict[str, list[str]] = {
    "RPA-SEC-001": [
        "Remove the value from the file and read it at run time from a credential store: in UiPath use an Orchestrator credential asset (Get Credential) or a secret-vault integration such as CyberArk, Azure Key Vault, HashiCorp Vault or AWS Secrets Manager.",
        "Do not pass passwords as workflow arguments or log them: argument values can appear in job logs, and a SecureString can be converted back to plain text, so keep it as a SecureString and use it only where needed.",
        "Treat the exposed value as compromised: change it and remove it from version control history.",
    ],
    "RPA-NET-001": [
        "Change the address to https:// and confirm the service supports TLS.",
        "If the service only speaks HTTP, reach it through a gateway that adds TLS, or keep it on a private network and document the exception.",
    ],
    "RPA-CODE-001": [
        "Replace the shell or script call with a built-in activity or an approved API where one exists.",
        "If a command is unavoidable, call a fixed, reviewed script by full path, and never build the command text from data the robot reads (files, emails, web pages).",
    ],
    "RPA-CODE-002": [
        "Review the embedded code the way you would review any code: who wrote it, what it reads and what it can change.",
        "Keep embedded code small, and move reusable logic into a reviewed library with version control.",
    ],
    "UIP-DB-001": [
        "Use parameterized queries: put placeholders in the SQL text and pass the values as parameters instead of joining them into the string.",
        "Validate values that must be part of the statement (such as a table name) against a fixed list.",
    ],
    "UIP-LOG-001": [
        "Remove the secret-like variable from the log message, or log only a safe label (for example 'login succeeded').",
        "Never write passwords, keys or tokens to logs, even at Verbose level.",
    ],
    "UIP-PRJ-001": [
        "Pin each dependency to an exact version (the [x.y.z] form that Studio writes) and update packages on purpose after review.",
        "Remove floating versions such as '*' or open ranges.",
    ],
    "UIP-PRJ-002": [
        "Add keywords such as password, secret, token and Private:* to the project's excluded-logged-data list so matching variable and argument values stay out of Verbose logs.",
    ],
    "UIP-PRJ-003": [
        "Plan a move to a current project type (Windows or Cross-platform) so the project gets runtime and security updates.",
    ],
}
ALTERNATIVES: dict[str, dict] = {
    "RPA-SEC-001": {"title": "Use short-lived access", "steps": [
        "Use a service account with the least access needed, rotate it on a schedule, and fetch it from a vault each run."]},
    "RPA-NET-001": {"title": "Use a private connection", "steps": [
        "Connect over a VPN or private endpoint and keep the address inside your network."]},
    "RPA-CODE-001": {"title": "Call an approved service instead", "steps": [
        "Wrap the task in a small internal service or approved command-line tool and call it with fixed arguments."]},
    "RPA-CODE-002": {"title": "Use a reviewed library", "steps": [
        "Package the logic as a library that goes through code review and is versioned separately from the workflow."]},
    "UIP-DB-001": {"title": "Call a stored procedure", "steps": [
        "Move the query into a stored procedure that takes typed parameters, and give the robot permission to run only that."]},
    "UIP-LOG-001": {"title": "Mask before logging", "steps": [
        "Build the message from a masked copy of the value (for example the last four characters only)."]},
    "UIP-PRJ-001": {"title": "Use an internal feed", "steps": [
        "Publish reviewed packages to your own feed and point the project at it, so only approved versions can be restored."]},
    "UIP-PRJ-002": {"title": "Restrict log levels", "steps": [
        "Run production robots at Info or higher, so Verbose output with variable values is not written."]},
    "UIP-PRJ-003": {"title": "Migrate in stages", "steps": [
        "Start with the least complex processes, test each on the new project type, then retire the legacy copy."]},
}
EXAMPLES: dict[str, dict] = {
    "RPA-NET-001": {"before": 'EndPoint="http://api.partner.example.com/v1/orders"', "after": 'EndPoint="https://api.partner.example.com/v1/orders"'},
    "UIP-PRJ-001": {"before": '"UiPath.System.Activities": "24.10.5"', "after": '"UiPath.System.Activities": "[24.10.5]"'},
}
scanner.FIXES.update(FIXES)
scanner.ALTERNATIVES.update(ALTERNATIVES)
scanner.EXAMPLES.update(EXAMPLES)


# ---------------------------------------------------------------------------------------------------------------------
def _ext(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def kind_of(content) -> str | None:
    """'uipath-project', 'uipath-xaml', 'automation-anywhere', 'blue-prism' or None."""
    if not isinstance(content, dict):
        return None
    if content.get("format") == "rpa-file" and isinstance(content.get("text"), str):
        plat = EXT_PLATFORM.get(_ext(str(content.get("name", ""))))
        if plat is None and _ext(str(content.get("name", ""))) == ".xml":
            head = content["text"][:4000].lower()
            plat = "Blue Prism" if "blueprism" in head else "UiPath" if "schemas.uipath.com" in head else None
        return {"UiPath": "uipath-xaml", "Automation Anywhere": "automation-anywhere", "Blue Prism": "blue-prism"}.get(plat or "")
    deps = content.get("dependencies")
    if isinstance(deps, dict) and (str(content.get("main", "")).lower().endswith(".xaml") or any(k in content for k in UIPATH_KEYS)):
        return "uipath-project"
    return None


def scan_rpa(filename: str, content: dict, policy: dict | None = None) -> dict:
    kind = kind_of(content)
    if kind is None:
        raise ValueError("Not a recognised RPA file (UiPath project.json or .xaml, Automation Anywhere .bot/.atmx, Blue Prism .bprelease).")
    base = filename.rsplit(".", 1)[0]
    findings: list[dict] = []

    def add(sev, rule, title, detail, where, jpath):
        findings.append({"severity": sev, "ruleId": rule, "title": title, "detail": detail, "location": where,
                         "jsonPath": [str(p) for p in jpath], "fix": scanner.FIXES.get(rule, []),
                         "alternative": scanner.ALTERNATIVES.get(rule), "example": scanner.EXAMPLES.get(rule)})

    if kind == "uipath-project":
        name, platform, typ, steps, md = _project(base, content, add)
    elif kind == "uipath-xaml":
        name, platform, typ, steps, md = _xaml(base, content, add)
    else:
        name, platform, typ, steps, md = _generic(base, content, kind, add)
    return _finish(base, name, platform, typ, steps, md, findings, policy)


def _finish(base, name, platform, typ, steps, md, findings, policy) -> dict:
    disabled, override = clean_policy(policy)
    findings = [{**f, **meta(f["ruleId"]), "severity": override.get(f["ruleId"], f["severity"]),
                 "fingerprint": "|".join([base, f["ruleId"], f["location"], ".".join(f["jsonPath"])])}
                for f in findings if f["ruleId"] not in disabled]
    by_loc: dict[str, list[dict]] = {}
    for f in findings:
        by_loc.setdefault(f["location"], []).append(f)
    for s in steps:
        s["findings"] = by_loc.get("flow" if s["id"] == "flow:config" else s["id"], [])
    score = sum(scanner.SEV_WEIGHT[f["severity"]] for f in findings)
    risk = "High" if any(f["severity"] == "High" for f in findings) or score >= 12 else "Medium" if score >= 4 else "Low"
    md = {"Flow name": name, "Platform": platform, "Type": typ, "State": "Defined", **md}
    return {"flowId": base, "name": name, "state": "Defined", "connectors": [], "triggerCount": 0, "actionCount": max(0, len(steps) - 1),
            "findings": findings, "risk": risk, "score": score, "metadata": {k: v for k, v in md.items() if v is not None},
            "connections": [], "dataFlows": [], "steps": steps}


def _clip(v: str, n: int = 200) -> str:
    v = re.sub(r"\s+", " ", v).strip()
    for r in TOKEN_RES:
        v = r.sub(REDACTED, v)
    return v if len(v) <= n else v[: n - 1] + "…"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _lit(v: str) -> str | None:
    """The literal text of a value, or None when it is an expression ([...]) or markup extension ({...}). A quoted VB/C# string counts as literal."""
    s = v.strip()
    m = re.fullmatch(r'\[\s*"([^"]*)"\s*\]', s) or re.fullmatch(r'"([^"]*)"', s)
    if m:
        return m.group(1)
    return None if s.startswith(("[", "{")) else s


def _child(el, name: str):
    return next((c for c in el if _local(c.tag) == name), None)


def _texts(el) -> str:
    return " ".join(t.strip() for t in el.itertext() if t.strip()) if el is not None else ""


def _http_hits(v: str) -> list[str]:
    out = []
    for u in URL_RE.findall(v):
        host = (urlparse(u).hostname or "").lower()
        if host and host not in LOCAL_HOSTS and not host.endswith(SCHEMA_HOSTS):
            out.append(host)
    return out


def value_issues(name: str, value: str) -> list[tuple]:
    """Checks that need no vendor schema. Returns (rule, severity, title, detail, secret)."""
    out: list[tuple] = []
    low = name.lower()
    if low in SKIP_ATTRS or not value.strip():
        return out
    lit = _lit(value)
    cred = (lit is not None and SECRET_KEY.search(name) and not re.match(r"^https?://", lit, re.I) and _literal(lit)) \
        or _has_token(value) or any(_literal(m.group(2)) and not m.group(2).startswith(("[", "{", "@", "$"))
                                    for m in CONNSTR_PW.finditer(value))
    if cred:
        out.append(("RPA-SEC-001", "High", "Hard-coded credential in an automation file",
                    f"'{name or 'value'}' holds a literal credential. The value is hidden in this report.", True))
    for host in sorted(set(_http_hits(value))):
        out.append(("RPA-NET-001", "High", "Unencrypted HTTP address", f"'{name or 'value'}' uses http://{host}.", False))
    if SHELL_RE.search(value) or (low in SHELL_ATTRS and SHELL_EXE.match((lit or value).strip())):
        out.append(("RPA-CODE-001", "Medium", "Shell or system command started", f"'{name or 'value'}' starts a command shell or script host.", False))
    return out


# ---- UiPath project.json -------------------------------------------------------------------------------------------
def _project(base, content, add):
    name = str(content.get("name") or base)
    deps = content.get("dependencies") or {}
    loose = {k: str(v) for k, v in deps.items() if not re.fullmatch(r"\[[^\],\s]+\]", str(v).strip())}
    if loose:
        floating = [k for k, v in loose.items() if "*" in v or re.search(r",\s*\)", v) or not v.strip()]
        first = next(iter(floating or loose))
        listed = ", ".join(list(loose)[:4]) + ("…" if len(loose) > 4 else "")
        add("Medium" if floating else "Low", "UIP-PRJ-001", "Project dependencies not pinned to an exact version",
            f"{len(loose)} of {len(deps)} package(s) are not pinned with an exact [version]: {listed}.", "flow", ["dependencies", first])
    ro = content.get("runtimeOptions")
    if isinstance(ro, dict):
        ex = ro.get("excludedLoggedData")
        if not isinstance(ex, list) or not any(re.search(r"password|secret|private|token", str(x), re.I) for x in ex):
            add("Low", "UIP-PRJ-002", "Sensitive values not excluded from logs",
                "excludedLoggedData has no password, secret or private-data keyword." if isinstance(ex, list) else "excludedLoggedData is not set.",
                "flow", ["runtimeOptions"] + (["excludedLoggedData"] if isinstance(ex, list) else []))
    if str(content.get("targetFramework", "")).lower() == "legacy":
        add("Low", "UIP-PRJ-003", "Project uses the legacy framework", "targetFramework is Legacy.", "flow", ["targetFramework"])
    flagged = set()
    for p in _secret_paths(content):
        flagged.add(p)
        add("High", "RPA-SEC-001", "Hard-coded credential in an automation file",
            f"'{'.'.join(str(x) for x in p)}' holds a literal credential. The value is hidden in this report.", "flow", p)

    def hide(o, path=()):
        if isinstance(o, dict):
            return {k: (REDACTED if path + (k,) in flagged else hide(v, path + (k,))) for k, v in o.items()}
        if isinstance(o, list):
            return [REDACTED if path + (i,) in flagged else hide(v, path + (i,)) for i, v in enumerate(o)]
        return o
    steps = [{"id": "flow:config", "kind": "flow", "name": "project.json", "type": "Metadata", "path": "flow", "depth": 0,
              "connector": None, "connection": None, "json": hide(content)}]
    md = {"Main workflow": content.get("main"), "Dependencies": len(deps), "Target framework": content.get("targetFramework"),
          "Studio version": content.get("studioVersion") or content.get("toolVersion"), "Expression language": content.get("expressionLanguage")}
    return name, "UiPath", "UiPath project", steps, md


# ---- UiPath XAML ---------------------------------------------------------------------------------------------------
def _parse_xml(text: str) -> ET.Element:
    if len(text) > MAX_TEXT:
        raise ValueError("The file is too large to analyse.")
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise ValueError("The file contains a DTD or entity definition, which is not read for safety.")
    text = re.sub(r"^﻿?\s*<\?xml[^>]*\?>", "", text.lstrip("﻿"))
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"The file is not valid XML: {e}")


def _xaml(base, content, add):
    root = _parse_xml(content["text"])
    parent = {c: p for p in root.iter() for c in p}
    owners: dict[int, str] = {}
    used: dict[str, int] = {}
    steps_by: dict[str, dict] = {}
    seen: set = set()

    def owner_of(el):
        o = el
        while o is not None and not o.get("DisplayName"):
            o = parent.get(o)
        return o if o is not None else root

    def label_of(o) -> str:
        if id(o) not in owners:
            raw = o.get("DisplayName") or "Workflow"
            used[raw] = used.get(raw, 0) + 1
            owners[id(o)] = raw if used[raw] == 1 else f"{raw} ({used[raw]})"
        return owners[id(o)]

    def path_of(o) -> str:
        names, cur = [], o
        while cur is not None:
            if cur.get("DisplayName"):
                names.append(cur.get("DisplayName"))
            cur = parent.get(cur)
        return " > ".join(reversed(names)) or "Workflow"

    def hit(rule, sev, title, detail, el, key, shown):
        o = owner_of(el)
        label = label_of(o)
        sig = (rule, label, key, shown)
        if sig in seen:
            return
        seen.add(sig)
        st = steps_by.setdefault(label, {"activity": _local(o.tag), "path": path_of(o), "details": []})
        st["details"].append({"element": _local(el.tag), key: shown})
        add(sev, rule, title, detail, f"action:{label}", ["details", len(st["details"]) - 1, key])

    n_var = n_act = 0
    invoked: list[str] = []
    for el in root.iter():
        local = _local(el.tag)
        if "." in local:
            continue
        attrs = {_local(k): v for k, v in el.attrib.items()}
        if el.get("DisplayName"):
            n_act += 1
        if local == "Variable":
            n_var += 1
            lit = _lit(attrs.get("Default", ""))
            if lit and IDENT_SECRET.search(attrs.get("Name", "")) and _literal(lit):
                hit("RPA-SEC-001", "High", "Hard-coded credential in an automation file",
                    f"Variable '{attrs.get('Name')}' has a literal default value. The value is hidden in this report.", el, "Default", REDACTED)
        if local == "Assign":
            to_txt = attrs.get("To") or _texts(_child(el, "Assign.To"))
            val_txt = attrs.get("Value") or _texts(_child(el, "Assign.Value"))
            lit = _lit(val_txt) if val_txt else None
            if lit and IDENT_SECRET.search(to_txt) and _literal(lit):
                hit("RPA-SEC-001", "High", "Hard-coded credential in an automation file",
                    f"'{to_txt.strip('[] ')}' is assigned a literal value. The value is hidden in this report.", el, "Value", REDACTED)
        if local in ("InvokeCode", "InvokePowerShell"):
            hit("RPA-CODE-002", "Medium" if local == "InvokePowerShell" else "Low", "Embedded code or script step",
                f"{'PowerShell' if local == 'InvokePowerShell' else 'Custom code'} runs inside this workflow.", el, "Activity", local)
        if local == "InvokeWorkflowFile" and attrs.get("WorkflowFileName"):
            invoked.append(attrs["WorkflowFileName"])
        pairs = list(attrs.items())
        txt = (el.text or "").strip()
        if txt:
            cur = el
            while cur is not None and "." not in _local(cur.tag):
                cur = parent.get(cur)
            pairs.append((_local(cur.tag).split(".")[-1] if cur is not None else local, txt))
        for key, val in pairs:
            if key.lower() in SKIP_ATTRS:
                continue
            for rule, sev, title, detail, secret in value_issues(key, val):
                shown = REDACTED if secret else _clip(val)
                if secret and CONNSTR_PW.search(val):
                    shown = _clip(CONNSTR_PW.sub(lambda m: m.group(1) + "=" + REDACTED, val))
                hit(rule, sev, title, detail, el, key, shown)
            for m in CODE_SECRET.finditer(val):
                if _literal(m.group(2)):
                    hit("RPA-SEC-001", "High", "Hard-coded credential in an automation file",
                        f"Code in '{key}' assigns a literal to a credential-looking name. The value is hidden in this report.", el, key, REDACTED)
            if PS_PLAIN.search(val) or NET_CRED.search(val):
                hit("RPA-SEC-001", "High", "Hard-coded credential in an automation file",
                    f"'{key}' builds a secure value or credential from plain text. The value is hidden in this report.", el, key, REDACTED)
            if SQL_NAMES.search(key) and val.strip().startswith("[") and SQL_WORDS.search(val) and SQL_CONCAT.search(val):
                hit("UIP-DB-001", "Medium", "SQL built by string concatenation", f"'{key}' joins text and variables into a SQL statement.", el, key, _clip(val))
            if local == "LogMessage" and key == "Message" and val.strip().startswith("["):
                if IDENT_SECRET.search(re.sub(r'"[^"]*"', "", val)):
                    hit("UIP-LOG-001", "Medium", "Possible secret written to the log",
                        "The log message includes a variable that looks like a password, key or token.", el, key, _clip(val))

    steps = [{"id": "flow:config", "kind": "flow", "name": "Workflow file", "type": "Metadata", "path": "flow", "depth": 0,
              "connector": None, "connection": None,
              "json": {"file": base + ".xaml", "workflow": next((v for k, v in root.attrib.items() if _local(k) == "Class"), None),
                       "activities": n_act, "variables": n_var, "invokedWorkflows": sorted(set(invoked))}}]
    for label, st in steps_by.items():
        steps.append({"id": f"action:{label}", "kind": "action", "name": label, "type": st["activity"], "path": st["path"], "depth": 0,
                      "connector": None, "connection": None, "json": st})
    md = {"Activities": n_act, "Variables": n_var, "Invoked workflows": len(set(invoked)) or None}
    return base, "UiPath", "UiPath workflow", steps, md


# ---- Automation Anywhere and Blue Prism: schema-free checks --------------------------------------------------------
GENERIC_KEYS = {"value", "string", "text", "val", "content", "data", "expression", "literal"}


def _json_values(obj, path=(), ctx=""):
    """Yield (where, name, value) for every string. In {"name": "x", "value": ...} style entries the value is named after "x"."""
    if isinstance(obj, dict):
        ctx = obj["name"] if isinstance(obj.get("name"), str) and obj["name"] else ctx
        for k, v in obj.items():
            yield from _json_values(v, path + (k,), ctx)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _json_values(v, path + (i,), ctx)
    elif isinstance(obj, str):
        key = path[-1] if path and isinstance(path[-1], str) else ""
        yield ".".join(str(p) for p in path), (ctx if key.lower() in GENERIC_KEYS and ctx else key), obj


def _generic(base, content, kind, add):
    text = content["text"]
    if len(text) > MAX_TEXT:
        raise ValueError("The file is too large to analyse.")
    platform = "Automation Anywhere" if kind == "automation-anywhere" else "Blue Prism"
    values: list[tuple[str, str, str]] = []      # (where, name, value)
    fmt = "text"
    s = text.lstrip("﻿").lstrip()
    if s.startswith(("{", "[")):
        try:
            values.extend(_json_values(json.loads(s)))
            fmt = "json"
        except ValueError:
            pass
    if fmt == "text" and s.startswith("<"):
        root = _parse_xml(text)
        fmt = "xml"
        code_stages = 0
        pw_items = 0

        def walk(el, trail):
            nonlocal code_stages, pw_items
            tag = _local(el.tag)
            here = trail + [f"{tag}[{el.get('name')}]" if el.get("name") else tag]
            where = " > ".join(here[-4:])
            for k, v in el.attrib.items():
                values.append((where, _local(k), v))
            if (el.text or "").strip():
                values.append((where, tag, el.text.strip()))
            if platform == "Blue Prism":
                if tag == "stage" and str(el.get("type", "")).lower() == "code":
                    code_stages += 1
                kids = {_local(c.tag): (c.text or "").strip() for c in el}
                if kids.get("datatype", "").lower() == "password" and kids.get("initialvalue"):
                    pw_items += 1
                    values.append((where, "password", kids["initialvalue"]))
            for c in el:
                walk(c, here)
        walk(root, [])
    if fmt == "text":
        for i, line in enumerate(text.splitlines(), 1):
            values.append((f"line {i}", "", line))

    matches: list[dict] = []
    seen: set = set()
    for where, name, val in values:
        for rule, sev, title, detail, secret in value_issues(name, val):
            shown = REDACTED if secret else _clip(val)
            sig = (rule, where, name, shown)
            if sig in seen or len(matches) >= MAX_MATCHES:
                continue
            seen.add(sig)
            matches.append({"where": where, "name": name, "value": shown})
            add(sev, rule, title, detail, "flow", ["matches", len(matches) - 1, "value"])
    if fmt == "xml" and platform == "Blue Prism" and code_stages:
        matches.append({"where": "stage[type=Code]", "name": "count", "value": str(code_stages)})
        add("Low", "RPA-CODE-002", "Embedded code or script step", f"{code_stages} Code stage(s) run custom code inside this process.", "flow", ["matches", len(matches) - 1, "value"])
    steps = [{"id": "flow:config", "kind": "flow", "name": "Export file", "type": "Metadata", "path": "flow", "depth": 0,
              "connector": None, "connection": None,
              "json": {"file": content.get("name"), "platform": platform, "format": fmt, "characters": len(text), "matches": matches,
                       "note": "Basic checks only; this vendor format has not been verified against real exports."}}]
    return base, platform, f"{platform} export (basic checks)", steps, {"Format": fmt}


def autofix_http(text: str) -> tuple[str, list[str]]:
    """Rewrite non-local http:// addresses to https:// in exported text. Returns (new text, list of changed addresses)."""
    changed: list[str] = []

    def swap(m):
        u = m.group(0)
        host = (urlparse(u).hostname or "").lower()
        if host and host not in LOCAL_HOSTS and not host.endswith(SCHEMA_HOSTS):
            changed.append(u)
            return "https://" + u[7:]
        return u
    return URL_RE.sub(swap, text), changed

"""Connector knowledge: who operates a connector, what data it touches, and whether it involves AI.

Static analysis only. The catalog covers common connectors; anything else is reported as
"custom / unlisted" so a reviewer looks at it rather than it being silently trusted.
"""
import re
from urllib.parse import urlparse

MS, TP = "Microsoft", "Third-party"

# key -> (display name, publisher, category, data sensitivity, data typically touched, ai provider or None)
_C = {
    # --- Microsoft 365 / Power Platform ---
    "shared_sharepointonline": ("SharePoint", MS, "Documents & lists", "High",
                                ["List items and fields", "Item metadata (created/modified by, dates)", "Files and attachments"], None),
    "shared_office365": ("Office 365 Outlook", MS, "Email & calendar", "High",
                         ["Email subject, body and attachments", "Sender and recipient addresses", "Calendar events"], None),
    "shared_office365users": ("Office 365 Users", MS, "Directory", "Medium",
                              ["User profiles (name, email, manager, phone)"], None),
    "shared_teams": ("Microsoft Teams", MS, "Chat & collaboration", "Medium",
                     ["Chat and channel messages", "Team and channel membership"], None),
    "shared_onedriveforbusiness": ("OneDrive for Business", MS, "Files", "High",
                                   ["File contents", "File and folder metadata"], None),
    "shared_commondataserviceforapps": ("Microsoft Dataverse", MS, "Business data", "High",
                                        ["Business records (table rows)", "Record owners and audit columns"], None),
    "shared_sql": ("SQL Server", MS, "Database", "High", ["Database rows and columns"], None),
    "shared_excelonlinebusiness": ("Excel Online (Business)", MS, "Files", "Medium", ["Workbook tables and rows"], None),
    "shared_approvals": ("Approvals", MS, "Workflow", "Medium", ["Approval requests, responses and approvers"], None),
    "shared_azureblob": ("Azure Blob Storage", MS, "Storage", "High", ["Blob contents and metadata"], None),
    "shared_keyvault": ("Azure Key Vault", MS, "Secrets", "High", ["Secrets, keys and certificates"], None),
    "shared_servicebus": ("Service Bus", MS, "Messaging", "Medium", ["Queue and topic messages"], None),
    "shared_eventhubs": ("Event Hubs", MS, "Messaging", "Medium", ["Event stream messages"], None),
    "shared_forms": ("Microsoft Forms", MS, "Surveys", "Medium", ["Form responses (may contain personal data)"], None),
    "shared_planner": ("Planner", MS, "Tasks", "Low", ["Plans, tasks and assignees"], None),
    "shared_todo": ("Microsoft To Do", MS, "Tasks", "Low", ["Personal tasks"], None),
    "shared_onenote": ("OneNote", MS, "Notes", "Medium", ["Notebook pages"], None),
    "shared_powerbi": ("Power BI", MS, "Analytics", "Medium", ["Datasets and report data"], None),
    "shared_flowmanagement": ("Power Automate Management", MS, "Admin", "Low", ["Flow definitions and run metadata"], None),
    # --- Microsoft AI ---
    "shared_azureopenai": ("Azure OpenAI", MS, "AI", "High", ["Prompts and generated text"], "Azure OpenAI"),
    "shared_cognitiveservicestextanalytics": ("Azure AI Language", MS, "AI", "Medium", ["Text sent for analysis"], "Azure AI Language"),
    "shared_cognitiveservicescomputervision": ("Azure AI Vision", MS, "AI", "Medium", ["Images sent for analysis"], "Azure AI Vision"),
    "shared_cognitiveservicesformrecognizer": ("Azure AI Document Intelligence", MS, "AI", "High", ["Documents sent for extraction"], "Azure AI Document Intelligence"),
    "shared_cognitiveservicestranslator": ("Azure AI Translator", MS, "AI", "Medium", ["Text sent for translation"], "Azure AI Translator"),
    "shared_copilotstudio": ("Copilot Studio", MS, "AI", "High", ["Conversation text and context"], "Copilot Studio"),
    # --- Third-party ---
    "shared_openai": ("OpenAI", TP, "AI", "High", ["Prompts and generated text"], "OpenAI"),
    "shared_slack": ("Slack", TP, "Chat", "Medium", ["Channel messages and files"], None),
    "shared_gmail": ("Gmail", TP, "Email", "High", ["Email subject, body and attachments"], None),
    "shared_googledrive": ("Google Drive", TP, "Files", "High", ["File contents and metadata"], None),
    "shared_dropbox": ("Dropbox", TP, "Files", "High", ["File contents and metadata"], None),
    "shared_box": ("Box", TP, "Files", "High", ["File contents and metadata"], None),
    "shared_salesforce": ("Salesforce", TP, "CRM", "High", ["Customer records"], None),
    "shared_servicenow": ("ServiceNow", TP, "ITSM", "High", ["Tickets and user records"], None),
    "shared_zendesk": ("Zendesk", TP, "Support", "High", ["Support tickets and customer details"], None),
    "shared_jira": ("Jira", TP, "Issues", "Medium", ["Issues and comments"], None),
    "shared_github": ("GitHub", TP, "Code", "Medium", ["Repositories, issues and pull requests"], None),
    "shared_trello": ("Trello", TP, "Tasks", "Low", ["Boards and cards"], None),
    "shared_twitter": ("X (Twitter)", TP, "Social", "Low", ["Public posts"], None),
    "shared_mailchimp": ("Mailchimp", TP, "Marketing", "Medium", ["Subscriber lists and campaigns"], None),
    "shared_sendgrid": ("SendGrid", TP, "Email", "Medium", ["Outbound email content"], None),
    "shared_smtp": ("SMTP", TP, "Email", "High", ["Outbound email content and attachments"], None),
    "shared_twilio": ("Twilio", TP, "SMS", "Medium", ["SMS content and phone numbers"], None),
}

AI_HOSTS = [
    (r"(^|\.)openai\.com$", "OpenAI", False),
    (r"\.openai\.azure\.com$", "Azure OpenAI", True),
    (r"\.cognitiveservices\.azure\.com$", "Azure AI Services", True),
    (r"(^|\.)anthropic\.com$", "Anthropic", False),
    (r"generativelanguage\.googleapis\.com$", "Google Gemini", False),
    (r"(^|\.)cohere\.(ai|com)$", "Cohere", False),
    (r"(^|\.)mistral\.ai$", "Mistral", False),
    (r"(^|\.)huggingface\.co$", "Hugging Face", False),
]
MS_HOSTS = re.compile(r"(\.sharepoint\.com|graph\.microsoft\.com|\.dynamics\.com|\.office\.com|\.office365\.com|\.microsoft\.com|\.azure\.com|\.windows\.net)$", re.I)
AI_OPS = re.compile(r"(aibuilder|predict|prompt|copilot|genai|openai|completion)", re.I)
READ = re.compile(r"^(get|list|search|find|read|retrieve|query|predict|check|export|download)", re.I)
WRITE = re.compile(r"^(send|post|create|add|upload|update|patch|put|write|insert|set|reply|forward|share|publish|copy|move|append|run|execute|start)", re.I)
DELETE = re.compile(r"^(delete|remove|purge)", re.I)

RANK = {"Low": 1, "Medium": 2, "High": 3}


def _direction(op: str, method: str = "") -> str:
    op = op or ""
    if DELETE.search(op) or method.upper() == "DELETE":
        return "deletes"
    if READ.search(op) or method.upper() == "GET":
        return "reads"
    if WRITE.search(op) or method.upper() in ("POST", "PUT", "PATCH"):
        return "sends / writes"
    return "uses"


def _target(key: str, params: dict) -> str | None:
    """Which site / list / mailbox / folder the action points at, when stated literally."""
    if not isinstance(params, dict):
        return None
    bits = []
    for label, k in (("site", "dataset"), ("list", "table"), ("folder", "folderPath"), ("mailbox", "mailboxAddress"),
                     ("to", "emailMessage/To"), ("file", "id")):
        v = params.get(k)
        if isinstance(v, str) and v and not v.startswith("@"):
            bits.append(f"{label}: {v}")
    return " · ".join(bits[:3]) or None


def _datatypes(key: str, base: list[str], op: str) -> list[str]:
    o = (op or "").lower()
    if key == "shared_sharepointonline":
        if "file" in o:
            return ["File contents", "File metadata (name, path, author, dates)"]
        if "attachment" in o:
            return ["Attachments"]
        if "item" in o or "list" in o:
            return ["List items and fields", "Item metadata (created/modified by, dates)"]
    if key == "shared_office365":
        if "calendar" in o or "event" in o:
            return ["Calendar events and attendees"]
        if "email" in o or "mail" in o:
            return ["Email subject, body and attachments", "Sender and recipient addresses"]
    return base


def classify(item: dict, key: str | None) -> dict | None:
    """Describe the connection a trigger or action uses, or None if it uses none."""
    inputs = item.get("inputs") if isinstance(item.get("inputs"), dict) else {}
    host = inputs.get("host") or {}
    op = str(host.get("operationId", ""))
    typ = str(item.get("type", ""))

    # ---- plain HTTP ----
    if typ in ("Http", "HttpWebhook") or (isinstance(inputs.get("uri"), str) and not key):
        uri = str(inputs.get("uri", ""))
        h = urlparse(uri).hostname or ""
        method = str(inputs.get("method", ""))
        ai = next(((p, ms) for pat, p, ms in AI_HOSTS if re.search(pat, h, re.I)), None)
        ms_host = bool(MS_HOSTS.search(h))
        publisher = "External HTTP"
        dest = f"External host {h or '(expression)'} — outside the Power Platform connector model"
        sens, data = "Medium", ["Whatever the request body and headers contain"]
        if ms_host and not ai:
            publisher, dest = MS, f"Microsoft cloud endpoint {h} called directly over HTTP"
        if ai:
            publisher = MS if ai[1] else TP
            dest = f"AI service {ai[0]} at {h}"
            sens, data = "High", ["Prompts / content sent for AI processing"]
        return {"connector": "http", "name": "HTTP", "publisher": publisher, "category": "HTTP call",
                "thirdParty": publisher in (TP, "External HTTP"), "destination": dest,
                "direction": _direction(op, method), "sensitivity": sens, "dataTypes": data,
                "ai": {"provider": ai[0], "microsoft": ai[1]} if ai else None, "target": uri or None,
                "why": f"Calls {h or 'a URL built at run time'} with {method or 'an HTTP method'}; "
                       f"{'it is an AI endpoint, so request content is processed by that AI service' if ai else 'data in the request leaves the connector model and is not covered by connector DLP'}."}

    if not key:
        return None

    cat = _C.get(key)
    direction = _direction(op)
    target = _target(key, inputs.get("parameters") or {})
    if cat:
        name, publisher, category, sens, data, ai_name = cat
        third = publisher == TP
        data = _datatypes(key, data, op)
        ai = {"provider": ai_name, "microsoft": publisher == MS} if ai_name else None
        if not ai and key == "shared_commondataserviceforapps" and AI_OPS.search(op):
            ai = {"provider": "AI Builder / Copilot prompt (Microsoft)", "microsoft": True}
        dest = (f"{name} — operated by a third party outside your Microsoft 365 tenant" if third
                else f"{name} inside your Microsoft 365 / Azure tenant")
        why = f"{direction.capitalize()} {name} data ({'; '.join(data)})"
        why += f" at {target}" if target else ""
        why += ". " + ("Data leaves Microsoft 365 to a third-party service." if third else "Stays within Microsoft services.")
        if ai:
            why += f" AI involved: {ai['provider']}."
        return {"connector": key, "name": name, "publisher": publisher, "category": category,
                "thirdParty": third, "destination": dest, "direction": direction, "sensitivity": sens,
                "dataTypes": data, "ai": ai, "target": target, "why": why}

    # not in the catalog: probably a custom connector
    short = key.replace("shared_", "")
    return {"connector": key, "name": short, "publisher": "Custom / unlisted", "category": "Unknown",
            "thirdParty": True, "destination": f"Custom or unlisted connector '{short}': its author decides where data goes",
            "direction": direction, "sensitivity": "Medium", "dataTypes": ["Unknown: review the connector definition"],
            "ai": None, "target": target,
            "why": f"'{short}' is not a known Microsoft or marketplace connector, so its destination and data handling "
                   f"must be reviewed manually."}

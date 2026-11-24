# Falcon Scan: Automation & AI Security Analyzer

*Scan the automation. Understand the risk. Secure the workflow.*

Falcon Scan assesses automation technologies for security risk. **Power Automate is the only active integration.**
UiPath, other RPA platforms and AI agents are planned (see `backend/platforms.py`, `GET /platforms`, and the
Platforms tab in the workbench). Adapters for new platforms should convert their input into the findings shape
produced by `scanner.scan_flow` so analysis, risk scoring and reporting stay shared.

## Power Automate (Milestone 1)

Connect → Authenticate → Select Environment → List Flows → Retrieve Definition → Display JSON

## One-time Entra setup
1. Entra admin center → App registrations → New (single tenant). Authentication → enable **Allow public client flows**.
2. API permissions (delegated): "PowerApps Service" (User) and "Flow Service" (User); grant consent.
   Names vary by tenant; search for those two APIs.
3. Copy `backend/.env.example` to `backend/.env` and fill in TENANT_ID / CLIENT_ID.

## Run
    cd backend && python -m venv .venv && .venv\Scripts\activate
    pip install -r requirements.txt && uvicorn main:app --reload
    cd frontend && npm install && npm run dev      # http://localhost:5173

"Admin scope" lists every flow in the environment and needs Power Platform admin rights.
Only definitions/metadata are read — never run history or payloads.

## Release gate, fixes and solution import

Scan before an automation goes to production. From `backend/`:

    python falconscan.py flows/ MySolution.zip --policy gate.json --format sarif --output falcon.sarif
    python falconscan.py flows/ --fail-on Medium --fix-dir fixed/

Exit code `0` = gate passed, `1` = gate failed (blocking findings), `2` = bad input. Formats: `text`, `json`, `sarif` (SARIF 2.1.0).
`--fix-dir` writes corrected copies of flows that have a safe automatic fix.

`gate.json` (every key is optional):

    {"failOn": "High",
     "disabled": ["PA-TRG-002"],
     "severity": {"PA-GOV-003": "Medium"},
     "dlp": {"business": ["office365"], "nonBusiness": ["twitter"], "blocked": ["dropbox"], "defaultGroup": "nonBusiness"},
     "waivers": [{"ruleId": "PA-ACT-002", "flow": "Nightly export", "location": "action:Call_partner",
                  "reason": "Approved partner API", "owner": "j.doe", "expires": "2027-03-31"}]}

A waiver needs a `ruleId`, a `reason` and an `expires` date; expired or incomplete waivers do not apply.
The `dlp` block turns on two extra rules (PA-DLP-001 blocked connector, PA-DLP-002 business and non-business connectors mixed).

Automatic fixes are limited to changes that are safe and mechanical: `http://` to `https://`, secure inputs/outputs on HTTP actions,
and a Terminate that reports Succeeded on an error path. Secrets, authentication, trigger access and recipients need a human decision,
so they are listed as "not changed" with the reason. A fixed copy is a file for review; nothing is changed in any environment.

API: `POST /solution/extract` (solution .zip as base64), `POST /fix`, `POST /gate`. In the workbench, drop a solution `.zip` into any file
dropzone, right-click a flow for **Generate fixed copy**, and use **Scan > Release gate check**.

## New scan, SA&A report and POA&M

In the workbench: **New scan** (toolbar, or Edit > New scan) clears the current results, findings and console so you can scan again; saved
assessments stay under My Assessments. Edit > Delete this assessment / Delete all assessments remove saved ones (with a confirmation).
**SA&A report** (toolbar, or File > SA&A Assessment Report) builds a Security Assessment Report from the selected assessment and your triage
statuses and comments: executive summary, scope and limits, flow inventory, results by severity/status and category, data exposure, detailed
findings with remediation, accepted-risk register, POA&M and sign-off block. Open it and use Print > Save as PDF, or download the .html.
**File > Export POA&M (CSV)** lists the open findings with blank owner, resources, milestones and completion-date columns.
The report is not mapped to NIST 800-53 or any other control framework.

### Saving the SA&A report as a PDF (to email)

**SA&A report > Download PDF** saves a real `.pdf` you can attach to an email. The backend makes it with the Microsoft Edge or
Google Chrome already installed on the machine that runs it (Edge ships with Windows), so no extra Python package is needed.
Set `FALCON_BROWSER` to a browser's full path to choose one. If none is found, the app opens the report instead and you use
Print > Save as PDF. The `.html` download is also self-contained (the logo is embedded), so it can be emailed as a file too.

## AI agents and MCP servers

Drop an MCP configuration (`mcp.json`, desktop AI client or editor `mcpServers`, VS Code `servers`) or an agent definition file (instructions plus a `tools`
list and/or a model, OpenAI / Azure style) into any file dropzone, the command line (`python falconscan.py mcp.json agent.json`) or `POST /scan/upload`.
The same gate, waivers, SARIF output, SA&A report and "Generate fixed copy" work for these files. Samples: `samples/mcp-config-risky.json`,
`samples/ai-agent-risky.json`, `samples/ai-agent-clean.json` (all credentials in them are fake).

18 rules (`AG-*`), each with CWE and OWASP LLM Top 10 (2025) references: secrets in config, remote MCP servers over HTTP or without a credential,
unpinned packages/images, shell or inline-code launchers, broad file access, privileged containers, disabled TLS checks, auto-approved tools,
code-execution tools, tools without approval, unconstrained tool input, prompt-injection and data-exfiltration paths, wildcard permissions,
third-party or plain-HTTP model endpoints, and agent-to-agent delegation.

Limits: configuration only (nothing is run or contacted). The path checks (`AG-AGT-004`, `AG-AGT-005`) are heuristics based on tool names and
descriptions: they flag combinations worth a decision, not proven exploits. Not covered yet: Copilot Studio exports, other agent frameworks' formats,
and runtime or live prompt testing. Secret values are hidden in results, reports and SARIF; automatic fixes cover only https URLs, disabled TLS
settings, auto-approval and `require_approval: never`.

## n8n and Make

**Active.** Drop an exported n8n workflow (`.json`) or a Make scenario blueprint (`.json`) into any file dropzone, the command line or the API; Falcon Scan recognises them by their structure. Thirteen `WF-*` rules cover webhooks open to anyone, hard-coded secrets (in node settings, headers and code steps), plain-HTTP addresses, disabled TLS checks, shell and code steps, SQL built from workflow data, data sent to AI services, ignored errors, pinned test data, a missing error workflow and inactive workflows. Secret values are hidden in results and reports. Checks use the fields the products document; a field missing from an export means the check does not fire, so a clean result is not proof of safety. Samples are in `samples/` (`n8n-risky.json`, `n8n-clean.json`, `make-risky.json`). Zapier, Workato and ServiceNow Flow Designer are planned.

## UiPath and other RPA platforms

**UiPath (active).** Drop `project.json`, `.xaml` workflows, or a `.nupkg` / `.zip` package into any file dropzone, the command line
(`python falconscan.py MyProject/ Package.nupkg`) or `POST /scan/upload`. Rules: `RPA-SEC-001` hard-coded credentials (variables, assignments,
activity properties, connection strings, code), `RPA-NET-001` plain-HTTP addresses, `RPA-CODE-001` shell commands, `RPA-CODE-002` embedded
code or PowerShell, `UIP-DB-001` SQL built by concatenation, `UIP-LOG-001` secret-looking variables in log messages, and for `project.json`:
`UIP-PRJ-001` unpinned dependencies, `UIP-PRJ-002` sensitive values not excluded from logs, `UIP-PRJ-003` legacy framework.
Secret values are hidden in results, reports and SARIF. Automatic fixes: `http://` to `https://`, and dependency minimums to exact `[x.y.z]`.
Samples: `samples/uipath-project.json`, `uipath-Main.xaml`, `uipath-clean.xaml` (synthetic, fake credentials).

**Automation Anywhere (.bot, .atmx) and Blue Prism (.bprelease, .bpobject, .bpprocess): basic checks only.** The vendor file layouts have not been
verified against real exports, so these files get schema-free value checks: credential-looking names with literal values, token shapes,
connection-string passwords, plain-HTTP addresses and shell commands (plus Blue Prism Code stages). Treat the output as a first pass, and send a
real export if you want vendor-specific rules added.

Not covered yet: Orchestrator assets, queues and robot configuration, Config.xlsx, Power Apps, and live testing.

## Shared server: sign-in, roles, audit log, schedules, tickets, executive summary

Sign-in is **on by default**. Everything is stored in one SQLite file on the server (`backend/data/falconscan.db`, or `FALCON_DB`), so
every user sees the same applications, assessments and triage decisions. That file holds findings and password hashes: keep it private and
back it up. Set `FALCON_AUTH=off` to go back to single-user mode (no sign-in, data stays in the browser).

**First run.** Open the app: it asks you to create the first administrator. That is only allowed from the server itself, or from another computer if
`FALCON_SETUP_TOKEN` is set on the server and entered on the page. After sign-in, anything saved in this browser before can be imported once.

**Roles.** `viewer` reads everything and can make reports; `assessor` also scans, manages applications, triages, files tickets and manages schedules;
`admin` also manages users, sees the audit log and can delete all assessments. The server enforces roles; the screens only hide what you cannot do.

**Passwords and sessions.** 12+ characters, hashed with scrypt. Five wrong passwords lock the account for 15 minutes (an admin can unlock it).
Sessions end after 2 idle hours or 12 hours in all; changing a role or password ends that user's sessions at once. The session cookie is HttpOnly and
SameSite=Strict, and every change request must carry the `X-Falcon-CSRF` header. If you serve this over a network, put it behind HTTPS and set
`FALCON_COOKIE_SECURE=1`. Not built yet: single sign-on with Microsoft Entra ID (needs an app registration), multi-factor sign-in, password
reset by email, and throttling by address (there is throttling per account).

**Audit log.** Administration > Audit log lists sign-ins (including failures and lock-outs), refused requests, user changes, scans, report exports,
assessment deletions, triage changes, schedules and tickets, never passwords or tokens. Each entry stores the fingerprint of the one before it, so an edit
or deletion in the middle shows as "Log altered". Removing the newest entries cannot be detected from inside the database, so export the CSV (it ends with
the head fingerprint) on a schedule and keep a copy elsewhere.

**Scheduled scans.** Schedules tab: re-scan a saved application every hour, 6 hours, day or week, or a folder on the server (only under `FALCON_SCAN_ROOT`).
Each run is stored as an assessment, and the result says whether the release gate would pass, ignoring findings marked Fixed, Accepted risk or Noise.
Run the backend as a single process (`uvicorn main:app`, no extra workers) and leave it running. Not built: email or chat notifications.

**Tickets (Jira or Azure DevOps).** Set these on the server, never in the browser:
`FALCON_TICKETS=jira` with `FALCON_JIRA_URL`, `FALCON_JIRA_EMAIL`, `FALCON_JIRA_TOKEN`, `FALCON_JIRA_PROJECT` (and optional `FALCON_JIRA_ISSUETYPE`), or
`FALCON_TICKETS=azuredevops` with `FALCON_ADO_ORG_URL`, `FALCON_ADO_PROJECT`, `FALCON_ADO_PAT` (and optional `FALCON_ADO_TYPE`). Then a finding's detail pane shows
**Create ticket**; the title, rule, location, explanation and fix steps are sent after you confirm, never file contents or secret values, and one finding gets one ticket.
These two integrations follow the vendors' documented APIs and are tested against a local stand-in, not against a live Jira or Azure DevOps.

**Executive summary.** File > Executive Summary (PDF): a one-to-two page view across all applications: position, open High findings with how long they have been
open, where the risk concentrates, progress and recommended next steps.


## Workbench menus, folders and custom rules

- **File, Edit, Scan, View and Perspective** follow the layout of AppScan Source: Add Application (new, existing, solution .zip, Power Platform), Add Folder, Open and Close Assessment, Reports, Copy Finding, Duplicate and Rename Application, Find and Find Next, Scan All Applications, Scan Selection (F4), Scan Again and Cancel Scan.
- **Add Folder** reads every automation file in the chosen folder and its sub-folders into a new application. Other files are skipped and counted.
- **Cancel Scan** stops the browser waiting. The server finishes the scan it was already running, and nothing is saved.
- **Rule Library** (View menu) lists every built-in rule by bundle (category). **Custom rules** are words or phrases that must not appear in a file, matched as plain text and ignoring capitals (not patterns, so they cannot hang the server). Up to 50 rules, 200 characters each. A hit becomes a finding with your title, severity and fix text. The matched text is never repeated in findings or reports. Custom rules are part of the scan configuration, so they apply in the release gate, the CLI (`"custom": [...]` in the policy file) and SARIF output as well.

## Running the website and the API as one program (deployment)

```
cd frontend && npm install && npm run build
cd ../backend && pip install -r requirements.txt
set FALCON_SETUP_TOKEN=choose-a-long-random-value
set FALCON_COOKIE_SECURE=1
uvicorn server:app --host 0.0.0.0 --port 8000
```

`server.py` serves the built website from `frontend/dist` (override with `FALCON_STATIC`) and the API under `/api`, on one address, so no CORS settings or separate web host are needed. The landing page and login page are public. Everything else needs an account.

- Put it behind HTTPS (the host or a reverse proxy normally does this) and keep `FALCON_COOKIE_SECURE=1`, which also turns on the HSTS header.
- Set `FALCON_SETUP_TOKEN` before the first visit from another computer. The first administrator is created with it.
- Every response carries a strict Content-Security-Policy and the usual protection headers.
- Run a single process with a persistent disk for `FALCON_DB` (SQLite), and back that file up.
- For development keep using `uvicorn main:app` with `npm run dev`.

## Public website (landing page only)

`npm run build:site` in `frontend/` builds a public website into `frontend/dist-site/` from `site.html`. It holds the landing page and a notice where login would be. None of the application (workbench, scanner screens, API code) is included. Set `VITE_BASE` to the path it is served from, for example `VITE_BASE=/my-repo/ npm run build:site`.

`.github/workflows/pages.yml` builds and publishes it to GitHub Pages on every push to `main` that touches `frontend/`. Turn it on once under Settings, then Pages, then Source: **GitHub Actions**. The repository itself can stay private: only the built site is published. GitHub Pages from a private repository needs a plan that supports it (for example Pro or Team), so check Settings, Pages before relying on it.

## Putting the live application online (Render)

GitHub Pages only hosts the landing page. To run the real application (sign-in, scanner, workbench) online you need a host that runs Python. The repository contains a `Dockerfile` and a `render.yaml` for [Render](https://render.com):

1. On render.com choose **New ▸ Blueprint**, connect this GitHub repository and apply `render.yaml`. It builds the website and starts one service.
2. In the service's **Environment** tab copy the generated value of `FALCON_SETUP_TOKEN`.
3. Open the service address, choose **Login**, and on "Create the first administrator" enter your username and password and the setup token. The token is always required once it is set.
4. Add other people under Administration ▸ Users. Give a read-only (viewer) account to anyone who only needs to look.
5. Make the landing page link to it: in the GitHub repository open Settings ▸ Secrets and variables ▸ Actions ▸ **Variables**, add `APP_URL` with the service address (for example `https://falcon-scan.onrender.com`), then re-run "Publish public website". The Login buttons on the public site then open the live application.

### Sign in with GitHub (optional)

Instead of a password, people can sign in with their GitHub account, but only the usernames you list.

1. On GitHub open Settings ▸ Developer settings ▸ OAuth Apps ▸ **New OAuth App**. Set the callback URL to `<service address>/api/account/github/callback` and create a client secret.
2. In the Render **Environment** tab set `FALCON_GITHUB_CLIENT_ID`, `FALCON_GITHUB_CLIENT_SECRET`, `FALCON_PUBLIC_URL` (the service address) and `FALCON_GITHUB_USERS`, for example `kudosGan:admin,friend:viewer`. The role defaults to `assessor`.
3. The login page then shows **Sign in with GitHub**, and the first-administrator form is hidden. Role changes in `FALCON_GITHUB_USERS` apply at the next sign-in.

Things to know about the free Render plan: the service sleeps when idle (the first visit after a pause takes about a minute), and there is no disk, so the database is wiped whenever it restarts. For data that persists, use a paid plan and uncomment the `disk` section in `render.yaml`. Scheduled scans are off, and PDF reports fall back to the browser's print dialog, because the container has no Chrome or Edge.

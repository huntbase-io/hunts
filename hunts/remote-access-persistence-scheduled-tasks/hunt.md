---
analysis: A standard rule cannot differentiate between an IT admin using a management
  tool and an attacker using it after a geographic sign-in anomaly; this hunt uses
  multi-step correlation and fleet-wide prevalence to provide the necessary context.
blind_spots:
- id: no-geo-data
  owner: Identity Provider Team
  question: whether the source location is actually unauthorized
  remediation: Enable high-fidelity geo-enrichment on the auth logging service.
  requires: IP-to-location enrichment in hb_auth_signin
  risk: A login from a proxy or VPN originating from a permitted country will bypass
    the lead query.
  stage: external-remote-access
- id: no-endpoint-visibility
  owner: IT Operations
  question: whether the host is reporting its task configuration
  remediation: Audit endpoint agent health and coverage on all outward-facing servers.
  requires: endpoint agent reporting hb_scheduled_job
  risk: An intruder on a server without a functioning agent will persist invisibly
    through the scheduler.
  stage: scheduled-task-persistence
coverage:
- stage: external-remote-access
  status: covered
  steps:
  - scoping-remote-logons
- stage: remote-admin-tool-execution
  status: covered
  steps:
  - rare-admin-tools
- stage: scheduled-task-persistence
  status: covered
  steps:
  - new-scripted-tasks
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: External remote services remain a critical entry point; a multi-surface
    hunt is required to distinguish legitimate administration from unauthorized persistence
    using the same tools.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has gained access via an external remote service and established
  persistence using a scheduled task that executes a remote administration tool or
  a malicious script.
labels:
- hunt
- attack.t1133
- attack.t1053.005
- execution
- initial access
- persistence
name: Remote access and persistence via scheduled tasks
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  permitted_countries:
    default:
    - US
    - GB
    - FR
    - DE
    description: ISO country codes where logins are expected.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: soc-policy
    type: list[string]
  remote_admin_tools:
    default:
    - anydesk.exe
    - teamviewer.exe
    - screenconnect.exe
    - rustdesk.exe
    - logmein.exe
    description: Common remote management tool filenames to flag.
    from:
      kind: article
      observed: '2026-09-10'
      ref: sekoia-blog
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts from the lead query to focus the fan-out.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/why-multi-tenant-socs-need-multi-level-agents
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on administrative users and hosts with direct internet exposure first.
  Ensure the permitted_countries list is customized for the specific organization
  or business unit being hunted. Include rows where country data is missing to capture
  masked origins.
references:
- name: "Sekoia \u2014 Why One SOC Agent Is Not Enough for Every Customer"
  url: https://www.sekoia.com/blog/why-multi-tenant-socs-need-multi-level-agents
related:
- hunt: registry-persistence-via-uncommon-tools
  reason: Attackers may also persist via Run keys which requires hb_registry_activity.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: External Remote Service Access
    observables:
    - VPN connections
    - logins from supplier remote services
    - administrative activity from unusual geographic locations or corporate networks
    slug: external-remote-access
    tactic: initial-access
    techniques:
    - T1133
  - name: Remote Administration Tool Execution
    observables:
    - execution of remote administration software
    - unusual administrative commands
    - network traffic from management tools to unexpected endpoints
    slug: remote-admin-tool-execution
    tactic: execution
    techniques:
    - T1133
  - name: Persistence via Scheduled Task
    observables:
    - schtasks.exe
    - creation of new scheduled tasks by service accounts
    - tasks running recurring scripts or admin binaries
    - C:\Windows\System32\Tasks
    slug: scheduled-task-persistence
    tactic: persistence
    techniques:
    - T1053.005
  summary: This campaign involves attackers gaining initial access via external remote
    services like VPNs, followed by the execution of remote administration tools to
    manage the environment and establishing long-term persistence using scheduled
    tasks.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Remote access and persistence via scheduled tasks

This hunt identifies potential intruders who use external-facing services for initial entry, followed by the installation of persistence via Windows Task Scheduler. It follows a gated flow: a cheap lead query first identifies successful logins from unauthorized geographic locations or potential VPN services. If an agent confirms the risk, the hunt fans out to gather evidence of newly created scheduled tasks running scripts and the execution of rare remote management tools across the fleet. A final triage weighs the combined evidence to determine if an intrusion chain is active.

## scoping-remote-logons
<!-- Suspicious Remote Service Logons -->
Identify successful logins from unauthorized countries or potential VPN protocols that could represent a beachhead.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, permitted_countries=permitted_countries)
~~~yaml
expected: Rows show logins from non-permitted countries or unknown origins. Silence
  suggests no geographic anomalies occurred during the window.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- logon_type
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, logon_type, auth_protocol, time FROM hb_auth_signin WHERE status_id = 1 AND (src_location_country IS NULL OR instr(',' || '{{permitted_countries}}' || ',', ',' || src_location_country || ',') = 0) AND (logon_type IN ('Remote Interactive', 'Network') OR LOWER(auth_protocol) LIKE '%vpn%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Logon Lead -->
```agent target=hunter
cite: required
context:
- scoping-remote-logons
max_iterations: 3
objective: Determine if any successful sign-ins represent unauthorized access by reviewing
  the source country and actor history.
success_criteria: A per-host verdict on whether the login is suspicious.
tools:
- endpoint
- identity
```

## gate-on-lead
<!-- Gate on Risk -->
if~: "The evaluate-lead agent identifies a session as suspicious or from an unauthorized location." (confidence: high, judge=hunter)
then: → persistence-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-geo-data)
else: → close-out

## persistence-fan-out
<!-- Gather Persistence Evidence -->
parallel:
- → new-scripted-tasks
- → rare-admin-tools
join: → triage-intrusion

## new-scripted-tasks
<!-- New Scripted Scheduled Tasks -->
Identify new tasks that execute script interpreters often used for persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of new scripted tasks. Suspicious matches include commands that download
  and execute code.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE activity_id = 1 AND (LOWER(job_cmd_line) LIKE '%powershell%' OR LOWER(job_cmd_line) LIKE '%cmd.exe%' OR LOWER(job_cmd_line) LIKE '%cscript%' OR LOWER(job_cmd_line) LIKE '%wscript%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-admin-tools
<!-- Rare Remote Administration Tools -->
Find rare execution of management tools by matching basenames or paths against the known tool list.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, remote_admin_tools=remote_admin_tools, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Tools appearing on very few hosts. A tool used fleet-wide is likely a business
  standard; a tool on one host is a lead.
prevalence:
  by: device_hostname
  key:
  - process_original_file_name
  rare_below: 3
reads:
- process_name
- process_original_file_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT LOWER(process_name) AS tool_path, process_original_file_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{remote_admin_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{remote_admin_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY tool_path, process_original_file_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-intrusion
<!-- Triage Intrusion Chain -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- new-scripted-tasks
- rare-admin-tools
max_iterations: 6
objective: Determine if the suspicious logon identified earlier correlates with the
  creation of a task or the execution of a rare management tool on the same host.
success_criteria: A malicious, suspicious, or benign verdict citing the cross-surface
  rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage-intrusion verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-visibility)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and rotate the credentials for the account involved in the suspicious logon.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited rows. Determine if the identified remote management tool is an undocumented but approved tool for this specific business unit. Update the parameters if needed.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record the results. If common false positives were found, update the remote_admin_tools list to exclude them from future runs.
```
→ end

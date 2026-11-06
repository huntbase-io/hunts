---
analysis: A single detection rule would struggle with the variability of user-pasted
  commands; this hunt pivots from the execution context (explorer as parent) to network
  indicators and follow-on persistence (scheduled tasks) to distinguish accidental
  user error from active infostealer compromise.
blind_spots:
- id: limited-retention-windows
  owner: Security Engineering
  question: whether the initial DNS query to psw.amatera occurred before the 14-day
    lookback
  remediation: Increase DNS log retention for developer-class workstations.
  requires: 60+ days of hb_dns_activity
  risk: A host infected three weeks ago may show persistence but no longer have the
    initial network delivery telemetry in the lookback window.
  stage: initial-access-delivery
- id: clipboard-monitoring-gap
  owner: Detection Engineering
  question: whether the user actually copied malicious content from a browser before
    pasting it into the Run dialog
  remediation: Explore EDR capability for monitoring clipboard-to-command-line transfers.
  requires: hb_clipboard_activity (not currently available)
  risk: The hunt relies on the process parent-child relationship (explorer -> powershell)
    and command line content, which can be bypassed if the user runs the command through
    other means.
  stage: execution-user-pasted-commands
coverage:
- stage: initial-access-delivery
  status: covered
  steps:
  - dns-to-amatera-infra
- stage: execution-user-pasted-commands
  status: covered
  steps:
  - execution-from-run-dialog
- stage: persistence-scheduled-task
  status: covered
  steps:
  - new-scheduled-tasks
- stage: defense-evasion-history-clearing
  status: covered
  steps:
  - powershell-history-tampering
- reason: 'Belongs to another part of the ''Amatera: How the prolific infostealer
    works and spreads'' series.'
  stage: credential-and-clipboard-collection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Amatera: How the prolific infostealer
    works and spreads'' series.'
  stage: cloud-resource-authorization
  status: out_of_scope
- reason: 'Belongs to another part of the ''Amatera: How the prolific infostealer
    works and spreads'' series.'
  stage: impact-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Amatera infostealer detections in Latin America topped the charts
    in 2026; its ability to steal developer secrets and M365 tokens makes it a critical
    threat to organizational cloud infrastructure. A negative result confirms that
    these specific social engineering techniques are not currently successful in the
    estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used social engineering to trick a user into executing
  PowerShell commands from the Run dialog, leading to the installation of the Amatera
  infostealer and persistent scheduled tasks.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1218.011
- attack.t1053.005
- attack.t1070
- attack.t1555
- attack.t1115
- collection
- credential access
- defense evasion
- execution
- impact
- initial access
- persistence
name: Amatera Infostealer Initial Access and Persistence
parameters:
  amatera_domains:
    default:
    - psw.amatera
    description: Known domains associated with Amatera infrastructure.
    from:
      kind: article
      observed: '2026-10-29'
      ref: eset-research-amatera
    type: list[domain]
  dev_tool_patterns:
    default:
    - claude
    - jetbrains
    - snowflake
    - notebooklm
    - comet
    description: Software patterns to identify potential high-value developer workstations.
    from:
      kind: article
      observed: '2026-10-29'
      ref: eset-research-amatera
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for initial execution and follow-on activity.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; leave empty to scan the
      entire estate.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The campaign specifically targets developers and users of AI tools. Focus
  first on workstations with JetBrains, Claude, or Snowflake client software. Use
  a 14-day lookback to capture both the initial social engineering (ClickFix) and
  subsequent persistence mechanisms.
references:
- name: "ESET Research \u2014 Amatera: How the prolific infostealer works and spreads"
  url: https://www.welivesecurity.com/en/malware/amatera-how-prolific-infostealer-works-spreads/
related:
- hunt: browser-extension-and-cookie-theft
  reason: Amatera also steals browser cookies and session tokens, which requires specialized
    hunting in hb_file_activity for browser profile access.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Social Engineering and SEO Poisoning
    observables:
    - Impersonation of AI tools (Claude Code, NotebookLM, JetBrains)
    - Fake CAPTCHA sites
    - Fake browser error/crash pages
    - Compromised WordPress sites
    - SVG files and fake documents
    - Domain psw.amatera
    slug: initial-access-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: User-Initiated Command Execution
    observables:
    - Commands pasted into Run dialog (Win+R)
    - powershell.exe
    - rundll32.exe
    - Suspicious PowerShell script blocks containing download instructions
    slug: execution-user-pasted-commands
    tactic: execution
    techniques:
    - T1059.001
    - T1218.011
  - name: Task Scheduler Persistence
    observables:
    - schtasks.exe
    - Creation of new scheduled tasks
    - Unusual task XML definitions
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: PowerShell History Tampering
    observables:
    - Deletion or clearing of ConsoleHost_history.txt
    slug: defense-evasion-history-clearing
    tactic: defense-evasion
    techniques:
    - T1070
  - name: Local Credential and Wallet Theft
    observables:
    - Access to browser 'Login Data', 'Cookies', and 'Web Data' SQLite files
    - Clipboard monitoring for cryptocurrency wallet addresses
    - Theft of SSH keys and FTP credentials
    slug: credential-and-clipboard-collection
    tactic: credential-access
    techniques:
    - T1555
    - T1115
  - name: OAuth Token and Cloud Storage Access
    observables:
    - ConsentFix OAuth token authorization grants
    - Unauthorized access to SharePoint and OneDrive files
    - Extraction of secrets from development environments
    slug: cloud-resource-authorization
    tactic: collection
    techniques:
    - T1566
    - T1530
  - name: Ransomware Rebranding Activity
    observables:
    - Encryption of files on target systems
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Amatera is a C++ infostealer distributed via 'ClickFix' social engineering,
    SEO poisoning, and malicious ads targeting developers. Once executed, it establishes
    persistence through scheduled tasks and exfiltrates browser credentials, session
    tokens, and sensitive files from local systems and cloud storage services like
    SharePoint.
series:
  index: 1
  slug: amatera-how-the-prolific-infostealer-works-and-spreads
  title: 'Amatera: How the prolific infostealer works and spreads'
  total: 2
severity: high
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
tlp: clear
type: investigation
---


# Amatera Infostealer Initial Access and Persistence

Amatera is a professionalized infostealer that frequently uses ClickFix techniques, where victims are social-engineered into pasting malicious commands directly into Windows system utilities. This hunt identifies the initial user-driven execution, corroborates it with known network infrastructure, and then tracks follow-on persistence and defense evasion through PowerShell history tampering.

## software-scoping
<!-- Scope to developer workstations -->
Identify hosts running tools mentioned in the Amatera campaign to prioritize the hunt on developer workstations.

```sqlite target=endpoint role=scoping params=(dev_tool_patterns=dev_tool_patterns)
~~~yaml
expected: A list of hosts frequently using AI or development tools. Silence means
  no such software was found, not that the hosts are safe.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{dev_tool_patterns}}' || ',', ',' || LOWER(package_name) || ',') > 0) GROUP BY device_hostname, package_name, package_version
```

## initial-infection-signals
<!-- Detect initial infection indicators -->
parallel:
- → execution-from-run-dialog
- → dns-to-amatera-infra
join: → early-stage-triage

## execution-from-run-dialog
<!-- PowerShell execution from Run dialog -->
Find PowerShell or Rundll32 processes launched directly from explorer.exe, which is the hallmark of the ClickFix social engineering vector.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell commands with obfuscated or download-related flags launched by
  explorer.exe. This typically represents a user pasting a command from the browser.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%\explorer.exe') AND (LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\rundll32.exe') AND (LOWER(process_cmd_line) LIKE '%-enc%' OR LOWER(process_cmd_line) LIKE '%invoke-webrequest%' OR LOWER(process_cmd_line) LIKE '%iwr%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-to-amatera-infra
<!-- DNS activity to Amatera domains -->
Identify if any hosts in the estate have attempted to resolve the reported Amatera infostealer C2 or distribution infrastructure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, amatera_domains=amatera_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Any DNS resolution for psw.amatera. Silence does not prove safety as domains
  rotate frequently.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{amatera_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage initial access evidence -->
```agent target=hunter
cite: required
context:
- execution-from-run-dialog
- dns-to-amatera-infra
max_iterations: 4
objective: Determine if any host shows evidence of a user-driven infection via pasted
  commands corroborated by network activity.
success_criteria: A verdict for each host with supporting row citations.
tools:
- endpoint
```

## persistence-and-evasion-signals
<!-- Identify follow-on persistence and evasion -->
parallel:
- → new-scheduled-tasks
- → powershell-history-tampering
join: → follow-on-triage

## new-scheduled-tasks
<!-- New scheduled task creation -->
Amatera is known to create unusual scheduled tasks for persistence. This query finds jobs created or updated during the lookback period.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of non-standard tasks, particularly those running PowerShell or
  binaries from user-writable paths.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE activity_id IN (1, 2) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## powershell-history-tampering
<!-- PowerShell history tampering -->
The report suggests attackers clear PowerShell history to hide the pasted commands. This query finds deletions of the ConsoleHost_history.txt file.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Deletions or suspicious updates to the PowerShell history file. This is
  rare in standard administrative workflows.
prevalence:
  by: device_hostname
  key:
  - file_path
  rare_below: 3
reads:
- device_hostname
- file_path
- process_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-30'
~~~
SELECT device_hostname, file_path, process_name, activity_name, COUNT(*) OVER (PARTITION BY file_path) as global_frequency, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\microsoft\windows\powershell\powershell\consolehost_history.txt' AND activity_id IN (3, 4) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## follow-on-triage
<!-- Weigh complete infection chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- new-scheduled-tasks
- powershell-history-tampering
max_iterations: 5
objective: Decide if the host has been compromised by Amatera based on the full chain
  of execution, network, persistence, and evasion evidence.
success_criteria: A final verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The follow-on-triage verdict is malicious or suspicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-retention-windows)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the suspicious PowerShell history file and any binaries referenced in the scheduled tasks for analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Review and secret rotation -->
```manual target=analyst
Review the rows cited by the agents. If malicious, perform a full secret rotation including M365 session tokens, passwords, and SSH keys. Review Microsoft 365 Unified Audit Logs for the affected user during the lookback period.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the hosts examined. If no suspicious activity was found, record this as evidence of absence for the Amatera campaign in this estate.
```
→ end

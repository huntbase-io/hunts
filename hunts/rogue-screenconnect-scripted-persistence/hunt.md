---
analysis: A single rule for ScreenConnect or scheduled tasks triggers too frequently
  in authorized contexts. This hunt correlates the specific multi-stage script logic
  (swapping instances) with custom evasion tools and fleet-wide rarity across three
  different telemetry surfaces.
blind_spots:
- id: no-script-block-logging
  question: What specifically occurred during the execution of the SCAutoFix.ps1 script?
  requires: hb_script_activity (PowerShell Script Block Logging)
  risk: Without script block logging, we see the script ran but not the specific commands
    it used to manipulate the ScreenConnect instances or uninstall previous versions.
  stage: scripted-multi-stage-deployment
- id: short-dns-retention
  question: Did the host contact the relay domains prior to the current logging window?
  requires: hb_dns_activity (historical logs)
  risk: If the initial infection occurred weeks ago, the DNS signal will be lost,
    leaving only the persistence task and active process as evidence.
  stage: rmm-command-and-control
coverage:
- stage: scripted-multi-stage-deployment
  status: covered
  steps:
  - script-deployment
  - early-stage-read
- stage: rmm-persistence-tasks
  status: covered
  steps:
  - persistence-tasks
- stage: rmm-command-and-control
  status: covered
  steps:
  - dns-to-relays
- stage: defense-evasion-cloaking
  status: covered
  steps:
  - evasion-tool
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: initial-access-powerbi-phishing
  status: out_of_scope
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: rmm-payload-download
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries are actively abusing trusted cloud domains like Power
    BI to deliver rogue RMMs. Identifying the scripted deployment and cloaking is
    critical to preventing long-term remote access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trusted Power BI domains to stage rogue RMM installers,
  which then use PowerShell scripts to rotate instances and establish persistent tasks
  while cloaking their presence with evasion tools.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1566
- command and control
- defense evasion
- execution
- initial access
- persistence
name: Rogue ScreenConnect Scripted Persistence and Evasion
parameters:
  c2_domains:
    default:
    - instance-g01s1n-relay.screenconnect.com
    - onthegotree.site
    - dailylifeproject.site
    - burnsworth.site
    - essaywritingservice.site
    - openpediatrics.site
    description: Reported rogue RMM relay and staging domains.
    from:
      kind: article
      observed: '2026-10-07'
      ref: huntress-power-bi
    type: list[domain]
  deployment_scripts:
    default:
    - LyN03DvVjUKPrun.cmd
    - SCAutoFix.ps1
    description: Script names used for multi-stage RMM deployment and swapping.
    from:
      kind: article
      observed: '2026-10-07'
      ref: huntress-power-bi
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  persistence_task_name:
    default: SCAutoRepairEvery2Min
    description: Name of the scheduled task created for persistence.
    from:
      kind: article
      observed: '2026-10-07'
      ref: huntress-power-bi
    type: string
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt, often populated from
      the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/screenconnect-power-bi
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints running ScreenConnect specifically from temporary paths
  (e.g., %temp% or user Downloads); prioritize servers and administrative workstations.
references:
- name: "Huntress \u2014 Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue\
    \ RMMs"
  url: https://www.huntress.com/blog/screenconnect-power-bi
related:
- hunt: initial-access-powerbi-phishing
  reason: This hunt focuses on the post-infection endpoint activity rather than the
    initial phishing link delivery mechanism.
  relation: out-of-scope-alternative
- hunt: power-bi-phishing-screenconnect-rmm
  relation: follows
scenario:
  stages:
  - name: Phishing via Power BI Dashboard
    observables:
    - app.powerbi.com/view?r=eyJrIjoiNTk0NmViNDktYzM1Yy00MjEwLTkyZTctNGU5ZTJmYzMzYjEwIiwidCI6IjU1YTI4YmU2LTFiYzQtNDIzMS05MTA0LTdkMmFlYTVmMGZhNiJ9
    - dailylifeproject.site
    - burnsworth.site
    - essaywritingservice.site
    - openpediatrics.site
    - check.vykyn.click
    slug: initial-access-powerbi-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Rogue ScreenConnect Download
    observables:
    - hamham27.screenconnect.com
    - ScreenConnect.ClientSetup.exe
    - 5956f9afb3ba610c38b2cfda88dd15be98783963769a12020c93ce05e749b3c3
    slug: rmm-payload-download
    tactic: execution
    techniques:
    - T1059.001
  - name: Scripted RMM Deployment
    observables:
    - LyN03DvVjUKPrun.cmd
    - SCAutoFix.ps1
    - C:\Temp\ScreenConnect.ClientSetup.msi
    - ScreenConnect.ClientSetup (6).exe
    - onthegotree.site
    slug: scripted-multi-stage-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task Persistence
    observables:
    - SCAutoRepairEvery2Min
    slug: rmm-persistence-tasks
    tactic: persistence
    techniques:
    - T1053.005
  - name: RMM C2 Communication
    observables:
    - instance-g01s1n-relay.screenconnect.com
    slug: rmm-command-and-control
    tactic: c2
  - name: Defense Evasion and Cloaking
    observables:
    - HideUL_x64.exe
    slug: defense-evasion-cloaking
    tactic: defense-evasion
  summary: Threat actors are abusing legitimate Microsoft Power BI links to bypass
    email filters and deliver rogue ScreenConnect RMM installers. The campaign utilizes
    multi-stage execution with CMD and PowerShell scripts to deploy redundant RMM
    instances, establishing persistence through scheduled tasks while using specialized
    tools to hide attacker activity.
series:
  index: 2
  slug: phishing-campaign-abuses-microsoft-power-bi-to-deploy-rogue-rmms
  title: Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs
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


# Rogue ScreenConnect Scripted Persistence and Evasion

This hunt identifies the post-infection lifecycle of a phishing campaign that abuses Microsoft Power BI. It follows a phased approach: first, it identifies hosts with rogue ScreenConnect activity and correlates it with known RMM relay domains and deployment scripts; second, it pivots to find secondary scripted persistence via rare scheduled tasks and the execution of the HideUL evasion tool. By weighing early-stage execution against follow-on persistence and evasion, the hunt identifies active intrusions that simple RMM-based alerts might miss.

## scoping-screenconnect
<!-- Scope ScreenConnect Activity -->
Identify hosts running ScreenConnect components or installers specifically from temporary directories to focus the hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts with ScreenConnect activity in temp paths. Silence is expected
  in clean environments.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%screenconnect%' OR LOWER(process_cmd_line) LIKE '%screenconnect%') AND LOWER(process_cmd_line) LIKE '%temp%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-evidence-gathering
<!-- Gather Early-Stage Indicators -->
parallel:
- → dns-to-relays
- → script-deployment
join: → early-stage-read

## dns-to-relays
<!-- DNS to RMM Relays -->
Match host DNS activity against known rogue ScreenConnect relay domains for the scoped host list.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolutions for reported rogue infrastructure from hosts showing suspicious
  RMM activity.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## script-deployment
<!-- Rogue Deployment Scripts -->
Search script activity for the specific deployment commands used to swap RMM installers, gated by the scoped hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, deployment_scripts=deployment_scripts, scope_hosts=scope_hosts)
~~~yaml
expected: Presence of reported script names or internal SCAutoFix logic on scoped
  hosts.
reads:
- device_hostname
- script_name
- script_path
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, script_name, script_path, script_content, time FROM hb_script_activity WHERE (instr(',' || '{{deployment_scripts}}' || ',', ',' || LOWER(script_name) || ',') > 0 OR LOWER(script_content) LIKE '%scautofix%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-read
<!-- Assess Early-Stage Infection -->
```agent target=hunter
cite: required
context:
- scoping-screenconnect
- dns-to-relays
- script-deployment
max_iterations: 3
objective: Determine if any host shows evidence of rogue ScreenConnect installation
  and deployment scripts.
success_criteria: A list of hosts showing confirmed early-stage campaign signals.
tools:
- endpoint
```

## follow-on-evidence
<!-- Hunt Follow-on Persistence and Evasion -->
parallel:
- → persistence-tasks
- → evasion-tool
join: → follow-on-read

## persistence-tasks
<!-- Scheduled Task Persistence -->
Identify rare scheduled tasks that execute the deployment scripts on systems that showed rogue RMM activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, persistence_task_name=persistence_task_name, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare scheduled task appearing on scoped hosts referencing the rogue scripts.
prevalence:
  by: device_hostname
  key:
  - job_name
  - job_cmd_line
  rare_below: 3
reads:
- device_hostname
- job_name
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT job_name, job_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE (LOWER(job_name) = LOWER('{{persistence_task_name}}') OR LOWER(job_cmd_line) LIKE '%scautofix.ps1%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_name, job_cmd_line HAVING hosts < 3
```

## evasion-tool
<!-- HideUL Evasion Tool -->
Detect the execution of HideUL_x64.exe on the same systems where the RMM was deployed.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Matches on the HideUL binary indicating active cloaking of the RMM.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%hideul_x64.exe%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-read
<!-- Final Triage and Correlation -->
```agent target=hunter
cite: required
context:
- early-stage-read
- persistence-tasks
- evasion-tool
max_iterations: 5
objective: Confirm active, persistent, and cloaked RMM infections by weighing evidence
  from both deployment and persistence phases.
success_criteria: A final verdict of malicious or suspicious per host with cited evidence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the follow-on-read verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-script-block-logging)
else: → analyst-review

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate forensic collection of any ScreenConnect installers or HideUL binaries found in temporary directories.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the DNS and PowerShell script rows; verify if the ScreenConnect instances are authorized and if the HideUL binary matches known malware hashes.
```
→ close-out

## close-out
<!-- Hunt Close Out -->
```manual target=analyst
Document any variations in filenames or relay domains discovered during the hunt to update future detection logic.
```
→ end

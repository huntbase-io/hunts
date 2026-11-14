---
analysis: A single detection rule might fire on a ransom note filename, but it provides
  no context on the evasion method used. This hunt pivots between process staging,
  kernel module prevalence, and impact files to reconstruct the attack timeline, allowing
  the analyst to verify if the defense-evasion (BYOVD) phase was successful before
  encryption occurred.
blind_spots:
- id: telemetry-rollover
  owner: Security Engineering
  question: whether AnyDesk was installed more than 14 days before the encryption
    wave
  remediation: Extend process and file event retention to at least 30 days.
  requires: extended hb_process_activity retention
  risk: A 17-day lull between initial access and ransomware deployment may exceed
    default EDR retention periods on some endpoints.
  stage: remote-access-deployment
- id: missing-module-telemetry
  owner: IT Infrastructure
  question: whether the BYOVD driver was successfully loaded into the kernel
  remediation: Deploy Sysmon with Event ID 7 enabled or enable osquery kernel_module
    tables.
  requires: hb_module_activity
  risk: Hosts without Sysmon Event ID 7 or osquery kernel module auditing will not
    report the driver load, making the BYOVD phase invisible.
  stage: defense-evasion-byovd
coverage:
- stage: remote-access-deployment
  status: covered
  steps:
  - staging-and-rat-scoping
- stage: defense-evasion-byovd
  status: covered
  steps:
  - rare-modules-in-staging
- stage: ransomware-encryption-impact
  status: covered
  steps:
  - inc-ransom-note-detection
- reason: 'Belongs to another part of the ''The Tale of Two INC Ransom Notes: A Ransomware
    Timeline | Huntress'' series.'
  stage: persistence-via-nonsense-scheduled-task
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Tale of Two INC Ransom Notes: A Ransomware
    Timeline | Huntress'' series.'
  stage: obfuscated-powershell-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Tale of Two INC Ransom Notes: A Ransomware
    Timeline | Huntress'' series.'
  stage: rdp-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The encryption phase represents the point of maximum business impact;
    identifying the specific BYOVD tools and RAT precursors allows for rapid containment
    of the incident before the full impact of the second ransom wave.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed remote access tools and Bring Your Own Vulnerable
  Driver (BYOVD) loaders to neutralize security products before executing INC ransomware.
labels:
- hunt
- attack.t1059.001
- attack.t1053.005
- attack.t1486
- attack.t1021.001
name: 'INC Ransomware Wave 2: BYOVD and RAT Deployment'
parameters:
  byovd_module_names:
    default:
    - hwauidoos2ec.sys
    - hwau.exe
    - healthupdater.exe
    - netscan.exe
    description: Filenames associated with the BYOVD loader and the vulnerable kernel
      driver.
    from:
      kind: article
      observed: '2026-09-21'
      ref: huntress-inc-ransomware
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine; the reported 17-day lull may require
      extension for earlier persistence.
    type: number
  ransom_note_filenames:
    default:
    - inc-readme.txt
    - dataleak_press_release.txt
    description: Filenames of the INC ransomware notes used for impact confirmation.
    from:
      kind: article
      observed: '2026-09-21'
      ref: huntress-inc-ransomware
    type: list[string]
  rat_process_names:
    default:
    - anydesk.exe
    - anydesk
    - screenconnect.exe
    - teamviewer.exe
    - rustdesk.exe
    description: Common Remote Access Tool (RAT) process names observed in the second
      wave.
    from:
      kind: article
      observed: '2026-09-21'
      ref: huntress-inc-ransomware
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; leave empty to run fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/two-inc-ransom-notes
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes hosts based on Remote Access Tool (RAT) names and common
  ransomware staging paths (Public, PerfLogs, ProgramData). This lead focuses on the
  second wave beachhead before pivoting to driver and encryption artifacts.
references:
- name: "Huntress \u2014 The Tale of Two INC Ransom Notes: A Ransomware Timeline"
  url: https://www.huntress.com/blog/two-inc-ransom-notes
related:
- hunt: inc-ransomware-wave-1-persistence
  reason: Wave 1 focuses on initial access brokers and their use of nonsense-named
    scheduled tasks for persistence.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Persistence via Randomised Scheduled Task
    observables:
    - Nonweighise\Cancellationizing\Illuminateers
    - nationhood kinestheticization preironish fictionallyes
    - C:\ProgramData\Vendettister\jocularities.ps1
    slug: persistence-via-nonsense-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Obfuscated PowerShell C2
    observables:
    - throughoutes.net
    - jocularities.ps1
    - heavily obfuscated PowerShell
    slug: obfuscated-powershell-c2
    tactic: execution
    techniques:
    - T1059.001
  - name: RDP Lateral Movement
    observables:
    - Compromised user account moving between endpoints via RDP
    slug: rdp-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Remote Access Tool Deployment
    observables:
    - AnyDesk installation
    - 213.111.185.108
    slug: remote-access-deployment
    tactic: command-and-control
    techniques:
    - T1059.001
  - name: Defense Evasion via BYOVD
    observables:
    - hwau.exe
    - HWAuidoOs2Ec.sys
    - HwAudio kernel-driver service
    - HealthUpdater.exe
    - C:\Program Files\7-Zip\HealthUpdater.exe
    - netscan.exe
    - atexec.py temporary scheduled tasks
    slug: defense-evasion-byovd
    tactic: defense-evasion
    techniques:
    - T1053.005
  - name: Ransomware Encryption and Impact
    observables:
    - INC-README.txt
    - DATALEAK_PRESS_RELEASE.txt
    slug: ransomware-encryption-impact
    tactic: impact
    techniques:
    - T1486
  summary: An INC ransomware campaign featuring a 17-day lull between early persistence
    and final impact, likely indicating a hand-off from an access broker to an affiliate.
    The attackers utilized obfuscated PowerShell implants via scheduled tasks and
    RDP for movement, eventually deploying AnyDesk and a vulnerable driver (BYOVD)
    to disable security software before encrypting over 175 endpoints.
series:
  index: 2
  slug: the-tale-of-two-inc-ransom-notes-a-ransomware-timeline-huntress
  title: 'The Tale of Two INC Ransom Notes: A Ransomware Timeline | Huntress'
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


# INC Ransomware Wave 2: BYOVD and RAT Deployment

This hunt focuses on the second wave of activity observed in INC ransomware attacks, where threat actors move from initial persistence to active defense evasion and encryption. The hunt identifies the deployment of remote access tools like AnyDesk and suspicious staging in public folders, then corroborates this with the loading of rare kernel-level modules and the appearance of specific INC ransom notes. An agent weighs these findings per host to confirm the attack progression and prompt containment.

## staging-and-rat-scoping
<!-- Lead Scoping: RATs and Staging Paths -->
Identify potential beachhead hosts where remote access tools were installed or suspicious staging occurred.

```sqlite target=endpoint role=scoping params=(rat_process_names=rat_process_names, lookback_days=lookback_days)
~~~yaml
expected: Rows identify hosts with AnyDesk or binaries running from unusual paths.
  Silence proves absence only for these specific names and directories.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{rat_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\perflogs\%' OR LOWER(process_path) LIKE '%\programdata\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-wave-artifacts
<!-- Corroborate Defense Evasion and Impact -->
parallel:
- → rare-modules-in-staging
- → inc-ransom-note-detection
join: → wave-2-triage

## rare-modules-in-staging
<!-- Rare Modules and Driver Loading -->
Identify the loading of the vulnerable HwAudio driver or renamed tools by looking for rare modules in the estate.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, byovd_module_names=byovd_module_names, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A module seen on only one or two hosts, specifically the HwAudio driver
  or tools in public paths.
prevalence:
  by: device_hostname
  key:
  - module_name
  - module_path
  rare_below: 3
reads:
- module_name
- module_path
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT module_name, module_path, process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_module_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(module_path) LIKE '%\users\public\%' OR instr(',' || '{{byovd_module_names}}' || ',', ',' || LOWER(module_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY module_name, module_path, process_name HAVING host_count <= 2
```

## inc-ransom-note-detection
<!-- INC Ransom Note Discovery -->
Detect the final stage of the attack by identifying the creation of INC ransom notes on the endpoints.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, ransom_note_filenames=ransom_note_filenames, lookback_days=lookback_days)
~~~yaml
expected: Presence of INC-README.txt or DATALEAK_PRESS_RELEASE.txt files on any host.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{ransom_note_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## wave-2-triage
<!-- Wave 2 Attack Triage -->
```agent target=hunter
cite: required
context:
- staging-and-rat-scoping
- rare-modules-in-staging
- inc-ransom-note-detection
max_iterations: 4
objective: Review the process staging, module loading, and file creation events to
  determine if a host is undergoing an active INC ransomware infection.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing the
  specific timestamps of RAT deployment and ransomware notes.
tools:
- endpoint
```

## route-on-verdict
<!-- Route Based on Verdict -->
if~: "the agent determines at least one host is malicious due to a progression from AnyDesk to ransom notes" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → forensic-task
unavailable: → forensic-task (blind_spot: missing-module-telemetry)
else: → forensic-task

## isolate-infected-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot if encryption is in progress; preserve volatile memory for driver analysis.
```
→ forensic-task

## forensic-task
<!-- Forensic Investigation -->
```manual target=analyst
Review the cited rows for AnyDesk. Search specifically for the creation of temporary scheduled tasks (atexec) and the presence of netscan.exe. Collect the HWAuidoOs2Ec.sys file from C:\Users\Public if present.
```
→ remediation-task

## remediation-task
<!-- Remediation and Closeout -->
```manual target=analyst
Document the ransomware wave timeline. Promote the ransom note detection query to a standing rule and record any new malicious C2 IPs found in AnyDesk logs.
```
→ end

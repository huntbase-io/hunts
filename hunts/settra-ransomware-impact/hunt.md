---
analysis: A simple detection rule might fire on 'reagentc /disable', but this hunt
  uses a phased flow to correlate that command with domain-specific binary execution
  and BYOVD driver drops. This contextual weighting creates a complete attack timeline.
blind_spots:
- id: misspelled-log-evasion
  question: Which security events were recorded because the attacker misspelled the
    log path?
  requires: Microsoft-Windows-Defender/Operational log configuration
  risk: Visibility into local defense actions will be lost if the typo is fixed in
    future versions.
  stage: anti-recovery-and-evasion
- id: diskpart-script-visibility
  question: What instructions were contained in the diskpart script?
  requires: hb_script_activity text capture for diskpart
  risk: While the execution of diskpart is visible, the specific actions cannot be
    confirmed without the script content.
  stage: anti-recovery-and-evasion
- id: endpoint-telemetry-gap
  question: Are there hosts where Settra is active but the agent is not reporting?
  requires: Consistent EDR agent coverage across all Windows hosts
  risk: If the agent is killed before it can report the early-stage signals, the hunt
    will fail to see the compromise.
coverage:
- stage: defense-evasion-byovd
  status: covered
  steps:
  - byovd-driver-search
- stage: execution-ransomware-launcher
  status: covered
  steps:
  - launcher-execution-search
- stage: anti-recovery-and-evasion
  status: covered
  steps:
  - anti-recovery-baseline
- stage: impact-data-encryption
  status: covered
  steps:
  - encryption-artifact-search
- reason: 'Belongs to another part of the ''Ready, Settra, Go: New Settra Ransomware
    Variant Deploys MeshAgent RMM'' series.'
  stage: initial-access-remote-services
  status: out_of_scope
- reason: 'Belongs to another part of the ''Ready, Settra, Go: New Settra Ransomware
    Variant Deploys MeshAgent RMM'' series.'
  stage: persistence-rmm-meshagent
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Settra ransomware poses a severe risk to business continuity through
    data destruction. Identifying the transition from defensive evasion (BYOVD) to
    impact (Anti-recovery/Encryption) provides confirmation of an active intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is executing Settra ransomware, using a domain-specific launcher
  and a BYOVD driver to disable defenses before inhibiting recovery and encrypting
  files.
labels:
- hunt
- attack.t1486
- attack.t1059.001
- attack.t1562.001
- attack.t1070.001
- attack.t1490
name: Settra Ransomware Local Impact and Recovery Inhibition
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to hunt across the entire
      estate.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: analyst-scoping-input
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/new-settra-ransomware-variant
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows endpoints, specifically servers and admin workstations.
  Widen the scope if MeshAgent RMM activity has been observed.
references:
- name: "Huntress \u2014 Ready, Settra, Go: New Settra Ransomware Variant Deploys\
    \ MeshAgent RMM"
  url: https://www.huntress.com/blog/new-settra-ransomware-variant
related:
- hunt: settra-rmm-persistence-meshagent
  reason: This hunt focuses on the local impact and encryption stage; RMM persistence
    is a separate precursor stage.
  relation: out-of-scope-alternative
- hunt: settra-persistence-meshagent-remote-access
  relation: follows
scenario:
  stages:
  - name: External Remote Service Compromise
    observables:
    - VPN credential compromise
    - RDP session usage
    slug: initial-access-remote-services
    tactic: initial-access
    techniques:
    - T1133
    - T1021.001
  - name: Persistence via MeshAgent RMM
    observables:
    - mvtcs.exe
    - MeshAgent RMM installation
    - 45.13.122.7
    - 193.5.65.114
    - Workstation name WIN-LIVFRVQFMKO
    slug: persistence-rmm-meshagent
    tactic: persistence
  - name: BYOVD Security Tool Disabling
    observables:
    - gdrv.sys
    - Disable antivirus services
    slug: defense-evasion-byovd
    tactic: defense-evasion
  - name: Settra Ransomware Execution
    observables:
    - '*_win64.exe'
    - C:\Perflogs
    - \Documents\*_win64.exe
    slug: execution-ransomware-launcher
    tactic: execution
  - name: Inhibit Recovery and Clear Logs
    observables:
    - reagentc /disable
    - ipconfig /flushdns
    - diskpart.exe execution with recovery partition script
    - 'cipher /w:'
    - wevtutil log clearing (Application, Security, System, Setup, ForwardedEvents)
    - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    - Microsoft-Windows-TerminalServices-RDPClient/Operational
    - Microsoft-Windows-Sysmon/Operational
    - Microsoft-Windows-PowerShell/Operational
    - Microsoft-Windows-WinRM/Operational
    - Microsoft-Windows-TaskScheduler/Operational
    - Microsoft-Windows-Windows-Defender/Operational
    slug: anti-recovery-and-evasion
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Data Encrypted for Impact
    observables:
    - .locked extension
    - .locked_wip extension
    - RESTORE_FILES.txt
    slug: impact-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Settra ransomware incidents involve initial persistence via MeshAgent RMM
    and the use of BYOVD (gdrv.sys) to disable security tools before executing a ransomware
    binary named after the victim domain. The threat actor employs extensive anti-recovery
    measures including clearing multiple event logs, disabling the Windows Recovery
    Environment, and overwriting free disk space using native Windows utilities.
series:
  index: 2
  slug: ready-settra-go-new-settra-ransomware-variant-deploys-meshagent-rmm
  title: 'Ready, Settra, Go: New Settra Ransomware Variant Deploys MeshAgent RMM'
  total: 2
severity: critical
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


# Settra Ransomware Local Impact and Recovery Inhibition

This hunt follows the Settra ransomware attack chain on the endpoint, focusing on the transition from defense evasion to data destruction. It first identifies early indicators such as the drop of a vulnerable gdrv.sys driver and the execution of a domain-named launcher. The hunt then phases into a follow-on stage that correlates these leads with anti-recovery behaviors—disabling Windows Recovery, wiping free space, and clearing event logs—and the presence of encrypted file artifacts. This phased approach distinguishes malicious ransomware activity from legitimate administrative maintenance.

## windows-host-inventory
<!-- Identify Windows host estate -->
Scope the hunt to Windows endpoints where the Settra ransomware variant is known to operate.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of active Windows hosts. Silence proves no Windows hosts have reported
  inventory within the lookback window.
reads:
- hostname
- platform
- time
- os_version
- last_seen
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT DISTINCT hostname AS device_hostname, os_version, last_seen FROM hb_devices WHERE LOWER(platform) = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-detection
<!-- Detect early stage indicators -->
parallel:
- → byovd-driver-search
- → launcher-execution-search
join: → early-stage-agent

## byovd-driver-search
<!-- BYOVD driver drop -->
Find the creation of gdrv.sys, used by the attacker to disable security software.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A row identifying the host and path where gdrv.sys was dropped. Silence
  is evidence of absence for this specific driver name.
reads:
- device_hostname
- file_name
- file_path
- time
- activity_id
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(file_name) = 'gdrv.sys' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## launcher-execution-search
<!-- Settra launcher execution -->
Identify the execution of the Settra launcher, which is typically named after the domain name.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes identifying the launcher, user context, and host. Naming a binary
  after a domain string is a specific Settra pattern.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, parent_process_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%_win64.exe' OR LOWER(process_cmd_line) LIKE '%_win64.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-agent
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- byovd-driver-search
- launcher-execution-search
max_iterations: 4
objective: Decide if the combination of gdrv.sys and a domain-named binary indicates
  an active Settra ransomware attempt on any host.
success_criteria: A verdict citing specific hosts and rows where both indicators align.
tools:
- endpoint
```

## follow-on-impact
<!-- Detect follow-on impact and recovery inhibition -->
parallel:
- → anti-recovery-baseline
- → encryption-artifact-search
join: → impact-assessment-agent

## anti-recovery-baseline
<!-- Rare anti-recovery commands -->
Find individual events of recovery inhibition commands that are rare across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts running these commands where the activity is rare across
  the fleet. This allows pinning the behavior to a specific timeline and host identity.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- user_name
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(process_cmd_line) LIKE '%reagentc% /disable%' OR LOWER(process_cmd_line) LIKE '%cipher% /w:%' OR LOWER(process_cmd_line) LIKE '%wevtutil% cl %' OR LOWER(process_cmd_line) LIKE '%diskpart% /s %') AND LOWER(process_cmd_line) IN (SELECT LOWER(process_cmd_line) FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%reagentc% /disable%' OR LOWER(process_cmd_line) LIKE '%cipher% /w:%' OR LOWER(process_cmd_line) LIKE '%wevtutil% cl %' OR LOWER(process_cmd_line) LIKE '%diskpart% /s %') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_cmd_line) HAVING COUNT(DISTINCT device_hostname) < 3)
```

## encryption-artifact-search
<!-- Encrypted files and ransom notes -->
Find the final evidence of encryption by searching for specific file extensions and the ransom note.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Files renamed with .locked or .locked_wip extensions, or the creation of
  RESTORE_FILES.txt.
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
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_name) LIKE '%.locked%' OR LOWER(file_name) = 'restore_files.txt') AND time >= datetime('now', '-{{lookback_days}} days')
```

## impact-assessment-agent
<!-- Final impact assessment -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- anti-recovery-baseline
- encryption-artifact-search
max_iterations: 5
objective: Confirm if any host shows a complete Settra ransomware attack chain, from
  launcher execution and driver drop to recovery inhibition and file encryption.
success_criteria: A final verdict citing specific hosts where early indicators and
  follow-on impacts overlap.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The impact assessment confirms that early-stage indicators (driver or launcher) on a host are followed by successful anti-recovery commands and file encryption." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-telemetry-gap)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the confirmed compromised endpoint immediately to prevent further file encryption. Preserve the system state for forensic analysis; do not reboot unless necessary.
```
→ analyst-review

## analyst-review
<!-- Analyst incident review -->
```manual target=analyst
Review the cited rows for the launcher path and the anti-recovery commands. Verify the extent of the encryption via file system artifacts and check if any recovery partitions were successfully removed.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the hunt findings and visibility gaps. If the launcher execution patterns were consistent, promote the domain-named binary detection to a permanent rule.
```
→ end

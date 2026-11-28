---
analysis: A static rule might flag 'lsassa.exe', but this hunt uses a baseline of
  FTP traffic to find rare exfiltration destinations and correlates that activity
  across scheduled tasks and script blocks, providing context for a two-month dwell
  time.
blind_spots:
- id: telemetry-retention-gap
  question: whether exfiltration happened before the current retention window
  requires: 60-day network and script telemetry retention
  risk: A standard 14-day window misses the day-20 exfiltration event cited in the
    two-month intrusion report.
  stage: exfiltration-rclone-ftp
- id: obfuscated-scripts
  question: whether rclone keywords are hidden by obfuscation
  requires: script deobfuscation in hb_script_activity
  risk: Simple string matching fails if the attacker uses PowerShell character replacement
    or hex encoding for 'rclone'.
  stage: exfiltration-rclone-ftp
coverage:
- stage: persistence-custom-backdoor
  status: covered
  steps:
  - backdoor-process-lead
  - persistence-tasks
- stage: exfiltration-rclone-ftp
  status: covered
  steps:
  - ftp-prevalence
  - exfiltration-scripts
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: initial-access-js-downloader
  status: out_of_scope
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: execution-brute-ratel-loader
  status: out_of_scope
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: discovery-reconnaissance-commands
  status: out_of_scope
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: c2-latrodectus-backconnect
  status: out_of_scope
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: credential-access-unattend-xml
  status: out_of_scope
- reason: 'Belongs to another part of the ''From a Single Click: How Lunar Spider
    Enabled a Near Two-Month Intrusion'' series.'
  stage: lateral-movement-and-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The adversary maintained control for two months and exfiltrated sensitive
    data via FTP. Detecting these late-stage signals provides high-assurance evidence
    of data theft that simple endpoint rules may miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is maintaining long-term access via a masqueraded .NET backdoor
  and exfiltrating data via Rclone over FTP to a rare external destination.
labels:
- hunt
- attack.t1053.005
- attack.t1567.002
- attack.t1048.003
- attack.t1036.005
name: Persistence and Exfiltration of Lunar Spider
parameters:
  backdoor_names:
    default:
    - lsassa.exe
    - lsasss.exe
    - lssas.exe
    description: Filename variations for the masqueraded .NET backdoor.
    from:
      kind: article
      observed: '2024-05-01'
      ref: https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/
    type: list[string]
  exfil_keywords:
    default:
    - rclone.ps1
    - backup_sync.ps1
    - upload.exe
    description: Filenames of scripts used to automate data exfiltration.
    from:
      kind: manual
      observed: '2025-01-01'
      ref: common-ttp
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine; the original intrusion had a two-month
      dwell time.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The intrusion spanned two months; ensure the lookback period covers the
  exfiltration phase (reported around day 20). Focus on file servers and backup servers
  where large volumes of data reside.
references:
- name: "The DFIR Report \u2014 From a Single Click: How Lunar Spider Enabled a Near\
    \ Two-Month Intrusion"
  url: https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/
related:
- hunt: lunar-spider-initial-access
  reason: Initial access via JS and Brute Ratel loading are handled in the first hunt
    of this series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Tax-themed JS Downloader
    observables:
    - Form_W-9_Ver-i40_53b043910-86g91352u7972-6495q3.js
    - 91.194.11.64/MSI.msi
    - disk1.cab
    slug: initial-access-js-downloader
    tactic: initial-access
    techniques:
    - T1566.002
    - T1204.002
  - name: Brute Ratel Loader Execution
    observables:
    - rundll32.exe
    - upfilles.dll
    - stow
    - wscadminui.dll
    - wsca
    slug: execution-brute-ratel-loader
    tactic: execution
    techniques:
    - T1218.011
  - name: Host and Domain Reconnaissance
    observables:
    - ipconfig
    - systeminfo
    - nltest
    - whoami
    - AdFind
    slug: discovery-reconnaissance-commands
    tactic: discovery
    techniques:
    - T1087.002
    - T1082
    - T1016
    - T1033
  - name: Latrodectus and BackConnect C2
    observables:
    - 193.168.143.196
    - explorer.exe
    - DLLHost.exe
    - chcp 65001
    slug: c2-latrodectus-backconnect
    tactic: command-and-control
    techniques:
    - T1055
    - T1071.001
  - name: Answer File Credential Access
    observables:
    - unattend.xml
    slug: credential-access-unattend-xml
    tactic: credential-access
    techniques:
    - T1552.001
  - name: Lateral Movement and Vulnerability Exploitation
    observables:
    - PsExec.exe
    - runas
    - rustscan
    - CVE-2020-1472
    slug: lateral-movement-and-propagation
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1570
    - T1210
  - name: Custom .NET Backdoor Persistence
    observables:
    - lsassa.exe
    - lsassa&&
    slug: persistence-custom-backdoor
    tactic: persistence
    techniques:
    - T1053.005
  - name: Data Exfiltration via Rclone
    observables:
    - rclone
    - FTP
    - port 21
    slug: exfiltration-rclone-ftp
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1048.003
  summary: An intrusion attributed to Lunar Spider began with a tax-themed JavaScript
    loader that deployed Latrodectus and Brute Ratel C4. The actors escalated privileges
    by discovering plaintext credentials in an unattend.xml file and moved laterally
    using PsExec, RDP, and the Zerologon vulnerability. Over a two-month dwell period,
    they maintained persistence via custom .NET backdoors and exfiltrated data using
    Rclone over FTP.
series:
  index: 3
  slug: from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion
  title: 'From a Single Click: How Lunar Spider Enabled a Near Two-Month Intrusion'
  total: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Persistence and Exfiltration of Lunar Spider

This hunt targets the final phases of a multi-month intrusion. It focuses on identifying a custom .NET backdoor masquerading as 'lsassa.exe' and data exfiltration patterns using Rclone and FTP. The hunt identifies persistence via scheduled tasks and uses stack-counting to isolate rare outbound FTP connections, which are then corroborated by script activity.

## backdoor-process-lead
<!-- Masqueraded Backdoor Process Execution -->
Identify the execution of the masqueraded .NET backdoor binary based on its reported filename or suspicious execution path.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, backdoor_names=backdoor_names)
~~~yaml
expected: A process execution with a name like 'lsassa.exe' or a binary running from
  a public user directory. This serves as the primary lead for the persistence phase.
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
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{backdoor_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR (LOWER(process_path) LIKE '%\\users\\public\\%' AND LOWER(process_name) LIKE '%.exe')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Parallel Investigation of Persistence and Exfiltration -->
parallel:
- → persistence-tasks
- → ftp-prevalence
- → exfiltration-scripts
join: → agent-triage

## persistence-tasks
<!-- Scheduled Task Persistence -->
Corroborate the process lead by finding scheduled tasks configured to execute the backdoor binary.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A scheduled job entry pointing to the suspected backdoor path or name, confirming
  long-term persistence.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%lsassa%' OR LOWER(job_cmd_line) LIKE '%\\users\\public\\%' OR LOWER(job_cmd_line) LIKE '%\\programdata\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## ftp-prevalence
<!-- Rare FTP Destination Baseline -->
Detect rare outbound FTP connections that might represent data exfiltration to attacker-controlled infrastructure.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: FTP connections to external IPs seen from very few internal hosts. High
  traffic volume to these rare destinations is a strong indicator of exfiltration.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- traffic_bytes
- time
- dst_endpoint_port
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, SUM(traffic_bytes) AS total_bytes, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = 21 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING host_count <= 2 ORDER BY total_bytes DESC
```

## exfiltration-scripts
<!-- Exfiltration Script Execution -->
Identify the use of Rclone or FTP automation scripts in the environment.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, exfil_keywords=exfil_keywords)
~~~yaml
expected: Script logs containing rclone commands (sync, copy) or filenames specified
  in the exfil_keywords parameter.
reads:
- device_hostname
- script_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-23'
~~~
SELECT device_hostname, script_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%rclone%' OR instr(',' || '{{exfil_keywords}}' || ',', ',' || LOWER(script_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage Persistence and Theft Evidence -->
```agent target=hunter
cite: required
context:
- backdoor-process-lead
- persistence-tasks
- ftp-prevalence
- exfiltration-scripts
max_iterations: 6
objective: Determine if any host shows evidence of both the custom backdoor persistence
  and data exfiltration using Rclone or FTP.
success_criteria: A verdict of malicious, suspicious, or benign for each host found
  in the queries.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route Based on Intrusion Risk -->
if~: "the agent-triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → contain-threat
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: telemetry-retention-gap)
else: → close-out

## contain-threat
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the suspected lsassa.exe binary and any identified script files for forensic analysis.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Analyze the cited script contents and network traffic. Determine the volume of data exfiltrated. Validate if the 'lsassa.exe' binary is a legitimate .NET backdoor. Pivot to earlier stages of the intrusion (Latrodectus, initial access) if a compromise is confirmed.
```
→ end

## close-out
<!-- Hunt Closure -->
```manual target=analyst
Record the evidence of absence if no hits were found. If suspicious activity was found but overturned, update the parameters to reduce false positives.
```
→ end

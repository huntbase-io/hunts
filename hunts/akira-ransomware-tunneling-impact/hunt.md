---
analysis: A single rule on shadow copy deletion may have false positives from backup
  software; this hunt pivots to look for persistence (GOST) and data staging (RClone)
  to confirm malicious intent.
blind_spots:
- id: script-block-logging-disabled
  question: whether shadow copies were deleted via PowerShell
  requires: PowerShell Script Block Logging (Event ID 4104)
  risk: If logging is disabled, the script-based recovery inhibition remains invisible.
  stage: inhibit-recovery-shadow-copy-deletion
- id: egress-filtering-blindness
  question: whether the tunnel connected to a different IP or via a proxy
  requires: hb_network_connection with dst_endpoint_ip
  risk: A tunnel using an unreported IP or chained proxy would be missed by the network
    query.
  stage: gost-tunneling-persistence
coverage:
- stage: gost-tunneling-persistence
  status: covered
  steps:
  - perflogs-host-discovery
  - gost-network-activity
- stage: rclone-data-exfiltration
  status: covered
  steps:
  - rclone-prevalence
- stage: inhibit-recovery-shadow-copy-deletion
  status: covered
  steps:
  - shadow-copy-deletion
- stage: akira-data-encryption
  status: covered
  steps:
  - akira-artifacts
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: rdp-lateral-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: defense-evasion-service-stop
  status: out_of_scope
- reason: 'Belongs to another part of the ''Up a Creek Without a Command Line: Mapping
    an Akira Ransomware Attack'' series.'
  stage: lsass-credential-dumping
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Akira ransomware causes total availability loss; detecting the GOST
    tunnel and RClone exfiltration provides a critical window to prevent encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a beachhead by deploying a GOST tunneling
  tool for persistence and is using RClone for exfiltration, followed by shadow copy
  deletion and Akira ransomware encryption.
labels:
- hunt
- attack.t1572
- attack.t1041
- attack.t1567.002
- attack.t1490
- attack.t1047
- attack.t1059.001
- attack.t1486
- command and control
- credential access
- defense evasion
- exfiltration
- impact
- lateral movement
name: 'Akira Ransomware: GOST Tunneling and Data Impact'
parameters:
  akira_hashes:
    default:
    - 1f1bb322591b6d27fd2946e373d7d2efc2f4e1e66818846060d391600b600fba
    - d00833318a04caa019c6f95dcb3598ad947d405010bfb2f3cbd04530a00bc3a4
    description: Known Akira ransomware and tunnel tool hashes from the report.
    from:
      kind: article
      observed: '2026-10-06'
      ref: huntress-akira-2026
    type: list[hash]
  c2_ips:
    default:
    - 64.227.4.134
    description: GOST tunnel C2 IP address.
    from:
      kind: article
      observed: '2026-10-06'
      ref: huntress-akira-2026
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard-config
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to investigate; leave empty to scan the entire estate.
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
    from: https://www.huntress.com/blog/mapping-akira-ransomware-attack
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should target domain controllers, file servers, and any hosts
  with access to internal network shares.
references:
- name: "Huntress \u2014 Mapping an Akira Ransomware Attack"
  url: https://www.huntress.com/blog/mapping-akira-ransomware-attack
related:
- hunt: akira-initial-access-rdp
  reason: Initial access via RDP is handled by a separate authentication-focused hunt.
  relation: out-of-scope-alternative
- hunt: akira-remote-access-security-disruption
  relation: follows
scenario:
  stages:
  - name: RDP Lateral Access
    observables:
    - Workstation name C1IFRYXI
    - RDP connection from non-customer workstation
    slug: rdp-lateral-access
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Bitdefender Service Disablement
    observables:
    - Bitdefender Endpoint Update Service stopped
    - Bitdefender Endpoint Integration Service stopped
    - Bitdefender Endpoint Protected Service stopped
    - Bitdefender Endpoint Security Service stopped
    slug: defense-evasion-service-stop
    tactic: defense-evasion
  - name: LSASS Credential Dumping
    observables:
    - procdump.exe
    - C:\PerfLogs\procdump.exe
    - lsass.exe dump
    slug: lsass-credential-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: GOST Tunneling Persistence
    observables:
    - C:\PerfLogs\Temp\svchost.exe
    - C:\PerfLogs\Temp\config.dll
    - d00833318a04caa019c6f95dcb3598ad947d405010bfb2f3cbd04530a00bc3a4
    - 64.227.4.134
    slug: gost-tunneling-persistence
    tactic: command-and-control
    techniques:
    - T1572
    - T1041
  - name: RClone Data Exfiltration
    observables:
    - rclone.exe
    - C:\PerfLogs\rclone.exe
    slug: rclone-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Recovery Inhibition via Shadow Copy Deletion
    observables:
    - powershell.exe -Command Get-WmiObject Win32_Shadowcopy | Remove-WmiObject
    slug: inhibit-recovery-shadow-copy-deletion
    tactic: impact
    techniques:
    - T1490
    - T1047
    - T1059.001
  - name: Akira Data Encryption
    observables:
    - win.exe
    - 1f1bb322591b6d27fd2946e373d7d2efc2f4e1e66818846060d391600b600fba
    - Akira log files
    - Shellbags access to Shares folder
    slug: akira-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Akira ransomware affiliates gained access via RDP and disabled Bitdefender
    security services before using Procdump to harvest credentials. The attackers
    established persistence using the GOST tunnel tool and exfiltrated data via RClone
    before executing the Akira ransomware, which deleted volume shadow copies and
    encrypted files.
series:
  index: 2
  slug: up-a-creek-without-a-command-line-mapping-an-akira-ransomware-attack
  title: 'Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Akira Ransomware: GOST Tunneling and Data Impact

This hunt follows the Akira ransomware attack chain as observed by researchers, focusing on the post-compromise stages of persistence and impact. It identifies the deployment of the GOST (Go Simple Tunnel) utility, often disguised as a system process in the PerfLogs directory, and the subsequent execution of RClone for data exfiltration. The hunt then moves to the impact phase, looking for the characteristic PowerShell/WMI commands used to inhibit system recovery by deleting volume shadow copies, and finally identifies Akira ransomware artifacts including specific file hashes and log markers. By using a phased approach, the hunt allows an analyst to see the progression from a persistent tunnel to active data destruction.

## perflogs-host-discovery
<!-- Discovery of activity in PerfLogs -->
Identify hosts where the C:\PerfLogs directory has been touched, which is the primary staging area for Akira tools.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, akira_hashes=akira_hashes)
~~~yaml
expected: A list of hostnames. Any result in C:\PerfLogs or matching report hashes
  is suspicious.
reads:
- device_hostname
- file_hash_sha256
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT DISTINCT device_hostname FROM hb_file_activity WHERE (LOWER(file_path) LIKE 'c:\perflogs\%' OR instr(',' || '{{akira_hashes}}' || ',', ',' || LOWER(file_hash_sha256) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-investigation
<!-- Parallel hunt for persistence and exfiltration -->
parallel:
- → gost-network-activity
- → rclone-prevalence
join: → early-stage-triage

## gost-network-activity
<!-- GOST tunnel network activity -->
Find network connections to known C2 IPs or behavioral indicators like high-port egress from the PerfLogs directory.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound connections from processes in C:\PerfLogs to either reported IPs
  or high ports, confirming the proxy tunnel.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR (LOWER(process_path) LIKE 'c:\perflogs\%' AND dst_endpoint_port > 1024)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rclone-prevalence
<!-- Prevalence of RClone across the fleet -->
Identify hosts where RClone is executing and determine if it is a rare occurrence in the environment.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count showing RClone is only on a few hosts. If it is not a standard
  IT tool, any hit is suspicious.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT LOWER(process_name) AS proc, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%rclone%' OR LOWER(process_cmd_line) LIKE '%rclone%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING hosts <= 3
```

## early-stage-triage
<!-- Early stage persistence triage -->
```agent target=hunter
cite: required
context:
- perflogs-host-discovery
- gost-network-activity
- rclone-prevalence
max_iterations: 3
objective: Confirm whether the adversary established a tunnel and staged data via
  RClone.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing process
  paths and network peers.
tools:
- endpoint
- network
```

## impact-investigation
<!-- Parallel hunt for ransomware impact -->
parallel:
- → shadow-copy-deletion
- → akira-artifacts
join: → full-chain-triage

## shadow-copy-deletion
<!-- Recovery inhibition via shadow copy deletion -->
Identify the specific PowerShell commands used by Akira to delete volume shadow copies.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks matching the shadow copy removal pattern. This is a high-fidelity
  indicator of ransomware impact.
reads:
- actor_user_name
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%win32_shadowcopy%' AND LOWER(script_content) LIKE '%remove-wmiobject%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## akira-artifacts
<!-- Akira file artifacts and logs -->
Locate the ransomware binary and the specific Akira log files created during encryption, focusing on suspect paths.

```sqlite target=endpoint role=triage params=(akira_hashes=akira_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Ransomware arrival evidence (activity_id 1/3) matching win.exe in suspect
  paths or Akira log files.
reads:
- activity_id
- device_hostname
- file_hash_sha256
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, file_name, file_path, file_hash_sha256, time FROM hb_file_activity WHERE (activity_id IN (1, 3)) AND (LOWER(file_name) LIKE 'akira_log%' OR (LOWER(file_name) = 'win.exe' AND (LOWER(file_path) LIKE 'c:\perflogs\%' OR LOWER(file_path) LIKE 'c:\users\public\%')) OR instr(',' || '{{akira_hashes}}' || ',', ',' || LOWER(file_hash_sha256) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## full-chain-triage
<!-- Full scenario impact triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- shadow-copy-deletion
- akira-artifacts
max_iterations: 6
objective: Determine if a host shows the complete progression from GOST persistence
  to shadow copy deletion and ransomware execution.
success_criteria: A final verdict citing specific hosts where the full Akira ransomware
  impact is confirmed.
tools:
- endpoint
- network
```

## route-on-impact
<!-- Route on full scenario verdict -->
if~: "the full-chain-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: script-block-logging-disabled)
else: → closure

## isolate-host
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke any credentials that logged into this host within the lookback window.
```
→ forensic-review

## forensic-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited GOST tunnel process and shadow copy deletion scripts. Check Registry activity for evidence of share traversal to confirm the encryption target.
```
→ closure

## closure
<!-- Hunt closure -->
```manual target=analyst
Record all found Akira artifacts. If the shadow-copy-deletion query was successful, recommend it for a standing detection rule.
```
→ end

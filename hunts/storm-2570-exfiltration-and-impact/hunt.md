---
analysis: A standard rule might alert on rclone, but this hunt correlates process
  execution, attributed aggregate network volume via 5-tuple joins, and file system
  burst activity to provide the high-confidence context required for a critical isolation
  decision.
blind_spots:
- id: no-network-flow-logs
  question: the total volume of data exfiltrated by a specific process
  requires: hb_network_connection flow log provider (state_kind = log)
  risk: A negative result does not prove exfiltration did not occur; it only proves
    it was not seen on the flow surface.
  stage: exfiltration-cloud-storage
- id: low-level-api-encryption
  question: whether encryption is occurring via APIs that bypass standard activity
    logging
  requires: kernel-level file monitor on every host
  risk: Advanced ransomware may use drivers or low-level disk access to encrypt data
    without generating standard file activity rows.
  stage: ransomware-impact
coverage:
- stage: exfiltration-cloud-storage
  status: covered
  steps:
  - exfil-tool-execution
  - high-volume-outbound
- stage: ransomware-impact
  status: covered
  steps:
  - file-impact-indicators
- reason: Handled in a separate hunt focused on MeshAgent and other RMM tools.
  stage: rmm-persistence-and-execution
  status: out_of_scope
- reason: Handled in a separate hunt focused on cloudflared and ngrok.
  stage: c2-protocol-tunneling
  status: out_of_scope
- reason: Handled in a separate hunt focused on NetScan and nmap.
  stage: network-and-file-discovery
  status: out_of_scope
- reason: Handled in a separate hunt focused on ntdsutil and mimikatz.
  stage: credential-dumping-ad
  status: out_of_scope
- reason: Handled in a separate hunt focused on Defender tampering.
  stage: defense-evasion-tampering
  status: out_of_scope
- reason: Handled in a separate hunt focused on PsExec and batch-enabled RDP.
  stage: lateral-movement-psexec-rdp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Data exfiltration and ransomware encryption represent the ultimate
    objective of the Storm-2570 threat actor; a negative result over these stages
    confirms the attack chain was broken early.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is exfiltrating staged directories and Active Directory database
  fragments using synchronization tools before deploying a ransomware payload for
  mass encryption.
labels:
- hunt
- attack.t1041
- attack.t1567.002
- attack.t1486
- attack.t1003.001
- attack.t1021.001
name: Storm-2570 Data Exfiltration and Ransomware Impact
parameters:
  exfil_tools:
    default:
    - rclone.exe
    - s5cmd.exe
    description: Names of exfiltration and synchronization tools.
    from:
      kind: article
      observed: '2026-09-24'
      ref: msrc-blog
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: default-retention
    type: number
  scope_hosts:
    default: []
    description: Limit the hunt to these hostnames; leave empty to hunt across the
      estate.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: analyst-scoping
    type: list[host]
  scope_processes:
    default: []
    description: Limit impact searches to these process names; leave empty for all
      processes.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: analyst-scoping
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on file servers and domain controllers where Storm-2570 frequently
  stages NTDS.dit files and conducts mass encryption.
references:
- name: "Beyond the ransomware: Tracking Storm-2570\u2019s consistent tradecraft across\
    \ deployments"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/
related:
- hunt: storm-2570-rmm-persistence
  reason: This hunt focuses on final impact; initial persistence and RMM usage are
    handled in a preceding hunt.
  relation: out-of-scope-alternative
- hunt: storm-2570-rmm-tunneling-persistence
  relation: follows
scenario:
  stages:
  - name: Persistence via RMM Tooling
    observables:
    - meshagent64.exe
    - AteraAgent.exe
    - Splashtop Streamer
    - NinjaRMM
    - Remotely_Agent
    - MeshAgent-related binaries renamed to victim-themed names like meshagent64-[organization].exe
    - Base64-encoded command execution via RMM
    slug: rmm-persistence-and-execution
    tactic: persistence
    techniques:
    - T1021.006
  - name: Persistent Outbound Tunneling
    observables:
    - Cloudflared.exe installed as a service under LocalSystem
    - ngrok exposing TCP 3389
    - Persistent Cloudflare Tunnel service creation
    slug: c2-protocol-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: Internal Discovery
    observables:
    - NetScan.exe
    - SoftPerfect Network Scanner Portable
    - nmap.exe
    - Native Windows discovery commands for host identification
    slug: network-and-file-discovery
    tactic: discovery
    techniques:
    - T1018
    - T1046
  - name: Active Directory Database Dumping
    observables:
    - ntdsutil.exe
    - ntdsutil 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\'
    - ntds.dit extraction
    - Mimikatz
    - LaZagne
    - pypykatz
    slug: credential-dumping-ad
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  - name: Security Software Tampering
    observables:
    - Microsoft Defender exclusions for C:\PerfLogs
    - Registry value DisableAntiSpyware set to 1
    - Registry value DisableRealtimeMonitoring set to 1
    - Modification of WinDefend service keys
    slug: defense-evasion-tampering
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Lateral Movement and Remote Execution
    observables:
    - PsExec.exe using host lists like @ip.txt
    - rdp.bat enabling RDP access
    - NetExec SMB commands
    - Impacket offensive framework
    - reg add Terminal Server /v fDenyTSConnections /d 0
    - netsh advfirewall firewall add rule name="Remote Desktop" localport=3389
    slug: lateral-movement-psexec-rdp
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1021.002
  - name: Data Staging and Exfiltration
    observables:
    - s5cmd.exe
    - rclone.exe
    - Outbound data transfers to cloud storage providers
    slug: exfiltration-cloud-storage
    tactic: exfiltration
    techniques:
    - T1041
    - T1567.002
  - name: Data Encryption for Impact
    observables:
    - Qilin ransomware
    - DragonForce ransomware
    - Anubis ransomware
    - BERT ransomware
    slug: ransomware-impact
    tactic: impact
    techniques:
    - T1486
  summary: Storm-2570 is a ransomware affiliate that employs a consistent set of RMM
    tools, tunneling utilities, and hands-on-keyboard techniques to deploy payloads
    like Qilin and DragonForce. They prioritize persistent remote access via MeshAgent
    and Cloudflared tunnels before moving to Active Directory credential dumping and
    broad lateral movement using PsExec and RDP.
series:
  index: 3
  slug: beyond-the-ransomware-tracking-storm-2570-s-consistent-tradecraft-across-deployments
  title: "Beyond the ransomware: Tracking Storm-2570\u2019s consistent tradecraft\
    \ across deployments"
  total: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Storm-2570 Data Exfiltration and Ransomware Impact

This hunt targets the final, high-impact stages of a Storm-2570 intrusion. It first identifies the execution of exfiltration tools, the staging of the NTDS database, and the use of RDP enablement scripts. It then attributes large network outbound transfers to specific processes by joining endpoint socket states with network flow logs. Finally, it corroborates these signals with rapid file modification bursts to identify active ransomware events.

## exfil-tool-execution
<!-- Exfiltration tool and staging activity -->
Find the launch of synchronization tools or commands that stage the Active Directory database and RDP enablement scripts.

```sqlite target=endpoint role=triage params=(exfil_tools=exfil_tools, lookback_days=lookback_days)
~~~yaml
expected: Hits identify the host, user, and specific staging or exfiltration tool
  used. Silence means no known synchronization or database staging binaries were seen.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%rclone%' OR LOWER(process_cmd_line) LIKE '%s5cmd%' OR LOWER(process_cmd_line) LIKE '%rdp.bat%' OR LOWER(process_cmd_line) LIKE '%ntds.dit%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## correlate-impact
<!-- Correlate exfiltration and impact -->
parallel:
- → high-volume-outbound
- → file-impact-indicators
join: → triage-impact

## high-volume-outbound
<!-- High volume outbound traffic -->
Attribute network transfer volume to specific processes by joining endpoint socket states with flow logs.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A hit shows a process that has transferred over 100MB of data. Correlate
  these results with the exfiltration tools found in the lead query.
reads:
- device_hostname
- process_name
- traffic_bytes
- state_kind
- direction
- src_endpoint_ip
- src_endpoint_port
- dst_endpoint_ip
- dst_endpoint_port
- protocol
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT e.device_hostname, e.process_name, SUM(f.traffic_bytes) AS total_bytes_sent FROM hb_network_connection e JOIN hb_network_connection f ON e.src_endpoint_ip = f.src_endpoint_ip AND e.src_endpoint_port = f.src_endpoint_port AND e.dst_endpoint_ip = f.dst_endpoint_ip AND e.dst_endpoint_port = f.dst_endpoint_port AND e.protocol = f.protocol WHERE e.state_kind = 'live' AND f.state_kind = 'log' AND f.direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || e.device_hostname || ',') > 0) AND f.time >= datetime('now', '-{{lookback_days}} days') GROUP BY e.device_hostname, e.process_name HAVING total_bytes_sent > 104857600
```

## file-impact-indicators
<!-- Ransomware file activity bursts -->
Identify processes that are performing mass file creations, modifications, or renames on the target hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, scope_processes=scope_processes)
~~~yaml
expected: A hit shows a process modifying or renaming hundreds of files in a short
  window. This is the primary indicator of encryption.
reads:
- device_hostname
- process_name
- activity_id
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, activity_name, COUNT(*) AS event_count, MIN(time) AS start_time, MAX(time) AS end_time FROM hb_file_activity WHERE activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_processes}}' = '' OR instr(',' || '{{scope_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, activity_name HAVING event_count > 500
```

## triage-impact
<!-- Evaluate impact and exfiltration -->
```agent target=hunter
cite: required
context:
- exfil-tool-execution
- high-volume-outbound
- file-impact-indicators
max_iterations: 4
objective: Determine if any host is exhibiting the combined indicators of exfiltration
  (high network volume from synchronization tools) and encryption (mass file modification
  bursts).
success_criteria: A structured per-host verdict of malicious, suspicious, or benign
  citing process names and network metrics.
tools:
- endpoint
- network
```

## route-on-impact
<!-- Route on impact verdict -->
if~: "the agent determines malicious ransomware encryption is occurring on at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-network-flow-logs)
else: → manual-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately after confirming malicious file encryption activity. Collect the binaries identified in the triage step.
```
→ manual-review

## manual-review
<!-- Review suspicious impact evidence -->
```manual target=analyst
Review hosts with suspicious network volume or file event counts. Confirm if the associated process matches a known backup or development workflow.
```
→ remediation-cleanup

## remediation-cleanup
<!-- Remediation and evidence capture -->
```manual target=analyst
For isolated hosts, capture the ransomware binary and check for extensions matching Qilin, DragonForce, Anubis, or BERT. Document the exfiltration staging path.
```
→ end

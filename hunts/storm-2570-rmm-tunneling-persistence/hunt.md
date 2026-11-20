---
analysis: While single rules may fire on 'ngrok.exe', this hunt pivots between inventory,
  renamed binary execution (via original file name), and network outbound traffic
  to distinguish attacker activity from legitimate IT administration.
blind_spots:
- id: incomplete-telemetry
  question: Are there hosts in the estate not reporting software inventory or process
    events?
  requires: Complete endpoint agent coverage
  risk: An intruder could establish persistence on an unmanaged server that remains
    invisible to this hunt.
  stage: rmm-persistence-and-execution
- id: ephemeral-processes
  question: Did discovery tools run and terminate between snapshot intervals?
  requires: High-fidelity process event stream
  risk: Short-lived scanning activity like Nmap might be missed if the data source
    only provides point-in-time snapshots.
  stage: network-and-file-discovery
coverage:
- stage: rmm-persistence-and-execution
  status: covered
  steps:
  - scoping-rmm-inventory
  - rmm-execution-activity
- stage: c2-protocol-tunneling
  status: covered
  steps:
  - tunnel-and-discovery-network
- stage: network-and-file-discovery
  status: covered
  steps:
  - tunnel-and-discovery-network
- reason: "Belongs to another part of the 'Beyond the ransomware: Tracking Storm-2570\u2019\
    s consistent tradecraft across deployments' series."
  stage: credential-dumping-ad
  status: out_of_scope
- reason: "Belongs to another part of the 'Beyond the ransomware: Tracking Storm-2570\u2019\
    s consistent tradecraft across deployments' series."
  stage: defense-evasion-tampering
  status: out_of_scope
- reason: "Belongs to another part of the 'Beyond the ransomware: Tracking Storm-2570\u2019\
    s consistent tradecraft across deployments' series."
  stage: lateral-movement-psexec-rdp
  status: out_of_scope
- reason: "Belongs to another part of the 'Beyond the ransomware: Tracking Storm-2570\u2019\
    s consistent tradecraft across deployments' series."
  stage: exfiltration-cloud-storage
  status: out_of_scope
- reason: "Belongs to another part of the 'Beyond the ransomware: Tracking Storm-2570\u2019\
    s consistent tradecraft across deployments' series."
  stage: ransomware-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Storm-2570 moves quickly from establishing remote access to ransomware
    deployment. Detecting their persistent bridges early is the most effective way
    to disrupt the chain before data encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established redundant persistent access using commercial
  RMM tools and outbound tunneling utilities to bypass firewalls and conduct internal
  reconnaissance.
labels:
- hunt
- attack.t1021.006
- attack.t1572
- attack.t1018
- attack.t1046
name: Storm-2570 Persistent Remote Access and Discovery
parameters:
  lookback_days:
    default: '14'
    description: Days of activity history to examine.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: standard-lookback
    type: number
  rmm_tools:
    default:
    - ateraagent.exe
    - remotely_agent.exe
    - ninjarmm.exe
    - splashtop.exe
    - screenconnect.exe
    - meshagent64.exe
    description: Known RMM tool binary names mentioned in the Storm-2570 research.
    from:
      kind: article
      observed: '2026-09-24'
      ref: msrc-blog-storm-2570
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames to focus the search; leave empty to run across
      the whole estate.
    from:
      kind: manual
      observed: '2026-09-24'
      ref: scoping-input
    type: list[host]
  tunnel_discovery_tools:
    default:
    - cloudflared.exe
    - ngrok.exe
    - netscan.exe
    - nmap.exe
    - netexec.exe
    description: Outbound tunneling and internal network discovery tools used by the
      actor.
    from:
      kind: article
      observed: '2026-09-24'
      ref: msrc-blog-storm-2570
    type: list[string]
  tunnel_endpoints:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - trycloudflare.com
    - ngrok-free.app
    description: Common domains associated with tunneling services.
    from:
      kind: article
      observed: '2026-09-24'
      ref: msrc-blog-storm-2570
    type: list[domain]
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
rationale: Focus on servers and admin jump hosts where unauthorized RMM tools would
  have the highest impact. Use the inventory query to narrow down hosts with known
  RMM software first to prioritize analysis.
references:
- name: "Beyond the ransomware: Tracking Storm-2570\u2019s consistent tradecraft across\
    \ deployments"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/
related:
- hunt: storm-2570-lateral-movement-psexec
  reason: This hunt focuses on persistence and discovery; a follow-on hunt is required
    for PsExec and RDP movement.
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
  index: 1
  slug: beyond-the-ransomware-tracking-storm-2570-s-consistent-tradecraft-across-deployments
  title: "Beyond the ransomware: Tracking Storm-2570\u2019s consistent tradecraft\
    \ across deployments"
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


# Storm-2570 Persistent Remote Access and Discovery

Storm-2570 (a ransomware affiliate for Qilin and BERT) consistently establishes redundant backdoors using remote monitoring and management tools like MeshAgent and Atera. They often rename these tools to blend into the environment and pair them with tunneling utilities like Cloudflared to create encrypted outbound channels. This hunt identifies the installation and execution of these persistent agents and correlates their presence with network activity targeting known tunnel endpoints or internal scanning patterns.

## scoping-rmm-inventory
<!-- Inventory of RMM Software -->
Identify hosts with installed RMM software mentioned in the report to focus the behavioral search.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts that have these management tools installed. Silence means
  none of the specific named packages are present in the current inventory.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT DISTINCT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%atera%' OR LOWER(package_name) LIKE '%meshagent%' OR LOWER(package_name) LIKE '%splashtop%' OR LOWER(package_name) LIKE '%ninja%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-corroboration
<!-- Corroborate on process and network surfaces -->
parallel:
- → rmm-execution-activity
- → tunnel-and-discovery-network
join: → storm-2570-triage

## rmm-execution-activity
<!-- Execution of RMM Tools -->
Find the execution of RMM agents, specifically identifying renamed binaries using the original filename and path-insensitive matching.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, rmm_tools=rmm_tools, lookback_days=lookback_days)
~~~yaml
expected: Processes executing RMM binaries regardless of path or file renaming. Silence
  proves absence of these agents executing during the window.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(replace(process_name, rtrim(process_name, replace(process_name, '\', '')), '')) || ',') > 0 OR LOWER(process_name) LIKE '%meshagent%' OR LOWER(process_name) LIKE '%ateraagent%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## tunnel-and-discovery-network
<!-- Tunnel and Discovery Network Footprint -->
Identify network connections from tunneling or discovery tools, specifically highlighting outbound traffic to tunnel providers or internal scanners.

```sqlite target=network role=baseline params=(tunnel_discovery_tools=tunnel_discovery_tools, tunnel_endpoints=tunnel_endpoints, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Outbound connections to tunnel services or unusual internal RDP traffic.
  Silence means no such connections were logged.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_hostname
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-25'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_port, COUNT(*) AS conn_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (instr(',' || '{{tunnel_discovery_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{tunnel_endpoints}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR (dst_endpoint_port = 3389 AND direction = 'outbound')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_port
```

## storm-2570-triage
<!-- Triage Storm-2570 Activity -->
```agent target=hunter
cite: required
context:
- rmm-execution-activity
- tunnel-and-discovery-network
max_iterations: 4
objective: Determine if any host is running unauthorized RMM tools or tunneling utilities
  that match the Storm-2570 pattern of persistent remote access and discovery, correlating
  the presence of a binary with its outbound network footprint.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing the
  relevant process and network rows.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Verdict Decision -->
if~: "the triage verdict is malicious for at least one host based on correlated RMM execution and tunnel traffic" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → manual-forensic-review
unavailable: → manual-forensic-review (blind_spot: incomplete-telemetry)
else: → hunt-close-out

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active sessions for the users observed running the unauthorized tools.
```
→ manual-forensic-review

## manual-forensic-review
<!-- Manual Forensic Review -->
```manual target=analyst
Examine the file system for the RMM binary and its configuration directory. Review authentication logs to determine which account installed the agent and if lateral movement occurred.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the findings. If benign RMM tools were found, add them to an exclusion list for future runs. Document any unmanaged assets discovered during the scoping phase.
```
→ end

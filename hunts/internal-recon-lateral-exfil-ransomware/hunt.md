---
analysis: "A single detection rule might fire on 'adfind.exe'. This hunt instead looks\
  \ for a cluster of signals: rare server authentication followed by reconnaissance\
  \ binaries with specific flags, and finally outbound FTP activity \u2014 identifying\
  \ a coherent adversary narrative that isolated rules cannot capture."
blind_spots:
- id: missing-endpoint-telemetry
  question: Are there unmanaged servers where reconnaissance tools are running without
    detection?
  requires: Endpoint agent coverage on all servers
  risk: A compromised unmanaged server can scan the network or perform AD queries
    without triggering process-level alerts.
  stage: discovery-and-reconnaissance
- id: ftp-encryption-blind-spot
  question: Is data being exfiltrated via SFTP or HTTPS instead of unencrypted FTP?
  requires: TLS decryption or high-fidelity proxy logs
  risk: If the adversary switches from port 21 to port 443 or 22, the network query
    will miss the traffic unless the exfiltration tool binary (WinSCP) is caught by
    process monitoring.
  stage: collection-and-exfiltration
coverage:
- stage: discovery-and-reconnaissance
  status: covered
  steps:
  - discovery-tool-execution
- stage: lateral-movement-and-credentials
  status: covered
  steps:
  - rare-rdp-server-logons
- stage: collection-and-exfiltration
  status: covered
  steps:
  - ftp-exfiltration-traffic
- stage: betruger-backdoor-deployment
  status: covered
  steps:
  - loader-child-processes
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: initial-access-masquerading-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: sectoprat-execution-and-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: persistence-and-privilege-escalation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: systembc-proxy-tunnel
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Ransomware affiliates typically move from initial access to domain-wide
    compromise within hours. Detecting the reconnaissance and lateral movement phase
    is the final opportunity to prevent enterprise-wide encryption and data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is performing Active Directory discovery, moving laterally
  via RDP with high-privilege accounts, and staging data for exfiltration over unencrypted
  FTP.
labels:
- hunt
- attack.t1087.002
- attack.t1482
- attack.t1018
- attack.t1046
- attack.t1021.001
- attack.t1021.002
- attack.t1003.006
- attack.t1560.001
- attack.t1048.003
- attack.t1105
name: Internal Recon, Lateral Movement, and Exfiltration
parameters:
  exfil_binaries:
    default:
    - winrar.exe
    - rar.exe
    - winscp.exe
    description: Tools used for compression and exfiltration.
    from:
      kind: article
      observed: '2025-09-08'
      ref: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  recon_binaries:
    default:
    - adfind.exe
    - sharphound.exe
    - netscan.exe
    - gt_net.exe
    - nltest.exe
    - ipconfig.exe
    description: Common discovery and reconnaissance tools named in the report.
    from:
      kind: article
      observed: '2025-09-08'
      ref: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on (e.g., Domain Controllers,
      Backup Servers).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: 'Focus on high-value targets: Domain Controllers, Backup Servers (Veeam),
  and File Servers. The initial query finds Windows servers specifically, but the
  analyst can paste any suspect hostnames into the scope_hosts parameter.'
references:
- name: "The DFIR Report \u2014 Blurring the Lines: Intrusion Shows Connection With\
    \ Three Major Ransomware Gangs"
  url: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
related:
- hunt: initial-access-masquerading-installer
  reason: This hunt examines the post-exploitation actions taken after the masquerading
    installer establishes the initial beachhead.
  relation: follows
scenario:
  stages:
  - name: Masqueraded Software Installer
    observables:
    - EarthTime.exe
    - Brave Pragmatic Network Technology Co., Ltd. (revoked certificate)
    slug: initial-access-masquerading-installer
    tactic: initial-access
    techniques:
    - T1036.005
    - T1204.002
  - name: SectopRAT Injected Execution
    observables:
    - cmd.exe spawning MSBuild.exe from Downloads folder
    - MSBuild.exe with no command-line arguments
    - 45.141.87.55 on ports 9000 and 15647
    - Pastebin connection for C2 configuration
    slug: sectoprat-execution-and-c2
    tactic: execution
    techniques:
    - T1059.003
    - T1127.001
    - T1055
  - name: Account Creation and Startup Persistence
    observables:
    - Shortcut in Startup folder
    - New local account with administrative privileges
    - net user and net localgroup commands
    slug: persistence-and-privilege-escalation
    tactic: persistence
    techniques:
    - T1547.001
    - T1136.001
  - name: SystemBC Proxy Deployment
    observables:
    - C:\Users\Public\Music\WakeWordEngine.dll
    - C:\Users\Public\Music\conhost.dll
    - rundll32.exe WakeWordEngine.dll, Reset
    - 149.28.101.219:443
    slug: systembc-proxy-tunnel
    tactic: command-and-control
    techniques:
    - T1090
    - T1218.011
  - name: Domain and Host Discovery
    observables:
    - AdFind for AD queries
    - SharpHound for directory mapping
    - SoftPerfect NetScan
    - Grixba (GT_NET.exe)
    - ipconfig
    - nltest
    slug: discovery-and-reconnaissance
    tactic: discovery
    techniques:
    - T1087.002
    - T1482
    - T1018
    - T1046
  - name: RDP Movement and Credential Harvesting
    observables:
    - RDP using new local account or built-in Administrator
    - wmiexec enumeration
    - PsExec to execute SystemBC as SYSTEM
    - DCSync attack against Domain Controller
    - PowerShell script for Veeam credentials
    slug: lateral-movement-and-credentials
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1021.002
    - T1003.006
  - name: Data Staging and FTP Exfiltration
    observables:
    - WinRAR archives of file shares
    - WinSCP transferring data to cloud host via FTP
    slug: collection-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1560.001
    - T1048.003
  - name: Secondary Backdoor Access
    observables:
    - Betruger backdoor payload spawned by SectopRAT
    slug: betruger-backdoor-deployment
    tactic: command-and-control
    techniques:
    - T1105
  summary: A threat actor used a masqueraded EarthTime installer to deploy SectopRAT
    and SystemBC, establishing a proxy tunnel to facilitate domain reconnaissance
    and lateral movement via RDP. After harvesting credentials and archives from file
    shares using tools like Grixba and AdFind, the actor exfiltrated sensitive data
    via WinSCP before deploying a secondary Betruger backdoor.
series:
  index: 2
  slug: blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs
  title: 'Blurring the Lines: Intrusion Shows Connection With Three Major Ransomware
    Gangs'
  total: 2
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Internal Recon, Lateral Movement, and Exfiltration

This hunt targets the post-exploitation lifecycle of a ransomware affiliate who pivots from an initial beachhead to domain-wide control. It focuses on identifying reconnaissance tools (AdFind, SharpHound, Grixba), rare RDP authentication patterns involving servers, and the final data exfiltration phase using WinSCP or WinRAR over FTP. By correlating these independent signals across process, authentication, and network surfaces, we identify the transition from single-host compromise to enterprise-wide risk. The hunt specifically seeks to identify secondary payloads (like Betruger) that exhibit fileless characteristics and the use of legitimate administration tools for malicious discovery.

## scope-windows-servers
<!-- Scope to Windows Servers -->
Identify Windows servers which serve as primary targets for lateral movement and data staging.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames representing servers. Narrowing to servers reduces noise
  from user-driven recon activity on workstations.
reads:
- hostname
- os_name
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname as device_hostname, os_name, platform FROM hb_devices WHERE platform = 'windows' AND (LOWER(os_name) LIKE '%server%' OR LOWER(hostname) LIKE '%dc%' OR LOWER(hostname) LIKE '%fs%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence-gathering
<!-- Parallel evidence gathering -->
parallel:
- → discovery-tool-execution
- → rare-rdp-server-logons
- → ftp-exfiltration-traffic
- → loader-child-processes
join: → triage-narrative

## discovery-tool-execution
<!-- Discovery tool execution -->
Identify known reconnaissance binaries or command-line patterns used to map AD or the network.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, recon_binaries=recon_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of AdFind (even renamed, via flags like -f or -gcb), SharpHound,
  or Grixba. Focus on high-value targets like Domain Controllers.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{recon_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '% -f %' OR LOWER(process_cmd_line) LIKE '% -gcb %' OR LOWER(process_cmd_line) LIKE '%adfind%' OR LOWER(process_cmd_line) LIKE '%sharphound%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-rdp-server-logons
<!-- Rare RDP server logons -->
Identify rare source-destination RDP logon pairs that may indicate lateral movement using legitimate or newly created credentials.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A successful logon to a server from an unusual source IP or a newly created
  user. Case-insensitive matching ensures reliable scoping and grouping.
prevalence:
  by: target_host
  key:
  - user
  - src_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_name
- actor_user_name
- src_endpoint_ip
- metadata_product
- activity_id
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(dst_endpoint_name) as target_host, LOWER(actor_user_name) as user, src_endpoint_ip, COUNT(*) as logon_count, MIN(time) as first_seen FROM hb_auth_signin WHERE metadata_product = 'windows' AND activity_id = 1 AND status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING logon_count <= 3 ORDER BY logon_count ASC
```

## ftp-exfiltration-traffic
<!-- FTP exfiltration traffic -->
Find evidence of data exfiltration over unencrypted FTP, potentially involving archive tools like WinRAR or transfer tools like WinSCP.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, exfil_binaries=exfil_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound connections on port 21 originating from servers, or network activity
  associated with WinSCP or WinRAR.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (dst_endpoint_port = 21 OR instr(',' || '{{exfil_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## loader-child-processes
<!-- Loader child processes -->
Identify secondary payloads like Betruger being spawned by known injection targets like MSBuild or Rundll32, focusing on fileless execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Fileless child processes (on_disk = 0) of MSBuild or Rundll32. This specifically
  targets the injection and deployment of the Betruger backdoor.
reads:
- device_hostname
- process_name
- parent_process_name
- process_cmd_line
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, on_disk, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%msbuild.exe' OR LOWER(parent_process_name) LIKE '%rundll32.exe') AND on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-narrative
<!-- Triage the ransomware chain -->
```agent target=hunter
cite: required
context:
- discovery-tool-execution
- rare-rdp-server-logons
- ftp-exfiltration-traffic
- loader-child-processes
max_iterations: 4
objective: Determine if any host exhibits a combination of discovery tool execution
  (like AdFind or SharpHound), rare RDP logon, and exfiltration activity, indicating
  a ransomware affiliate operation.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows that connect the discovery, lateral movement, and exfiltration stages.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host, specifically showing a temporal link between recon activity, rare logons, and outbound FTP/C2 connections." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → analyst-close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host and revoke any credentials (especially local admin or Veeam accounts) identified in the logs.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the cited evidence for the cluster of reconnaissance, RDP movement, and data staging. If confirmed, activate the ransomware response playbook.
```
→ analyst-close-out

## analyst-close-out
<!-- Analyst close out -->
```manual target=analyst
Document the investigation outcome. If the results were false positives, refine the RDP baseline by excluding expected maintenance windows or known administrative source IPs.
```
→ end

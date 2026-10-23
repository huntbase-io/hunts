---
analysis: This hunt pivots from the specific SystemBC staging path in Public Music
  to the network egress plane. It requires an analyst to correlate suspicious process
  execution with outbound traffic to verify exfiltration.
blind_spots:
- id: incomplete-network-telemetry
  question: whether SystemBC is using port 443 with domain-based C2 that bypasses
    IP filters
  requires: Full network flow logs or decrypted TLS visibility
  risk: Connections to cloud providers might look like legitimate traffic if they
    avoid the reported IPs.
  stage: command-and-control
- id: short-lived-exfiltration
  question: whether WinSCP was used and closed between polling intervals
  requires: Process-attributed network socket logging
  risk: A quick exfiltration event may not be captured by point-in-time snapshot surfaces.
  stage: collection-and-exfiltration
coverage:
- stage: collection-and-exfiltration
  status: covered
  steps:
  - exfiltration-activity
- stage: command-and-control
  status: covered
  steps:
  - systembc-execution
  - c2-infrastructure-connections
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: initial-access-trojanized-installer
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: execution-sectoprat-injection
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: persistence-mechanisms
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: credential-access-and-privilege-escalation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: discovery-internal-reconnaissance
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: lateral-movement
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: defense-evasion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SystemBC and WinSCP-based exfiltration are signature behaviors of
    this ransomware affiliate. Identifying these egress patterns is critical to preventing
    data loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using SystemBC for proxy tunneling and WinSCP for unencrypted
  FTP exfiltration from the Public Music directory to known ransomware affiliate infrastructure.
labels:
- hunt
- attack.t1090.003
- attack.t1105
- attack.t1560.001
- attack.t1048.003
name: SystemBC C2 and WinSCP Exfiltration
parameters:
  c2_ips:
    default:
    - 45.141.87.55
    - 149.28.101.219
    description: C2 infrastructure IPs associated with SystemBC and SectopRAT.
    from:
      kind: article
      observed: '2025-09-08'
      ref: dfir-report-2025-09-08
    type: list[ip]
  infected_hosts:
    default: []
    description: Hostnames identified as compromised in the first step; filter network
      queries to these systems.
    type: list[host]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
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
rationale: Focus on file servers and domain controllers where SystemBC was observed
  in the source article. Prioritize hosts with external network egress capabilities.
references:
- name: 'DFIR Report: Blurring the Lines'
  url: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
related:
- hunt: winrar-staging-behavior
  reason: WinRAR archiving of file shares is a precursor to exfiltration that requires
    hb_file_activity monitoring.
  relation: out-of-scope-alternative
- hunt: identity-based-lateral-movement-and-credential-access
  relation: follows
scenario:
  stages:
  - name: Trojanized EarthTime Installer
    observables:
    - EarthTime.exe from Downloads folder
    - Brave Pragmatic Network Technology Co., Ltd. revoked certificate
    - GlobalSign GCC R45 EV CodeSigning CA 2020
    slug: initial-access-trojanized-installer
    tactic: initial-access
    techniques:
    - T1204.002
    - T1036.005
  - name: SectopRAT Injection and C2 Fetch
    observables:
    - EarthTime.exe spawning cmd.exe spawning MSBuild.exe with no arguments
    - Process injection into MSBuild.exe
    - Pastebin connection for C2 configuration
    slug: execution-sectoprat-injection
    tactic: execution
    techniques:
    - T1059.003
    - T1127.001
    - T1055
  - name: Startup Shortcut and Local Account Creation
    observables:
    - Shortcut (.lnk) created in %AppData%\Microsoft\Windows\Start Menu\Programs\Startup
    - Creation of a new local account with administrative privileges
    slug: persistence-mechanisms
    tactic: persistence
    techniques:
    - T1547.001
    - T1136.001
  - name: DCSync and Veeam Credential Harvesting
    observables:
    - DCSync attack against Domain Controller
    - PowerShell script executed on backup server to retrieve Veeam credentials
    slug: credential-access-and-privilege-escalation
    tactic: credential-access
    techniques:
    - T1484.002
    - T1003.006
    - T1059.001
  - name: Internal Discovery Tool Deployment
    observables:
    - AdFind.exe
    - SharpHound.exe
    - netscan.exe (SoftPerfect)
    - GT_NET.exe (Grixba)
    - ipconfig
    - nltest
    slug: discovery-internal-reconnaissance
    tactic: discovery
    techniques:
    - T1087
    - T1482
    - T1018
    - T1046
  - name: Lateral Movement via RDP and PsExec
    observables:
    - RDP connections (port 3389) using created local account and built-in Administrator
    - PsExec used to execute SystemBC on remote hosts
    - wmiexec used for remote reconnaissance commands
    slug: lateral-movement
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1570
    - T1021.002
  - name: WinRAR Staging and WinSCP Exfiltration
    observables:
    - WinRAR archiving file shares
    - WinSCP transferring archives to cloud host via unencrypted FTP
    slug: collection-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1560.001
    - T1048.003
  - name: SystemBC and Betruger C2 Infrastructure
    observables:
    - WakeWordEngine.dll or conhost.dll (SystemBC) in C:\Users\Public\Music\
    - rundll32.exe calling exported Reset function
    - Betruger backdoor deployment
    - 'C2 IPs: 45.141.87.55 (9000, 15647) and 149.28.101.219 (443)'
    slug: command-and-control
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1105
  - name: Security Tampering and Masquerading
    observables:
    - Disabling Microsoft Defender protections
    - Binaries with spoofed metadata (SentinelOne, Avast)
    - Timestomping activities
    - Use of C:\Users\Public\Music\ as staging directory
    slug: defense-evasion
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1027
    - T1036
  summary: An affiliate threat actor likely linked to multiple ransomware groups used
    a trojanized version of the EarthTime application to deploy SectopRAT and SystemBC.
    They performed extensive internal discovery with tools like AdFind and Grixba,
    moved laterally via RDP and PsExec, and ultimately archived and exfiltrated sensitive
    data via WinSCP over clear-text FTP.
series:
  index: 3
  slug: blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs
  title: 'Blurring the Lines: Intrusion Shows Connection With Three Major Ransomware
    Gangs'
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


# SystemBC C2 and WinSCP Exfiltration

This hunt targets the command-and-control and exfiltration phases of a ransomware affiliate operation. It identifies the execution of SystemBC payloads from the Public Music directory. It then fans out to inspect network connections for both hardcoded C2 infrastructure and unencrypted FTP activity. By correlating process execution with egress traffic, we identify the specific hosts serving as exfiltration beachheads.

## systembc-execution
<!-- SystemBC DLL Execution via Rundll32 -->
Find instances of SystemBC being launched from the Public Music directory, which is the primary staging marker for this affiliate.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A rundll32 process calling the Reset export on a DLL in the Music folder.
  This is a high-fidelity indicator of SystemBC execution.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%\users\public\music\%' AND LOWER(process_cmd_line) LIKE '%rundll32%' AND LOWER(process_cmd_line) LIKE '%reset%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## network-fan-out
<!-- Examine Network Egress -->
parallel:
- → c2-infrastructure-connections
- → exfiltration-activity
join: → triage-c2-and-exfil

## c2-infrastructure-connections
<!-- SystemBC and SectopRAT C2 Connections -->
Verify that C2 traffic to known infrastructure is originating from the compromised hosts found in the lead step.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, infected_hosts=infected_hosts)
~~~yaml
expected: Direct outbound connections to 45.141.87.55 or 149.28.101.219 from hosts
  running SystemBC.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{infected_hosts}}' = '' OR instr(',' || '{{infected_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exfiltration-activity
<!-- Unencrypted FTP and WinSCP Activity -->
Attribute potential data theft to the same systems running SystemBC by looking for unencrypted FTP or WinSCP egress.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, infected_hosts=infected_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections on port 21 or from the winscp.exe process. Silence means no
  unencrypted exfiltration was seen on these ports.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_port = 21 OR LOWER(process_name) LIKE '%winscp%') AND ('{{infected_hosts}}' = '' OR instr(',' || '{{infected_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip
```

## triage-c2-and-exfil
<!-- Triage C2 and Exfiltration Evidence -->
```agent target=hunter
cite: required
context:
- systembc-execution
- c2-infrastructure-connections
- exfiltration-activity
max_iterations: 4
objective: Evaluate whether the combination of SystemBC staging in Public Music and
  outbound connections confirm an active compromise.
success_criteria: Verdicts for every host found in the queries.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage-c2-and-exfil verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-collection
unavailable: → forensic-collection (blind_spot: incomplete-network-telemetry)
else: → hunt-closure

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Stop the rundll32 processes identified as SystemBC. Secure the Public Music folder for forensic analysis.
```
→ forensic-collection

## forensic-collection
<!-- Collect Forensic Evidence -->
```manual target=analyst
Collect WakeWordEngine.dll and conhost.dll from the Public Music folder. Export WinSCP connection logs and WinRAR temporary staging directories if found.
```
→ hunt-closure

## hunt-closure
<!-- Hunt Closure and Reporting -->
```manual target=analyst
Record the findings. If SystemBC staging was detected but no network traffic was observed, increase monitoring on those hosts for lateral movement.
```
→ end

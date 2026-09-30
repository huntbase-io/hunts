---
analysis: A simple rule for AdFind or MSBuild will generate noise; this hunt correlates
  the initial trojan execution (EarthTime) with the MSBuild injection anomaly and
  the subsequent rare discovery tool execution across the fleet, providing context
  that a single rule lacks.
blind_spots:
- id: limited-endpoint-telemetry
  question: whether the revoked certificate was checked by the local OS
  requires: detailed certificate validation logs on the endpoint
  risk: We might miss attempts where the installer failed to run because of certificate
    revocation, but the host is still being targeted.
  stage: initial-access-trojanized-installer
- id: process-injection-visibility
  question: whether the MSBuild process has SectopRAT resident in memory
  requires: hb_module_activity with in-memory YARA scan capability
  risk: Relying on command-line anomalies for MSBuild might miss later versions that
    use different injection vectors.
  stage: execution-sectoprat-injection
coverage:
- stage: initial-access-trojanized-installer
  status: covered
  steps:
  - earthtime-scoping
- stage: execution-sectoprat-injection
  status: covered
  steps:
  - msbuild-anomaly
  - c2-connections
- stage: persistence-mechanisms
  status: covered
  steps:
  - persistence-and-staging
- stage: discovery-internal-reconnaissance
  status: covered
  steps:
  - discovery-prevalence
- stage: defense-evasion
  status: covered
  steps:
  - defender-tampering
  - persistence-and-staging
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: credential-access-and-privilege-escalation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: lateral-movement
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: collection-and-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: command-and-control
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The presence of ransomware-linked tools like Grixba and AdFind following
    a trojanized installer execution indicates a high risk of imminent ransomware
    deployment. Detecting this early stage is critical to preventing the final impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via a trojanized EarthTime installer,
  established a beachhead using SectopRAT with MSBuild injection, and is now performing
  environment discovery using specialized ransomware reconnaissance tools.
labels:
- hunt
- attack.t1204.002
- attack.t1036.005
- attack.t1127.001
- attack.t1055
- attack.t1547.001
- attack.t1087
- attack.t1482
- attack.t1562.001
name: EarthTime Trojan to Ransomware Reconnaissance
parameters:
  c2_ips:
    default:
    - 45.141.87.55
    - 149.28.101.219
    description: Known SectopRAT and SystemBC C2 infrastructure.
    from:
      kind: article
      observed: '2025-09-08'
      ref: dfir-report
    type: list[ip]
  discovery_tools:
    default:
    - adfind.exe
    - sharphound.exe
    - netscan.exe
    - gt_net.exe
    description: Reconnaissance tools used by ransomware affiliates.
    from:
      kind: article
      observed: '2025-09-08'
      ref: dfir-report
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Target hosts for follow-on queries; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2025-01-01'
      ref: hunt-standard
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially focus on workstations where EarthTime.exe would
  likely be downloaded, then expand to domain controllers and file servers once discovery
  tools are identified.
references:
- name: "The DFIR Report \u2014 Blurring the Lines: Intrusion Shows Connection With\
    \ Three Major Ransomware Gangs"
  url: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
related:
- hunt: ransomware-lateral-movement-rdp
  reason: Lateral movement via RDP using local accounts is handled in the second hunt
    of this series.
  relation: out-of-scope-alternative
- hunt: ransomware-data-exfiltration-ftp
  reason: WinSCP exfiltration to FTP servers is handled in the third hunt of this
    series.
  relation: out-of-scope-alternative
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
  index: 1
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


# EarthTime Trojan to Ransomware Reconnaissance

This hunt follows the progression from a social-engineered initial access event to full-scale environment discovery. It first identifies the initial beachhead created by a trojanized installer and the subsequent MSBuild process injection. It then pivots to find evidence of follow-on activities typical of ransomware affiliates, including local persistence, staging in public folders, and the execution of discovery tools like Grixba, AdFind, and SharpHound. The hunt uses a phased approach to correlate the initial infection with the heavy reconnaissance footprint seen in multi-gang ransomware intrusions.

## earthtime-scoping
<!-- Identify EarthTime beachhead hosts -->
Find hosts where the malicious EarthTime.exe was executed from the user's Downloads folder.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: The specific trojanized installer executing from a predictable user path.
  Silence confirms the absence of this specific initial access vector.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%\downloads\earthtime.exe' AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Investigate initial execution and C2 -->
parallel:
- → msbuild-anomaly
- → c2-connections
join: → early-stage-agent

## msbuild-anomaly
<!-- MSBuild execution without arguments -->
Find MSBuild.exe launched from the downloads directory with no arguments, a sign of SectopRAT injection.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A high-fidelity indicator of ArechClient2/SectopRAT process injection.
reads:
- current_directory
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, current_directory, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%\msbuild.exe' AND (process_cmd_line IS NULL OR process_cmd_line = '' OR LOWER(process_cmd_line) LIKE '%msbuild.exe') AND LOWER(current_directory) LIKE '%\downloads%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-connections
<!-- Network connections to C2 IPs -->
Identify any host communicating with the infrastructure named in the report.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Connections to ports 9000, 15647, or 443 at the target IPs.
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
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-agent
<!-- Triage early compromise -->
```agent target=hunter
cite: required
context:
- earthtime-scoping
- msbuild-anomaly
- c2-connections
max_iterations: 3
objective: Verify if the EarthTime execution led to MSBuild injection and network
  activity.
success_criteria: A per-host verdict of infected or clean.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Hunt follow-on ransomware activities -->
parallel:
- → persistence-and-staging
- → discovery-prevalence
- → defender-tampering
join: → full-intrusion-agent

## persistence-and-staging
<!-- Persistence shortcuts and staging files -->
Find shortcuts in the startup folder and malicious DLL staging in the Public Music folder.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: File writes like WakeWordEngine.dll or conhost.dll in the public music folder.
reads:
- activity_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, activity_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%\microsoft\windows\start menu\programs\startup\%' OR LOWER(file_path) LIKE '%\users\public\music\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## discovery-prevalence
<!-- Discovery tool execution prevalence -->
Stack-count discovery tool execution across the fleet to highlight rare or unauthorized usage.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, discovery_tools=discovery_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts running specialized recon tools like Grixba (GT_NET.exe)
  or AdFind.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS tool, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{discovery_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) = 'nltest.exe' OR LOWER(process_name) = 'adfind.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY tool HAVING hosts <= 3 ORDER BY hosts ASC
```

## defender-tampering
<!-- Microsoft Defender registry tampering -->
Check for registry modifications aimed at disabling Defender protections.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Modification of DisableAntiSpyware or Real-Time Protection keys.
reads:
- device_hostname
- process_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, reg_target, reg_value_data, process_name, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\policies\microsoft\windows defender\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## full-intrusion-agent
<!-- Comprehensive intrusion analysis -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- persistence-and-staging
- discovery-prevalence
- defender-tampering
max_iterations: 6
objective: Weigh whether the early compromise indicators and the follow-on discovery
  tool execution suggest an active ransomware affiliate intrusion.
success_criteria: A verdict of malicious for hosts exhibiting multiple stages of the
  attack chain.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on compromise level -->
if~: "the agent verdict is malicious for at least one host involving both initial execution and follow-on discovery tools" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Prioritize domain controllers and file servers if they appear in the results.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Detailed analyst investigation -->
```manual target=analyst
Examine the hosts for new local administrator accounts and startup shortcuts. Look for Betruger backdoor remnants (spawned by SectopRAT) and investigate the WinSCP/FTP activity for potential data theft.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the hosts affected and the tools identified. If MSBuild injection was confirmed, promote the msbuild-anomaly query to a standing detection rule.
```
→ end

---
analysis: This hunt pivots between sign-in anomalies and behavioural script content.
  A single rule firing on a logon is too noisy, and a rule on script keywords misses
  the context of which account performed the action; the hunt weighs the sequence
  across three surfaces to confirm an intrusion.
blind_spots:
- id: no-identity-visibility
  question: whether an RDP session used a saved credential or an interactive login
  requires: hb_auth_signin with full logon type support
  risk: Legitimate automated administrative tasks might be confused with lateral movement
    if logon types are not granular.
  stage: lateral-movement
- id: script-block-logging
  question: the exact script content when scripts are obfuscated or executed in memory
  requires: Full PowerShell Script Block Logging (Event ID 4104)
  risk: Attackers can hide credential-harvesting logic inside complex, in-memory script
    blocks that bypass simple process command-line detection.
  stage: credential-access-and-privilege-escalation
coverage:
- stage: credential-access-and-privilege-escalation
  status: covered
  steps:
  - credential-harvesting-scripts
  - lateral-tool-execution
- stage: lateral-movement
  status: covered
  steps:
  - anomalous-admin-logons
  - lateral-tool-execution
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
  stage: discovery-internal-reconnaissance
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: collection-and-exfiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Blurring the Lines: Intrusion Shows Connection
    With Three Major Ransomware Gangs'' series.'
  stage: command-and-control
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
  justification: Lateral movement and credential extraction on backup infrastructure
    are precursors to environment-wide ransomware deployment. Identifying these pivots
    on critical servers provides the highest-value containment opportunity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has moved laterally to high-value infrastructure like domain
  controllers and backup servers using hijacked accounts or newly created local admins,
  then executed scripts to harvest credentials.
labels:
- hunt
- attack.t1021.001
- attack.t1021.002
- attack.t1059.001
- attack.t1003.006
- attack.t1484.002
- attack.t1570
name: Identity-Based Lateral Movement and Credential Access
parameters:
  critical_servers:
    default:
    - dc01
    - dc02
    - backup
    - veeam
    - filesrv
    description: Hostnames or substrings for Domain Controllers and Backup servers.
    type: list[host]
  lateral_tools:
    default:
    - psexec.exe
    - psexesvc.exe
    - wmiexec.exe
    - wmiexec.vbs
    - grixba.exe
    - netscan.exe
    description: Common lateral movement tool filenames.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts from the scoping step to focus the fan-out.
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
rationale: Focus the hunt on critical systems including domain controllers, backup
  servers, and file servers. The first query filters specifically for these high-value
  targets to reduce noise from common user logons.
references:
- name: "The DFIR Report \u2014 Blurring the Lines: Intrusion Shows Connection With\
    \ Three Major Ransomware Gangs"
  url: https://thedfirreport.com/2025/09/08/blurring-the-lines-intrusion-shows-connection-with-three-major-ransomware-gangs/
related:
- hunt: discovery-internal-reconnaissance
  reason: Internal reconnaissance using Grixba and NetScan is handled in a separate
    hunt focused on discovery artifacts.
  relation: out-of-scope-alternative
- hunt: earthtime-trojan-ransomware-recon
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
  index: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Identity-Based Lateral Movement and Credential Access

This hunt targets the middle and late stages of an intrusion where attackers pivot across the identity plane. It identifies anomalous RDP logons to critical servers followed by the execution of specialized scripts for Veeam credential extraction or Active Directory replication. The hunt uses a funnel flow: scoping for unusual administrative logins, then fanning out to examine the command lines and script text that confirm credential harvesting and lateral pivoting.

## anomalous-admin-logons
<!-- Anomalous Administrative Logons -->
Identify successful logins to critical servers from source IPs or users that are rare for those hosts.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, critical_servers=critical_servers)
~~~yaml
expected: A list of critical hosts and users logging in from unusual sources. Silence
  indicates no infrequent logins were recorded to these systems.
reads:
- dst_endpoint_name
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, src_endpoint_ip, actor_user_name, COUNT(*) AS logon_count, MIN(time) AS first_logon FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{critical_servers}}' || ',', ',' || LOWER(dst_endpoint_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name, src_endpoint_ip, actor_user_name HAVING logon_count < 10 ORDER BY logon_count ASC
```

## corroborate-activity
<!-- Corroborate logons with activity -->
parallel:
- → credential-harvesting-scripts
- → lateral-tool-execution
join: → triage-identity-pivot

## credential-harvesting-scripts
<!-- Credential Harvesting Script Content -->
Search for executed script blocks that target backup software secrets or local account databases.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing keywords associated with credential extraction
  tools or techniques. Silence suggests no such scripts ran on the scoped hosts.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%veeam%' OR LOWER(script_content) LIKE '%reg save %sam%' OR LOWER(script_content) LIKE '%sekurlsa%' OR LOWER(script_content) LIKE '%dpapi%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lateral-tool-execution
<!-- Lateral Movement Tool Execution -->
Find the execution of remote administration tools or behavioral markers like local admin account creation.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lateral_tools=lateral_tools)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Process command lines for tool execution or local user creation. Silence
  indicates no matching tool signatures were observed.
prevalence:
  by: device_hostname
  key:
  - process_name
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
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{lateral_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%net user % /add%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-identity-pivot
<!-- Triage Identity Pivot Evidence -->
```agent target=hunter
cite: required
context:
- anomalous-admin-logons
- credential-harvesting-scripts
- lateral-tool-execution
max_iterations: 5
objective: Determine if any host shows an anomalous administrative login followed
  by credential extraction or lateral tool usage.
success_criteria: A verdict of malicious | suspicious | benign per host with citations
  of the specific rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route Based on Triage -->
if~: "the triage verdict is malicious for at least one critical server" (confidence: high, judge=hunter)
then: → isolate-pivot-host
indeterminate: → audit-identity-changes
unavailable: → audit-identity-changes (blind_spot: no-identity-visibility)
else: → close-out-hunt

## isolate-pivot-host
<!-- Isolate Pivot Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host and initiate an emergency password reset for any administrative accounts involved in the suspicious logons.
```
→ audit-identity-changes

## audit-identity-changes
<!-- Audit Identity Changes -->
```manual target=analyst
Review the local administrators group and newly created user accounts on the identified servers. Verify the source IPs of RDP connections in the security event logs to confirm they originate from unauthorized locations.
```
→ close-out-hunt

## close-out-hunt
<!-- Close-out Hunt -->
```manual target=analyst
Record the timeline of lateral movement. Document any missing telemetry such as truncated script blocks or lack of auth protocol details.
```
→ end

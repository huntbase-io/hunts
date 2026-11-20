---
analysis: A single detection rule for 'mimikatz.exe' is easily bypassed by renaming.
  This hunt correlates the rare presence of RMM tools (AnyDesk/TeamViewer) with the
  high-integrity execution of discovery binaries and anomalous authentication paths
  to find the actor even when tools are rotated.
blind_spots:
- id: limited-endpoint-visibility
  question: Are there internal servers performing network discovery that are not reporting
    process activity?
  requires: Endpoint agent coverage on all internal servers
  risk: A host without an agent allows an actor to run NetExec or Mimikatz invisibly
    at the host level; lateral movement would only be visible at the authentication
    source.
  stage: discovery-and-credential-dumping
- id: no-script-block-logging
  question: Was the ShareFinder.ps1 function run in-memory without a script file?
  requires: PowerShell Script Block Logging (Event ID 4104)
  risk: SafePay uses ShareFinder.ps1 for AD enumeration. If the actor loads the script
    content directly into memory, hb_process_activity may only see the powershell.exe
    launch, not the specific recon commands.
  stage: discovery-and-credential-dumping
coverage:
- stage: discovery-and-credential-dumping
  status: covered
  steps:
  - recon-tool-execution
- stage: lateral-movement-and-rmm-abuse
  status: covered
  steps:
  - rmm-inventory
  - lateral-auth-baseline
- reason: The query includes common UAC bypass binaries such as fodhelper.exe and
    computerdefaults.exe and filters for high-integrity execution.
  stage: privilege-escalation-uac-bypass
  status: covered
  steps:
  - recon-tool-execution
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: initial-access-vpn-and-phishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: persistence-via-account-manipulation
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: defense-evasion-and-stealth
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: exfiltration-and-collection
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: impact-and-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: SafePay is a high-impact ransomware group targeting critical infrastructure;
    detecting their lateral movement and internal discovery phase is the last opportunity
    to prevent large-scale encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: SafePay actors have established a foothold and are using repurposed administrative
  tools, credential dumpers, and anomalous RDP or SMB sessions to move laterally toward
  file shares.
labels:
- hunt
- attack.t1003
- attack.t1021.001
- attack.t1021.002
- attack.t1021.006
- attack.t1059.001
- attack.t1134.001
- attack.t1548.002
- attack.t1569.002
- defense evasion
- discovery
- exfiltration
- impact
- initial access
- lateral movement
- persistence
- privilege escalation
name: 'SafePay: Internal Enumeration and Lateral Movement'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  recon_tools:
    default:
    - mimikatz.exe
    - sharpshares.exe
    - netexec.exe
    - nxc.exe
    - psexec.exe
    - paexec.exe
    - fodhelper.exe
    - computerdefaults.exe
    description: Filenames for discovery, credential dumping, and UAC bypass used
      by SafePay.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
  rmm_tools:
    default:
    - anydesk
    - teamviewer
    - screenconnect
    - connectwise
    description: RMM package or vendor names mentioned in SafePay reporting.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the search; leave empty for the
      whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start the hunt by examining workstations with internet-facing RMM tools
  installed, then widen the scope if rare sign-ins to file servers are detected from
  those hosts.
references:
- name: "CISA AA26-293A \u2014 #StopRansomware: SafePay Ransomware"
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
related:
- hunt: safepay-initial-access
  reason: This hunt examines the internal spread that occurs after the initial VPN
    or phishing breach.
  relation: follows
- hunt: safepay-impact-and-encryption
  reason: Lateral movement and share discovery are the prerequisites for the mass
    encryption phase.
  relation: precedes
- hunt: safepay-perimeter-breach-account-persistence
  relation: follows
scenario:
  stages:
  - name: VPN Exploitation and Credential Access
    observables:
    - CVE-2020-3259
    - CVE-2023-20269
    - Mullvad VPN IP addresses
    - Brute force password attacks
    slug: initial-access-vpn-and-phishing
    tactic: initial-access
    techniques:
    - T1190
    - T1110
    - T1133
    - T1566
  - name: Account Creation and Privilege Gain
    observables:
    - Creation of new administrative accounts
    - Administrative privileges granted to existing accounts
    slug: persistence-via-account-manipulation
    tactic: persistence
    techniques:
    - T1098
    - T1136
  - name: Network Discovery and Credential Access
    observables:
    - ShareFinder.ps1
    - SharpShares.exe
    - NetExec
    - Mimikatz
    - Kerberos ticket extraction
    slug: discovery-and-credential-dumping
    tactic: discovery
    techniques:
    - T1059.001
    - T1059.003
    - T1003
    - T1550.002
  - name: Remote Command Execution and Lateral Pivot
    observables:
    - PsExec
    - WinRM
    - RDP
    - ScreenConnect
    - AnyDesk
    - TeamViewer
    slug: lateral-movement-and-rmm-abuse
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1021.002
    - T1021.006
    - T1569.002
    - T1218
  - name: UAC Bypass and Token Impersonation
    observables:
    - Elevated process creation via COM component
    - Token impersonation methods
    slug: privilege-escalation-uac-bypass
    tactic: privilege-escalation
    techniques:
    - T1548.002
    - T1134.001
  - name: Security Software Impairment and Stealth
    observables:
    - Disabling security software
    - Software packing or VM-based concealment
    - Self-deletion from filesystem
    slug: defense-evasion-and-stealth
    tactic: defense-evasion
    techniques:
    - T1685
    - T1027.002
    - T1070.004
  - name: Data Packaging and Exfiltration
    observables:
    - 7-Zip
    - WinRAR
    - FileZilla
    - RClone
    - WinSCP
    - b2.exe (Backblaze CLI)
    - OneDrive
    slug: exfiltration-and-collection
    tactic: exfiltration
    techniques:
    - T1560.001
    - T1048
    - T1567
    - T1567.002
    - T1041
  - name: Ransomware Encryption and Recovery Inhibition
    observables:
    - Files appended with .SafePay
    - Halting Volume Shadow Copy Service
    - Resetting NAS to factory settings
    - Ransom note on desktop
    - TOR .onion website link in note
    slug: impact-and-encryption
    tactic: impact
    techniques:
    - T1486
    - T1490
    - T1090.003
  summary: SafePay ransomware actors gain initial access through VPN vulnerabilities,
    brute-force, or phishing, subsequently establishing persistence via account creation
    and privilege manipulation. They move laterally using LOLBins and RMM tools like
    ScreenConnect and AnyDesk, before exfiltrating data via cloud-sync utilities and
    deploying ransomware that encrypts files with a .SafePay extension and disables
    recovery mechanisms.
series:
  index: 2
  slug: stopransomware-safepay-ransomware
  title: '#StopRansomware: SafePay Ransomware'
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


# SafePay: Internal Enumeration and Lateral Movement

SafePay actors rely on legitimate tools (AnyDesk, TeamViewer) for persistence and open-source scripts (ShareFinder, NetExec) for network discovery. This hunt identifies the presence of these RMM tools, detects the execution of common enumeration binaries at elevated integrity, and baselines internal authentication to find rare lateral movement paths. An agent weighs the findings to determine if an actor is actively traversing the estate.

## rmm-inventory
<!-- Inventory of SafePay-associated RMM software -->
Identify hosts where AnyDesk, TeamViewer or ScreenConnect are installed, establishing the initial search scope.

```sqlite target=endpoint role=scoping params=(rmm_tools=rmm_tools)
~~~yaml
expected: A list of hosts containing RMM tools. Silence means no such software was
  recorded in the latest snapshot.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## corroborate-activity
<!-- Corroborate activity on two surfaces -->
parallel:
- → recon-tool-execution
- → lateral-auth-baseline
join: → weigh-evidence

## recon-tool-execution
<!-- SafePay discovery and bypass tool execution -->
Find the execution of binaries for share discovery and UAC bypass, filtering for high-integrity launches that indicate successful elevation.

```sqlite target=endpoint role=detection-candidate params=(recon_tools=recon_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process events for SharpShares, Mimikatz, or PsExec running with high integrity.
  Silence confirms these specific binaries did not run at high integrity on enrolled
  hosts.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- integrity_level
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, integrity_level, time FROM hb_process_activity WHERE (instr(',' || '{{recon_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{recon_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%sharefinder%') AND integrity_level IN ('High', 'System') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lateral-auth-baseline
<!-- Rare internal network sign-ins -->
Baseline internal sign-ins to identify rare lateral movement paths using RDP or SMB that differ from normal admin patterns.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few hosts showing rare incoming sessions from internal source IPs. Silence
  indicates no new or low-volume lateral paths were observed.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- src_endpoint_ip
- device_hostname
- logon_type_id
- status
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT actor_user_name, src_endpoint_ip, device_hostname, logon_type, COUNT(*) AS logins, MIN(time) AS first_login FROM hb_auth_signin WHERE status = 'Success' AND logon_type_id IN (3, 10) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, device_hostname HAVING logins < 15
```

## weigh-evidence
<!-- Weigh the intrusion evidence -->
```agent target=hunter
cite: required
context:
- rmm-inventory
- recon-tool-execution
- lateral-auth-baseline
max_iterations: 4
objective: Determine if the presence of AnyDesk/TeamViewer, the high-integrity execution
  of SharpShares or NetExec, and the rare internal sign-ins indicate an active SafePay
  intrusion.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  rows from the tool and auth queries.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route on verdict -->
if~: "the weigh-evidence verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: limited-endpoint-visibility)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the hosts identified as malicious and terminate any active RDP or WinRM sessions for the involved users.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst investigation -->
```manual target=analyst
Review the cited process and sign-in logs. Check hb_file_activity for bulk access to sensitive shares from the compromised hosts during the time window.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. If SharpShares or NetExec execution was confirmed as unauthorized, promote the recon-tool-execution query to a standing rule.
```
→ end

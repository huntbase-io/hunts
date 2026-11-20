---
analysis: A single detection rule for PsExec or AnyDesk creates excessive noise in
  environments where these are used legitimately. This hunt provides the necessary
  context by correlating tool execution with share discovery scripts and rare network
  patterns, allowing an analyst to distinguish between administrative work and an
  active intrusion.
blind_spots:
- id: missing-endpoint-visibility
  question: Are there domain-joined hosts not running an agent that are performing
    share enumeration?
  requires: endpoint agent coverage on all domain-joined hosts
  risk: Adversaries may pivot from an unmanaged beachhead to managed servers, remaining
    invisible until they touch a managed resource.
  stage: discovery-share-enumeration
- id: obfuscated-scripts
  question: Are the enumeration scripts using base64 or other obfuscation that avoids
    the LIKE filters?
  requires: hb_script_activity with full block reconstruction
  risk: A simple string match on common cmdlets can be bypassed by character replacement
    or encoding.
  stage: defense-evasion-security-impairment
coverage:
- stage: discovery-share-enumeration
  status: covered
  steps:
  - identify-living-off-land-tools
  - hunt-malicious-scripting
- stage: lateral-movement-rmm-psexec
  status: covered
  steps:
  - identify-living-off-land-tools
  - examine-remote-service-traffic
- reason: The 'defender_tamper_script_block' rule already monitors for Set-MpPreference
    and DisableRealtimeMonitoring commands.
  stage: defense-evasion-security-impairment
  status: existing_rule
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: initial-access-exploitation-and-brute-force
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: persistence-account-manipulation
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: privilege-escalation-uac-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: collection-exfiltration-utilities
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: impact-encryption-recovery-inhibition
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SafePay is a highly active ransomware variant targeting critical
    infrastructure. Identifying lateral movement before the impact stage (encryption)
    is the only way to prevent large-scale data loss and operational downtime.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using legitimate administrative tools and scripts to enumerate
  network shares and move laterally via remote management protocols while disabling
  local security software.
labels:
- hunt
- attack.t1059.001
- attack.t1059.003
- attack.t1021.001
- attack.t1021.002
- attack.t1021.006
- attack.t1569.002
- attack.t1685
- attack.t1027.002
- defense evasion
- discovery
- exfiltration
- impact
- initial access
- lateral movement
- persistence
- privilege escalation
name: 'SafePay: Internal Discovery and Lateral Movement'
parameters:
  discovery_tools:
    default:
    - psexec.exe
    - psexec64.exe
    - winrm.exe
    - anydesk.exe
    - teamviewer.exe
    - sharpshares.exe
    - netexec.exe
    - screenconnect.exe
    - b2.exe
    - acronisdiskdirector.exe
    description: Process names of tools used by SafePay for discovery and movement.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for the entire estate.
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
rationale: Start with workstations exhibiting unusual outbound RDP or WinRM traffic.
  Focus on systems where Windows Defender alerts have recently cleared or where 'Real-time
  monitoring' is reported as disabled.
references:
- name: 'CISA AA26-293A: #StopRansomware: SafePay Ransomware'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
related:
- hunt: safepay-initial-access-exploitation
  reason: This hunt assumes the attacker has already gained a foothold via VPN or
    edge vulnerability exploitation.
  relation: precedes
- hunt: safepay-exfiltration-encryption
  reason: Once lateral movement is complete, the attacker will proceed to data collection
    and encryption.
  relation: follows
- hunt: safepay-external-access-identity-consolidation
  relation: follows
scenario:
  stages:
  - name: Edge Device Exploitation and Brute Force
    observables:
    - CVE-2020-3259
    - CVE-2023-20269
    - CVE-2023-27532
    - CVE-2024-40711
    - CVE-2024-40766
    - Mullvad VPN IP addresses
    - VPN authentication failures
    slug: initial-access-exploitation-and-brute-force
    tactic: initial-access
    techniques:
    - T1190
    - T1110
    - T1133
  - name: Account Persistence and Privilege Gain
    observables:
    - net user /add
    - Password changes for existing system users
    - Creation of new administrative accounts
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1098
    - T1136
  - name: Local Privilege Escalation
    observables:
    - UAC bypass via COM component objects
    - Token impersonation activity
    slug: privilege-escalation-uac-bypass
    tactic: privilege-escalation
    techniques:
    - T1548.002
    - T1134.001
  - name: Active Directory and Share Discovery
    observables:
    - ShareFinder.ps1
    - SharpShares.exe
    - NetExec
    slug: discovery-share-enumeration
    tactic: discovery
    techniques:
    - T1059.001
    - T1059.003
  - name: Lateral Movement and Remote Management
    observables:
    - psexec.exe
    - winrm.exe
    - AnyDesk.exe
    - TeamViewer.exe
    - ScreenConnect
    - RDP connections
    slug: lateral-movement-rmm-psexec
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1021.002
    - T1021.006
    - T1569.002
  - name: Defense Impairment and Stealth
    observables:
    - Set-MpPreference -DisableRealtimeMonitoring
    - Disabling security software
    - Software packing or VM protection
    slug: defense-evasion-security-impairment
    tactic: defense-evasion
    techniques:
    - T1685
    - T1027.002
  - name: Data Collection and Exfiltration
    observables:
    - 7z.exe
    - WinRAR.exe
    - rclone.exe
    - FileZilla.exe
    - WinSCP.exe
    - b2.exe (Backblaze)
    - OneDrive exfiltration
    slug: collection-exfiltration-utilities
    tactic: exfiltration
    techniques:
    - T1560.001
    - T1048
    - T1567
    - T1567.002
  - name: Encryption and Recovery Inhibition
    observables:
    - .SafePay extension
    - vssadmin.exe delete shadows
    - Resetting NAS to factory settings
    - Self-deletion of ransomware binary
    slug: impact-encryption-recovery-inhibition
    tactic: impact
    techniques:
    - T1486
    - T1490
    - T1070.004
  summary: SafePay ransomware actors gain initial access through credential harvesting,
    brute-force attacks, and exploitation of vulnerabilities in VPN and edge devices
    like Cisco and Veeam. Once inside, they escalate privileges via UAC bypass, move
    laterally using RDP and PsExec, and utilize RMM tools for persistence before exfiltrating
    data and deploying encryption.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# SafePay: Internal Discovery and Lateral Movement

This hunt focuses on the middle phase of a SafePay ransomware intrusion. SafePay actors use living-off-the-land binaries (LOLBins) like PsExec and WinRM alongside legitimate RMM tools such as AnyDesk and ScreenConnect to pivot through the network. They concurrently use PowerShell scripts like ShareFinder to identify valuable assets and modify Windows Defender settings to avoid detection. The hunt identifies the execution of these tools, correlates them with suspicious script content, and examines network traffic to remote management ports.

## identify-living-off-land-tools
<!-- Identify administrative and RMM tools -->
Find the execution of tools SafePay uses for lateral movement and host enumeration, filtering for rare occurrences.

```sqlite target=endpoint role=detection-candidate params=(discovery_tools=discovery_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows show legitimate tools running in unusual contexts, such as from user
  profiles or by unauthorized users, limited to rare sightings across the fleet.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_cmd_line
  rare_below: 4
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- process_original_file_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, process_path, parent_process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{discovery_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{discovery_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path, parent_process_name, process_cmd_line, device_hostname HAVING COUNT(DISTINCT device_hostname) <= 3
```

## correlate-discovery-and-evasion
<!-- Correlate with script and network activity -->
parallel:
- → hunt-malicious-scripting
- → examine-remote-service-traffic
join: → triage-lateral-movement

## hunt-malicious-scripting
<!-- Search for share discovery and enumeration scripts -->
Locate PowerShell activity targeting network shares or performing Active Directory enumeration to identify valuable assets.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing ShareFinder functions or AD query commands. Silence
  suggests no such scripts were executed within the window.
reads:
- actor_user_name
- device_hostname
- script_content
- script_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, script_name, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%sharefinder%' OR LOWER(script_content) LIKE '%get-netshare%' OR LOWER(script_content) LIKE '%invoke-sharefinder%' OR LOWER(script_content) LIKE '%netshareenum%' OR LOWER(script_content) LIKE '%get-adcomputer%' OR LOWER(script_content) LIKE '%ldap://%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## examine-remote-service-traffic
<!-- Identify remote service connections -->
Stack-count network connections to remote management ports used for lateral movement.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts connecting to RDP or WinRM ports, or using RMM software.
  Rare connections stand out from normal administrative baseline.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_port
  rare_below: 4
reads:
- device_hostname
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, dst_endpoint_port, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_port IN (3389, 5985, 5986) OR LOWER(process_name) LIKE '%anydesk%' OR LOWER(process_name) LIKE '%teamviewer%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_port HAVING COUNT(DISTINCT device_hostname) <= 3
```

## triage-lateral-movement
<!-- Triage lateral movement evidence -->
```agent target=hunter
cite: required
context:
- identify-living-off-land-tools
- hunt-malicious-scripting
- examine-remote-service-traffic
max_iterations: 5
objective: Identify hosts used for lateral pivots.
success_criteria: A verdict of malicious, suspicious, or benign per host with cited
  evidence.
tools:
- endpoint
- network
```

## evaluate-threat-presence
<!-- Evaluate threat presence -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: missing-endpoint-visibility)
else: → reporting-and-cleanup

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate a full forensic review of the user sessions active during the detected window.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst investigation -->
```manual target=analyst
Review the cited process command lines and script content. Cross-reference with hb_auth_signin to identify the originating source IP of the lateral movement attempts.
```
→ reporting-and-cleanup

## reporting-and-cleanup
<!-- Reporting and cleanup -->
```manual target=analyst
Document all discovered lateral movement paths and recommend tuning for the RMM tool detection candidate if the findings were verified.
```
→ end

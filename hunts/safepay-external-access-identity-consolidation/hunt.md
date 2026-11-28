---
analysis: A simple rule for UAC bypass or account creation often triggers false positives
  for legitimate administrative tasks. This hunt uses a gated vulnerability check
  and an agent-led triage to correlate vulnerable state with suspicious behavior,
  providing higher confidence before containment.
blind_spots:
- id: incomplete-vuln-scoping
  question: Are all firewalls and VPN gateways currently reporting their vulnerability
    status?
  requires: Complete coverage of edge devices in hb_vulnerability_finding
  risk: A host missing from the vulnerability inventory will bypass the lead gate
    and be excluded from behavioral analysis.
  stage: initial-access-exploitation-and-brute-force
- id: agent-visibility-gap
  question: Can we observe account changes if they occur directly on a domain controller
    not enrolled in the hunt?
  requires: Endpoint agents on all domain controllers
  risk: Account manipulation on an unmonitored DC will be invisible to the hb_account_change
    surface.
coverage:
- stage: initial-access-exploitation-and-brute-force
  status: covered
  steps:
  - vulnerable-gate
  - brute-force-triage
- stage: persistence-account-manipulation
  status: covered
  steps:
  - account-persistence
- stage: privilege-escalation-uac-bypass
  status: covered
  steps:
  - uac-bypass-check
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: discovery-share-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: lateral-movement-rmm-psexec
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: defense-evasion-security-impairment
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
  justification: SafePay is a top-tier ransomware threat targeting critical infrastructure
    with rapid post-exploitation consolidation. Identifying these early stages prevents
    the transition to full encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a known edge vulnerability to gain a foothold
  and is consolidating control by creating administrative accounts and escalating
  local privileges via UAC bypass.
labels:
- hunt
- attack.t1190
- attack.t1110
- attack.t1133
- attack.t1098
- attack.t1136
- attack.t1548.002
- attack.t1134.001
- defense evasion
- discovery
- exfiltration
- impact
- initial access
- lateral movement
- persistence
- privilege escalation
name: 'SafePay: External Access and Identity Consolidation'
parameters:
  lookback_days:
    default: '14'
    description: History of history to examine.
    type: number
  safepay_cves:
    default:
    - CVE-2020-3259
    - CVE-2023-20269
    - CVE-2023-27532
    - CVE-2024-40711
    - CVE-2024-40766
    description: CVEs associated with SafePay initial access vectors.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
  scope_hosts:
    default: []
    description: Limit analysis to specific hostnames identified in the scoping step.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing assets including VPN gateways, backup servers
  (Veeam), and firewalls. Expand to administrative workstations if account manipulation
  is detected.
references:
- name: 'CISA Advisory AA26-293A: #StopRansomware: SafePay Ransomware'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
related:
- hunt: safepay-discovery-and-lateral-movement
  reason: This hunt identifies the beachhead; the next hunt focuses on ShareFinder
    and PsExec activity.
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
  index: 1
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


# SafePay: External Access and Identity Consolidation

SafePay actors use vulnerabilities in Cisco VPNs, Veeam backups, and SonicWall firewalls to enter the network. The hunt identifies exposed assets and monitors for brute-force attacks against the beachhead. The gated structure ensures the analyst only performs expensive behavioral analysis on hosts that show a real exposure. The hunt then checks for new account creations and privilege escalation attempts before an agent weighs the combined evidence and an analyst confirms the threat.

## vulnerable-gate
<!-- Identify vulnerable edge infrastructure -->
Find devices currently reporting vulnerabilities used by SafePay for initial access.

```sqlite target=endpoint role=scoping params=(safepay_cves=safepay_cves)
~~~yaml
expected: A list of device UIDs and resource paths vulnerable to the specified CVEs.
  Silence means no known-vulnerable assets are reporting.
reads:
- cve_uid
- device_uid
- resource_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_uid, cve_uid, severity, resource_uid, status FROM hb_vulnerability_finding WHERE (instr(',' || '{{safepay_cves}}' || ',', ',' || cve_uid || ',') > 0) AND status != 'suppressed'
```

## lead-assessment
<!-- Evaluate exposure gate -->
```agent target=hunter
cite: required
context:
- vulnerable-gate
max_iterations: 3
objective: 'Summarize the exposure: how many hosts are vulnerable to SafePay-linked
  CVEs and which CVEs are most prevalent.'
success_criteria: A per-host vulnerability summary.
tools:
- endpoint
- identity
```

## gate-decision
<!-- Gate on vulnerability results -->
if~: "vulnerable-gate finds at least one host or resource with a critical or high severity vulnerability" (confidence: high, judge=hunter)
then: → fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-vuln-scoping)
else: → close-out

## fan-out
<!-- Fan out behavioral queries -->
parallel:
- → brute-force-triage
- → account-persistence
- → uac-bypass-check
join: → triage-investigation

## brute-force-triage
<!-- Brute-force and logon anomalies -->
Identify external brute-force attempts targeting administrative or phished accounts.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A high volume of failed sign-ins from a single source IP, potentially targeting
  multiple accounts.
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT src_endpoint_ip, actor_user_name, device_hostname, COUNT(*) as attempts, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_auth_signin WHERE status_id = 2 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, device_hostname HAVING attempts > 20 ORDER BY attempts DESC
```

## account-persistence
<!-- Suspicious account manipulation -->
Detect the creation of new accounts or unauthorized password resets used for persistence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Account creation (activity_id 1) or password changes/resets (3, 4) on critical
  servers, especially by unexpected actors.
reads:
- activity_id
- activity_name
- actor_user_name
- device_hostname
- time
- user_name
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, user_name, actor_user_name, activity_name, time FROM hb_account_change WHERE activity_id IN (1, 3, 4) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## uac-bypass-check
<!-- Local privilege escalation via UAC bypass -->
Find high-integrity processes spawned from interactive or shell-based parents, indicating UAC bypass.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: High integrity processes with command-line arguments that imply interactive
  shell execution. Silence proves the absence of this specific behavior on the monitored
  hosts.
reads:
- device_hostname
- integrity_level
- parent_process_name
- process_cmd_line
- process_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, integrity_level, time FROM hb_process_activity WHERE integrity_level = 'High' AND (LOWER(parent_process_name) LIKE '%\\explorer.exe' OR LOWER(parent_process_name) LIKE '%\\cmd.exe' OR LOWER(parent_process_name) LIKE '%\\powershell.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-investigation
<!-- Triage initial access and consolidation -->
```agent target=hunter
cite: required
context:
- lead-assessment
- brute-force-triage
- account-persistence
- uac-bypass-check
max_iterations: 6
objective: Determine if any host showing initial access indicators (vuln + brute force)
  has also progressed to persistence or privilege escalation.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing specific
  rows for each stage of the attack chain.
tools:
- endpoint
- identity
```

## route-to-response
<!-- Route for containment or review -->
if~: "The triage verdict is malicious for at least one host showing both account manipulation and privilege escalation." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: agent-visibility-gap)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Lock the actor's session and revoke the credentials used for the suspicious account activity.
```
→ analyst-review

## analyst-review
<!-- Analyst manual review -->
```manual target=analyst
Review the triage verdicts. For suspicious hosts, verify the source IPs of the auth failures and the process tree of the UAC bypass. Confirm if the account changes were authorized.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the vulnerable hosts identified. If the behavioral queries were empty, document the negative result as evidence of absence of post-exploitation activity on the exposed surface.
```
→ end

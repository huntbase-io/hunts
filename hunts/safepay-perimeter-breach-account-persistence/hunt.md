---
analysis: A single rule might catch an admin group change, but this hunt pivots from
  unpatched vulnerabilities to authentication anomalies from specific VPNs and then
  to those account changes, providing context that a static rule cannot.
blind_spots:
- id: missing-vpn-auth-telemetry
  question: whether the VPN appliance itself is reporting authentication attempts
  requires: VPN device sign-in logs in hb_auth_signin
  risk: Attackers exploiting unpatched VPN vulnerabilities may bypass standard logging
    if the appliance does not forward auth events.
  stage: initial-access-vpn-and-phishing
- id: ephemeral-proxy-ips
  question: whether the adversary is using a new or unlisted Mullvad IP
  requires: Up-to-date Mullvad exit node lists or robust proxy classification
  risk: A negative result for the IP list does not prove absence if the actor recently
    rotated their VPN infrastructure.
  stage: initial-access-vpn-and-phishing
coverage:
- stage: initial-access-vpn-and-phishing
  status: covered
  steps:
  - vulnerable-edge-assets
  - signins-from-vpn-proxies
- stage: persistence-via-account-manipulation
  status: covered
  steps:
  - high-privilege-account-changes
  - new-account-creation
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: discovery-and-credential-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: lateral-movement-and-rmm-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''#StopRansomware: SafePay Ransomware''
    series.'
  stage: privilege-escalation-uac-bypass
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
  handoff: promote-to-detection
  justification: SafePay is a highly active ransomware variant targeting critical
    infrastructure. Identifying the initial beachhead and persistence early prevents
    the catastrophic encryption of the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited unpatched edge vulnerabilities or use VPN-based
  brute force to gain initial access, subsequently creating or elevating accounts
  to secure administrative persistence.
labels:
- hunt
- attack.t1190
- attack.t1110
- attack.t1133
- attack.t1566
- attack.t1098
- attack.t1136
- defense evasion
- discovery
- exfiltration
- impact
- initial access
- lateral movement
- persistence
- privilege escalation
name: 'SafePay Ransomware: Perimeter Breach and Account Persistence'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  mullvad_ips:
    default: []
    description: Known Mullvad VPN exit node IP addresses used by threat actors.
    from:
      kind: article
      observed: '2026-10-20'
      ref: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
    type: list[ip]
  scope_hosts:
    default: []
    description: Specific hostnames to focus on (leave empty for the entire estate).
    type: list[host]
  target_cves:
    default:
    - CVE-2020-3259
    - CVE-2023-20269
    - CVE-2023-27532
    - CVE-2024-40711
    - CVE-2024-40766
    description: CVE identifiers associated with SafePay initial access vectors.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
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
rationale: Focus first on edge devices (VPN concentrators, firewalls) and backup servers.
  Widen scope to all domain controllers if privileged account changes are detected.
references:
- name: 'CISA AA26-293A: #StopRansomware: SafePay Ransomware'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
related:
- hunt: safepay-discovery-lateral-movement
  reason: This hunt focuses on the initial breach; the follow-on hunt examines internal
    discovery and tool abuse.
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


# SafePay Ransomware: Perimeter Breach and Account Persistence

SafePay ransomware actors frequently use vulnerabilities in edge devices, such as Cisco ASA/FTD or Veeam components, or perform brute-force attacks from known VPN providers like Mullvad to gain a foothold. Once inside, they prioritize the creation of new administrative accounts or the addition of users to local/domain admin groups to ensure long-term control before moving laterally. This hunt identifies vulnerable infrastructure, correlates access attempts from high-risk IP addresses, and monitors for suspicious account management activities that signify a beachhead establishment.

## vulnerable-edge-assets
<!-- Identify vulnerable edge infrastructure -->
Identify hosts or resources in the environment currently reporting vulnerabilities used by SafePay for initial access.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of devices and their unpatched CVEs. A match indicates an exposed
  surface area matching SafePay's known targeting.
reads:
- affected_package_name
- affected_package_version
- cve_uid
- device_uid
- severity
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT device_uid, cve_uid, affected_package_name, affected_package_version, severity, status FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0 AND status != 'suppressed'
```

## suspicious-access-and-persistence
<!-- Correlate access attempts and account changes -->
parallel:
- → signins-from-vpn-proxies
- → high-privilege-account-changes
- → new-account-creation
join: → triage-access-and-persistence

## signins-from-vpn-proxies
<!-- VPN and proxy authentication patterns -->
Find sign-in attempts or successful logons originating from Mullvad VPN or anonymizing proxies.

```sqlite target=identity role=detection-candidate params=(mullvad_ips=mullvad_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A successful logon from a proxy or Mullvad IP is a high-fidelity indicator
  of account compromise or external unauthorized access.
reads:
- actor_user_name
- device_hostname
- is_proxy
- src_endpoint_ip
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT src_endpoint_ip, actor_user_name, status, COUNT(*) AS attempts, MIN(time) AS first_attempt, MAX(time) AS last_attempt FROM hb_auth_signin WHERE (is_proxy = 'true' OR instr(',' || '{{mullvad_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, status
```

## high-privilege-account-changes
<!-- New administrators and group additions -->
Detect the addition of accounts to privileged groups, a key SafePay persistence mechanism.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A row identifying an account added to an administrative group. If the actor_user_name
  is a service account or an unusual user, it is highly suspicious.
reads:
- activity_id
- activity_name
- actor_user_name
- device_hostname
- group_name
- group_uid
- time
- user_name
silence: not_evidence_of_absence
source: hb_group_management
verified: dry-run
verified_at: '2026-10-21'
~~~
SELECT device_hostname, actor_user_name, group_name, user_name, activity_name, time FROM hb_group_management WHERE (LOWER(group_name) LIKE '%admin%' OR group_uid = 'S-1-5-32-544') AND activity_id = 3 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## new-account-creation
<!-- Suspicious account creation -->
Detect the creation of new user accounts which SafePay actors use to establish control.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The creation of a new account not associated with documented provisioning
  activity.
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
verified_at: '2026-10-21'
~~~
SELECT device_hostname, user_name, actor_user_name, activity_name, time FROM hb_account_change WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-access-and-persistence
<!-- Weigh perimeter and account evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-edge-assets
- signins-from-vpn-proxies
- high-privilege-account-changes
- new-account-creation
max_iterations: 6
objective: Determine if the sign-in patterns from proxies/VPNs and subsequent administrative
  account changes on vulnerable hosts indicate successful initial access and persistence
  by SafePay actors.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict identifies successful unauthorized administrative account creation or sign-ins on vulnerable hosts" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-vpn-auth-telemetry)
else: → close-out

## isolate-and-remediate
<!-- Isolate host and disable accounts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised endpoint from the network. Disable the newly created or modified administrative accounts identified in the triage. Revoke active sessions for those users.
```
→ analyst-review

## analyst-review
<!-- Review beachhead findings -->
```manual target=analyst
Verify the sign-in source IPs against known Mullvad exit nodes. Confirm the legitimacy of the account modifications with the system owner. Check hb_process_activity for the beachhead host, specifically looking for the 'legitimate system tools' (T1059) mentioned in the advisory (e.g., net.exe, powershell.exe) being used to modify accounts. Look for early signs of lateral movement (e.g., SMB connections from the beachhead).
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the vulnerable hosts and IPs found. If no malicious activity was identified, note the status of unpatched edge vulnerabilities for the vulnerability management team.
```
→ end

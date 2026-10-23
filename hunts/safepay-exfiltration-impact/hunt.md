---
analysis: A standard detection rule for .SafePay files is inherently reactive. This
  hunt uses prevalence counting for staging tools (catching renamed binaries via original
  filename metadata) and correlates them with recovery inhibition behaviors across
  three different surfaces, allowing for intervention before the final payload completes.
blind_spots:
- id: missing-file-telemetry
  question: Was the host encrypted if file auditing was disabled or inhibited?
  requires: EDR file auditing on all endpoints
  risk: SafePay often disables security tools; if the EDR agent's file stream is halted,
    the .SafePay extension signal will be lost.
  stage: impact-encryption-recovery-inhibition
- id: nas-reset-visibility
  question: Did the actor successfully reset the backup storage to factory defaults?
  requires: Audit logs from Network Attached Storage (NAS) devices
  risk: SafePay resets NAS devices to destroy backups; this hunt cannot observe those
    external network actions without native NAS log ingestion.
  stage: impact-encryption-recovery-inhibition
coverage:
- stage: collection-exfiltration-utilities
  status: covered
  steps:
  - rare-exfiltration-tools
- stage: impact-encryption-recovery-inhibition
  status: covered
  steps:
  - recovery-inhibition-lead
  - safepay-file-extension
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
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: SafePay ransomware has affected over 600 victims globally. Detecting
    the staging and impact stages provides the last opportunity to prevent catastrophic
    data loss and full business interruption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries have staged data using rare archival or cloud-sync tools and
  are now inhibiting system recovery by deleting shadow copies before executing a
  ransomware payload that renames user files to include the .SafePay extension.
labels:
- hunt
- attack.t1560.001
- attack.t1048
- attack.t1567.002
- attack.t1486
- attack.t1490
- attack.t1070.004
- defense evasion
- discovery
- exfiltration
- impact
- initial access
- lateral movement
- persistence
- privilege escalation
name: 'SafePay Ransomware: Exfiltration and Impact'
parameters:
  exfil_tools:
    default:
    - 7z.exe
    - winrar.exe
    - rclone.exe
    - filezilla.exe
    - winscp.exe
    - b2.exe
    description: Filenames and original filenames of exfiltration and archival tools
      used by SafePay actors.
    from:
      kind: article
      observed: '2026-10-20'
      ref: AA26-293A
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-20'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the search; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-10-20'
      ref: analyst-scoping
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
rationale: Prioritize servers hosting sensitive data, backup storage controllers,
  and administration workstations. SafePay typically inhibits recovery before the
  final encryption phase.
references:
- name: 'CISA AA26-293A: #StopRansomware: SafePay Ransomware'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a
related:
- hunt: safepay-initial-access-and-lateral-movement
  reason: Initial access and lateral movement phases require identity and network-listener
    surfaces that are handled in a separate hunt.
  relation: out-of-scope-alternative
- hunt: safepay-discovery-lateral-movement
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
  index: 3
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
tlp: clear
type: investigation
---


# SafePay Ransomware: Exfiltration and Impact

SafePay ransomware, active since August 2024, follows a high-velocity chain from data collection to encryption. This hunt focuses on the high-impact finale: data exfiltration and the destructive impact phase. It identifies the use of archival and sync tools (RClone, FileZilla, B2) that are rare across the fleet—leveraging original filename metadata to catch renamed binaries—and correlates them with attempts to inhibit recovery by deleting shadow copies. Finally, it looks for the characteristic file renaming activity that appends the .SafePay extension. The hunt follows a funnel flow, using recovery inhibition as a scoping lead before fanning out to parallel behavioral and prevalence checks.

## recovery-inhibition-lead
<!-- Lead: Shadow copy deletion and recovery inhibition -->
Identify hosts where system recovery mechanisms are being disabled, a common precursor to ransomware encryption. Ordering by time and host allows the analyst to see the sequence of destructive commands.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing vssadmin or wbadmin being used to delete backup data, sequenced
  by host. This narrows the hunt to hosts at immediate risk of impact.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ((LOWER(process_name) LIKE '%\\vssadmin.exe' AND LOWER(process_cmd_line) LIKE '%delete%') OR (LOWER(process_name) LIKE '%\\wbadmin.exe' AND LOWER(process_cmd_line) LIKE '%delete%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY device_hostname, time
```

## parallel-corroboration
<!-- Corroborate tools and encryption -->
parallel:
- → rare-exfiltration-tools
- → safepay-file-extension
join: → agent-triage

## rare-exfiltration-tools
<!-- Rare archival and exfiltration tools -->
Find tools like RClone or FileZilla using both robust basename matching and original filename metadata to detect renamed binaries. Stack-counting identifies which tools are rare and thus suspicious.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, exfil_tools=exfil_tools, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Execution of archival tools on five or fewer hosts. Matching against original
  filename catches cases where SafePay actors renamed RClone or FileZilla to evade
  filename filters.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_original_file_name
  rare_below: 5
reads:
- process_name
- process_original_file_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT LOWER(process_name) AS tool_path, process_original_file_name, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR LOWER(process_name) LIKE '%\\7z.exe' OR LOWER(process_name) LIKE '%\\winrar.exe' OR LOWER(process_name) LIKE '%\\rclone.exe' OR LOWER(process_name) LIKE '%\\filezilla.exe' OR LOWER(process_name) LIKE '%\\winscp.exe' OR LOWER(process_name) LIKE '%\\b2.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY tool_path, process_original_file_name HAVING host_count <= 5 ORDER BY host_count, runs
```

## safepay-file-extension
<!-- SafePay ransomware extension activity -->
Locate the primary indicator of encryption: the creation or renaming of files to the .SafePay extension. Including activity_id 5 catches mass renames typical of encryption.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A burst of file renames or creations with the .safepay extension. Zero results
  suggests the impact stage has not yet triggered or is not visible on enrolled hosts.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
- activity_id
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%.safepay' AND activity_id IN (1, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage ransomware staging and impact -->
```agent target=hunter
cite: required
context:
- recovery-inhibition-lead
- rare-exfiltration-tools
- safepay-file-extension
max_iterations: 5
objective: Decide whether the evidence supports a diagnosis of SafePay ransomware
  activity, specifically identifying hosts where recovery inhibition (shadow deletion)
  or exfiltration tool usage preceded .SafePay file activity.
success_criteria: A verdict of malicious for hosts with .SafePay files or shadow copy
  deletions combined with rare archival tools.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host based on mass file renames or backup deletion" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not reboot or power down. Preserve memory if possible before forensic imaging.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the hosts flagged for rare tools and recovery inhibition. Cross-reference with authorized IT maintenance windows. If legitimate archival software is found, update the rare_exfiltration_tools parameter to exclude it.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document all confirmed malicious activity. Record the time between exfiltration tool usage and encryption start to help tune future detection latency. Note any hosts that were scoped but lacked file telemetry.
```
→ end

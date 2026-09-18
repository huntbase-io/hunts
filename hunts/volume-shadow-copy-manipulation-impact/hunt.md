---
analysis: 'While static rules can catch ''vssadmin delete shadows'', this hunt adds
  context: it correlates the VSS command with specific file access (ntds.dit) and
  fleet-wide rarity of the calling process, distinguishing legitimate RMM tools from
  attackers.'
blind_spots:
- id: vss-api-evasion
  owner: Endpoint Security Team
  question: Was VSS manipulated via direct Win32 API calls rather than command-line
    tools?
  remediation: Ingest Windows Event Log 13 (VSS service started) and 8224 (VSS provider
    activity).
  requires: Microsoft-Windows-VSS event logs or hb_api_activity
  risk: Sophisticated actors using direct API calls (e.g., via PowerShell or custom
    C++ binaries) bypass CLI-based detection rules entirely.
  stage: vss-credential-access
- id: event-suppression-during-churn
  owner: Detection Engineering
  question: Did the endpoint agent drop file activity events during a period of massive
    disk I/O?
  remediation: Monitor agent performance metrics for 'dropped events' during high-churn
    detection windows.
  requires: hb_file_activity with zero dropped-event indicator
  risk: Mass encryption is exceptionally noisy; if the agent suppresses events to
    maintain system performance, the 'total_events' count may fall below the hunt
    threshold.
  stage: ransomware-encryption
coverage:
- stage: vss-credential-access
  status: covered
  steps:
  - vss-tool-execution
  - ntds-access
- stage: vss-recovery-inhibition
  status: covered
  steps:
  - vss-tool-execution
- stage: ransomware-encryption
  status: covered
  steps:
  - file-churn-baseline
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: initial-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: lateral-movement-psexec
  status: out_of_scope
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: internal-reconnaissance
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Volume Shadow Copies are a primary target for ransomware operators
    and a quiet vector for credential theft. Ensuring these features are not being
    manipulated by unauthorized processes is a critical security obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is abusing the Volume Shadow Copy Service (VSS) to either
  extract the Active Directory database (ntds.dit) for credential theft or delete
  recovery points to prevent rollback before encrypting data.
labels:
- hunt
- attack.t1490
- attack.t1486
- attack.t1003.003
name: Volume Shadow Copy Manipulation and Impact
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: article
      observed: '2026-09-14'
      ref: huntress-vss-abuse
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to scope; leave empty for the entire Windows server
      fleet.
    from:
      kind: manual
      observed: '2026-09-14'
      ref: analyst-entry
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/vss-abuse-explained
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on domain controllers and high-value servers (DB, File). Use the
  scope_hosts parameter to narrow the behavior queries if the estate is very large.
references:
- name: "Huntress \u2014 How Attackers Abuse VSS, and How Huntress Detects It"
  url: https://www.huntress.com/blog/vss-abuse-explained
related:
- hunt: lateral-movement-psexec-hunting
  reason: PsExec is frequently used to launch VSS tools on remote domain controllers;
    that hunt handles the remote execution vector.
  relation: precedes
- hunt: vss-abuse-precursors-exploitation-lateral-movement
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Application
    observables:
    - Exploitation of internet-facing host
    - Vulnerability exploitation in web servers or databases
    slug: initial-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Lateral Movement via SMB and PsExec
    observables:
    - PsExec usage
    - Spawning of SYSTEM-level command shell processes
    - Activity on domain controllers
    slug: lateral-movement-psexec
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: Session and Network Reconnaissance
    observables:
    - Enumeration of active Remote Desktop sessions
    - DNS enumeration commands
    - Reconnaissance against additional network hosts
    slug: internal-reconnaissance
    tactic: discovery
    techniques:
    - T1021.001
  - name: Credential Access via Shadow Copy
    observables:
    - vssadmin create shadow
    - Extraction of ntds.dit from volume shadow copy
    slug: vss-credential-access
    tactic: credential-access
    techniques:
    - T1490
  - name: Inhibit System Recovery via Shadow Deletion
    observables:
    - vssadmin delete shadows /all /quiet
    - Deletion of shadow copies following credential extraction
    slug: vss-recovery-inhibition
    tactic: impact
    techniques:
    - T1490
  - name: Data Encrypted for Impact
    observables:
    - Mass file encryption
    - Ransomware detonation
    slug: ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Attackers leverage Volume Shadow Copy (VSS) to facilitate credential theft
    by creating shadows to extract the NTDS.dit database or to inhibit recovery by
    deleting shadows prior to ransomware deployment. These techniques are often preceded
    by lateral movement using tools like PsExec and internal reconnaissance against
    domain controllers.
series:
  index: 2
  slug: how-attackers-abuse-vss-and-how-huntress-detects-it
  title: How Attackers Abuse VSS, and How Huntress Detects It
  total: 2
severity: medium
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


# Volume Shadow Copy Manipulation and Impact

This hunt targets the abuse of Windows VSS infrastructure as described in recent threat research. It begins by identifying the Windows server estate, specifically targeting Domain Controllers and critical servers. It then monitors for suspicious command-line invocations of vssadmin or wmic used to create or delete shadow copies. To distinguish between administrative tasks and malicious activity, the hunt corroborates these leads by checking for direct file access to ntds.dit within shadow copy paths (the credential theft path) and identifying rare processes performing high-volume file modifications indicative of ransomware. A triage agent then correlates these findings across process lineage and time windows to provide a definitive verdict.

## scope-to-servers
<!-- Identify Windows Servers and DCs -->
Focus the hunt on Windows systems where NTDS.dit extraction or mass encryption would have the highest business impact.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames identifying the server estate. Silence means no Windows
  servers were seen in the lookback window.
reads:
- hostname
- os_name
- ip_address
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, os_name, ip_address FROM hb_devices WHERE platform = 'windows' AND (LOWER(os_name) LIKE '%server%' OR LOWER(hostname) LIKE '%dc%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## vss-tool-execution
<!-- Suspicious VSS CLI Manipulation -->
Find command-line invocations of vssadmin or wmic that specifically create or delete shadow copies.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes launching VSS commands. Deletion with '/quiet' or creation by
  unusual parents (like PsExec or cmd) are high-priority leads.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND ((LOWER(process_name) LIKE '%vssadmin.exe' AND (LOWER(process_cmd_line) LIKE '%create%shadow%' OR LOWER(process_cmd_line) LIKE '%delete%shadows%')) OR (LOWER(process_name) LIKE '%wmic.exe' AND LOWER(process_cmd_line) LIKE '%shadowcopy%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate VSS Intent -->
parallel:
- → ntds-access
- → file-churn-baseline
join: → vss-triage

## ntds-access
<!-- Credential Database Access via Shadow Copy -->
Identify processes accessing the Active Directory database (ntds.dit) through a volume shadow copy path.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any row showing a process reading ntds.dit from a 'HarddiskVolumeShadowCopy'
  path is an immediate indicator of credential theft.
reads:
- device_hostname
- process_name
- file_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND LOWER(file_name) = 'ntds.dit' AND LOWER(file_path) LIKE '%shadowcopy%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## file-churn-baseline
<!-- High-Volume Rare Process File Churn -->
Identify rare processes performing high-volume file updates or deletions, characteristic of ransomware.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process rare in the fleet but generating hundreds of file events on a
  single host. Known backup agents will have a high 'affected_hosts' count and can
  be ignored.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS affected_hosts, COUNT(*) AS total_events, MIN(time) AS first_seen FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND activity_id IN (3, 4, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING affected_hosts < 3 AND total_events > 500 ORDER BY total_events DESC
```

## vss-triage
<!-- Triage VSS Activity and Correlated Signals -->
```agent target=hunter
cite: required
context:
- vss-tool-execution
- ntds-access
- file-churn-baseline
max_iterations: 4
objective: Determine if the observed VSS manipulation on a host is part of an active
  attack. Look for temporal proximity (within 1 hour) between VSS tool execution and
  either ntds.dit access or high-volume file churn. Distinguish from legitimate backup
  software by checking the process name and affected host count.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  process paths and timestamps.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is 'malicious' for at least one host involving either access to ntds.dit or mass file churn" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-incident-review
unavailable: → analyst-incident-review (blind_spot: vss-api-evasion)
else: → analyst-incident-review

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR. Proceed to collect memory artifacts and specifically the ntds.dit file if theft was indicated.
```
→ analyst-incident-review

## analyst-incident-review
<!-- Analyst Review and Close-out -->
```manual target=analyst
Review the agent's cited evidence. If the 'malicious' verdict was triggered by an unauthorized but known admin tool, update the whitelist. If the verdict was benign but the activity is high-volume, consider refining the churn threshold.
```
→ end

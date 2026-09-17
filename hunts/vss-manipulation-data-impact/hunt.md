---
analysis: A single rule on shadow deletion is too noisy due to legitimate IT maintenance.
  This hunt pivots to prevalence and corroborates with targeted file telemetry to
  reduce false positives.
blind_spots:
- id: short-file-retention
  question: Did encryption occur several days after the shadow copy was deleted?
  requires: extended retention of hb_file_activity
  risk: Corroboration of mass encryption may be lost if file activity logs are purged
    before the hunt runs.
  stage: data-encryption-impact
- id: vss-api-abuse
  question: Was VSS manipulated without calling known administrative binaries?
  requires: COM/API level event logging for VSS
  risk: Custom tools that interact directly with Volume Shadow Copy COM interfaces
    will bypass process-based detection.
  stage: vss-deletion-and-inhibition
coverage:
- stage: vss-creation-for-credentials
  status: covered
  steps:
  - vss-manipulation-commands
  - ntds-extraction-attempts
- stage: vss-deletion-and-inhibition
  status: covered
  steps:
  - vss-manipulation-commands
  - vss-parent-rarity
- stage: data-encryption-impact
  status: covered
  steps:
  - mass-file-activity
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: lateral-movement-psexec
  status: out_of_scope
- reason: Belongs to another part of the 'How Attackers Abuse VSS, and How Huntress
    Detects It' series.
  stage: host-and-session-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries targeting VSS are explicitly attempting to bypass recovery
    controls or steal core identity data. Confirming its absence provides high confidence
    that these high-impact playbooks are not active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is creating Volume Shadow Copies to steal Active Directory
  databases or deleting them to prevent ransomware recovery.
labels:
- hunt
- attack.t1003.003
- attack.t1490
- attack.t1486
name: VSS Manipulation and Data Impact
parameters:
  file_touch_threshold:
    default: '500'
    description: Minimum count of file modifications/deletions on a single host to
      signal ransomware activity.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scoping_hosts:
    default: []
    description: List of hostnames from the scoping step; leave empty to scan all
      Windows hosts.
    type: list[host]
  vss_hosts:
    default: []
    description: List of hostnames where VSS manipulation was detected; mandatory
      for corroboration steps.
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
    model: hb_google/gemini-3-flash-preview
rationale: Start with Domain Controllers and high-value File Servers. Populate 'scoping_hosts'
  with the identified Windows systems to focus subsequent analysis.
references:
- name: "Huntress \u2014 VSS Abuse Explained"
  url: https://www.huntress.com/blog/vss-abuse-explained
related:
- hunt: lateral-movement-psexec
  reason: Lateral movement is the precursor; this hunt focuses on the subsequent VSS
    and data impact phase.
  relation: out-of-scope-alternative
- hunt: remote-admin-discovery-recon
  relation: follows
scenario:
  stages:
  - name: Lateral Movement via PsExec
    observables:
    - PsExec spawning SYSTEM-level command shell
    - psexec.exe
    - cmd.exe
    slug: lateral-movement-psexec
    tactic: lateral-movement
    techniques:
    - T1021.002
  - name: Session and Network Reconnaissance
    observables:
    - Enumeration of active Remote Desktop sessions
    - DNS enumeration commands
    - Reconnaissance against remote hosts
    - qwinsta.exe
    slug: host-and-session-discovery
    tactic: discovery
    techniques:
    - T1021.001
  - name: Shadow Copy Creation
    observables:
    - vssadmin create shadow
    - ntds.dit extraction
    - vssadmin.exe
    slug: vss-creation-for-credentials
    tactic: credential-access
    techniques:
    - T1003.003
  - name: Inhibit System Recovery
    observables:
    - vssadmin delete shadows /all /quiet
    - vssadmin.exe
    - Blocked attempts to delete shadow copies
    slug: vss-deletion-and-inhibition
    tactic: impact
    techniques:
    - T1490
  - name: Data Encrypted for Impact
    observables:
    - Encryption of local files
    - Ransomware detonation
    slug: data-encryption-impact
    tactic: impact
    techniques:
    - T1486
  summary: Attackers exploit Windows Volume Shadow Copy (VSS) for both credential
    theft and ransomware protection. By creating shadow copies, they can perform offline
    extraction of sensitive files like the Active Directory database (ntds.dit), and
    by deleting them, they prevent victims from using local snapshots to recover from
    ransomware encryption.
series:
  index: 2
  slug: how-attackers-abuse-vss-and-how-huntress-detects-it
  title: How Attackers Abuse VSS, and How Huntress Detects It
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
tlp: clear
type: investigation
---


# VSS Manipulation and Data Impact

This hunt identifies the abuse of the Volume Shadow Copy Service (VSS) by correlating the execution of administrative tools with downstream high-impact file activity. It first identifies the use of vssadmin, ntdsutil, and wmic for shadow copy manipulation and then corroborates these leads by checking for ntds.dit extraction or mass file modifications. By scoping to Windows assets and constraining corroboration to high-signal hosts, the hunt minimizes noise from legitimate backup agents and RMM scripts while ensuring high-performance execution across large fleets.

## windows-asset-inventory
<!-- Identify Windows Assets -->
Focus the hunt on Windows hosts that likely contain VSS capabilities or critical data targets.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames running Windows. Silence indicates no Windows hosts
  are monitored.
reads:
- device_hostname
- vendor_name
- package_name
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(vendor_name) LIKE '%microsoft%' OR LOWER(package_name) LIKE '%windows%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## vss-manipulation-commands
<!-- VSS Manipulation Commands -->
Detect the use of vssadmin, ntdsutil, wmic, or powershell to create or delete shadow copies on the identified Windows assets.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scoping_hosts=scoping_hosts)
~~~yaml
expected: Command lines explicitly manipulating shadow copies. Presence on non-backup
  servers is highly suspicious.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) IN ('vssadmin.exe', 'wmic.exe', 'powershell.exe', 'ntdsutil.exe')) AND LOWER(process_cmd_line) LIKE '%shadow%' AND (instr(',' || '{{scoping_hosts}}' || ',', ',' || device_hostname || ',') > 0 OR '{{scoping_hosts}}' = '') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-impact
<!-- Corroborate with Impact Data -->
parallel:
- → vss-parent-rarity
- → ntds-extraction-attempts
- → mass-file-activity
join: → triage-vss-abuse

## vss-parent-rarity
<!-- Rare VSS Parent Processes -->
Identify unusual initiators of vssadmin.exe that do not match known backup or RMM agent patterns.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A parent process seen on only one or two hosts; suggests a manual command
  or non-standard tool.
prevalence:
  by: device_hostname
  key:
  - parent_process_name
  rare_below: 3
reads:
- parent_process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT parent_process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%vssadmin.exe' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY parent_process_name HAVING host_count <= 2
```

## ntds-extraction-attempts
<!-- Access to NTDS.dit -->
Identify processes interacting with the Active Directory database on hosts where VSS manipulation was already observed.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, vss_hosts=vss_hosts)
~~~yaml
expected: Processes touching the AD database. High-confidence sign of credential theft
  when paired with VSS creation.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%ntds.dit' AND instr(',' || '{{vss_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## mass-file-activity
<!-- Mass File Modification Count -->
Identify targeted hosts experiencing high rates of file updates or deletions, which suggests ransomware encryption follow-on.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, vss_hosts=vss_hosts, file_touch_threshold=file_touch_threshold)
~~~yaml
expected: A significant volume of file touches on a suspicious host. Zero results
  proof nothing without host-level visibility.
reads:
- device_hostname
- activity_id
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, activity_name, COUNT(*) AS touches FROM hb_file_activity WHERE (activity_id IN (3, 4, 5)) AND instr(',' || '{{vss_hosts}}' || ',', ',' || device_hostname || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, activity_name HAVING touches >= {{file_touch_threshold}}
```

## triage-vss-abuse
<!-- Evaluate VSS Abuse Pattern -->
```agent target=hunter
cite: required
context:
- vss-manipulation-commands
- vss-parent-rarity
- ntds-extraction-attempts
- mass-file-activity
max_iterations: 5
objective: Determine if the VSS activity is malicious by linking shadow copy manipulation
  to either ntds.dit extraction or mass file encryption within a 60-minute window.
  Use context from all previous steps.
success_criteria: A per-host verdict (Malicious, Suspicious, Benign) citing specific
  process and file activity rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is 'Malicious' for any host due to confirmed VSS manipulation paired with data impact" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: short-file-retention)
else: → manual-review

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately to halt further encryption or exfiltration.
```
→ manual-review

## manual-review
<!-- Analyst Review -->
```manual target=analyst
Review the process lineage for VSS manipulation; confirm if it was preceded by lateral movement and if ransomware encryption is in progress.
```
→ end

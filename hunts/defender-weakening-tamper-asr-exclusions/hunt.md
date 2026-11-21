---
analysis: Every weakening action is also a routine admin action. The hunt decides
  by comparing each host with the rest of the fleet, by who made the change and with
  what, and by what ran afterwards, which no single rule on a registry write can do.
blind_spots:
- id: extension-not-answering
  owner: Endpoint engineering
  question: Did Defender record anything on hosts where the extension is missing,
    cannot decrypt the database, or Defender is passive behind another antivirus?
  remediation: Deploy the extension through extensions.load on all Windows hosts and
    alert on defender_mpengine_status rows with a non-empty error.
  requires: the defender_mpengine osquery extension loaded by osqueryd (running as
    SYSTEM) on every Windows host, with Microsoft Defender Antivirus as the active
    engine and defender_mpengine_status.error empty
  risk: Those hosts return no rows, which looks the same as a clean host. An attacker
    who has removed or stopped Defender also leaves an empty or stale database.
- id: state-values-undocumented
  question: Does a recorded state mean off, audit or block?
  remediation: Read the values on hosts whose configuration is known and record the
    mapping with this hunt.
  requires: Microsoft documentation of the MpTamperProtectionState and ASR state values
    stored in AttributePersistContext
  risk: 'Values are read as stored. Protokol-7 notes the Tamper Protection record
    cannot be tied to attacker activity on its own: an administrator produces the
    same value.'
  stage: tamper-protection-off
- id: exclusion-timing
  question: When was an exclusion added, and by which process?
  requires: registry change telemetry (Sysmon event 13 or object-access auditing on
    the Defender keys) in hb_registry_activity
  risk: The registry table's mtime is per key, not per value, so one new exclusion
    dates the whole list. Without change telemetry the exclusion is visible but not
    attributable.
  stage: exclusions-added
- id: passive-or-replaced-av
  question: Is a stale database a stopped engine or a host where another antivirus
    is primary?
  requires: Defender as the active antivirus
  risk: With a third-party antivirus, Defender is passive or off and its database
    stops filling legitimately; antivirus_products in defender-engine-state shows
    which.
coverage:
- reason: How the operator obtained administrative rights is outside this hunt; it
    starts at the first change to Defender.
  stage: administrative-access
  status: out_of_scope
- stage: tamper-protection-off
  status: covered
  steps:
  - tamper-protection-state
  - defender-engine-state
- stage: asr-downgrade
  status: covered
  steps:
  - asr-rule-state-changes
  - defender-policy-registry-writes
- stage: exclusions-added
  status: covered
  steps:
  - defender-exclusions-now
  - defender-policy-registry-writes
  - defender-tamper-commands
- stage: payload-and-recovery-inhibition
  status: covered
  steps:
  - execution-after-weakening
  - ransomware-tracking
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: environment-specific
  handoff: promote-to-detection
  justification: An antivirus switched down on one host is the step before encryption
    in most ransomware intrusions, and it is the step that removes the alerts that
    would have caught what follows.
  methodology: structured-hypothesis-driven
  trigger: detection-gap
hypothesis: 'An operator with administrative rights on a Windows host has weakened
  Microsoft Defender before running tooling or ransomware: Tamper Protection off,
  ASR rules moved to audit or off, scan exclusions added, or the engine stopped, on
  one host rather than through fleet policy.'
labels:
- hunt
- attack.t1562.001
- attack.t1112
- attack.t1490
- attack.t1486
- defense evasion
- impact
- privilege escalation
- hb-endpoint-control
name: 'Defender Weakening: Tamper Protection, ASR Rules and Exclusions'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine. Defender keeps roughly two weeks in mpenginedb.db.
    type: number
  scope_hosts:
    default: []
    description: Hosts to focus the follow-up queries on, as osquery reports their
      hostname; empty runs them across the estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase
    org: huntbase.io
  generated:
    by: hand-authored-with-claude
    from: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
    gates:
    - dry-run
    - lint
    model: claude-opus-5-5
rationale: Run across every Windows host; the comparison across the fleet is what
  separates policy from hands-on change. Look first at servers and at hosts with local
  exclusions. Paste the hosts weakening-triage names into scope_hosts before the follow-up
  steps.
references:
- name: "Protokol-7 \u2014 Defender's hidden flight recorder: mpenginedb.db"
  url: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
- name: osquery-defender-extension (defender_mpengine_* tables)
  url: https://github.com/rakeshrm/osquery-defender-extension
- name: "Protokol-7 \u2014 mpenginedb_parser (deleted-row recovery, full timeline)"
  url: https://github.com/Protokol-7/mpenginedb_parser
related:
- hunt: defender-exclusion-abuse
  reason: Goes deeper on exclusions alone, including the setting that hides them from
    local administrators.
  relation: sibling
- hunt: defender-asr-near-miss-follow-through
  reason: ASR rules that stayed on record blocked attempts; that hunt follows them.
  relation: sibling
- hunt: defender-attack-scoring-without-alert
  reason: Reads Defender's attack scoring, which only helps where the engine is still
    running.
  relation: sibling
scenario:
  stages:
  - name: Administrative access on the host
    observables:
    - Local administrator or SYSTEM context
    slug: administrative-access
    tactic: privilege-escalation
    techniques:
    - T1078
  - name: Tamper Protection turned off
    observables:
    - MpTamperProtectionState recorded off in AttributePersistContext
    slug: tamper-protection-off
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: ASR rules moved to audit or off
    observables:
    - AsrRuleStateChangeFor:<guid> records
    - Writes under Windows Defender Exploit Guard\ASR
    - Set-MpPreference -AttackSurfaceReductionRules_Actions
    slug: asr-downgrade
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Scan exclusions added
    observables:
    - Add-MpPreference -ExclusionPath
    - Values under Windows Defender\Exclusions\Paths
    slug: exclusions-added
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1112
  - name: Payload from excluded folder and recovery inhibited
    observables:
    - vssadmin delete shadows
    - wbadmin delete
    - bcdedit recoveryenabled no
    - RansomwareDetections and BackupProcessInfo rows
    slug: payload-and-recovery-inhibition
    tactic: impact
    techniques:
    - T1490
    - T1486
  summary: 'An operator with administrative rights weakens Microsoft Defender on a
    host: Tamper Protection off, ASR rules downgraded, exclusions added or the engine
    stopped. The payload then runs from the excluded location and recovery is inhibited
    before encryption.'
series:
  index: 1
  slug: defender-mpenginedb-flight-recorder
  title: Hunting with Defender's Flight Recorder (mpenginedb.db)
  total: 5
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
  hb-endpoint-control:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: osquery with the Defender MpEngineDb extension (Huntbase Endpoint Control)
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Defender Weakening: Tamper Protection, ASR Rules and Exclusions

Ransomware operators turn Defender down before they deploy. The usual moves are an exclusion for the staging folder, ASR rules switched to audit, Tamper Protection off, or the service stopped. Each one is ordinary admin work when it arrives through Group Policy or Intune, which is why a single rule rarely catches it.

Defender's own database, mpenginedb.db, keeps the engine's view of Tamper Protection and the ASR rule state changes it applied, and it stops filling when the engine stops recording. The defender_mpengine osquery extension decrypts it on each host. This hunt reads that state, adds the live exclusion list from the registry and the registry writes and commands that made the change, and stacks every change across the fleet. A change on one host stands apart from a policy rollout.

Hosts that were weakened by hand are then checked for what usually follows: payloads running from the excluded folders, shadow-copy and backup deletion, and Defender's own ransomware detections and rollback tracking.

## defender-engine-state
<!-- Defender engine state per host -->
Establish which hosts can answer and what state their engine is in. The extension's own status says whether the database decrypted; the newest attack-scoring and path-tag records say whether the engine is still writing; Windows Security Center says whether Defender is the active, up-to-date antivirus. A busy host whose newest record is days old has an engine that stopped recording.

```osquery target=hb-endpoint-control role=scoping
~~~yaml
expected: One row per Windows host. error = '' and quick_check = 'ok' mean the host
  can answer. A non-empty error, a missing Defender entry or a Defender state other
  than On, or newest records far older than checked_at on an active host are findings
  in themselves. A host that returns no row has no extension.
reads:
- db_size
- wal_size
- protection
- key_source
- quick_check
- error
silence: not_evidence_of_absence
source: defender_mpengine_status
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, s.protection, s.key_source, s.quick_check, s.error, s.db_size, s.wal_size, (SELECT MAX(insert_time) FROM defender_mpengine_rolling_queues) AS newest_scoring_record, (SELECT MAX(insert_time) FROM defender_mpengine_persist_context) AS newest_path_record, (SELECT GROUP_CONCAT(name || ' state=' || state || ' sigs=' || signatures_up_to_date, '; ') FROM windows_security_products WHERE type = 'Antivirus') AS antivirus_products, CAST(strftime('%s', 'now') AS INTEGER) AS checked_at FROM defender_mpengine_status s
```

## parallel-weakening-evidence
<!-- Weakening evidence -->
parallel:
- → tamper-protection-state
- → asr-rule-state-changes
- → defender-exclusions-now
- → defender-policy-registry-writes
- → defender-tamper-commands
join: → weakening-triage

## tamper-protection-state
<!-- Tamper Protection state recorded by the engine -->
Read the Tamper Protection state the engine persists. Protokol-7 recovered a record of it set to off from the WAL of a test machine; it is the one place the engine's own view of Tamper Protection is kept outside the registry.

```osquery target=hb-endpoint-control role=enrichment
~~~yaml
expected: One row per host with the recorded state. A state meaning off on a host
  whose policy says on is the lead; the value is stored as Defender wrote it and is
  not documented, so compare it with hosts known to be correct.
reads:
- file_path
- context
- insert_time
- expire_time
silence: not_evidence_of_absence
source: defender_mpengine_persist_context
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, file_path, context AS recorded_state, insert_time, expire_time FROM defender_mpengine_persist_context WHERE file_path = 'MpTamperProtectionState' OR context LIKE '%TamperProtection%'
```

## asr-rule-state-changes
<!-- ASR rule state changes -->
List the attack surface reduction rule state changes the engine recorded. A policy rollout changes the same rule to the same state on hundreds of hosts; an operator switching one rule to audit or off does it on one.

```osquery target=hb-endpoint-control role=baseline
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rule and state pairs shared by most of the fleet are policy. A pair seen
  on fewer than three hosts, especially for the LSASS, Office child-process, PsExec/WMI
  or ransomware rules, is a lead.
prevalence:
  by: device_hostname
  key:
  - asr_rule_name
  - recorded_state
  rare_below: 3
reads:
- context
- record_kind
- asr_rule_id
- asr_rule_name
- insert_time
silence: not_evidence_of_absence
source: defender_mpengine_persist_context
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, asr_rule_id, asr_rule_name, context AS recorded_state, COUNT(*) AS records, MIN(insert_time) AS first_recorded, MAX(insert_time) AS last_recorded FROM defender_mpengine_persist_context WHERE record_kind = 'asr_rule_state' GROUP BY asr_rule_id, asr_rule_name, context
```

## defender-exclusions-now
<!-- Defender exclusions configured now -->
Inventory every path, process, extension and address excluded from scanning, local and policy. Exclusions are not in mpenginedb.db, but the registry holds them and osquery runs as SYSTEM, which can read them. An excluded folder is a folder the engine records nothing about.

```osquery target=hb-endpoint-control role=baseline
~~~yaml
expected: Exclusions shared across a fleet segment are configuration. A local exclusion
  on one or two hosts, or one covering a user-writable folder, a whole drive, a script
  host or an archive extension, is a lead.
prevalence:
  by: device_hostname
  key:
  - excluded_item
  rare_below: 3
reads:
- key
- name
- mtime
silence: not_evidence_of_absence
source: registry
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, key AS exclusion_key, name AS excluded_item, CASE WHEN LOWER(key) LIKE '%\policies\%' THEN 'policy' ELSE 'local' END AS exclusion_source, mtime AS key_last_written FROM registry WHERE (key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\%' OR key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\%') AND name NOT IN ('', '(Default)')
```

## defender-policy-registry-writes
<!-- Writes to Defender policy keys -->
Find who wrote Defender's exclusion, real-time protection, feature and ASR keys, and with what. This gives the time and the writing process that the registry inventory cannot.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Writes by the Group Policy or MDM client across many hosts are policy. A
  write by powershell.exe, reg.exe or an unknown binary on one host is a lead.
reads:
- time
- device_hostname
- actor_user_name
- reg_key_path
- reg_value_name
- reg_value_data
- process_name
- process_cmd_line
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, reg_key_path, reg_value_name, reg_value_data, process_name, process_cmd_line, actor_user_name FROM hb_registry_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(reg_key_path) LIKE '%\windows defender\exclusions\%' OR LOWER(reg_key_path) LIKE '%\windows defender\real-time protection%' OR LOWER(reg_key_path) LIKE '%\windows defender\features%' OR LOWER(reg_key_path) LIKE '%\windows defender exploit guard\asr%' OR (LOWER(reg_key_path) LIKE '%\windows defender%' AND LOWER(reg_value_name) IN ('disableantispyware', 'disableantivirus', 'disablerealtimemonitoring', 'disablebehaviormonitoring', 'disableioavprotection', 'tamperprotection'))) AND LOWER(COALESCE(process_name, '')) NOT LIKE '%\msmpeng.exe'
```

## defender-tamper-commands
<!-- Commands that weaken Defender -->
Catch the commands operators use: Set-MpPreference and Add-MpPreference exclusions or switches, WMI MSFT_MpPreference, MpCmdRun -RemoveDefinitions, stopping WinDefend, and reg.exe edits of Defender keys.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rare outside deployment tooling. An interactive or service account running
  one of these outside a change window is the strongest single signal in this hunt.
reads:
- time
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- integrity_level
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line, integrity_level FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND (((LOWER(process_cmd_line) LIKE '%set-mppreference%' OR LOWER(process_cmd_line) LIKE '%add-mppreference%') AND (LOWER(process_cmd_line) LIKE '%-exclusion%' OR LOWER(process_cmd_line) LIKE '%-disable%' OR LOWER(process_cmd_line) LIKE '%attacksurfacereductionrules_actions%' OR LOWER(process_cmd_line) LIKE '%-mapsreporting%' OR LOWER(process_cmd_line) LIKE '%-submitsamplesconsent%')) OR LOWER(process_cmd_line) LIKE '%msft_mppreference%' OR (LOWER(process_cmd_line) LIKE '%mpcmdrun%' AND LOWER(process_cmd_line) LIKE '%-removedefinitions%') OR ((LOWER(process_name) LIKE '%\sc.exe' OR LOWER(process_name) LIKE '%\net.exe' OR LOWER(process_name) LIKE '%\net1.exe') AND LOWER(process_cmd_line) LIKE '%windefend%') OR ((LOWER(process_name) LIKE '%\reg.exe') AND LOWER(process_cmd_line) LIKE '%windows defender%'))
```

## weakening-triage
<!-- Was Defender weakened, and by whom -->
```agent target=hunter
cite: required
context:
- defender-engine-state
- tamper-protection-state
- asr-rule-state-changes
- defender-exclusions-now
- defender-policy-registry-writes
- defender-tamper-commands
max_iterations: 4
objective: 'For each host, decide whether Defender was weakened in the window and
  how: Tamper Protection recorded off, an ASR rule moved to audit or off, a new exclusion,
  the engine stopped recording, or definitions removed. Treat a change that appears
  on many hosts within a short time and was written by the Group Policy or MDM client
  as policy. Treat a change on one host, made by PowerShell, reg.exe, sc.exe or WMI
  under a user or service account, or an exclusion of a user-writable folder, as hands-on.
  Hosts with no defender-engine-state row are unknown, not clean.'
success_criteria: A per-host list of hands-on weakening with the change, the time,
  the account and the process, citing rows; the hosts to paste into scope_hosts; and
  the hosts that could not answer.
tools:
- endpoint
- hb-endpoint-control
```

## parallel-after-weakening
<!-- What happened after -->
parallel:
- → execution-after-weakening
- → ransomware-tracking
join: → host-verdict

## execution-after-weakening
<!-- Execution and recovery inhibition after the change -->
Look for what weakening is usually for: binaries started from user-writable or excluded-looking folders, and the shadow-copy, backup, boot-recovery and log-clearing commands that come right before encryption.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: 'Recovery-inhibition commands on a weakened host are close to conclusive.
  User-space binaries need the exclusions from defender-exclusions-now to judge: a
  binary running from an excluded folder is the payload the exclusion was made for.'
reads:
- time
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(process_cmd_line) LIKE '%vssadmin%delete%shadows%' OR LOWER(process_cmd_line) LIKE '%shadowcopy%delete%' OR LOWER(process_cmd_line) LIKE '%wbadmin%delete%' OR LOWER(process_cmd_line) LIKE '%bcdedit%recoveryenabled%no%' OR LOWER(process_cmd_line) LIKE '%wevtutil%cl %' OR LOWER(process_cmd_line) LIKE '%cipher%/w%') OR (LOWER(process_name) LIKE '%\users\%' OR LOWER(process_name) LIKE '%\programdata\%' OR LOWER(process_name) LIKE '%\windows\temp\%' OR LOWER(process_name) LIKE '%\perflogs\%' OR LOWER(process_name) LIKE '%\$recycle.bin\%'))
```

## ransomware-tracking
<!-- Defender's ransomware detections and rollback tracking -->
Read what the engine itself concluded about ransomware on these hosts: detections with their remediation timeline, and the files and processes it started tracking for rollback.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any detection row is serious. Rollback tracking of a binary from a user-writable
  path on a weakened host means the engine suspected it even with protection reduced.
reads:
- detection_guid
- detection_time
- remediation_complete_time
- instance_time
- impacted_cbp_namespaces
silence: not_evidence_of_absence
source: defender_mpengine_ransomware_detections
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, 'detection' AS record, detection_guid AS item, detection_time AS event_time, remediation_complete_time AS remediated_at, impacted_cbp_namespaces FROM defender_mpengine_ransomware_detections WHERE detection_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || (SELECT hostname FROM system_info) || ',') > 0) UNION ALL SELECT (SELECT hostname FROM system_info) AS device_hostname, 'rollback_tracking' AS record, file_path AS item, instance_time AS event_time, NULL AS remediated_at, impacted_cbp_namespaces FROM defender_mpengine_backup_process_info WHERE instance_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || (SELECT hostname FROM system_info) || ',') > 0)
```

## host-verdict
<!-- Host verdict -->
```agent target=hunter
cite: required
context:
- weakening-triage
- execution-after-weakening
- ransomware-tracking
max_iterations: 4
objective: 'For each host from weakening-triage, decide whether the weakening was
  followed by attacker activity: recovery-inhibition commands, binaries running from
  excluded or user-writable folders, or Defender ransomware detections and rollback
  tracking. Order each host''s evidence in time from the weakening onwards.'
success_criteria: A verdict of malicious, suspicious or benign per host, with a timeline
  that cites rows from each step.
tools:
- endpoint
- hb-endpoint-control
```

## route-on-verdict
<!-- Route on verdict -->
if~: "host-verdict finds at least one host where Defender was weakened by a change that is not fleet policy" (confidence: high, judge=hunter)
then: → restore-defender-and-isolate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: extension-not-answering)
else: → close-out

## restore-defender-and-isolate
<!-- Isolate and restore protection -->
```action target=endpoint
~~~yaml
approval: required
~~~
Copy C:\ProgramData\Microsoft\Windows Defender\Scans off the host first; the steps below change the records this hunt read. Isolate the host. Remove the exclusions that are not in the approved baseline, set the changed ASR rules back to block, turn Tamper Protection on from the management console, and run a full scan with current definitions.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Check every weakened host against the change and deployment records for the window. For hands-on changes, find the account's other logons and run defender-tamper-commands across the estate for that account. Decrypt the copied Scans folder with the extension's --decrypt mode or Protokol-7's mpenginedb_parser, which also recovers deleted rows such as an earlier Tamper Protection state.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record weakened hosts and outcomes. Add approved exclusions to a baseline list so the next run shows only new ones. Schedule the pack queries defender_mpengine_tamper_protection and defender_mpengine_asr_rule_state with removed: true so state changes are logged as they happen, and alert on defender-tamper-commands.
```
→ end

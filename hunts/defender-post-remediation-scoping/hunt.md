---
analysis: The sweep values do not exist until the remediated host's records are read,
  and deciding whether a hash-cache hit means present, past or nothing takes the process
  and registry context around it.
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
- id: remediation-caches-unverified
  question: What did the malware change that Defender put back?
  requires: SystemRegistryCache and SystemFileCache rows from real remediations, and
    a decoder checked against them
  risk: These tables were empty on every host the extension was tested on; their columns
    follow the live schema but no real row has been decoded yet, and reg_operation
    is undocumented. Treat the step as best effort.
  stage: persistence-set
- id: hash-cache-has-no-path
  question: Where on disk was the file the hash cache remembers?
  requires: MFT or USN journal data to resolve volume serial and MFT entry to a path
  risk: The hash cache proves a host held the file, not where or when it went, and
    covers only files real-time protection scanned in about the last two weeks.
  stage: attacker-cleanup
- id: detection-forwarding
  question: Which hosts did Defender remediate?
  requires: Defender detections (events 1116/1117 or MDE alerts) in hb_detection_finding
  risk: Without forwarding the scoping step is empty; run threat-records-on-host across
    the estate instead.
coverage:
- stage: payload-on-disk
  status: covered
  steps:
  - threat-records-on-host
  - fleet-hash-cache-sweep
  - fleet-process-hash-sweep
- stage: persistence-set
  status: covered
  steps:
  - registry-values-restored
  - fleet-persistence-sweep
  - rare-autostart-values
- stage: system-file-tamper
  status: covered
  steps:
  - system-files-restored
- stage: spread-to-other-hosts
  status: covered
  steps:
  - fleet-hash-cache-sweep
  - fleet-process-hash-sweep
  - fleet-persistence-sweep
- stage: attacker-cleanup
  status: covered
  steps:
  - fleet-hash-cache-sweep
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: environment-specific
  handoff: keep-as-periodic-hunt
  justification: A remediation on one host is the cheapest lead an organisation gets,
    and treating it as the end of the incident is how the same malware stays on the
    hosts Defender missed.
  methodology: structured-hypothesis-driven
  trigger: incident-followup
hypothesis: Malware that Microsoft Defender remediated on one host also reached other
  hosts where Defender did not detect it or where the attacker deleted it first, and
  its persistence and file hashes are recoverable from Defender's remediation and
  hash caches.
labels:
- hunt
- attack.t1070.004
- attack.t1547.001
- attack.t1543.003
- attack.t1570
- defense evasion
- execution
- lateral movement
- persistence
- hb-endpoint-control
name: 'After Defender Remediates: What Changed and Where Else It Is'
parameters:
  artefact_hashes:
    default: []
    description: SHA-256, SHA-1 or MD5 of the remediated files, from artefact-extraction.
    from:
      kind: incident
      ref: artefact-extraction step of this hunt
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of history to examine. Defender keeps roughly two weeks in mpenginedb.db.
    type: number
  persistence_value_names:
    default: []
    description: Registry value names the malware set, from artefact-extraction.
    type: list[string]
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
rationale: Run after any Defender remediation of a trojan, backdoor or hacktool, not
  adware. Paste the remediated hosts into scope_hosts for the first parallel steps,
  then fill artefact_hashes and persistence_value_names from artefact-extraction before
  the fleet sweep, which runs across the whole estate.
references:
- name: "Protokol-7 \u2014 Defender's hidden flight recorder: mpenginedb.db"
  url: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
- name: osquery-defender-extension (defender_mpengine_* tables)
  url: https://github.com/rakeshrm/osquery-defender-extension
- name: "Protokol-7 \u2014 mpenginedb_parser (deleted-row recovery, full timeline)"
  url: https://github.com/Protokol-7/mpenginedb_parser
related:
- hunt: defender-weakening-tamper-asr-exclusions
  reason: An exclusion or a stopped engine is a common reason Defender missed the
    other hosts.
  relation: sibling
scenario:
  stages:
  - name: Malware written and run
    observables:
    - Detected file
    - RecentThreatsOnMachine entries
    slug: payload-on-disk
    tactic: execution
    techniques:
    - T1204.002
  - name: Persistence set in the registry
    observables:
    - Run, Winlogon or service values in SystemRegistryCache old_data
    slug: persistence-set
    tactic: persistence
    techniques:
    - T1547.001
    - T1543.003
  - name: System files patched
    observables:
    - SystemFileCache infected and clean hashes
    slug: system-file-tamper
    tactic: persistence
  - name: Spread to other hosts
    observables:
    - Same hash or persistence value on other hosts
    slug: spread-to-other-hosts
    tactic: lateral-movement
    techniques:
    - T1570
  - name: Attacker deletes files
    observables:
    - Hash in FileHashes with no file on disk
    slug: attacker-cleanup
    tactic: defense-evasion
    techniques:
    - T1070.004
  summary: Malware lands on several hosts, sets persistence and may patch system files.
    Defender detects and remediates it on one host; on others it is missed or the
    attacker deletes the files first.
series:
  index: 5
  slug: defender-mpenginedb-flight-recorder
  title: Hunting with Defender's Flight Recorder (mpenginedb.db)
  total: 5
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


# After Defender Remediates: What Changed and Where Else It Is

When Defender reports a threat as remediated, the usual response stops there. But the same file often arrived on other hosts, where a different variant, an exclusion or the attacker's own clean-up kept it from being detected. Defender's database, mpenginedb.db, holds what is needed to check: the registry values and system files remediation changed, with the malicious values and hashes, the engine's threat records, and a hash cache of files it scanned that keeps entries after the file is deleted.

This hunt starts from Defender's remediations, reads those records on the remediated hosts through the defender_mpengine osquery extension, and has an agent turn them into hashes and registry values. It then sweeps the fleet for them: the hash cache on every host, process telemetry, registry telemetry, and a count of rare autostart values for persistence that was renamed.

The outcome is a list of hosts where the malware is still present, hosts where it was and is gone, and remediated hosts where it came back.

## remediated-detections
<!-- Defender remediations in the window -->
Start from what Defender cleaned: its detections in the window, with the threat, the file and the outcome. These hosts are the starting point.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Detections with a remediated or quarantined disposition. Paste their hosts
  into scope_hosts. Empty when Defender detections are not forwarded; run the next
  step across the estate instead.
reads:
- time
- provider
- finding_title
- finding_status
- disposition
- malware_name
- file_path
- process_path
- user_name
- device_hostname
- metadata_product
silence: not_evidence_of_absence
source: hb_detection_finding
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, malware_name, finding_title, file_path, process_path, disposition, finding_status, user_name FROM hb_detection_finding WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(COALESCE(metadata_product, '')) LIKE '%defender%' OR LOWER(COALESCE(provider, '')) LIKE '%defender%')
```

## parallel-what-changed
<!-- What the malware changed -->
parallel:
- → threat-records-on-host
- → registry-values-restored
- → system-files-restored
join: → artefact-extraction

## threat-records-on-host
<!-- Threats and dropped executables on the host -->
Read the engine's own threat records and the executables it saw dropped and run, which name the process images involved even when the detection did not.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Behavior:Win32/... names with the image they were raised against, and dropped
  paths. Images other than the detected file are part of the chain.
reads:
- queue_type
- entry_key
- entry_value
- pid
- process_start
- insert_time
silence: not_evidence_of_absence
source: defender_mpengine_rolling_queues
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, queue_type, entry_key, pid, process_start, CASE WHEN json_valid(entry_value) THEN json_extract(entry_value, '$.Process_Img') END AS image, insert_time FROM defender_mpengine_rolling_queues WHERE queue_type IN ('recent_threats', 'dropped_executable') AND insert_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || (SELECT hostname FROM system_info) || ',') > 0)
```

## registry-values-restored
<!-- Registry values Defender put back -->
Read the registry values remediation changed, before and after. The value before is what the malware wrote: its persistence or configuration.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Run keys, services, Winlogon or policy values with the malicious data in
  old_data. reg_operation is an undocumented code.
reads:
- instance_time
- reg_path
- reg_operation
- old_type_name
- old_data
- old_data_hex
- new_type_name
- new_data
silence: not_evidence_of_absence
source: defender_mpengine_system_registry_cache
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, instance_time, reg_path, reg_operation, old_type_name, old_data, old_data_hex, new_type_name, new_data FROM defender_mpengine_system_registry_cache WHERE instance_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || (SELECT hostname FROM system_info) || ',') > 0)
```

## system-files-restored
<!-- System files Defender restored -->
Read the system files remediation replaced, with the infected and clean hashes.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A patched or replaced Windows binary, with the infected hash to search for
  elsewhere.
reads:
- instance_time
- system_file_path
- infected_file_sha
- clean_file_sha
silence: not_evidence_of_absence
source: defender_mpengine_system_file_cache
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, instance_time, system_file_path, infected_file_sha, clean_file_sha FROM defender_mpengine_system_file_cache WHERE instance_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || (SELECT hostname FROM system_info) || ',') > 0)
```

## artefact-extraction
<!-- Extract the artefacts to sweep for -->
```agent target=hunter
cite: required
context:
- remediated-detections
- threat-records-on-host
- registry-values-restored
- system-files-restored
max_iterations: 4
objective: 'From the detections, threat records, restored registry values and restored
  system files, list the artefacts: file hashes (detected files, infected_file_sha,
  hashes of dropped images where known), registry value names and data the malware
  wrote, and image paths. Note any host where a restored value has the malicious data
  again, which means remediation did not hold.'
success_criteria: Values to paste into artefact_hashes and persistence_value_names,
  citing rows, and the hosts where remediation did not hold.
tools:
- endpoint
- hb-endpoint-control
```

## parallel-fleet-sweep
<!-- Where else -->
parallel:
- → fleet-hash-cache-sweep
- → fleet-process-hash-sweep
- → fleet-persistence-sweep
- → rare-autostart-values
join: → spread-verdict

## fleet-hash-cache-sweep
<!-- Defender's hash cache across the fleet -->
Search every host's real-time protection hash cache for the artefact hashes. The cache keeps hashes of files Defender scanned even after the file is deleted, so it finds hosts where the attacker cleaned up.

```osquery target=hb-endpoint-control role=triage params=(artefact_hashes=artefact_hashes)
~~~yaml
expected: Hosts other than the remediated ones that held an artefact. mft_entry and
  volume_serial locate the file in the MFT; there is no path.
reads:
- instance_time
- volume_serial
- mft_entry
- mft_sequence
- usn
- md5
- sha1
- sha256
silence: not_evidence_of_absence
source: defender_mpengine_file_hashes
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, sha256, sha1, md5, volume_serial, mft_entry, mft_sequence, usn, instance_time FROM defender_mpengine_file_hashes WHERE instr(',' || LOWER('{{artefact_hashes}}') || ',', ',' || LOWER(sha256) || ',') > 0 OR instr(',' || LOWER('{{artefact_hashes}}') || ',', ',' || LOWER(sha1) || ',') > 0 OR instr(',' || LOWER('{{artefact_hashes}}') || ',', ',' || LOWER(md5) || ',') > 0
```

## fleet-process-hash-sweep
<!-- Artefact hashes executing across the fleet -->
Find hosts where an artefact ran, from process telemetry.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, artefact_hashes=artefact_hashes)
~~~yaml
expected: Execution on a host Defender did not remediate.
reads:
- time
- device_hostname
- process_name
- process_cmd_line
- process_hash_sha256
- parent_process_name
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line, process_hash_sha256 FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND instr(',' || LOWER('{{artefact_hashes}}') || ',', ',' || LOWER(process_hash_sha256) || ',') > 0
```

## fleet-persistence-sweep
<!-- The malware's registry values across the fleet -->
Find hosts where the same persistence value names were written.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, persistence_value_names=persistence_value_names)
~~~yaml
expected: The same value names on other hosts. Silence means only that these names
  were not reused; see rare-autostart-values.
reads:
- time
- device_hostname
- actor_user_name
- reg_key_path
- reg_value_name
- reg_value_data
- process_name
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, reg_key_path, reg_value_name, reg_value_data, process_name, actor_user_name FROM hb_registry_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND instr(',' || LOWER('{{persistence_value_names}}') || ',', ',' || LOWER(reg_value_name) || ',') > 0
```

## rare-autostart-values
<!-- Rare autostart values -->
Stack every autostart value written in the window by name and data across the fleet, so renamed persistence from the same family still stands out.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Values whose data has the same shape as the restored ones (same folder,
  same launcher, random-looking names) on other hosts.
prevalence:
  by: device_hostname
  key:
  - value_name
  - reg_value_data
  rare_below: 3
reads:
- time
- device_hostname
- reg_key_path
- reg_value_name
- reg_value_data
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT LOWER(reg_value_name) AS value_name, reg_value_data, COUNT(DISTINCT device_hostname) AS hosts, GROUP_CONCAT(DISTINCT device_hostname) AS host_list, MIN(time) AS first_seen FROM hb_registry_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(reg_key_path) LIKE '%\currentversion\run%' OR LOWER(reg_key_path) LIKE '%\winlogon%' OR LOWER(reg_key_path) LIKE '%\image file execution options\%' OR (LOWER(reg_key_path) LIKE '%\system\currentcontrolset\services\%' AND LOWER(reg_value_name) IN ('imagepath', 'servicedll'))) GROUP BY LOWER(reg_value_name), reg_value_data HAVING COUNT(DISTINCT device_hostname) < 3
```

## spread-verdict
<!-- Spread verdict -->
```agent target=hunter
cite: required
context:
- artefact-extraction
- fleet-hash-cache-sweep
- fleet-process-hash-sweep
- fleet-persistence-sweep
- rare-autostart-values
max_iterations: 4
objective: List every host other than the remediated ones with an artefact hash in
  the Defender hash cache or in process telemetry, the same persistence value, or
  a rare autostart value shaped like the restored ones. For each, say whether the
  artefact is likely still present (running, persistence in place) or was there and
  is gone (hash cache only).
success_criteria: A per-host list of present, past or none, citing rows, and the remediated
  hosts where remediation did not hold.
tools:
- endpoint
- hb-endpoint-control
```

## route-on-verdict
<!-- Route on verdict -->
if~: "spread-verdict finds the malware present on at least one host Defender did not remediate, or remediation did not hold on a remediated host" (confidence: high, judge=hunter)
then: → isolate-and-scan
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: remediation-caches-unverified)
else: → close-out

## isolate-and-scan
<!-- Isolate and rescan -->
```action target=endpoint
~~~yaml
approval: required
~~~
Collect each host's Scans folder, then isolate it and run a full Defender scan with current definitions. Remove persistence values that the scan leaves in place.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
For hosts found only in the hash cache, locate the file in the MFT by volume serial and MFT entry, or the USN journal, to learn its path and when it went. Decrypt the collected Scans folders with Protokol-7's mpenginedb_parser, which recovers rows Defender has since dropped. Find the earliest host and how the malware got there.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the affected hosts and whether each is clean. Keep the artefact hashes and value names with the incident so the sweep can be repeated after the next remediation.
```
→ end

---
analysis: Tags fire on every installer that unpacks to AppData. Separating a payload
  from an updater takes the fleet-wide hash count, the writing process, the signature
  and what the file started.
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
- id: tag-retention
  question: Was an unsigned payload run before the tags expired?
  requires: path tags younger than their expire_time (about two weeks)
  risk: Older drops leave no tag; schedule the pack query to keep them.
  stage: unsigned-execution
- id: tag-semantics
  question: Exactly when does Defender set each tag?
  requires: Microsoft documentation of AttributePersistContext tags
  risk: Meanings are inferred from the names and Protokol-7's observations.
- id: deleted-files
  question: What was a tagged file that has since been deleted?
  requires: the file still on disk, or MFT and USN journal data
  risk: hash and authenticode return nothing for a missing file. Defender's hash cache
    keeps the hash but only an MFT reference, not the path.
- id: signed-payloads
  question: Was the payload signed with a stolen or abused certificate?
  requires: code-signing reputation beyond signed or unsigned
  risk: NoCert tags never fire for signed payloads; only the side-load tag and rarity
    still apply.
- id: module-load-telemetry
  question: Did the signed program actually load the tagged DLL?
  requires: image-load events (Sysmon event 7 or EDR) in hb_module_activity
  risk: Image loads are often not collected for volume; side-loading then rests on
    Defender's tag alone.
  stage: dll-side-loading
coverage:
- reason: The mail, chat or web lure that delivered the file is in mail and proxy
    telemetry; this hunt starts at the file on disk.
  stage: lure
  status: out_of_scope
- stage: payload-delivery
  status: covered
  steps:
  - user-space-pe-writes
  - path-tag-inventory
- stage: unsigned-execution
  status: covered
  steps:
  - tagged-user-space-files
  - dropped-then-executed
  - suspect-image-executions
- stage: dll-side-loading
  status: covered
  steps:
  - tagged-user-space-files
  - sideload-module-loads
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: environment-specific
  handoff: promote-to-detection
  justification: Commodity loaders, ClickFix payloads and side-loaded implants all
    pass through this step, and Defender has already flagged the files on hosts with
    no EDR.
  methodology: structured-hypothesis-driven
  trigger: detection-gap
hypothesis: A loader delivered through a browser download, archive or messaging app
  wrote an unsigned executable, or a DLL beside a signed program, into a user-writable
  folder and ran it, and Defender tagged the file without raising a detection.
labels:
- hunt
- attack.t1105
- attack.t1204.002
- attack.t1574.001
- command and control
- defense evasion
- execution
- initial access
- hb-endpoint-control
name: Unsigned Payloads and DLL Side-Loading Tagged by Defender
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine. Defender keeps roughly two weeks in mpenginedb.db.
    type: number
  pe_path_tags:
    default:
    - NewPECreatedNoCert
    - ExecutedPENoCert
    - BM_IsPotentialSideLoad
    - NewlyCreatedZip
    description: Defender path tags that mark unsigned PEs created or run, likely
      side-loading and new archives. Add tags path-tag-inventory reveals.
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
rationale: Run across all Windows workstations first; servers rarely have user-space
  executables. Paste the hosts staging-triage names into scope_hosts before the module
  and process steps.
references:
- name: "Protokol-7 \u2014 Defender's hidden flight recorder: mpenginedb.db"
  url: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
- name: osquery-defender-extension (defender_mpengine_* tables)
  url: https://github.com/rakeshrm/osquery-defender-extension
- name: "Protokol-7 \u2014 mpenginedb_parser (deleted-row recovery, full timeline)"
  url: https://github.com/Protokol-7/mpenginedb_parser
related:
- hunt: defender-attack-scoring-without-alert
  reason: Reads what Defender scored the payload's process for once it ran.
  relation: sibling
scenario:
  stages:
  - name: Lure
    observables:
    - Link or attachment
    slug: lure
    tactic: initial-access
    techniques:
    - T1566
  - name: Payload written to user space
    observables:
    - NewlyCreatedZip
    - Browser, archive tool or messaging app writing a PE
    slug: payload-delivery
    tactic: command-and-control
    techniques:
    - T1105
  - name: Unsigned payload runs
    observables:
    - NewPECreatedNoCert
    - ExecutedPENoCert
    - RQ_RecentExecDropped queue
    slug: unsigned-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: DLL side-loaded by a signed program
    observables:
    - BM_IsPotentialSideLoad
    - ffmpeg.dll or pcaui.dll in unusual folders
    slug: dll-side-loading
    tactic: defense-evasion
    techniques:
    - T1574.001
  summary: A lure leads a user to download or extract a payload into a user-writable
    folder. The payload is an unsigned executable, or a signed program with a malicious
    DLL beside it, and it runs. Defender tags the files but does not detect them.
series:
  index: 3
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


# Unsigned Payloads and DLL Side-Loading Tagged by Defender

Defender notes things about files that it does not alert on. When an unsigned PE is created it sets NewPECreatedNoCert on the path; when one runs, ExecutedPENoCert; when behaviour monitoring sees a likely side-load, BM_IsPotentialSideLoad; when a new archive appears, NewlyCreatedZip. It also queues executables it saw dropped and then executed. These tags sit in mpenginedb.db for about two weeks.

This hunt reads the tags on every Windows host through the defender_mpengine osquery extension, keeps those in user-writable folders, and adds the file's current hash and signature. Stacking hashes across the fleet removes installers and updaters, and file-write telemetry shows which browser, archive tool or messaging client wrote each one. It first counts every tag the fleet produces, because the tag names are undocumented and others may matter.

Suspect files are then checked for side-loading (an unsigned DLL loaded from the same folder as the signed program loading it) and for what they started, before an agent and an analyst decide.

## path-tag-inventory
<!-- Every path tag Defender wrote -->
Count every path tag the engine set in the window, per host. Microsoft does not document these tags; this shows which ones this fleet produces and how common each is, so a tag that is rare here, or one not yet in pe_path_tags, stands out.

```osquery target=hb-endpoint-control role=baseline params=(lookback_days=lookback_days)
~~~yaml
expected: NewPECreatedNoCert and NewlyCreatedZip on most hosts; ExecutedPENoCert and
  BM_IsPotentialSideLoad on fewer. A tag present on one or two hosts only is worth
  reading in full.
prevalence:
  by: device_hostname
  key:
  - context
  rare_below: 3
reads:
- file_path
- context
- record_kind
- insert_time
silence: not_evidence_of_absence
source: defender_mpengine_persist_context
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, context, COUNT(*) AS tagged_paths, MIN(insert_time) AS first_tagged, MAX(insert_time) AS last_tagged FROM defender_mpengine_persist_context WHERE record_kind = 'path_tag' AND file_path != 'MpTamperProtectionState' AND insert_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) GROUP BY context
```

## tagged-user-space-files
<!-- Tagged files in user-writable folders -->
For each tagged file in a user-writable folder, collect every tag it carries, its current SHA-256 and its signature status. A file that is both NewPECreatedNoCert and ExecutedPENoCert was dropped unsigned and then run; a DLL tagged BM_IsPotentialSideLoad is sitting where a signed program will load it.

```osquery target=hb-endpoint-control role=detection-candidate params=(lookback_days=lookback_days, pe_path_tags=pe_path_tags)
~~~yaml
expected: Installers and updaters unpacking under AppData appear on many hosts with
  the same SHA-256. An unsigned PE created and executed on one or two hosts, or a
  side-load candidate beside a signed binary, is the lead. sha256 is empty when the
  file is gone.
prevalence:
  by: device_hostname
  key:
  - sha256
  rare_below: 3
reads:
- file_path
- context
- record_kind
- insert_time
- path
silence: not_evidence_of_absence
source: defender_mpengine_persist_context
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, t.file_path, GROUP_CONCAT(DISTINCT t.context) AS tags, MIN(t.insert_time) AS first_tagged, MAX(t.insert_time) AS last_tagged, MAX(h.sha256) AS sha256, MAX(a.result) AS signature_result, MAX(a.subject_name) AS signer FROM defender_mpengine_persist_context t LEFT JOIN hash h ON h.path = t.file_path LEFT JOIN authenticode a ON a.path = t.file_path WHERE t.record_kind = 'path_tag' AND t.insert_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400) AND instr(',' || LOWER('{{pe_path_tags}}') || ',', ',' || LOWER(t.context) || ',') > 0 AND (LOWER(t.file_path) LIKE '%\users\%' OR LOWER(t.file_path) LIKE '%\programdata\%' OR LOWER(t.file_path) LIKE '%\windows\temp\%' OR LOWER(t.file_path) LIKE '%\perflogs\%' OR LOWER(t.file_path) LIKE '%\$recycle.bin\%') GROUP BY t.file_path
```

## parallel-delivery-context
<!-- How the files arrived -->
parallel:
- → dropped-then-executed
- → user-space-pe-writes
join: → staging-triage

## dropped-then-executed
<!-- Executables Defender saw dropped and run -->
Read the RQ_RecentExecDropped queues, where the engine lists executables it saw written and then executed.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Paths such as AppData\Local\Temp\7zS...\setup.exe. A path that is also in
  tagged-user-space-files confirms drop-and-run.
reads:
- queue
- queue_type
- entry_key
- insert_time
- expire_time
silence: not_evidence_of_absence
source: defender_mpengine_rolling_queues
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, entry_key AS dropped_path, queue, insert_time, expire_time FROM defender_mpengine_rolling_queues WHERE queue_type = 'dropped_executable' AND insert_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400)
```

## user-space-pe-writes
<!-- Rare executables written to user space -->
Stack every executable or DLL written to a user-writable folder by SHA-256 across the fleet, with the processes that wrote it. A browser, archive tool or messaging client writing a binary seen on fewer than three hosts is how most loaders arrive.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare hashes with the writing process. Browser, 7-Zip, WinRAR, Explorer (zip
  extraction), Teams, Slack, Telegram or Discord as writer marks delivery.
prevalence:
  by: device_hostname
  key:
  - file_hash_sha256
  rare_below: 3
reads:
- time
- device_hostname
- file_path
- file_hash_sha256
- process_name
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT file_hash_sha256, COUNT(DISTINCT device_hostname) AS hosts, GROUP_CONCAT(DISTINCT device_hostname) AS host_list, GROUP_CONCAT(DISTINCT process_name) AS writers, MIN(file_path) AS example_path, MIN(time) AS first_seen FROM hb_file_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(file_path) LIKE '%.exe' OR LOWER(file_path) LIKE '%.dll' OR LOWER(file_path) LIKE '%.scr' OR LOWER(file_path) LIKE '%.cpl') AND (LOWER(file_path) LIKE '%\users\%' OR LOWER(file_path) LIKE '%\programdata\%' OR LOWER(file_path) LIKE '%\windows\temp\%' OR LOWER(file_path) LIKE '%\perflogs\%' OR LOWER(file_path) LIKE '%\$recycle.bin\%') AND file_hash_sha256 IS NOT NULL AND file_hash_sha256 != '' GROUP BY file_hash_sha256 HAVING COUNT(DISTINCT device_hostname) < 3
```

## staging-triage
<!-- Which tagged files were delivered payloads -->
```agent target=hunter
cite: required
context:
- path-tag-inventory
- tagged-user-space-files
- dropped-then-executed
- user-space-pe-writes
max_iterations: 4
objective: 'For each file from tagged-user-space-files, decide whether it looks like
  a delivered payload: unsigned and both created and executed, a side-load candidate
  DLL beside a signed executable, preceded by a NewlyCreatedZip in the same profile,
  listed in dropped-then-executed, and rare across the fleet by SHA-256 or written
  by a browser, archive tool or messaging client. Discount files whose SHA-256 appears
  on many hosts.'
success_criteria: A list of suspect files with host, path, tags, SHA-256 and writer,
  citing rows; the hosts to paste into scope_hosts.
tools:
- endpoint
- hb-endpoint-control
```

## parallel-execution-context
<!-- What the files did -->
parallel:
- → sideload-module-loads
- → suspect-image-executions
join: → staging-verdict

## sideload-module-loads
<!-- Unsigned DLLs loaded from the loader's own folder -->
Confirm side-loading: a process loading a DLL that is not validly signed from the same user-writable folder as its own image.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A signed executable in AppData or ProgramData loading an unsigned DLL from
  its own folder. Protokol-7's examples were ffmpeg.dll and pcaui.dll in uncommon
  places.
reads:
- time
- device_hostname
- module_path
- module_signed
- module_signature_status
- module_signature_subject
- module_hash_sha256
- process_name
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, process_name, module_path, module_signed, module_signature_status, module_signature_subject, module_hash_sha256 FROM hb_module_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(module_path) LIKE '%.dll' AND (LOWER(module_path) LIKE '%\users\%' OR LOWER(module_path) LIKE '%\programdata\%' OR LOWER(module_path) LIKE '%\windows\temp\%' OR LOWER(module_path) LIKE '%\perflogs\%' OR LOWER(module_path) LIKE '%\$recycle.bin\%') AND LOWER(COALESCE(CAST(module_signed AS TEXT), '')) NOT IN ('1', 'true') AND LOWER(rtrim(module_path, replace(module_path, '\', ''))) = LOWER(rtrim(process_name, replace(process_name, '\', '')))
```

## suspect-image-executions
<!-- Execution from user-writable folders -->
Show the user-space images that ran on the suspect hosts, their parents and children, to see what each payload started.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The suspect image with its parent (browser, Explorer, archive tool) and
  the processes it started. Script hosts or LOLBins as children are the next stage.
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
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line, process_hash_sha256 FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(process_name) LIKE '%\users\%' OR LOWER(process_name) LIKE '%\programdata\%' OR LOWER(process_name) LIKE '%\windows\temp\%' OR LOWER(process_name) LIKE '%\perflogs\%' OR LOWER(process_name) LIKE '%\$recycle.bin\%') OR (LOWER(parent_process_name) LIKE '%\users\%' OR LOWER(parent_process_name) LIKE '%\programdata\%' OR LOWER(parent_process_name) LIKE '%\windows\temp\%' OR LOWER(parent_process_name) LIKE '%\perflogs\%' OR LOWER(parent_process_name) LIKE '%\$recycle.bin\%'))
```

## staging-verdict
<!-- Payload verdict -->
```agent target=hunter
cite: required
context:
- staging-triage
- sideload-module-loads
- suspect-image-executions
max_iterations: 4
objective: For each file from staging-triage, decide malicious, suspicious or benign
  from its signature, rarity, writer, side-load evidence and what it started. A vendor
  updater on many hosts is benign; an unsigned, rare DLL loaded by a signed binary
  in AppData that then starts PowerShell is malicious.
success_criteria: A verdict per file and host citing rows from each step.
tools:
- endpoint
- hb-endpoint-control
```

## route-on-verdict
<!-- Route on verdict -->
if~: "staging-verdict finds at least one malicious payload" (confidence: high, judge=hunter)
then: → isolate-and-scan
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: tag-retention)
else: → close-out

## isolate-and-scan
<!-- Isolate and quarantine -->
```action target=endpoint
~~~yaml
approval: required
~~~
Collect the suspect file and the host's Scans folder. Isolate the host, run a Defender custom scan of the file's folder, and quarantine the file if the scan does not.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Check each suspect file's Zone.Identifier stream for its download URL and the messages or mails that delivered it. Search the SHA-256 across the estate, and submit unknown files for analysis.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record findings. Keep the benign SHA-256 values as an allow list, and schedule tagged-user-space-files as a pack query so new rare unsigned payloads surface daily.
```
→ end

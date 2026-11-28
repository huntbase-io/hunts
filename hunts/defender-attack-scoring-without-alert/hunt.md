---
analysis: The attack-scoring rows are by definition below the threshold Defender alerts
  on, and most of them are benign software. Making use of them needs a fleet comparison,
  a check against what did alert, and the process tree around each PID, none of which
  a rule can supply.
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
- id: scoring-queue-ttl
  question: What did Defender score more than an hour ago?
  requires: the pack query defender_mpengine_process_techniques scheduled every 30
    minutes, with its results kept
  risk: Technique queue entries expire after about an hour. A live run sees only the
    last hour, so a burst of activity yesterday leaves no scoring rows.
  stage: credential-access-behaviour
- id: alert-forwarding
  question: Did a scored process alert somewhere this hunt cannot see?
  requires: Defender detections (Defender events 1116/1117 or MDE alerts) in hb_detection_finding
  risk: Without forwarding, 'never alerted' rests on the host's own threat queue only,
    and a process can be marked silent when it did alert.
- id: scoring-semantics
  question: Why was this technique attributed, and how close was it to an alert?
  requires: Microsoft documentation of how attack scoring attributes techniques and
    where the alert threshold sits
  risk: The attribution is Defender's opinion and is not documented; the hunt treats
    it as a lead, never as proof.
coverage:
- stage: suspicious-tool-execution
  status: covered
  steps:
  - scored-processes
  - scored-process-lineage
- stage: credential-access-behaviour
  status: covered
  steps:
  - scored-processes
  - scored-process-file-writes
- stage: persistence-behaviour
  status: covered
  steps:
  - scored-processes
- stage: injection-and-evasion
  status: covered
  steps:
  - scored-processes
  - lowfi-cloud-lookups
- reason: Network connections of the scored process are not examined; pivot to network
    telemetry for confirmed hosts.
  stage: command-and-control
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: environment-specific
  handoff: keep-as-periodic-hunt
  justification: Defender is the only behavioural sensor on many Windows fleets that
    do not license Defender for Endpoint, and its sub-threshold reasoning is otherwise
    thrown away.
  methodology: structured-hypothesis-driven
  trigger: detection-gap
hypothesis: An intruder's tooling on a Windows host performed credential access, injection,
  persistence or defence-evasion behaviour that Microsoft Defender attributed to the
  process as ATT&CK techniques, but stayed below the threshold for a detection, so
  nothing reached Protection History or the SIEM.
labels:
- hunt
- attack.t1003.001
- attack.t1055
- attack.t1059.001
- attack.t1218.011
- attack.t1547.001
- attack.t1053.005
- command and control
- credential access
- defense evasion
- execution
- persistence
- hb-endpoint-control
name: Processes Defender Scored but Never Alerted On
parameters:
  high_signal_techniques:
    default:
    - T1003
    - T1003.001
    - T1055
    - T1055.012
    - T1562.001
    - T1547.001
    - T1053.005
    - T1543.003
    - T1047
    - T1021.002
    - T1218.011
    - T1059.001
    description: ATT&CK techniques that move a scored process up the list when Defender
      attributes them.
    type: list[string]
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
rationale: 'Run across all Windows hosts, as often as practical: the technique queues
  keep about an hour. Where the pack query defender_mpengine_process_techniques has
  been scheduled, run the triage over its stored results for the full lookback. Paste
  the hosts alert-gap-triage names into scope_hosts before the lineage steps.'
references:
- name: "Protokol-7 \u2014 Defender's hidden flight recorder: mpenginedb.db"
  url: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
- name: osquery-defender-extension (defender_mpengine_* tables)
  url: https://github.com/rakeshrm/osquery-defender-extension
- name: "Protokol-7 \u2014 mpenginedb_parser (deleted-row recovery, full timeline)"
  url: https://github.com/Protokol-7/mpenginedb_parser
related:
- hunt: defender-unsigned-payloads-sideloading
  reason: Follows Defender's path tags for the unsigned payloads that scored processes
    often start from.
  relation: sibling
- hunt: defender-weakening-tamper-asr-exclusions
  reason: Checks the engine is running and not weakened, which this hunt depends on.
  relation: sibling
scenario:
  stages:
  - name: Tool or LOLBin executes
    observables:
    - Tech-pid:<pid>,ProcessStart:<filetime> queues
    - Process_Img in a user-writable path
    slug: suspicious-tool-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1218.011
  - name: Credential access behaviour
    observables:
    - T1003.001 attributed to a non-security process
    - .dmp file written
    slug: credential-access-behaviour
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Persistence behaviour
    observables:
    - T1547.001 or T1053.005 attributed
    slug: persistence-behaviour
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Injection and evasion
    observables:
    - T1055 attributed
    - LowFi signature hits
    slug: injection-and-evasion
    tactic: defense-evasion
    techniques:
    - T1055
  - name: Command and control
    observables:
    - Outbound connections from the scored process
    slug: command-and-control
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Tooling runs on a Windows host and performs credential access, injection,
    persistence or defence evasion. Defender attributes ATT&CK techniques to the process
    but stays below its alert threshold, so the activity is recorded only in its attack-scoring
    queues.
series:
  index: 2
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


# Processes Defender Scored but Never Alerted On

Defender does more reasoning than it reports. For each process it keeps a running list of the ATT&CK techniques its behaviour monitoring attributed, for example T1003.001 against a renamed procdump or T1547.001 against a rundll32, and it raises a detection only when the score crosses a threshold. Everything below the threshold stays in the attack-scoring queues of mpenginedb.db and is never shown.

This hunt reads those queues on every Windows host through the defender_mpengine osquery extension, joins each PID to the running process, and stacks the image and technique sets across the fleet so that software scored everywhere drops away. It then removes processes Defender did act on, using the host's own threat records, low-fidelity cloud lookups and the detections forwarded to the SIEM. The rest is a list of processes Defender suspected and never mentioned.

Each of those is put back in its process tree and checked for the files it wrote before an agent and an analyst decide what it was. The queues keep about an hour, so the hunt is most useful run often, or over results the pack query has been collecting.

## scored-processes
<!-- Processes Defender attributed techniques to -->
Read the attack-scoring queues: for each process, the ATT&CK techniques Defender attributed to it or that it inherited from its parent, keyed by PID and start time, joined to the running process where the PID and start time still match. Defender keeps these entries for about an hour, so this is a view of the last hour unless the pack query has been collecting them.

```osquery target=hb-endpoint-control role=baseline params=(high_signal_techniques=high_signal_techniques)
~~~yaml
expected: Installers, updaters and management agents are scored every day and appear
  on many hosts with the same techniques. A user-space image, or a LOLBin with credential-access,
  injection or persistence techniques on one or two hosts, is the lead. live_path
  is empty once the process has exited.
prevalence:
  by: device_hostname
  key:
  - scored_image
  - techniques
  rare_below: 3
reads:
- queue_type
- entry_value
- technique_id
- pid
- process_start
- insert_time
- path
silence: not_evidence_of_absence
source: defender_mpengine_rolling_queues
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, r.pid, r.process_start, CASE WHEN json_valid(r.entry_value) THEN json_extract(r.entry_value, '$.Process_Img') END AS scored_image, COUNT(DISTINCT r.technique_id) AS technique_count, GROUP_CONCAT(DISTINCT r.technique_id) AS techniques, SUM(CASE WHEN instr(',' || LOWER('{{high_signal_techniques}}') || ',', ',' || LOWER(r.technique_id) || ',') > 0 THEN 1 ELSE 0 END) AS high_signal_hits, MAX(CASE WHEN r.queue_type = 'inherited_techniques' THEN 1 ELSE 0 END) AS inherited, MIN(r.insert_time) AS first_scored, MAX(r.insert_time) AS last_scored, p.path AS live_path, p.cmdline AS live_cmdline, p.parent AS live_parent_pid FROM defender_mpengine_rolling_queues r LEFT JOIN processes p ON p.pid = r.pid AND ABS(p.start_time - r.process_start) <= 2 WHERE r.queue_type IN ('techniques', 'inherited_techniques') AND r.technique_id != '' GROUP BY r.pid, r.process_start ORDER BY high_signal_hits DESC, technique_count DESC
```

## parallel-alert-check
<!-- Did Defender say anything -->
parallel:
- → defender-threat-records
- → lowfi-cloud-lookups
- → defender-detections-reported
join: → alert-gap-triage

## defender-threat-records
<!-- Threats Defender recorded on the host -->
Read the RecentThreatsOnMachine queue: the behaviour detections the engine named, with the PID and image they were raised against. A scored process with a threat record was noticed; one without was not.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Behavior:Win32/... names against specific PIDs. Matching pid and process_start
  to scored-processes shows which scored processes Defender did act on.
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
SELECT (SELECT hostname FROM system_info) AS device_hostname, entry_key AS threat_name, pid, process_start, CASE WHEN json_valid(entry_value) THEN json_extract(entry_value, '$.Process_Img') END AS image, insert_time FROM defender_mpengine_rolling_queues WHERE queue_type = 'recent_threats' AND insert_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400)
```

## lowfi-cloud-lookups
<!-- Low-fidelity signature hits sent to the cloud -->
List files that matched a low-fidelity signature and were sent for an asynchronous cloud verdict. These are Defender's maybes; Protokol-7 found hashcat modules here.

```osquery target=hb-endpoint-control role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A LowFi hit on the scored image, or on a file beside it, strengthens the
  lead. Signature sequence numbers are not documented.
reads:
- instance_time
- file_name
- sig_seq
- sig_sha
- sig_is_sync
silence: not_evidence_of_absence
source: defender_mpengine_lowfi_async
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, file_name, sig_seq, sig_sha, sig_is_sync, instance_time FROM defender_mpengine_lowfi_async WHERE instance_time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{lookback_days}} * 86400)
```

## defender-detections-reported
<!-- Defender detections that reached the SIEM -->
List the Defender detections forwarded from these hosts in the window, to tell scored processes that alerted from those that did not.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Detections with a process_path or file_path matching a scored image mean
  the process alerted. No rows from a host with scored processes is either a real
  gap or detections not being forwarded.
reads:
- time
- provider
- finding_title
- severity
- disposition
- malware_name
- file_path
- process_path
- device_hostname
- metadata_product
silence: not_evidence_of_absence
source: hb_detection_finding
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, finding_title, malware_name, file_path, process_path, disposition, severity, metadata_product FROM hb_detection_finding WHERE time >= datetime('now', '-{{lookback_days}} days') AND (LOWER(COALESCE(metadata_product, '')) LIKE '%defender%' OR LOWER(COALESCE(provider, '')) LIKE '%defender%')
```

## alert-gap-triage
<!-- Scored but silent -->
```agent target=hunter
cite: required
context:
- scored-processes
- defender-threat-records
- lowfi-cloud-lookups
- defender-detections-reported
max_iterations: 4
objective: 'For each scored process, decide whether Defender raised anything about
  it: a threat record with the same pid and process_start, a detection on the same
  host for the same image near the same time, or a LowFi hit on the image. Keep those
  with none. Rank them by high_signal_hits, by rarity of the image and technique set
  across the fleet, by whether the image is in a user-writable folder or is a LOLBin,
  and by inherited techniques, which mean a scored parent started it.'
success_criteria: A ranked list of host, pid, start time, image and techniques for
  scored processes with no alert, citing rows; the hosts to paste into scope_hosts.
tools:
- endpoint
- hb-endpoint-control
```

## parallel-scored-context
<!-- What the scored processes did -->
parallel:
- → scored-process-lineage
- → scored-process-file-writes
join: → scored-process-verdict

## scored-process-lineage
<!-- Process lineage on scored hosts -->
Recover parent, command line, user and hash for user-space and LOLBin processes on the scored hosts, including ones that have exited, to put each scored PID in its process tree.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: The scored PID with its parent and command line. An Office, browser or archive-tool
  parent, or an encoded or download command line, supports the lead.
reads:
- time
- device_hostname
- pid
- process_name
- process_cmd_line
- process_hash_sha256
- parent_pid
- parent_process_name
- parent_process_cmd_line
- user_name
- integrity_level
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, pid, parent_pid, parent_process_name, parent_process_cmd_line, process_name, process_cmd_line, user_name, integrity_level, process_hash_sha256 FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(process_name) LIKE '%\users\%' OR LOWER(process_name) LIKE '%\programdata\%' OR LOWER(process_name) LIKE '%\windows\temp\%' OR LOWER(process_name) LIKE '%\perflogs\%' OR LOWER(process_name) LIKE '%\$recycle.bin\%') OR (LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\pwsh.exe' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\wscript.exe' OR LOWER(process_name) LIKE '%\cscript.exe' OR LOWER(process_name) LIKE '%\mshta.exe' OR LOWER(process_name) LIKE '%\rundll32.exe' OR LOWER(process_name) LIKE '%\regsvr32.exe' OR LOWER(process_name) LIKE '%\msbuild.exe' OR LOWER(process_name) LIKE '%\installutil.exe' OR LOWER(process_name) LIKE '%\certutil.exe' OR LOWER(process_name) LIKE '%\bitsadmin.exe' OR LOWER(process_name) LIKE '%\msiexec.exe' OR LOWER(process_name) LIKE '%\curl.exe'))
```

## scored-process-file-writes
<!-- Files written by user-space and LOLBin processes -->
Find the dumps, payloads and scripts these processes wrote. A .dmp written by a process scored for T1003.001 is a credential dump.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Files whose writer matches a scored image. Silence is common where file
  creation is not collected.
reads:
- time
- device_hostname
- file_path
- file_hash_sha256
- process_name
- process_cmd_line
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, process_name, process_cmd_line, file_path, file_hash_sha256 FROM hb_file_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(process_name) LIKE '%\users\%' OR LOWER(process_name) LIKE '%\programdata\%' OR LOWER(process_name) LIKE '%\windows\temp\%' OR LOWER(process_name) LIKE '%\perflogs\%' OR LOWER(process_name) LIKE '%\$recycle.bin\%') OR (LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\pwsh.exe' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\wscript.exe' OR LOWER(process_name) LIKE '%\cscript.exe' OR LOWER(process_name) LIKE '%\mshta.exe' OR LOWER(process_name) LIKE '%\rundll32.exe' OR LOWER(process_name) LIKE '%\regsvr32.exe' OR LOWER(process_name) LIKE '%\msbuild.exe' OR LOWER(process_name) LIKE '%\installutil.exe' OR LOWER(process_name) LIKE '%\certutil.exe' OR LOWER(process_name) LIKE '%\bitsadmin.exe' OR LOWER(process_name) LIKE '%\msiexec.exe' OR LOWER(process_name) LIKE '%\curl.exe')) AND (LOWER(file_path) LIKE '%.dmp' OR LOWER(file_path) LIKE '%.exe' OR LOWER(file_path) LIKE '%.dll' OR LOWER(file_path) LIKE '%.ps1' OR LOWER(file_path) LIKE '%.bat' OR LOWER(file_path) LIKE '%.vbs' OR LOWER(file_path) LIKE '%.js' OR LOWER(file_path) LIKE '%.hta' OR LOWER(file_path) LIKE '%.zip')
```

## scored-process-verdict
<!-- Scored process verdict -->
```agent target=hunter
cite: required
context:
- alert-gap-triage
- scored-process-lineage
- scored-process-file-writes
max_iterations: 4
objective: For each process from alert-gap-triage, decide whether it is malicious,
  suspicious or benign using its lineage, command line, files written and the techniques
  Defender attributed. A signed vendor binary in Program Files scored for the same
  techniques on many hosts is benign; a process that wrote a .dmp after a T1003.001
  attribution is malicious.
success_criteria: A verdict per scored process citing rows from each step, and the
  image and technique pairs judged benign.
tools:
- endpoint
- hb-endpoint-control
```

## route-on-verdict
<!-- Route on verdict -->
if~: "scored-process-verdict finds at least one malicious scored process" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: scoring-queue-ttl)
else: → close-out

## isolate-host
<!-- Isolate the host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Copy C:\ProgramData\Microsoft\Windows Defender\Scans and take a memory image first. Then isolate the host, and terminate the scored process if it is still running.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Decrypt the copied Scans folder with the extension's --decrypt mode or Protokol-7's mpenginedb_parser to see the full queue history, including deleted rows. Review the accounts that ran the scored process and their other hosts, and check the scored image's hash across the estate.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the scored processes and verdicts. Schedule the pack query defender_mpengine_process_techniques every 30 minutes, because the queues keep about an hour, and keep the benign image and technique pairs as a suppression list for the next run.
```
→ end

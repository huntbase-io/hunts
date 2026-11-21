---
analysis: Most ASR events are line-of-business noise, and a block on its own says
  nothing about whether the attacker succeeded. The hunt needs the fleet comparison
  to find near-misses and a per-host timeline across four other sources to decide
  what happened next.
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
- id: follow-through-telemetry
  question: What did the attacker do after the ASR event?
  requires: process creation with parent and command line (Sysmon 1 or 4688 with command
    line), service creation (7045) and task creation (4698) events in hb_ surfaces
    for the window
  risk: Without them the hunt finds the near-miss but cannot say whether the attacker
    got through, and the decision routes to an analyst.
  stage: credential-theft-attempt
- id: rules-not-enabled
  question: What would a rule that is not configured have recorded?
  requires: ASR rules configured in block or audit mode
  risk: A rule that is off records nothing in ProcessBlockHistory.
- id: block-history-retention
  question: Did anything trigger ASR before the history starts?
  requires: ProcessBlockHistory younger than about 90 days and a host not rebuilt
  risk: Older events and those on rebuilt hosts are gone.
- id: wmi-subscription-persistence
  question: Did persistence move to a WMI subscription after the rule fired?
  requires: WMI event subscription telemetry (Sysmon 19-21)
  risk: No hb_ surface in this hunt sees WMI subscriptions.
  stage: persistence-follow-on
coverage:
- stage: credential-theft-attempt
  status: covered
  steps:
  - asr-events
  - credential-theft-alternatives
- stage: office-child-execution
  status: covered
  steps:
  - asr-events
  - indirect-execution-alternatives
- stage: remote-process-creation
  status: covered
  steps:
  - asr-events
  - remote-service-creation
- stage: persistence-follow-on
  status: covered
  steps:
  - scheduled-task-creation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: environment-specific
  handoff: keep-as-periodic-hunt
  justification: Each near-miss is an observed attack attempt on a named host, and
    in most fleets nobody has looked at it.
  methodology: structured-hypothesis-driven
  trigger: detection-gap
hypothesis: An intruder triggered a Defender attack surface reduction rule, such as
  LSASS credential theft, an Office child process or PsExec/WMI process creation,
  and then reached the same objective by a route the rule does not cover; or the rule
  was only auditing and the action went ahead.
labels:
- hunt
- attack.t1003.001
- attack.t1047
- attack.t1204.002
- attack.t1569.002
- attack.t1053.005
- credential access
- execution
- lateral movement
- persistence
- hb-endpoint-control
name: 'ASR Near-Misses: Blocked Attempts and the Route Around Them'
parameters:
  asr_lookback_days:
    default: '90'
    description: Days of ASR history to read; Defender keeps ProcessBlockHistory for
      about 90 days.
    type: number
  asr_noise_processes:
    default: []
    description: Full process paths confirmed as benign ASR triggers (line-of-business
      apps, add-ins), left out of the ASR step.
    type: list[path]
  lookback_days:
    default: '30'
    description: Days of process, service and task telemetry to examine after the
      ASR events.
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
rationale: Run across all Windows hosts with ASR enabled in block or audit mode. Servers
  with PsExec/WMI or webshell events and workstations with LSASS events come first.
  Paste the hosts near-miss-triage names into scope_hosts before the follow-through
  steps, and set lookback_days to cover the time since the oldest near-miss.
references:
- name: "Protokol-7 \u2014 Defender's hidden flight recorder: mpenginedb.db"
  url: https://protokol-7.github.io/dfir/2026/11/10/defenders-hidden-flight-recorder-mpenginedb.html
- name: osquery-defender-extension (defender_mpengine_* tables)
  url: https://github.com/rakeshrm/osquery-defender-extension
- name: "Protokol-7 \u2014 mpenginedb_parser (deleted-row recovery, full timeline)"
  url: https://github.com/Protokol-7/mpenginedb_parser
related:
- hunt: defender-weakening-tamper-asr-exclusions
  reason: Finds ASR rules switched to audit or off, which turns blocks into audits
    and audits into nothing.
  relation: sibling
scenario:
  stages:
  - name: LSASS credential theft attempt
    observables:
    - ASR 'Block credential stealing from LSASS' with target lsass.exe
    - comsvcs MiniDump
    - reg save hklm\sam
    slug: credential-theft-attempt
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Office or script child process
    observables:
    - ASR Office child-process rules
    - Script host under wmiprvse.exe or dllhost.exe
    slug: office-child-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1047
  - name: PsExec or WMI process creation
    observables:
    - ASR PsExec/WMI rule
    - New service running cmd /c
    slug: remote-process-creation
    tactic: lateral-movement
    techniques:
    - T1569.002
    - T1047
  - name: Persistence after the block
    observables:
    - New scheduled task running a script host
    - ASR WMI-subscription rule
    slug: persistence-follow-on
    tactic: persistence
    techniques:
    - T1053.005
    - T1546.003
  summary: An intruder's action trips an ASR rule. In block mode the action is stopped
    and the intruder reaches the same objective another way; in audit mode it goes
    ahead. The ASR event is the only trace of the first attempt.
series:
  index: 4
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


# ASR Near-Misses: Blocked Attempts and the Route Around Them

An ASR block is a record of an attack attempt that was stopped, and an ASR audit event is a record of one that was not. Most organisations without Defender for Endpoint never see either: the events stay in the local Defender event log, which is rarely forwarded. Defender also keeps them in mpenginedb.db, in ProcessBlockHistory, for about 90 days.

This hunt reads that history on every Windows host through the defender_mpengine osquery extension, stacks each rule and process pair across the fleet so that line-of-business noise drops out, and lets an agent pick the near-misses and the objective each one served.

An attacker who is blocked usually tries another way. For each near-miss host the hunt looks for that route: credential theft without touching LSASS directly, a script host started through WMI or COM instead of from Word, a service or a scheduled task instead of PsExec. It then decides whether the attacker got through.

## asr-events
<!-- ASR blocks and audits per host -->
Read every attack surface reduction event the engine kept: rule, the process that triggered it, its target, and whether the rule was in block or audit mode. In block mode the event is an attempt that was stopped; in audit mode it is an attempt that went ahead. Without Defender for Endpoint these events stay on the host.

```osquery target=hb-endpoint-control role=triage params=(asr_lookback_days=asr_lookback_days, asr_noise_processes=asr_noise_processes)
~~~yaml
expected: 'A line-of-business app tripping the same rule on hundreds of hosts is noise
  to tune. A rule and process pair on one or two hosts is a near-miss: LSASS as target,
  Office or Acrobat starting children, PsExec or WMI creating processes, obfuscated
  scripts, or a vulnerable driver. action and taint_reason are undocumented codes.'
prevalence:
  by: device_hostname
  key:
  - asr_rule_name
  - process_path
  rare_below: 3
reads:
- time
- process_path
- target_path
- rule_id
- asr_rule_name
- is_audit
- action
- process_taint_reason
- process_integrity
silence: not_evidence_of_absence
source: defender_mpengine_process_block_history
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT (SELECT hostname FROM system_info) AS device_hostname, asr_rule_name, rule_id, process_path, target_path, is_audit, COUNT(*) AS events, MIN(time) AS first_event, MAX(time) AS last_event, MAX(process_integrity) AS process_integrity, MAX(process_taint_reason) AS taint_reason, MAX(action) AS action FROM defender_mpengine_process_block_history WHERE time >= (CAST(strftime('%s', 'now') AS INTEGER) - {{asr_lookback_days}} * 86400) AND NOT (instr(',' || LOWER('{{asr_noise_processes}}') || ',', ',' || LOWER(process_path) || ',') > 0) GROUP BY asr_rule_name, rule_id, process_path, target_path, is_audit
```

## near-miss-triage
<!-- Near-misses versus noise -->
```agent target=hunter
cite: required
context:
- asr-events
max_iterations: 3
objective: Separate noise (the same rule and process on many hosts, known add-ins,
  management agents) from near-misses (rare on the fleet, or a credential-theft, Office
  or Adobe child-process, PsExec/WMI, obfuscated-script, JavaScript/VBScript download,
  vulnerable-driver, webshell, copied-system-tool or Safe Mode rule). For each near-miss,
  record the host, the first event time, the triggering process, the objective the
  blocked action served (credential theft, code execution, lateral movement, persistence)
  and whether the rule was in audit mode, which means the action happened.
success_criteria: A list of near-misses per host with time, rule, process, objective
  and mode, citing rows; the hosts to paste into scope_hosts; and the noise processes
  to add to asr_noise_processes.
tools:
- endpoint
- hb-endpoint-control
```

## parallel-route-around
<!-- Did the attacker get there another way -->
parallel:
- → credential-theft-alternatives
- → indirect-execution-alternatives
- → remote-service-creation
- → scheduled-task-creation
join: → follow-through-verdict

## credential-theft-alternatives
<!-- Credential theft by other means -->
If the LSASS rule stopped a dump, look for the other ways to the same credentials: comsvcs MiniDump, procdump, renamed dumpers, saving the SAM, SECURITY and SYSTEM hives, NTDS copies and shadow copies.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any of these after an LSASS ASR event on the same host means the attacker
  kept going for credentials.
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
SELECT device_hostname, time, user_name, parent_process_name, process_name, process_cmd_line, integrity_level FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%comsvcs%minidump%' OR LOWER(process_cmd_line) LIKE '%procdump%lsass%' OR LOWER(process_cmd_line) LIKE '%procdump%-ma%' OR LOWER(process_cmd_line) LIKE '%sekurlsa%' OR LOWER(process_cmd_line) LIKE '%lsadump%' OR (LOWER(process_cmd_line) LIKE '%reg%save%' AND (LOWER(process_cmd_line) LIKE '%hklm\sam%' OR LOWER(process_cmd_line) LIKE '%hklm\security%' OR LOWER(process_cmd_line) LIKE '%hklm\system%')) OR LOWER(process_cmd_line) LIKE '%ntdsutil%ifm%' OR LOWER(process_cmd_line) LIKE '%esentutl%ntds%' OR LOWER(process_cmd_line) LIKE '%vssadmin%create%shadow%' OR LOWER(process_cmd_line) LIKE '%rdrleakdiag%' OR LOWER(process_cmd_line) LIKE '%sqldumper%')
```

## indirect-execution-alternatives
<!-- Script hosts and LOLBins started indirectly -->
If an Office, Adobe or script-host child process was blocked, look for the same payload started through WMI, COM, MMC or the task scheduler, or from an Office parent the rule does not cover.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: powershell, mshta or rundll32 under wmiprvse.exe or dllhost.exe shortly
  after a blocked Office child process is the classic route around the rule.
reads:
- time
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- parent_process_cmd_line
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, user_name, parent_process_name, parent_process_cmd_line, process_name, process_cmd_line FROM hb_process_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\pwsh.exe' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\wscript.exe' OR LOWER(process_name) LIKE '%\cscript.exe' OR LOWER(process_name) LIKE '%\mshta.exe' OR LOWER(process_name) LIKE '%\rundll32.exe' OR LOWER(process_name) LIKE '%\regsvr32.exe' OR LOWER(process_name) LIKE '%\msbuild.exe' OR LOWER(process_name) LIKE '%\installutil.exe' OR LOWER(process_name) LIKE '%\certutil.exe' OR LOWER(process_name) LIKE '%\bitsadmin.exe' OR LOWER(process_name) LIKE '%\msiexec.exe' OR LOWER(process_name) LIKE '%\curl.exe') AND (LOWER(parent_process_name) LIKE '%\wmiprvse.exe' OR LOWER(parent_process_name) LIKE '%\dllhost.exe' OR LOWER(parent_process_name) LIKE '%\mmc.exe' OR LOWER(parent_process_name) LIKE '%\taskeng.exe' OR LOWER(parent_process_name) LIKE '%\mshta.exe' OR LOWER(parent_process_name) LIKE '%\wscript.exe' OR LOWER(parent_process_name) LIKE '%\cscript.exe' OR LOWER(parent_process_name) LIKE '%\excel.exe' OR LOWER(parent_process_name) LIKE '%\winword.exe' OR LOWER(parent_process_name) LIKE '%\outlook.exe' OR LOWER(parent_process_name) LIKE '%\powerpnt.exe' OR LOWER(parent_process_name) LIKE '%\onenote.exe' OR LOWER(parent_process_name) LIKE '%\acrord32.exe')
```

## remote-service-creation
<!-- Services created with command or user-space binaries -->
If the PsExec/WMI rule stopped remote process creation, look for the same result through a new service.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A service running cmd /c, PowerShell or a binary in a user-writable folder,
  created after a PsExec/WMI near-miss, is lateral movement that went through.
reads:
- time
- device_hostname
- service_name
- service_cmd_line
- service_start_name
- service_binary
- actor_user_name
silence: not_evidence_of_absence
source: hb_service_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, service_name, service_cmd_line, service_binary, service_start_name, actor_user_name FROM hb_service_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(COALESCE(service_cmd_line, '') || ' ' || COALESCE(service_binary, '')) LIKE '%cmd%/c%' OR LOWER(COALESCE(service_cmd_line, '') || ' ' || COALESCE(service_binary, '')) LIKE '%powershell%' OR LOWER(COALESCE(service_cmd_line, '') || ' ' || COALESCE(service_binary, '')) LIKE '%comspec%' OR LOWER(COALESCE(service_cmd_line, '') || ' ' || COALESCE(service_binary, '')) LIKE '%\admin$\%' OR (LOWER(COALESCE(service_binary, service_cmd_line, '')) LIKE '%\users\%' OR LOWER(COALESCE(service_binary, service_cmd_line, '')) LIKE '%\programdata\%' OR LOWER(COALESCE(service_binary, service_cmd_line, '')) LIKE '%\windows\temp\%' OR LOWER(COALESCE(service_binary, service_cmd_line, '')) LIKE '%\perflogs\%' OR LOWER(COALESCE(service_binary, service_cmd_line, '')) LIKE '%\$recycle.bin\%'))
```

## scheduled-task-creation
<!-- Scheduled tasks running scripts or user-space binaries -->
Look for persistence or execution moved into the task scheduler after a blocked attempt, including after the WMI-subscription persistence rule fired.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A task created after the near-miss that runs a script host or a user-space
  binary.
reads:
- time
- device_hostname
- actor_user_name
- job_name
- job_cmd_line
- job_user_name
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, time, job_name, job_cmd_line, job_user_name, actor_user_name FROM hb_scheduled_job WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(job_cmd_line) LIKE '%\powershell.exe' OR LOWER(job_cmd_line) LIKE '%\pwsh.exe' OR LOWER(job_cmd_line) LIKE '%\cmd.exe' OR LOWER(job_cmd_line) LIKE '%\wscript.exe' OR LOWER(job_cmd_line) LIKE '%\cscript.exe' OR LOWER(job_cmd_line) LIKE '%\mshta.exe' OR LOWER(job_cmd_line) LIKE '%\rundll32.exe' OR LOWER(job_cmd_line) LIKE '%\regsvr32.exe' OR LOWER(job_cmd_line) LIKE '%\msbuild.exe' OR LOWER(job_cmd_line) LIKE '%\installutil.exe' OR LOWER(job_cmd_line) LIKE '%\certutil.exe' OR LOWER(job_cmd_line) LIKE '%\bitsadmin.exe' OR LOWER(job_cmd_line) LIKE '%\msiexec.exe' OR LOWER(job_cmd_line) LIKE '%\curl.exe') OR LOWER(job_cmd_line) LIKE '%powershell%' OR LOWER(job_cmd_line) LIKE '%mshta%' OR LOWER(job_cmd_line) LIKE '%rundll32%' OR (LOWER(job_cmd_line) LIKE '%\users\%' OR LOWER(job_cmd_line) LIKE '%\programdata\%' OR LOWER(job_cmd_line) LIKE '%\windows\temp\%' OR LOWER(job_cmd_line) LIKE '%\perflogs\%' OR LOWER(job_cmd_line) LIKE '%\$recycle.bin\%'))
```

## follow-through-verdict
<!-- Follow-through verdict -->
```agent target=hunter
cite: required
context:
- near-miss-triage
- credential-theft-alternatives
- indirect-execution-alternatives
- remote-service-creation
- scheduled-task-creation
max_iterations: 4
objective: For each near-miss from near-miss-triage, put the host's rows from the
  four follow-through steps in time order from the ASR event. Decide whether the objective
  the blocked action served was reached by another route, and for audit-mode events,
  what followed the action that was allowed. Treat a host with no telemetry in these
  steps as unknown.
success_criteria: A verdict per near-miss of reached, attempted only, or benign, with
  a timeline citing rows.
tools:
- endpoint
- hb-endpoint-control
```

## route-on-verdict
<!-- Route on verdict -->
if~: "follow-through-verdict finds at least one near-miss whose objective was reached by another route, or an audit-mode event that was followed by attacker activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: follow-through-telemetry)
else: → close-out

## isolate-host
<!-- Isolate the host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Where the objective was credential theft, treat every account that logged on to the host since the first ASR event as exposed and reset its password through the identity team.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Find how the triggering process got there: the document, script or tool, and the account. Check the other hosts that account used during the window, and whether the same rule fired there.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record near-misses and outcomes. For rules that only audited on hosts with near-misses, raise a change to move them to enforcement. Add confirmed benign triggers to asr_noise_processes so the next run starts cleaner.
```
→ end

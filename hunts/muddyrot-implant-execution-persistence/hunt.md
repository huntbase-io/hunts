---
analysis: A simple detection rule may catch 'DocumentsManagerReporter.exe', but this
  hunt uses a prevalence baseline for ProgramData-based processes loading networking
  DLLs and identifies staging files ('exit') that are typically only seen during an
  active interactive session. This multi-surface corroboration reduces false positives
  from legitimate RMM tools.
blind_spots:
- id: missing-endpoint-telemetry
  question: Are there endpoints running MuddyRot that are not sending telemetry?
  requires: hb_process_activity and hb_module_activity from every endpoint
  risk: A host without an EDR agent/osquery provides no visibility into local file
    or process creation, allowing the implant to persist undetected.
- id: mutex-visibility
  question: Can we see the 'DocumentUpdater' mutex directly?
  requires: A kernel-level mutex surface or memory forensics
  risk: No hb_ surface currently records mutex creation events, so we must rely on
    process and file artifacts as proxies.
  stage: muddyrot-execution-and-setup
coverage:
- stage: muddyrot-execution-and-setup
  status: covered
  steps:
  - implant-binary-execution
  - rare-programdata-modules
- stage: persistence-scheduled-task
  status: covered
  steps:
  - persistence-task
- reason: Identifying the 'exit' staging file and suspicious ProgramData process spawns
    covers the shell and exfil prep.
  stage: interactive-shell-and-exfiltration
  status: covered
  steps:
  - implant-binary-execution
  - staging-file-activity
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: initial-access-delivery
  status: out_of_scope
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: command-and-control-raw-tcp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MuddyRot is a custom validator for a state-sponsored actor (MOIS).
    Its presence indicates a high-priority breach. Because the malware uses custom
    obfuscation and dynamic loading, typical IOC-based detection on static imports
    may fail; a behavioral hunt for its local artifacts is necessary.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established presence using the MuddyRot implant, identifiable
  by its specific ProgramData directory, scheduled task persistence, and the creation
  of a 'exit' buffer file for data exfiltration.
labels:
- hunt
- attack.t1059
- attack.t1053.005
- attack.t1059.003
- attack.t1105
name: MuddyRot Implant Execution and Persistence
parameters:
  implant_binary:
    default: documentsmanagerreporter.exe
    description: The binary name used for persistence.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: string
  implant_subdir:
    default: c:\programdata\softwarememory\
    description: The directory MuddyRot uses for staging.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: path
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should focus on Windows endpoints and servers, particularly those
  accessible from the internet or used by employees in the targeted regions (Turkey,
  Azerbaijan, Israel). High-value servers like Exchange and SharePoint should be prioritized
  due to the actor's history of exploitation.
references:
- name: "Sekoia \u2014 MuddyWater replaces Atera with custom MuddyRot implant"
  url: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
related:
- hunt: initial-access-delivery
  reason: This hunt focuses on the local host implant, whereas the delivery stage
    involves phishing PDF and Egnyte link analysis.
  relation: out-of-scope-alternative
- hunt: command-and-control-raw-tcp
  reason: Networking activity (raw TCP 443) belongs to the C2 hunt, although local
    module loads for Ws2_32.dll are included here as behavioral evidence.
  relation: out-of-scope-alternative
- hunt: muddywater-delivery-egnyte-vulnerable-servers
  relation: follows
scenario:
  stages:
  - name: Initial Access via Phishing or Exploitation
    observables:
    - PDF decoys related to online courses or webinars
    - Links to Egnyte storage service
    - Malicious ZIP archives containing MuddyRot
    - Exploitation of Exchange or SharePoint servers
    slug: initial-access-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: MuddyRot Implant Execution
    observables:
    - Process documentsmanagerreporter.exe
    - Mutex named DocumentUpdater
    - Dynamic loading of Kernel32.dll, Advapi32.dll, Ole32.dll, and Ws2_32.dll
    - In-memory string deobfuscation
    slug: muddyrot-execution-and-setup
    tactic: execution
    techniques:
    - T1059
  - name: Persistence via Scheduled Task
    observables:
    - Path c:\programdata\softwarememory\documentsmanagerreporter.exe
    - Scheduled task named DocumentsManagerReporter
    - COM object CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DDBD3E73E6154572DD
    - Daily execution schedule
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: C2 Communication over Port 443
    observables:
    - IP 91.235.234.202
    - IP 146.19.143.14
    - TCP port 443
    - Obfuscated C2 traffic (byte subtraction by 3)
    slug: command-and-control-raw-tcp
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
  - name: Reverse Shell and File Triage
    observables:
    - cmd.exe spawned via anonymous pipes
    - Buffer file named 'exit' in working directory
    - Hostname and username fingerprinting in format 'hostname/username'
    slug: interactive-shell-and-exfiltration
    tactic: execution
    techniques:
    - T1059.003
  summary: MuddyWater is distributing a new C-based implant named MuddyRot via spear
    phishing PDF lures and Egnyte downloads, replacing their previous use of legitimate
    RMM tools like Atera. The implant establishes persistence via scheduled tasks
    using COM objects and provides reverse shell and file management capabilities
    over raw TCP port 443.
series:
  index: 2
  slug: muddywater-replaces-atera-with-custom-muddyrot-implant
  title: MuddyWater replaces Atera with custom MuddyRot implant
  total: 3
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


# MuddyRot Implant Execution and Persistence

This hunt targets the local host artifacts left by the MuddyRot implant. It identifies the execution of the implant from non-standard ProgramData subdirectories, examines the persistence layer via Windows Scheduled Tasks, and corroborates the behavior through module load analysis and the identification of staging files used by the reverse shell. By looking for the specific file name 'documentsmanagerreporter.exe' and its corresponding scheduled task, we can distinguish this custom implant from legitimate remote management software.

## implant-binary-execution
<!-- Implant execution from ProgramData -->
Identify any execution of the MuddyRot binary or any process running from its known staging directory.

```sqlite target=endpoint role=detection-candidate params=(implant_subdir=implant_subdir, implant_binary=implant_binary, lookback_days=lookback_days)
~~~yaml
expected: A process match for the specific implant name or directory. Silence suggests
  the specific binary is not present, though different names may be used in future
  variants.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE LOWER('{{implant_subdir}}%') OR LOWER(process_name) LIKE LOWER('%{{implant_binary}}')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-check
<!-- Parallel Corroboration of Implant Activity -->
parallel:
- → persistence-task
- → rare-programdata-modules
- → staging-file-activity
join: → triage

## persistence-task
<!-- Persistence via Scheduled Task -->
Verify if the 'DocumentsManagerReporter' task has been registered on the host.

```sqlite target=endpoint role=triage params=(implant_binary=implant_binary)
~~~yaml
expected: A scheduled task row pointing to the ProgramData binary. This is a strong
  indicator of persistence.
reads:
- device_hostname
- job_cmd_line
- job_name
- job_user_name
- last_run_time
- state_kind
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, last_run_time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE '%documentsmanagerreporter%' OR LOWER(job_cmd_line) LIKE LOWER('%{{implant_binary}}%')) AND state_kind = 'snapshot'
```

## rare-programdata-modules
<!-- Rare processes in ProgramData loading network DLLs -->
Identify processes in unusual subdirectories loading Ws2_32.dll, which MuddyRot does dynamically to obfuscate imports.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A process in ProgramData (likely MuddyRot) loading networking libraries.
  Prevalence should be low across the fleet.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- module_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, module_name, COUNT(*) as count FROM hb_module_activity WHERE LOWER(process_name) LIKE 'c:\programdata\%' AND LOWER(module_name) = 'ws2_32.dll' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, module_name HAVING count <= 5
```

## staging-file-activity
<!-- Creation of 'exit' staging file -->
Find the buffer file 'exit' used by MuddyRot for data exfiltration via reverse shell.

```sqlite target=endpoint role=enrichment params=(implant_subdir=implant_subdir, lookback_days=lookback_days)
~~~yaml
expected: A file named 'exit' created in the implant's directory. This serves as a
  fingerprint of active data staging/exfiltration.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'exit' AND LOWER(file_path) LIKE LOWER('{{implant_subdir}}%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage
<!-- Weigh MuddyRot local evidence -->
```agent target=hunter
cite: required
context:
- implant-binary-execution
- persistence-task
- rare-programdata-modules
- staging-file-activity
max_iterations: 3
objective: Determine if the combination of the binary path, scheduled task name, and
  'exit' staging file confirms the presence of the MuddyRot implant.
success_criteria: Verdicts (Malicious | Benign) per host with citations.
tools:
- endpoint
```

## route
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → close-out

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and perform memory capture to extract the MuddyRot implant strings and configuration.
```
→ analyst-review

## analyst-review
<!-- Analyst review and tuning -->
```manual target=analyst
Review the cited rows. Confirm if the 'exit' file was used for data exfiltration and extract any process paths or binary names not covered by current parameters.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the results; document that no hosts matching the MuddyRot local fingerprint were found.
```
→ end

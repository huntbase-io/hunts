---
analysis: A standard rule might flag 'schtasks' or 'encoded powershell'. This hunt
  goes further by pivoting between the task trigger, the hidden ADS file creation,
  and the in-memory script behavior (SSL bypass/XOR), providing a full-chain analysis
  that filters out legitimate administrative noise.
blind_spots:
- id: missing-script-block-logging
  owner: Endpoint Security Team
  question: What is the content of the PowerShell -EncodedCommand?
  remediation: Enable 'Turn on PowerShell Script Block Logging' via GPO for all Windows
    endpoints.
  requires: PowerShell ScriptBlock Logging (Event ID 4104)
  risk: Without script block logging, we only see the encoded command line; we cannot
    verify the XOR logic or the in-memory payload execution.
  stage: obfuscated-powershell-memory-load
- id: ads-visibility
  owner: Infrastructure Team
  question: Was a malicious payload written to an Alternate Data Stream?
  remediation: Ensure Sysmon Event ID 15 (FileCreateStreamHash) is enabled.
  requires: Sysmon or EDR visibility into FileStream creation
  risk: Standard file activity logs often miss writes to streams. This hunt relies
    on the colon character being present after the drive letter in the path.
  stage: persistence-via-ads-and-scheduled-task
coverage:
- stage: persistence-via-ads-and-scheduled-task
  status: covered
  steps:
  - find-malicious-task
  - ads-file-activity
- stage: obfuscated-powershell-memory-load
  status: covered
  steps:
  - powershell-execution-prevalence
  - powershell-script-blocks
- reason: 'Belongs to another part of the ''FSB Matryoshka: Gamaredon GammaLoad''
    series.'
  stage: c2-registry-caching-and-fingerprinting
  status: out_of_scope
- reason: 'Belongs to another part of the ''FSB Matryoshka: Gamaredon GammaLoad''
    series.'
  stage: in-memory-vbscript-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: GammaLoad represents a persistent threat from Gamaredon (FSB) targeting
    critical infrastructure. Its use of ADS and 'loader loading loader' behavior is
    designed to evade file-based security controls. A negative result provides high-confidence
    assurance that this specific persistence mechanism is not active in the environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence via a scheduled task executing
  code hidden in an Alternate Data Stream (ADS), which subsequently triggers an obfuscated
  PowerShell loader to execute payloads in-memory.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1564.004
name: 'Gamaredon GammaLoad: ADS Persistence and PowerShell Memory-Load'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  task_name_pattern:
    default: DsSvcCleanup%
    description: The name of the scheduled task reported in research (removed leading
      wildcard for indexing).
    from:
      kind: article
      observed: '2026-01-23'
      ref: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on Windows endpoints. Ensure PowerShell ScriptBlock logging
  (Event ID 4104) is enabled to populate hb_script_activity, as this is critical for
  detecting the memory-load phase.
references:
- name: "Sekoia.io \u2014 FSB's Matryoshka: GammaLoad"
  url: https://blog.sekoia.io/fsbs-matryoshka-2-3-gamaredons-gifts-that-keeps-unpacking-gammaload/
related:
- hunt: gammaload-registry-c2-caching
  reason: Registry-based C2 caching is handled by the first hunt in this series, focusing
    on hb_registry_activity.
  relation: out-of-scope-alternative
- hunt: gamaredon-gammaload-vbscript-registry
  relation: follows
scenario:
  stages:
  - name: C2 Registry Caching and Host Fingerprinting
    observables:
    - 'Registry keys: HKCU\Console\HistoryURL, HKCU\Console\WindowsResponby, HKCU\Console\CloudURL,
      HKCU\Console\IpURL'
    - 'DDR domains: te.legra.ph, telegram.me, check-host.net'
    - 'User-Agent fingerprint separators: ##, !!, ??, ==, ::, _, @, #, =, %, ?'
    - 'HTTP GET requests with anomalous Content-Length: 2114'
    - 'Fingerprint: %COMPUTERNAME% and system drive serial number'
    slug: c2-registry-caching-and-fingerprinting
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
  - name: In-Memory VBScript Execution
    observables:
    - VBScript ExecuteGlobal() function calls
    - Base64 obfuscated scripts with '&&' markers inserted every 54 characters
    slug: in-memory-vbscript-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via ADS and Scheduled Task
    observables:
    - 'Alternate Data Stream (ADS) file: %TEMP%\:divedz0f'
    - 'Scheduled Task name: \Windows\ApplicationData\DsSvcCleanup'
    - 'Scheduled Task interval: every 11 minutes'
    - Task action executing VBScript from ADS
    slug: persistence-via-ads-and-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Obfuscated PowerShell Memory Load
    observables:
    - 'Process command line: powershell.exe -nol -nop -encodedcommand'
    - 'PowerShell disabling SSL validation: [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}'
    - PowerShell XOR-decryption and IEX execution of downloaded strings
    slug: obfuscated-powershell-memory-load
    tactic: execution
    techniques:
    - T1059.001
  summary: Gamaredon uses a multi-stage infection chain known as GammaLoad to maintain
    persistent access and deploy stealers. The chain leverages VBScript loaders that
    use Dead Drop Resolvers and registry caching for C2 resiliency, ultimately persisting
    via scheduled tasks that execute payloads hidden in Alternate Data Streams (ADS).
series:
  index: 2
  slug: fsb-matryoshka-gamaredon-gammaload
  title: 'FSB Matryoshka: Gamaredon GammaLoad'
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


# Gamaredon GammaLoad: ADS Persistence and PowerShell Memory-Load

This hunt targets the persistence and execution phases of Gamaredon's 2026 GammaLoad campaign. It specifically looks for the 'DsSvcCleanup' scheduled task, the creation of Alternate Data Streams in temporary directories, and the subsequent PowerShell memory-loading behavior characterized by disabling SSL validation and XOR-decryption. By correlating task scheduling with low-prevalence encoded PowerShell commands and script-block content, we can identify active infections that standard file-based detection might miss.

## scope-windows-hosts
<!-- Scope Windows Hosts -->
GammaLoad targets Windows endpoints specifically; this step narrows the hunt to the relevant fleet.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of active Windows hosts. Silence means no Windows endpoints are enrolled.
reads:
- hostname
- device_uid
- os_name
- platform
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT hostname, device_uid, os_name FROM hb_devices WHERE platform = 'Windows' AND lifecycle_state = 'active'
```

## find-malicious-task
<!-- Identify Persistence Task -->
Identify the specific scheduled task used for persistence, searching for the reported name or command lines executing ADS payloads.

```sqlite target=endpoint role=detection-candidate params=(task_name_pattern=task_name_pattern)
~~~yaml
expected: Rows indicating tasks named DsSvcCleanup or tasks that execute files using
  a colon after the drive letter, indicative of an ADS. Silence means no tasks matching
  the specific naming or the ADS pattern were found.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_definition_path
- job_enabled
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_definition_path, time FROM hb_scheduled_job WHERE (LOWER(job_name) LIKE LOWER('{{task_name_pattern}}') OR instr(job_cmd_line, ':') > 2) AND job_enabled = 1 AND (LOWER(job_cmd_line) LIKE '%temp%' OR LOWER(job_cmd_line) LIKE '%appdata%')
```

## corroborate-activity
<!-- Corroborate Persistence and Execution -->
parallel:
- → ads-file-activity
- → powershell-execution-prevalence
- → powershell-script-blocks
join: → triage-evidence

## ads-file-activity
<!-- ADS File Creation in Temp Paths -->
Monitor for the creation of Alternate Data Streams within the TEMP directory, which GammaLoad uses for staging payloads.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: File creation events where the file path contains a colon (excluding drive
  letters) in a temp directory. Silence means no ADS file creations were detected
  in temp paths.
reads:
- device_hostname
- file_path
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE instr(file_path, ':') > 2 AND (LOWER(file_path) LIKE '%\appdata\local\temp\%' OR LOWER(file_path) LIKE '%\windows\temp\%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-execution-prevalence
<!-- Rare Encoded PowerShell Patterns -->
Stack-count PowerShell commands that use abbreviated or varied flag combinations to find rare outliers.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: PowerShell commands using NoLogo, NoProfile, and Encoded flags that appear
  on few hosts. Silence means no rare instances of these flag combinations were found.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(process_cmd_line) as cmd, COUNT(DISTINCT device_hostname) as hosts, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%-%no%l%' AND LOWER(process_cmd_line) LIKE '%-%no%p%' AND (LOWER(process_cmd_line) LIKE '%-%enc%' OR LOWER(process_cmd_line) LIKE '%-%encoded%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts < 5
```

## powershell-script-blocks
<!-- PowerShell Memory-Load Logic -->
Analyze PowerShell script content for signs of in-memory execution, SSL bypass, and XOR decryption reported in GammaLoad stages.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks that explicitly disable certificate validation or perform
  XOR operations on downloaded data. Silence suggests no such logic was executed in
  script blocks.
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE script_type = 'PowerShell' AND (LOWER(script_content) LIKE '%servercertificatevalidationcallback%' OR (LOWER(script_content) LIKE '%-xor%' AND LOWER(script_content) LIKE '%downloadstring%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage GammaLoad Evidence -->
```agent target=hunter
cite: required
context:
- find-malicious-task
- ads-file-activity
- powershell-execution-prevalence
- powershell-script-blocks
max_iterations: 5
objective: 'Determine if the evidence supports the GammaLoad persistence and execution
  chain: Scheduled Task -> ADS -> PowerShell Memory Load.'
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign citing specific
  rows from the persistence and execution steps.
tools:
- endpoint
```

## route-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is malicious for one or more hosts with correlated persistence (task) and execution (script logic) evidence." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-script-block-logging)
else: → close-hunt

## isolate-host
<!-- Isolate Host and Collect ADS -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host from the network. Capture the file residing in the Alternate Data Stream identified in 'ads-file-activity' before deleting the scheduled task.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the correlated evidence. Check for signs of GammaSteel (the subsequent stealer stage) and verify the source of the initial GammaLoad dropper.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
Document the absence of GammaLoad persistence and execution markers across the fleet.
```
→ end

---
analysis: This hunt pivots from anomalous registry volumes to script-level encryption
  calls and correlates them within a narrow time window, providing context that a
  single detection rule lacks.
blind_spots:
- id: no-script-block-logging
  question: What specific logic was executed to decrypt the staged registry payloads?
  requires: hb_script_activity with full auditing (Event ID 4104)
  risk: We might see the registry artifacts but fail to confirm the malicious script
    logic without full block logging.
  stage: registry-payload-staging
- id: registry-retention
  question: Which process performed the registry writes?
  requires: hb_registry_activity (Sysmon event stream / log rows)
  risk: If only snapshots are available, we identify the staged payloads but not the
    historical actor process that wrote them.
  stage: registry-payload-staging
coverage:
- stage: execution-powershell-dropper
  status: covered
  steps:
  - hidden-powershell-lead
- stage: registry-payload-staging
  status: covered
  steps:
  - registry-staging-scoping
  - dpapi-script-activity
- reason: "Belongs to another part of the \"FSB\u2019s matryoshka #3/3: Gamaredon's\
    \ Gammasteel Infostealer\" series."
  stage: persistence-run-key-pointer
  status: out_of_scope
- reason: "Belongs to another part of the \"FSB\u2019s matryoshka #3/3: Gamaredon's\
    \ Gammasteel Infostealer\" series."
  stage: drive-and-profile-discovery
  status: out_of_scope
- reason: "Belongs to another part of the \"FSB\u2019s matryoshka #3/3: Gamaredon's\
    \ Gammasteel Infostealer\" series."
  stage: s3-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: GammaSteel's DPAPI-bound registry staging bypasses traditional file-system
    monitoring; verifying the integrity of these registry hives is essential for detecting
    persistent, fileless espionage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has staged encrypted PowerShell payloads in the user Printers
  registry hive and is executing them via hidden processes that avoid file-based detection.
labels:
- hunt
- attack.t1059.001
- attack.t1547.001
name: Gammasteel Fileless PowerShell Registry Staging
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the full estate.
    from:
      kind: manual
      observed: '2026-06-11'
      ref: analyst-defined
    type: list[host]
  staging_registry_path:
    default: '%\printers\%'
    description: Registry path pattern where Gammasteel functions are staged, accounting
      for provider variations in hive naming.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia-gammasteel
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on user workstations where sensitive documentation is handled; Gamaredon
  targets HKCU, so the staging is user-specific.
references:
- name: "FSB\u2019s matryoshka #3/3: Gamaredon's Gammasteel Infostealer"
  url: https://www.sekoia.com/blog/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel
related:
- hunt: gamaredon-run-key-persistence
  reason: The Run key persistence pointer is handled in a separate hunt in this series.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: PowerShell Dropper Execution
    observables:
    - powershell.exe -nol -nop -enc
    - Start-Process -FilePath "powershell" -ArgumentList "-noexit"
    - -WindowStyle Hidden
    - Global\assembly307
    slug: execution-powershell-dropper
    tactic: execution
    techniques:
    - T1059.001
  - name: Fileless Registry Staging via DPAPI
    observables:
    - HKCU\Printers
    - KeZdDboas5kpxbkgxxvBx
    - ConvertTo-SecureString
    - ConvertFrom-SecureString
    - 71 PowerShell functions
    slug: registry-payload-staging
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Persistence via Run Key Pointer
    observables:
    - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    - 'Value name: $env:os'
    - YxwHku2chu0bznt3kkyAB
    - powershell.exe -w hidden -command "$a='HKCU:\Printers'; $b=Get-ItemProperty
      ..."
    slug: persistence-run-key-pointer
    tactic: persistence
    techniques:
    - T1547.001
  - name: WMI Drive and Profile Discovery
    observables:
    - gwmi win32_userprofile
    - S-1-5-21
    - Get-PSDrive -PSProvider FileSystem
    - Get-CimInstance Win32_LogicalDisk
    - System.Timers.Timer
    - 'Interval: 3600000'
    slug: drive-and-profile-discovery
    tactic: discovery
    techniques:
    - T1047
    - T1555
  - name: Data Exfiltration to S3 Storage
    observables:
    - tebi.io
    - MD5 hash deduplication log
    - plLmfuh4uctxjtrQSXC
    slug: s3-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: Gamaredon's GammaSteel infostealer utilizes an advanced fileless mechanism,
    staging 71 encrypted PowerShell functions directly in the Windows registry using
    DPAPI. The malware achieves persistence through Run key pointers and employs recurring
    WMI-based scans and hardware listeners to identify and exfiltrate user documents
    to S3-compatible cloud storage.
series:
  index: 1
  slug: fsb-s-matryoshka-3-3-gamaredon-s-gammasteel-infostealer
  title: "FSB\u2019s matryoshka #3/3: Gamaredon's Gammasteel Infostealer"
  total: 2
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


# Gammasteel Fileless PowerShell Registry Staging

This hunt identifies the initial staging and orchestrator execution of the GammaSteel infostealer. The malware uses DPAPI to encrypt over 70 functions directly into the HKCU\Printers registry key, achieving fileless persistence. The orchestrator then runs from a hidden PowerShell process, reading and executing these functions directly in memory. We correlate unusual registry write volume in the Printers hive with script execution patterns involving DPAPI and hidden process command lines.

## registry-staging-scoping
<!-- Scoping Registry Staging Volume -->
Identify hosts where an anomalous number of registry values are written to the Printers key, indicating payload staging.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, staging_registry_path=staging_registry_path)
~~~yaml
expected: Hosts with multiple registry values written to the Printers hive. GammaSteel
  typically writes 71 unique keys.
reads:
- device_hostname
- reg_target
- activity_id
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, COUNT(DISTINCT reg_target) AS unique_keys, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '{{staging_registry_path}}' AND activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING unique_keys > 5 ORDER BY unique_keys DESC
```

## corroborate-staging
<!-- Corroborate Script and Process Evidence -->
parallel:
- → dpapi-script-activity
- → hidden-powershell-lead
join: → triage-staging

## dpapi-script-activity
<!-- PowerShell DPAPI and Registry Staging Logic -->
Detect the script content that uses DPAPI or native cryptography calls to protect payloads before writing them to the Printers key.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks calling DPAPI encryption cmdlets or the ProtectedData class
  alongside references to the Printers hive.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%convert%securestring%' OR LOWER(script_content) LIKE '%protecteddata%' OR LOWER(script_content) LIKE '%cryptprotectdata%' OR LOWER(script_content) LIKE '%cryptunprotectdata%') AND LOWER(script_content) LIKE '%printers%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## hidden-powershell-lead
<!-- Hidden PowerShell Execution Patterns -->
Find hidden PowerShell processes that execute around the same time as the registry activity to identify the orchestrator.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell processes launched with hidden windows or suppressed profiles,
  especially when matching the timing of registry writes.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%powershell.exe' AND (LOWER(process_cmd_line) LIKE '%-w hidden%' OR LOWER(process_cmd_line) LIKE '%-windowstyle hidden%' OR LOWER(process_cmd_line) LIKE '%-nol %' OR LOWER(process_cmd_line) LIKE '%-nop %') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-staging
<!-- Evaluate Staging Evidence -->
```agent target=hunter
cite: required
context:
- registry-staging-scoping
- dpapi-script-activity
- hidden-powershell-lead
max_iterations: 6
objective: Determine if a host shows the GammaSteel staging pattern. Specifically,
  correlate the hidden PowerShell process execution with registry writes in the Printers
  hive within a 10-minute window, and identify DPAPI-related script blocks.
success_criteria: A per-host verdict citing the registry keys, script blocks, and
  temporal correlation with hidden processes.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on Staging Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → remediate-registry
unavailable: → remediate-registry (blind_spot: no-script-block-logging)
else: → remediate-registry

## isolate-endpoint
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the HKCU registry hive for forensic analysis.
```
→ remediate-registry

## remediate-registry
<!-- Analyst Review and Registry Remediation -->
```manual target=analyst
Review the cited script content. Check for the Global\assembly307 mutex. Purge any confirmed malicious values under HKCU\Printers and the corresponding Run key pointer.
```
→ close-out

## close-out
<!-- Close Out -->
```manual target=analyst
Record the findings and ensure the hidden PowerShell detection is tuned to monitor for high-volume registry activity in the Printers hive.
```
→ end

---
analysis: A simple detection rule on tebi.io or WMI commands might be too noisy in
  environments with heavy administrative automation. This hunt pivots between the
  unique script-based timer logic (3.6m ms) and the rare combination of profile/disk
  discovery across three different telemetry surfaces, using stack-counting to isolate
  the stealer.
blind_spots:
- id: script-logging-gap
  question: whether the orchestrator script executed if block logging is disabled
    or if the script is heavily obfuscated
  requires: hb_script_activity with full block logging enabled
  risk: The hunt may miss the initial orchestrator trigger, relying solely on process
    discovery commands and DNS traffic which are easier for admins to overlook.
  stage: drive-and-profile-discovery
- id: s3-provider-rotation
  question: whether the adversary has rotated from tebi.io to another S3 provider
  requires: hb_http_activity
  risk: The hunt matches specific known domains; a new infrastructure choice makes
    the exfiltration invisible to the DNS step.
  stage: s3-exfiltration
coverage:
- stage: drive-and-profile-discovery
  status: covered
  steps:
  - orchestrator-timer-logic
  - rare-wmi-discovery
- stage: s3-exfiltration
  status: covered
  steps:
  - exfil-dns-lookups
- reason: This is handled in the GammaLoad hunt, which focuses on the initial execution
    and staging.
  stage: execution-powershell-dropper
  status: out_of_scope
- reason: Registry staging requires detailed analysis of HKCU\Printers hive writes,
    belonging to a loader-focused hunt.
  stage: registry-payload-staging
  status: out_of_scope
- reason: A standard detection rule for suspicious Run keys already covers the persistence
    mechanism used to relaunch the orchestrator.
  stage: persistence-run-key-pointer
  status: existing_rule
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Detecting the document scanning and exfiltration phase is the last
    opportunity to prevent the loss of sensitive data. Since Gamaredon heavily targets
    documents for espionage, a negative result across the estate provides critical
    assurance that active theft is not underway.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a recurring PowerShell timer to discover documents
  across user profiles and local/network drives, then exfiltrating them to an S3-compatible
  storage endpoint.
labels:
- hunt
- attack.t1041
- attack.t1047
- attack.t1059.001
- attack.t1555
name: 'Gamaredon Gammasteel: Drive Discovery and S3 Exfiltration'
parameters:
  exfil_domains:
    default:
    - tebi.io
    description: Known exfiltration domains used by Gammasteel.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to hunt across
      the entire estate.
    type: list[host]
  timer_interval:
    default: '3600000'
    description: The one-hour interval in milliseconds used by the orchestrator timer.
    from:
      kind: article
      observed: '2026-06-11'
      ref: sekoia
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize workstations and file servers where sensitive documents are
  stored. Ensure PowerShell Script Block Logging (Event ID 4104) is enabled, as the
  hunt relies on script text visibility.
references:
- name: "FSB\u2019s matryoshka #3/3: Gamaredon's Gammasteel Infostealer"
  url: https://www.sekoia.com/blog/fsbs-matryoshka-3-3-gamaredons-gifts-that-keeps-unpacking-gammasteel
related:
- hunt: gamaredon-gammaload-stager
  reason: GammaLoad is responsible for the registry staging that the orchestrator
    analyzed in this hunt later retrieves and executes.
  relation: precedes
- hunt: gammasteel-registry-staging
  relation: follows
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
  index: 2
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


# Gamaredon Gammasteel: Drive Discovery and S3 Exfiltration

This hunt targets the document discovery and exfiltration phase of Gammasteel, a modular stealer used by Gamaredon. The adversary establishes a one-hour recurring timer in PowerShell to trigger document scanning across all user profiles and logical disks. The hunt identifies this timer-based orchestration in script blocks, then fans out to detect the resulting WMI discovery commands and DNS resolutions to the known S3-compatible exfiltration provider. By pivoting from script-based triggers to prevalence-filtered process commands, the hunt separates automated malicious discovery from standard administrative activity.

## orchestrator-timer-logic
<!-- Search for orchestrator timer logic -->
Find PowerShell script blocks containing the specific one-hour timer interval or the Gammasteel orchestrator function name.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, timer_interval=timer_interval)
~~~yaml
expected: Script blocks defining a System.Timers.Timer with a 3.6m ms interval. Silence
  means no scripts matching these specific orchestrator patterns were logged.
reads:
- device_hostname
- script_content
- script_path
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (script_content LIKE '%{{timer_interval}}%' OR LOWER(script_content) LIKE '%pllmfuh4uctxjtrqsxc%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate discovery and exfiltration -->
parallel:
- → exfil-dns-lookups
- → rare-wmi-discovery
join: → triage-stealer-behavior

## exfil-dns-lookups
<!-- DNS lookups to exfiltration domains -->
Match host DNS traffic against known Gamaredon exfiltration infrastructure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, exfil_domains=exfil_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to tebi.io, especially from PowerShell processes. Silence suggests
  a shift in infrastructure or absence of the exfiltration phase.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## rare-wmi-discovery
<!-- Rare WMI discovery commands -->
Identify rare execution of WMI queries for user profiles or logical disks that separate the stealer from normal admin noise.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: PowerShell or WMIC commands enumerating profiles or drives on a small number
  of hosts. Large host counts indicate standard environment discovery.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%win32_userprofile%' OR LOWER(process_cmd_line) LIKE '%win32_logicaldisk%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3 ORDER BY hosts
```

## triage-stealer-behavior
<!-- Triage stealer behavior -->
```agent target=hunter
cite: required
context:
- orchestrator-timer-logic
- exfil-dns-lookups
- rare-wmi-discovery
max_iterations: 4
objective: Determine if the PowerShell activity represents an automated document exfiltration
  tool by correlating the script timer logic with the subsequent drive discovery and
  network traffic.
success_criteria: A verdict of malicious | suspicious | benign citing specific rows
  and script content segments.
tools:
- endpoint
```

## evaluate-verdict
<!-- Evaluate verdict -->
if~: "the triage-stealer-behavior verdict is malicious for at least one host, particularly where script timer logic and exfiltration domains appear together" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-re-review
unavailable: → analyst-re-review (blind_spot: script-logging-gap)
else: → archive-hunt

## isolate-endpoint
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and preserve the PowerShell event logs and registry hives for HKCU\Printers.
```
→ analyst-re-review

## analyst-re-review
<!-- Detailed analyst review -->
```manual target=analyst
Examine hb_file_activity for the suspicious PowerShell process to determine which user documents were accessed. Check for the presence of the Global\assembly307 mutex to confirm Gammasteel orchestrator execution.
```
→ end

## archive-hunt
<!-- Archive hunt -->
```manual target=analyst
Summarize the hosts that showed timer activity vs those that showed DNS exfiltration. Note any false positives from legitimate administrative WMI scripts.
```
→ end

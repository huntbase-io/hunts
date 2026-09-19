---
analysis: "This hunt pivots from a non-standard module load to fleet-wide path prevalence\
  \ and process 'on_disk' status\u2014corroborating three independent behavioral signals\
  \ into one confirmed compromise verdict."
blind_spots:
- id: no-module-telemetry
  question: whether the sideloading occurred on hosts where module loads are not monitored
  requires: hb_module_activity with ImageLoaded events
  risk: A sideloading event would be invisible; detection would rely entirely on follow-on
    process hollowing signals.
  stage: dll-search-order-hijacking
- id: powershell-block-logging
  question: the exact URL and payload destination used in the staging script
  requires: hb_script_activity with full block text
  risk: An analyst cannot determine the source of the infection or what other files
    were staged.
  stage: initial-powershell-lure
coverage:
- stage: initial-powershell-lure
  status: covered
  steps:
  - powershell-staging-lure
- stage: dll-search-order-hijacking
  status: covered
  steps:
  - sideload-detection
  - rare-path-baseline
- stage: process-hollowing-injection
  status: covered
  steps:
  - process-hollowing-signal
- stage: remus-infostealer-activity
  status: covered
  steps:
  - triage-agent
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: edr-evasion-byovd
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The ClickFix campaign uses DLL sideloading and process hollowing
    to evade traditional endpoint alerts. A hunt across module and process planes
    identifies the behavioral chain that single rules may miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using ClickFix-themed social engineering to drop a legitimate
  Microsoft binary and a malicious NativeAOT library in a user-writable directory
  to achieve sideloading and process hollowing.
labels:
- hunt
- attack.t1574.002
- attack.t1055.012
- attack.t1059.001
- attack.t1555
name: ClickFix DLL Sideloading and Process Hollowing
parameters:
  hijack_dll:
    default: mscoree.dll
    description: The library name used for sideloading.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Paste hosts from the scoping step to focus the hunt; leave empty
      for fleet-wide.
    type: list[host]
  target_exes:
    default:
    - vb7to8.exe
    - servicemodelreg.exe
    description: Legitimate Microsoft binaries abused for sideloading and hollowing.
    from:
      kind: article
      observed: '2026-08-28'
      ref: elastic-security-labs
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with hosts running .NET software. Narrow the hunt to workstations
  first, as ClickFix is primarily a user-targeted social engineering lure.
references:
- name: "Elastic Security Labs \u2014 From 88 lines to 1: Detecting DLL hijacking\
    \ with Elastic Defend"
  url: https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend
related:
- hunt: edr-evasion-byovd
  reason: The driver-based EDR evasion component is a kernel-level behavior that requires
    its own hunt on driver loads and system services.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ClickFix PowerShell Staging
    observables:
    - PowerShell script block execution
    - ClickFix social engineering lure
    - Download and drop of vb7to8.exe and mscoree.dll
    slug: initial-powershell-lure
    tactic: execution
    techniques:
    - T1059.001
  - name: DLL Sideloading via Microsoft Binary
    observables:
    - mscoree.dll loaded by vb7to8.exe from its own directory
    - Visual Basic 8 Keyword Upgrade Tool binary
    - NativeAOT library characteristics
    - ModuleInitializerAttribute usage
    - Exported functions LoadLibraryShim and LoadStringRCEx
    slug: dll-search-order-hijacking
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Process Hollowing into ServiceModelReg.exe
    observables:
    - Creation of ServiceModelReg.exe in suspended state
    - Process creation flags 0x8000004 (CREATE_NO_WINDOW | CREATE_SUSPENDED)
    - Validation of MZ and PE bytes (4D 5A, 50 45) in target memory
    slug: process-hollowing-injection
    tactic: defense-evasion
    techniques:
    - T1055.012
  - name: BYOVD Defense Evasion
    observables:
    - Vulnerable driver delivery to disable Elastic Endpoint
    - Driver-based EDR termination
    slug: edr-evasion-byovd
    tactic: defense-evasion
  - name: Infostealer Credential Access
    observables:
    - Remus infostealer payload execution inside hollowed process
    slug: remus-infostealer-activity
    tactic: credential-access
    techniques:
    - T1555
  summary: The ClickFix campaign uses malicious PowerShell to deliver a signed Microsoft
    binary (vb7to8.exe) and a malicious NativeAOT-compiled DLL (mscoree.dll) for search-order
    hijacking. The sideloaded code then performs process hollowing on ServiceModelReg.exe
    to execute the Remus infostealer and attempts to disable security software using
    a vulnerable driver.
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


# ClickFix DLL Sideloading and Process Hollowing

This hunt follows the ClickFix execution chain documented by Elastic Security Labs. It begins by scoping hosts with .NET environments where NativeAOT libraries can execute, then identifies the loading of mscoree.dll from non-system directories. It corroborates this lead with fleet-wide path baselining of the Visual Basic Upgrade tool (vb7to8.exe), identifies process hollowing signals on the Service Model Registration tool (ServiceModelReg.exe), and recovers the initial PowerShell staging script.

## dotnet-host-scoping
<!-- Scope to .NET environments -->
Identify hosts that could execute the NativeAOT payload by checking for .NET software installations.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Since the payload is a .NET NativeAOT library, hosts
  with .NET runtimes are primary candidates for this campaign.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%microsoft.net%' OR LOWER(package_name) LIKE '%.net%runtime%'
```

## sideload-detection
<!-- Non-system load of mscoree.dll -->
Detect mscoree.dll being loaded from a directory that is not a standard system path, a primary indicator of sideloading.

```sqlite target=endpoint role=detection-candidate params=(hijack_dll=hijack_dll, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows showing mscoree.dll loaded into vb7to8.exe (or similar) from paths
  like \AppData\ or \Public\.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE LOWER(module_name) = '{{hijack_dll}}' AND LOWER(module_path) NOT LIKE 'c:\windows\system32\%' AND LOWER(module_path) NOT LIKE 'c:\windows\syswow64\%' AND LOWER(module_path) NOT LIKE 'c:\windows\microsoft.net\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-evidence
<!-- Corroborate execution and hollowing -->
parallel:
- → rare-path-baseline
- → powershell-staging-lure
- → process-hollowing-signal
join: → triage-agent

## rare-path-baseline
<!-- Rare execution paths for target binaries -->
Stack-count the paths of vb7to8.exe to identify instances running outside of standard administrative locations.

```sqlite target=endpoint role=baseline params=(target_exes=target_exes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A path like C:\Users\Public\vb7to8.exe appearing on only one or two hosts,
  whereas system-wide installations will have high counts.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{target_exes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3 ORDER BY hosts ASC
```

## powershell-staging-lure
<!-- ClickFix PowerShell staging scripts -->
Identify the PowerShell script blocks that downloaded or staged the malicious pair of files.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing web requests or file-move commands targeting the
  specific binary names mentioned in the report.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%vb7to8.exe%' OR LOWER(script_content) LIKE '%mscoree.dll%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## process-hollowing-signal
<!-- Hollowing of ServiceModelReg.exe -->
Identify instances of the service registration tool running without a backing binary on disk, a definitive sign of hollowing.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any row where on_disk = 0 for this process is evidence of successful injection.
reads:
- device_hostname
- process_name
- process_cmd_line
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, on_disk, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%servicemodelreg.exe%' AND on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage ClickFix campaign -->
```agent target=hunter
cite: required
context:
- sideload-detection
- rare-path-baseline
- powershell-staging-lure
- process-hollowing-signal
max_iterations: 5
objective: Determine if the loading of mscoree.dll into vb7to8.exe and subsequent
  spawning of a hollowed ServiceModelReg.exe indicates a successful ClickFix infection.
success_criteria: A verdict per host citing the 'on_disk' status and module load paths.
tools:
- endpoint
```

## verdict-decision
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-task
unavailable: → analyst-task (blind_spot: no-module-telemetry)
else: → analyst-task

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR. Collect the mscoree.dll and vb7to8.exe binaries from the observed directory for analysis.
```
→ analyst-task

## analyst-task
<!-- Analyst Review -->
```manual target=analyst
Examine the script_content from the staging step to identify the download URL. Verify if the host has already loaded the BYOVD driver mentioned in the article.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the hash of the malicious mscoree.dll. If the sideloading check was a true positive, consider promoting the non-system load of mscoree.dll to a standing detection rule.
```
→ end

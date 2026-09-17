---
analysis: A standard rule might fire on 'wscript spawning from ScreenConnect', but
  this hunt goes further by baselining the arguments across the fleet and corroborating
  the presence of staged files and EDR-profiling logic, which reduces false positives
  from legitimate administrative scripts.
blind_spots:
- id: no-process-logs
  question: Did ScreenConnect launch wscript on hosts whose process logs have already
    rotated?
  requires: hb_process_activity with command-line retention
  risk: A host that was compromised 30 days ago would show the software in inventory
    but no behavioral trace of the loader execution.
  stage: rogue-rmm-deployment
- id: script-block-visibility
  question: Can we see the content of 2.vbs and 3.vbs if they are encoded or in-memory
    only?
  requires: hb_script_activity with full VBScript block logging
  risk: If an attacker uses a different scripting engine or obfuscates the VBScript
    beyond what the collector captures, the 'profiling' logic may be missed.
  stage: vbs-loader-chain
coverage:
- stage: initial-access-social-engineering
  status: covered
  steps:
  - scoping-rmm-software
- stage: rogue-rmm-deployment
  status: covered
  steps:
  - suspicious-wscript-execution
- stage: vbs-loader-chain
  status: covered
  steps:
  - prevalence-wscript-args
  - staged-file-artifacts
- reason: Propagation is identified when the rare RMM -> wscript pattern is observed
    on multiple hosts within a short window.
  stage: worm-like-propagation
  status: covered
  steps:
  - suspicious-wscript-execution
  - prevalence-wscript-args
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: persistence-registry-run-key
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: command-and-control-network
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: RMM tools like ScreenConnect provide full interactive control and
    often bypass perimeter defenses. Rogue installations used to deploy multi-stage
    loaders suggest targeted activity or worm-like spread. A negative result confirms
    the estate is free of this specific persistent threat.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using rogue ScreenConnect instances, often deployed via
  Quick Assist scams, to execute a sequential VBScript loader chain that profiles
  EDR presence and establishes a worm-like propagation.
labels:
- hunt
- attack.t1021.001
- attack.t1059.001
- attack.t1566
- attack.t1547.001
name: Rogue ScreenConnect and VBScript Loader Chain
parameters:
  edr_profiling_keywords:
    default:
    - Huntress.exe
    - CAMP.exe
    - SentinelService.exe
    - MsMpEng.exe
    - CylanceSvc.exe
    - SavService.exe
    description: Common EDR process names checked by the profiling script (1.vbs).
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of process and file history to examine.
    from:
      kind: manual
      observed: '2024-05-15'
      ref: hunt-standard
    type: number
  rmm_processes:
    default:
    - ScreenConnect.WindowsClient.exe
    - UltraViewer_Desktop.exe
    - ScreenConnect.Client.exe
    - ScreenConnect.Service.exe
    description: Known RMM process names to monitor for suspicious child execution.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for the full estate.
    from:
      kind: manual
      observed: '2024-05-15'
      ref: scoping
    type: list[host]
  staged_indicators:
    default:
    - 1.vbs
    - 2.vbs
    - 3.vbs
    - 4.vbs
    - value.txt
    - map.txt
    - out.enc
    - runner.ps1
    - pytorchfix.ps1
    - WindowsServiceHost.vbs
    - WindowsServiceHost.bat
    description: Specific filenames observed in the loader and persistence chain.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-rogue-screenconnect
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rogue-screenconnect-installations
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should initially target hosts with ScreenConnect in their software
  inventory but remain open-estate for the behavioral wscript launch to catch 'fileless'
  or stand-alone instances like ScreenConnect.Client.exe.
references:
- name: "Huntress \u2014 Rogue ScreenConnect Installations Across Unrelated Hosts"
  url: https://www.huntress.com/blog/rogue-screenconnect-installations
related:
- hunt: persistence-registry-run-key
  reason: The 'WindowsServiceHost' registry key used for persistence is a common indicator
    that belongs in a broader persistence-focused hunt.
  relation: sibling
scenario:
  stages:
  - name: Social Engineering and Phishing
    observables:
    - Execution of Quick Assist (remote support tool)
    - Downloading ScreenConnect.ClientSetup.msi via Microsoft Edge
    - Execution of ScreenConnect.Client.exe following 'Geek Squad refund' searches
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Rogue RMM Deployment
    observables:
    - ScreenConnect.WindowsClient.exe spawning wscript.exe
    - Installation of UltraViewer remote desktop software
    - Execution of ScreenConnect.ClientSetup.msi from download directories
    slug: rogue-rmm-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Staged VBScript Chain
    observables:
    - wscript.exe executing 1.vbs, 2.vbs, 3.vbs, and 4.vbs
    - Creation of %TEMP%\value.txt (system profiling results)
    - Creation of %TEMP%\map.txt (XOR-encoded payload map)
    - Creation of %TEMP%\out.enc (encrypted AES payload)
    - Creation of %TEMP%\runner.ps1 (payload decryptor)
    slug: vbs-loader-chain
    tactic: execution
    techniques:
    - T1059.001
  - name: Registry Run Key Persistence
    observables:
    - Registry value 'WindowsServiceHost' in User Run Key
    - WindowsServiceHost.vbs located in AppData directory
    - WindowsServiceHost.bat execution
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Malicious Infrastructure C2
    observables:
    - Connections to 45.13.237.190, 131.123.40.98, 15.204.185.204
    - Connections to 146.59.55.107, 45.32.192.150 (UltraViewer)
    - Domain tele-sync.opik.net
    - Domain borertors92.anondns.net
    - Requests to Dropbox for map.txt downloads
    slug: command-and-control-network
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: ScreenConnect Internal Propagation
    observables:
    - ScreenConnect client pushing VBScript chain to connected endpoints
    - Execution of 1.vbs through 4.vbs on newly connected hosts
    slug: worm-like-propagation
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: "Threat actors are using social engineering and phishing to deploy rogue\
    \ ScreenConnect instances, which \u0633\u067E\u0633 execute a multi-stage VBScript\
    \ chain to profile hosts and deliver encrypted payloads. The campaign exhibits\
    \ worm-like propagation by utilizing the ScreenConnect client to push these malicious\
    \ scripts to newly connected systems, establishing persistence through registry\
    \ run keys."
series:
  index: 1
  slug: rogue-screenconnect-installations-across-unrelated-hosts-suggest-worm-like-activity
  title: Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like
    Activity
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


# Rogue ScreenConnect and VBScript Loader Chain

This hunt identifies rogue ScreenConnect installations and the subsequent execution of Windows Script Host (wscript.exe) used to run a multi-stage VBScript chain. We focus on identifying the anomalous parent-child relationship (ScreenConnect -> wscript), the profiling behavior used to evade EDR, and the creation of staged files in temporary directories. The hunt concludes by triaging the combined signal of RMM usage, rare script executions, and system profiling indicators.

## scoping-rmm-software
<!-- Inventory hosts with RMM software -->
Identify hosts that have ScreenConnect or UltraViewer installed to define the primary scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running these RMM tools. Legitimate software will be fleet-wide;
  rogue instances will be isolated or in unusual paths.
reads:
- device_hostname
- install_path
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%ultraviewer%')
```

## suspicious-wscript-execution
<!-- RMM processes spawning Windows Script Host -->
Identify the primary behavioral lead: ScreenConnect or UltraViewer spawning wscript.exe to execute external scripts.

```sqlite target=endpoint role=detection-candidate params=(rmm_processes=rmm_processes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: RMM binaries launching wscript.exe. This relationship is highly anomalous
  for legitimate administrative use of these tools.
reads:
- device_hostname
- parent_process_cmd_line
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, parent_process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) = 'wscript.exe' OR LOWER(process_name) = 'cscript.exe') AND (instr(',' || '{{rmm_processes}}' || ',', ',' || parent_process_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## prevalence-wscript-args
<!-- Stack-count wscript command lines -->
Identify rare script execution arguments that differ from standard fleet-wide administrative noise.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A script command line (e.g., executing 1.vbs) seen on only a few hosts.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) = 'wscript.exe' OR LOWER(process_name) = 'cscript.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## corroborate-activity
<!-- Corroborate artifacts and EDR presence -->
parallel:
- → check-edr-inventory
- → staged-file-artifacts
join: → triage-loader-chain

## check-edr-inventory
<!-- Inventory EDR presence for profiling context -->
Identify which security products are active on target hosts to help explain the 'state' variable results in the attacker's script.

```sqlite target=endpoint role=enrichment params=(edr_profiling_keywords=edr_profiling_keywords, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A list of running EDR processes on the scoped hosts. This allows the agent
  to confirm if the script's profiling logic would have found any tools.
reads:
- device_hostname
- process_file_description
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_file_description, time FROM hb_process_activity WHERE (instr(',' || '{{edr_profiling_keywords}}' || ',', ',' || process_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## staged-file-artifacts
<!-- Detect staged file indicators -->
Locate the specific .vbs, .txt, and .enc files created in Temp/AppData directories during the loader chain execution.

```sqlite target=endpoint role=triage params=(staged_indicators=staged_indicators, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Evidence of value.txt, map.txt, or out.enc being written to disk by wscript.exe
  or ScreenConnect.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, process_name, time FROM hb_file_activity WHERE (instr(',' || '{{staged_indicators}}' || ',', ',' || file_name || ',') > 0) AND (LOWER(file_path) LIKE '%\temp\%' OR LOWER(file_path) LIKE '%\appdata\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-loader-chain
<!-- Triage rogue RMM execution -->
```agent target=hunter
cite: required
context:
- suspicious-wscript-execution
- prevalence-wscript-args
- check-edr-inventory
- staged-file-artifacts
max_iterations: 5
objective: Identify if any host shows the pattern of a rogue ScreenConnect/UltraViewer
  installation that triggered a multi-stage script loader, citing the command lines
  and staged files as proof.
success_criteria: A list of compromised hosts with specific evidence of the 1.vbs-4.vbs
  sequence.
tools:
- endpoint
```

## decision-on-verdict
<!-- Route on malicious finding -->
if~: "the triage verdict is malicious for at least one host involving ScreenConnect or UltraViewer spawning wscript" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-task
unavailable: → analyst-task (blind_spot: no-process-logs)
else: → analyst-task

## isolate-host
<!-- Isolate malicious host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Do not reboot, as this may trigger the persistence mechanism (WindowsServiceHost run key). Collect memory and the %TEMP% folder contents.
```
→ analyst-task

## analyst-task
<!-- Manual investigation and cleanup -->
```manual target=analyst
1. Review cited command lines for 1.vbs, 2.vbs, etc.
2. Verify if the host has a legitimate ScreenConnect license; check the install path.
3. Check registry for 'WindowsServiceHost' in Run/RunOnce keys.
4. If out.enc was found, attempt to recover the runner.ps1 script for decryption context.
```
→ end

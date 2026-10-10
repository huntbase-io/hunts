---
analysis: "The hunt correlates three distinct stages\u2014initial access tools, anomalous\
  \ RMM child processes, and specific registry-based persistence\u2014using multiple\
  \ surfaces (process, registry, and script activity). This multi-stage context is\
  \ required to identify the campaign logic and reduce false positives from legitimate\
  \ IT activity."
blind_spots:
- id: vbs-script-visibility
  question: Can we see the decoded contents of the VBScript blocks?
  requires: hb_script_activity with full block retention
  risk: If the environment does not capture script block content, we cannot differentiate
    the profiling logic from legitimate administrative scripts.
  stage: host-profiling-and-discovery
- id: encrypted-payload-contents
  question: What is the final payload inside sys_cache.zip?
  requires: EDR memory scanning or forensic file recovery
  risk: The VBScript chain decrypts a ZIP file; without the AES key from the map.txt
    file or memory captures, the final 'worm' payload remains unknown.
  stage: powershell-payload-decryption
coverage:
- stage: initial-access-social-engineering
  status: covered
  steps:
  - social-engineering-lead
- stage: rogue-screenconnect-execution
  status: covered
  steps:
  - screenconnect-wscript-chain
- stage: host-profiling-and-discovery
  status: covered
  steps:
  - rare-script-profiling
  - edr-process-presence
- stage: persistence-via-run-key
  status: covered
  steps:
  - registry-persistence-lead
- reason: Script activity captures the execution of the numbered VBScripts and the
    runner.ps1 block.
  stage: powershell-payload-decryption
  status: covered
  steps:
  - rare-script-profiling
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: network-c2-and-staged-download
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: secondary-rmm-redundancy
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: "Adversaries are using legitimate RMM tools to bypass standard detection.\
    \ This hunt identifies the specific behavioral chain\u2014social engineering to\
    \ script execution to persistence\u2014that characterizes this campaign, which\
    \ a single rule would likely miss."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using social engineering to deploy rogue ScreenConnect
  clients that execute a multi-stage VBScript chain for host profiling and persistent
  access via registry run keys.
labels:
- hunt
- attack.t1566
- attack.t1021.001
- attack.t1059.001
- attack.t1547.001
- attack.t1071.001
name: Rogue ScreenConnect Host Execution and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: Huntress Article
    type: number
  profiling_keywords:
    default:
    - huntress.exe
    - ciscoamp.exe
    - falcon_sensor.exe
    - s1_agent.exe
    - sophos_edr.exe
    - windefend.exe
    description: Process names of security products the adversary scripts search for.
    from:
      kind: article
      observed: '2026-09-03'
      ref: Huntress Article
    type: list[string]
  rmm_processes:
    default:
    - screenconnect.windowsclient.exe
    - screenconnect.client.exe
    description: Known ScreenConnect client filenames.
    from:
      kind: article
      observed: '2026-09-03'
      ref: Huntress Article
    type: list[string]
  scope_hosts:
    default: []
    description: Limit the hunt to these hostnames; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2026-09-03'
      ref: User Input
    type: list[host]
  vbs_indicators:
    default:
    - 1.vbs
    - 2.vbs
    - 3.vbs
    - 4.vbs
    - windowsservicehost.vbs
    description: Filenames of scripts used in the reported staging and persistence
      phases.
    from:
      kind: article
      observed: '2026-09-03'
      ref: Huntress Article
    type: list[string]
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
rationale: Prioritize workstations and endpoints that show recent MSI installations
  in Downloads or Temp directories. Servers are lower priority given the social engineering
  component (Quick Assist/Phishing).
references:
- name: "Huntress \u2014 Rogue ScreenConnect Installations Suggest Worm-Like Activity"
  url: https://www.huntress.com/blog/rogue-screenconnect-installations
related:
- hunt: secondary-rmm-redundancy-check
  reason: This hunt focuses specifically on the ScreenConnect VBScript chain; a separate
    hunt should target other RMM tools like UltraViewer mentioned in the report.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access via Social Engineering
    observables:
    - Quick Assist
    - ScreenConnect.ClientSetup.msi
    - Geek Squad refund form
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
    - T1021.001
  - name: Rogue ScreenConnect and Script Execution
    observables:
    - ScreenConnect.WindowsClient.exe
    - ScreenConnect.Client.exe
    - wscript.exe
    - 1.vbs
    - 2.vbs
    - 3.vbs
    - 4.vbs
    slug: rogue-screenconnect-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Host Profiling and EDR Discovery
    observables:
    - 1.vbs
    - value.txt
    - Huntress
    - Cisco AMP
    - CrowdStrike
    - SentinelOne
    - Sophos
    - Malwarebytes
    - Microsoft Defender
    - RAM check > 5GB
    slug: host-profiling-and-discovery
    tactic: discovery
    techniques:
    - T1059.001
  - name: Persistence via Registry Run Key
    observables:
    - WindowsServiceHost
    - WindowsServiceHost.vbs
    - WindowsServiceHost.bat
    - AppData
    slug: persistence-via-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Network C2 and Staged Download
    observables:
    - 45.13.237.190
    - 131.123.40.98
    - 15.204.185.204
    - tele-sync.opik.net
    - borertors92.anondns.net
    - port 8041
    - Dropbox
    - map.txt
    - user.enc
    - acc.enc
    - combo.enc
    slug: network-c2-and-staged-download
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: PowerShell Payload Decryption and Execution
    observables:
    - runner.ps1
    - PyTorchFix.ps1
    - sys_cache.zip
    - out.enc
    - AES-CBC
    slug: powershell-payload-decryption
    tactic: execution
    techniques:
    - T1059.001
  - name: Secondary RMM Deployment
    observables:
    - UltraViewer
    - 146.59.55.107
    - 45.32.192.150
    slug: secondary-rmm-redundancy
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: Attackers leverage social engineering or phishing to deploy rogue ScreenConnect
    instances, which then execute a multi-stage VBScript chain to profile the host
    and bypass security products. The campaign establishes persistence through registry
    Run keys and downloads encrypted payloads from Dropbox, including secondary RMM
    tools like UltraViewer and tunneling utilities, with some samples exhibiting worm-like
    propagation via connected ScreenConnect endpoints.
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
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Rogue ScreenConnect Host Execution and Persistence

This hunt targets a specific attack pattern where ScreenConnect clients, often deployed after a social engineering prompt like Quick Assist, spawn Windows Script Host (wscript.exe) to execute a series of numbered VBScripts. The hunt follows a phased flow: first identifying initial access beachheads and anomalous process chains, then pivoting to registry-based persistence and host profiling logic. By weighing the presence of EDR processes against the specific VBScript content and persistence keys, an analyst can distinguish between unauthorized RMM tools and legitimate administrative activity.

## scoping-screenconnect
<!-- Identify ScreenConnect installations -->
Scope the estate to hosts with ScreenConnect or ConnectWise software to focus the behavioral queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with the relevant software. This does not confirm a rogue
  installation but narrows the scope.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(vendor_name) LIKE '%connectwise%')
```

## early-stage-activity
<!-- Analyze entry and anomalous execution -->
parallel:
- → social-engineering-lead
- → screenconnect-wscript-chain
join: → early-stage-read

## social-engineering-lead
<!-- Quick Assist and suspicious installers -->
Identify the reported social engineering tools (Quick Assist) and ScreenConnect setup files in non-standard paths.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Quick Assist usage or MSI execution followed by a ScreenConnect deployment.
  Silence proves absence of these specific launchers.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%quickassist.exe' OR LOWER(process_cmd_line) LIKE '%screenconnect.clientsetup.msi%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## screenconnect-wscript-chain
<!-- ScreenConnect spawning wscript.exe -->
Detect the anomalous core behavior where a ScreenConnect process launches the Windows Script Host.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rmm_processes=rmm_processes)
~~~yaml
expected: Anomalous parent-child process chains where the RMM client executes scripts.
  This is the primary behavioral detection candidate.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%wscript.exe') AND (instr(',' || '{{rmm_processes}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE '%screenconnect%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-read
<!-- Evaluate initial beachhead -->
```agent target=hunter
cite: required
context:
- social-engineering-lead
- screenconnect-wscript-chain
max_iterations: 3
objective: Determine if the Quick Assist or MSI activity correlates with ScreenConnect
  spawning wscript.exe to launch VBScripts.
success_criteria: A clear assessment of which hosts require follow-on hunting for
  persistence.
tools:
- endpoint
```

## follow-on-activity
<!-- Analyze persistence and profiling -->
parallel:
- → registry-persistence-lead
- → rare-script-profiling
- → edr-process-presence
join: → follow-on-read

## registry-persistence-lead
<!-- WindowsServiceHost Run key persistence -->
Find the registry Run key used by the adversary to maintain persistence across reboots.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry values pointing to VBScript or batch files in AppData or Temp folders.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\run\windowsservicehost' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-script-profiling
<!-- Rare profiling VBScripts -->
Identify rare VBScripts executed in the environment that match the report's filenames or logic.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, vbs_indicators=vbs_indicators)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare scripts containing 'value.txt' or the numbered filenames. These indicate
  the worm-like profiling logic is present.
prevalence:
  by: device_hostname
  key:
  - script_name
  - script_content
  rare_below: 3
reads:
- script_name
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT script_name, device_hostname, script_content, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_script_activity WHERE (instr(',' || '{{vbs_indicators}}' || ',', ',' || LOWER(script_name) || ',') > 0 OR instr(LOWER(script_content), 'value.txt') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_name, device_hostname, script_content HAVING host_count <= 3 ORDER BY host_count ASC
```

## edr-process-presence
<!-- Check presence of enumerated security software -->
Determine if the security products listed in the profiling script actually exist on the target hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, profiling_keywords=profiling_keywords)
~~~yaml
expected: A list of EDR processes present on the hosts. This context explains the
  'state variable' logic the adversary script uses.
reads:
- device_hostname
- process_name
- process_original_file_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_original_file_name, time FROM hb_process_activity WHERE instr(',' || '{{profiling_keywords}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-read
<!-- Full chain assessment -->
```agent target=hunter
cite: required
context:
- early-stage-read
- registry-persistence-lead
- rare-script-profiling
- edr-process-presence
max_iterations: 6
objective: Combine the early-stage read with the presence of registry persistence
  keys and rare profiling VBScripts to determine if a host has been successfully compromised
  by the rogue ScreenConnect worm.
success_criteria: A final verdict citing rows across the entry, execution, and persistence
  stages.
tools:
- endpoint
```

## route-on-risk
<!-- Route based on compromise confidence -->
if~: "the follow-on-read verdict is malicious for at least one host, with evidence of anomalous RMM execution and persistent registry keys" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: vbs-script-visibility)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect all files in the user's Temp and AppData folders for forensic analysis, then remove the rogue registry Run key.
```
→ analyst-review

## analyst-review
<!-- Forensic validation -->
```manual target=analyst
Review the ScreenConnect client installation path; if not in Program Files, it is highly suspect. Check for the presence of secondary tools like UltraViewer or the recovered sys_cache.zip.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record all identified C2 infrastructure and any recovered VBScript content in the incident report.
```
→ end

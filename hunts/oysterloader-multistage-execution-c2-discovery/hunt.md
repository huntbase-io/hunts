---
analysis: This hunt pivots between software inventory, fileless process behavior (on_disk=0),
  and network prevalence to distinguish legitimate installers from multi-stage intrusions.
blind_spots:
- id: no-etw-visibility
  question: Whether the specific API hammering (RevokeDragDrop, GetDC) occurred within
    the process.
  requires: EDR API monitoring or ETW threat intelligence
  risk: The hunt relies on secondary indicators like child processes rather than direct
    observation of evasion.
  stage: packer-api-hammering-evasion
- id: no-memory-permissions
  question: The exact permissions (RWX) of memory regions allocated by NtAllocateVirtualMemory.
  requires: hb_process_memory (not listed)
  risk: Missing the precise moment shellcode transitions to executable state.
  stage: shellcode-reflective-lzma-loading
coverage:
- stage: initial-access-signed-msi
  status: covered
  steps:
  - msi-software-scoping
- stage: packer-api-hammering-evasion
  status: covered
  steps:
  - anomalous-msiexec-children
  - unsigned-module-loads
- stage: shellcode-reflective-lzma-loading
  status: covered
  steps:
  - anomalous-msiexec-children
- stage: downloader-c2-communication
  status: covered
  steps:
  - rare-outbound-c2
- stage: post-exploitation-impact
  status: covered
  steps:
  - impact-file-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: OysterLoader is an active multi-stage dropper used by Rhysida ransomware.
    Its use of signed MSIs and extensive memory evasion makes it resistant to standard
    signature-based detection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via a signed MSI impersonating
  IT software and is executing in-memory shellcode to establish C2 and deploy ransomware
  or infostealers.
labels:
- hunt
- attack.t1090.003
- attack.t1486
- attack.t1555
- attack.t1204.002
- attack.t1566.002
- attack.t1497.001
- attack.t1106
- attack.t1027.002
- attack.t1055
name: OysterLoader Multi-stage Execution and C2 Discovery
parameters:
  impersonated_software:
    default:
    - putty
    - winscp
    - google authenticator
    - anydesk
    - teamviewer
    description: Names of legitimate software commonly impersonated by OysterLoader
      MSIs.
    from:
      kind: article
      observed: '2024-06-01'
      ref: sekoia-oysterloader-unmasked
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for execution and network events.
    from:
      kind: manual
      observed: '2024-06-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt based on scoping results.
    from:
      kind: manual
      observed: '2024-06-01'
      ref: analyst-input
    type: list[host]
  system_processes:
    default:
    - msiexec.exe
    - explorer.exe
    - svchost.exe
    description: Standard system processes often used as injection targets or parents
      in this chain.
    from:
      kind: manual
      observed: '2024-06-01'
      ref: article-analysis
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and administrative workstations where PuTTY or WinSCP
  installations might be expected but are rare as newly installed packages. Use the
  msi-software-scoping step to narrow the lookback for execution logs.
references:
- name: 'OysterLoader unmasked: the multi-stage evasion loader'
  url: https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/
related:
- hunt: gootloader-delivery-chain
  reason: OysterLoader is often delivered via Gootloader; this hunt focuses on the
    loader execution phase itself.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Signed MSI via Spoofed Software Sites
    observables:
    - Microsoft Installer (MSI) files
    - Impersonation of PuTTY, WinSCP, Google Authenticator
    - Fake software installer websites
    - Signed malicious MSI binaries
    slug: initial-access-signed-msi
    tactic: initial-access
    techniques:
    - T1204.002
    - T1566.002
  - name: TextShell Packer and API Hammering
    observables:
    - API hammering with RevokeDragDrop, GetDC, CreateSolidBrush, UnrealizeObject,
      SetMapMode, SetCommBreak
    - IsDebuggerPresent checks
    - 'Dynamic API resolution hash: h = (h * 0x2001 + ord(ch))'
    - 'API hashes: 0x9866A947, 0x895E0804, 0xEA1023BE, 0x8F1E88B1, 0x5CD5A5AA'
    - NtAllocateVirtualMemory with RWX permissions
    slug: packer-api-hammering-evasion
    tactic: defense-evasion
    techniques:
    - T1497.001
    - T1106
    - T1027
  - name: Custom LZMA Shellcode and Memory Execution
    observables:
    - Custom LZMA decompression routine
    - 'LZMA parameters: lc=3, lp=0, pb=2'
    - Relocation fixups for relative CALL (E8) and JMP (E9) opcodes
    - VirtualProtect calls to transition memory to executable state
    - In-memory execution of decompressed payload
    slug: shellcode-reflective-lzma-loading
    tactic: execution
    techniques:
    - T1027.002
    - T1055
  - name: Downloader C2 and Multi-hop Proxying
    observables:
    - Language and keyboard layout verification
    - InternetOpenW API calls
    - Multi-hop proxy infrastructure
    - C2 communication for final payload retrieval
    slug: downloader-c2-communication
    tactic: command-and-control
    techniques:
    - T1105
    - T1090.003
    - T1614
  - name: 'Payload Deployment: Vidar or Rhysida'
    observables:
    - Deployment of Vidar infostealer
    - Deployment of Rhysida ransomware
    - File encryption
    - Credential access from password stores
    slug: post-exploitation-impact
    tactic: impact
    techniques:
    - T1486
    - T1555
  summary: OysterLoader, also known as Broomstick or CleanUp, is a multi-stage C++
    loader distributed via fake websites impersonating software like PuTTY and WinSCP.
    The infection chain uses a heavily obfuscated packer with API hammering, a custom
    LZMA-compressed shellcode for memory execution, and a downloader stage that performs
    environment checks before communicating with C2 infrastructure, often leading
    to Rhysida ransomware or Vidar infostealer infections.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# OysterLoader Multi-stage Execution and C2 Discovery

OysterLoader (also known as Broomstick) uses a multi-stage infection chain beginning with a signed MSI that delivers the TextShell packer. This packer employs API hammering and custom LZMA shellcode to execute a downloader in-memory. This hunt follows a phased flow: first scoping for impersonated software packages, then identifying anomalous msiexec child processes and unsigned module loads, and finally correlating that execution with outbound C2 traffic and file-system impact characteristic of Rhysida ransomware or Vidar infostealers.

## msi-software-scoping
<!-- Scope hosts with suspicious software -->
Identify hosts that have recently installed software matching names commonly used by OysterLoader MSIs to narrow the investigation.

```sqlite target=endpoint role=scoping params=(impersonated_software=impersonated_software)
~~~yaml
expected: Hosts with software names like PuTTY or WinSCP. While these may be legitimate,
  they provide a starting list for cross-referencing with execution logs.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (instr(',' || '{{impersonated_software}}' || ',', ',' || LOWER(package_name) || ',') > 0) AND asset_scope = 'endpoint'
```

## early-stage-investigation
<!-- Investigate initial execution and memory evasion -->
parallel:
- → anomalous-msiexec-children
- → unsigned-module-loads
join: → triage-execution-evasion

## anomalous-msiexec-children
<!-- Anomalous msiexec child processes -->
Identify instances where msiexec.exe spawns unusual children or processes that exist only in memory (on_disk = 0).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: msiexec.exe spawning cmd.exe, powershell.exe, or unknown binaries. Processes
  with on_disk=0 suggest successful shellcode injection.
reads:
- device_hostname
- process_name
- process_cmd_line
- on_disk
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, on_disk, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%msiexec.exe%' OR on_disk = 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## unsigned-module-loads
<!-- Unsigned module loads in system processes -->
Find modules with invalid or missing signatures being loaded into standard system processes, which is a common byproduct of the loader downloader stage.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, system_processes=system_processes)
~~~yaml
expected: Modules with non-valid signature statuses loaded into legitimate processes
  like explorer.exe or svchost.exe.
reads:
- device_hostname
- process_name
- module_name
- module_path
- module_signature_status
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, module_name, module_path, module_signature_status, time FROM hb_module_activity WHERE module_signature_status != 'Valid' AND (instr(',' || '{{system_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-execution-evasion
<!-- Triage early execution evidence -->
```agent target=hunter
cite: required
context:
- msi-software-scoping
- anomalous-msiexec-children
- unsigned-module-loads
max_iterations: 3
objective: Determine if any host shows evidence of the OysterLoader Stage 1 or Stage
  2 execution based on MSI activity and memory evasion patterns.
success_criteria: A verdict of malicious or suspicious for hosts showing combined
  MSI and injection indicators.
tools:
- endpoint
- network
```

## follow-on-activity
<!-- Correlate with C2 and Impact -->
parallel:
- → rare-outbound-c2
- → impact-file-activity
join: → triage-full-infection

## rare-outbound-c2
<!-- Rare outbound C2 connections -->
Find outbound network connections from processes identified in the early stages, stack-counting destination IPs to find rare C2 nodes across the fleet.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, system_processes=system_processes)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections from system processes to rare destination IPs, representing
  potential C2 nodes.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, process_name, GROUP_CONCAT(DISTINCT device_hostname) as hosts_list, COUNT(DISTINCT device_hostname) as hosts, MIN(time) as first_seen FROM hb_network_connection WHERE (instr(',' || '{{system_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port, process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## impact-file-activity
<!-- Impact behavior: Ransomware and Infostealers -->
Detect the final stage impact by identifying mass file modification or access to credential stores.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Mass access to browser 'Login Data' files or creation of files with extensions
  like .rhysida, focusing on volume characteristic of ransomware.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
- file_name
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, COUNT(*) as file_count, MIN(time) as start_time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\login data' OR LOWER(file_name) LIKE '%.rhysida' OR LOWER(file_name) LIKE '%.locked') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_count > 10
```

## triage-full-infection
<!-- Triage full intrusion chain -->
```agent target=hunter
cite: required
context:
- triage-execution-evasion
- rare-outbound-c2
- impact-file-activity
max_iterations: 4
objective: Combine the evidence of MSI execution, in-memory evasion, C2 communication,
  and post-exploitation impact to determine if an intrusion has occurred.
success_criteria: A definitive verdict citing the progression from MSI installer to
  ransomware or infostealer impact.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on verdict -->
if~: "the triage-full-infection verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: no-etw-visibility)
else: → hunt-closure

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the endpoint agent to halt C2 and impact.
```
→ analyst-remediation

## analyst-remediation
<!-- Analyst remediation and review -->
```manual target=analyst
Review cited rows; confirm the malicious MSI and identify the initial download source.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure -->
```manual target=analyst
Record the results; if malicious activity was found, promote the anomalous-msiexec-children query to a detection rule.
```
→ end

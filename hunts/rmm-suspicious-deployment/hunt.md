---
analysis: "This hunt uses software inventory as a baseline to isolate 'authorized'\
  \ noise, stack-counts rare binaries in user-writable paths, and excludes known vendors\
  \ in the prevalence step\u2014pivots that a static rule cannot perform without high\
  \ false-positive rates."
blind_spots:
- id: missing-script-logging
  question: whether RMM components were downloaded via in-memory PowerShell cradles
  requires: PowerShell Script Block Logging
  risk: Adversaries using fileless RMM deployment would only be visible if a socket
    was captured, but intent would be lost.
  stage: execution-via-powershell-and-msi
- id: generic-msiexec-noise
  question: whether msiexec.exe was used to install an RMM service silently
  requires: hb_process_activity with parent command line
  risk: Unless the parent process is Syncro, it is hard to differentiate RMM sideloading
    from standard application updates.
  stage: persistence-via-rmm-services
coverage:
- stage: initial-access-phishing-lures
  status: covered
  steps:
  - suspicious-rmm-processes
  - rare-binaries-in-user-folders
- stage: execution-via-powershell-and-msi
  status: covered
  steps:
  - rmm-powershell-cradles
  - suspicious-rmm-processes
- stage: persistence-via-rmm-services
  status: covered
  steps:
  - suspicious-rmm-processes
  - scope-rmm-inventory
- stage: defense-evasion-binary-relocation
  status: covered
  steps:
  - suspicious-rmm-processes
  - rare-binaries-in-user-folders
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: credential-access-stealers
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: c2-rmm-network-patterns
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: impact-pre-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries use legitimate RMM tools because they are signed and
    trusted. A negative result across the estate ensures no unauthorized management
    tools are acting as persistent backdoors.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are deploying legitimate RMM tools (ScreenConnect, NetSupport,
  Syncro) to user-writable paths or using unusual process trees to establish persistent,
  signed remote access that bypasses standard detections.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1543.003
- attack.t1574.002
name: Suspicious RMM Deployment and Service Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of endpoint history to examine.
    type: number
  rmm_filenames:
    default:
    - client32.exe
    - remotepcservice.exe
    - rmmservice.exe
    - hostservice.exe
    - syncrolive.agent.runner.exe
    - remotepchost1.exe
    - screenconnect.client.exe
    - getscreen.exe
    - superops.exe
    description: Known RMM executable names to monitor for path anomalies.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm-abuse
    type: list[string]
  rmm_lures:
    default:
    - ssa.msi
    - invited.exe
    - ecard9140.exe
    - msteam-installer.msiin
    - irs-statement_pr2ui4j9cfa6yeu.exe
    - docmentfilecsm_jw98evavuqm5gb3.exe
    description: Specific lure filenames identified in RMM phishing campaigns.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm-abuse
    type: list[string]
  scope_hosts:
    default: []
    description: Comma-separated list of hostnames to focus on; populate this with
      hosts from the inventory step that lack authorized RMM.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/security-operations/rmm-detection/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Run the initial inventory query first. If results show 'unauthorized' hosts,
  add them to the scope_hosts parameter for behavior analysis. Focus on user workstations
  first.
references:
- name: "Red Canary \u2014 The dual-use dilemma: Rethinking detection for remote access\
    \ tool abuse"
  url: https://redcanary.com/blog/security-operations/rmm-detection/
related:
- hunt: c2-rmm-network-patterns
  reason: Once an RMM binary is identified, analyze network traffic for C2 communication
    to legitimate RMM domains.
  relation: follows
scenario:
  stages:
  - name: Phishing with RMM Lures
    observables:
    - ssa.msi
    - Ecard9140.exe
    - invited.exe
    - MSTeam-installer.msiin
    - IRS-Statement_Pr2ui4J9cfA6YEu.exe
    - docmentfilecsm_jw98evavuqm5gb3.exe
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: RMM Loader Execution
    observables:
    - PowerShell scripts downloading ZIP files
    - SyncroLive.Agent.Runner.exe spawning msiexec.exe
    - msiexec.exe used to sideload ScreenConnect
    - PowerShell cradles for ScreenConnect installation
    slug: execution-via-powershell-and-msi
    tactic: execution
    techniques:
    - T1059.001
  - name: RMM Service Establishment
    observables:
    - HostService.exe
    - remotepcservice.exe
    - RMMService.exe
    - JumpCloud installing GetScreen, ScreenConnect, and SuperOps
    slug: persistence-via-rmm-services
    tactic: persistence
    techniques:
    - T1543.003
  - name: Legitimate Binary Abuse and Relocation
    observables:
    - client32.exe relocated to C:\Users\Public\
    - client32.exe in folders with randomized names
    - remotepchost1.exe setup process
    - DicomPortable.exe sideloading malicious DLLs
    slug: defense-evasion-binary-relocation
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Credential Stealer Deployment
    observables:
    - DICOMportable.zip
    - DeerStealer
    - HijackLoader
    slug: credential-access-stealers
    tactic: credential-access
    techniques:
    - T1555
  - name: RMM-Specific C2 Communication
    observables:
    - 'User-Agent: NetSupport Manager/1.3'
    - 'User-Agent: JWrapperDownloader'
    - 'User-Agent: Servicing/1.0.29.18406'
    - client32.ini Gateway Address
    - remotepc.com
    - remotedesktop.com
    - syncromsp.com
    - syncroapi.com
    - kabutoservices.com
    - atera.com
    - atera-agent-heartbeat.servicebus.windows.net
    - cmdm.comodo.com
    - /access/JWrapper-Remote%20Access-version.txt
    slug: c2-rmm-network-patterns
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Ransomware Preparation
    observables:
    - Precursor activity for ransomware deployment
    slug: impact-pre-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Adversaries are increasingly abusing legitimate, signed Remote Monitoring
    and Management (RMM) tools like ScreenConnect, NetSupport, and PDQ Connect to
    bypass security controls. The campaign typically involves phishing for initial
    access, followed by the deployment of multiple RMM agents as loaders and layers
    of contingency to maintain persistent access before executing credential theft
    or ransomware.
series:
  index: 1
  slug: the-dual-use-dilemma-rethinking-detection-for-remote-access-tool-abuse
  title: 'The dual-use dilemma: Rethinking detection for remote access tool abuse'
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


# Suspicious RMM Deployment and Service Persistence

This hunt identifies endpoint-side installation and execution patterns of abused Remote Monitoring and Management (RMM) tools. It targets binary relocation (e.g., NetSupport in Public folders), anomalous process trees (e.g., Syncro spawning MSIExec for sideloading), and the presence of rare, renamed installers identified in recent phishing campaigns. By correlating software inventory with behavioral telemetry and stack-counting rare binaries in user-writable directories while excluding known-good vendors, we identify 'living-off-the-land' persistence that mimics standard IT support.

## scope-rmm-inventory
<!-- Inventory of Authorized RMM Software -->
Establish a baseline of hosts where RMM software is officially managed to identify unauthorized deployments later.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with legitimate RMM tools. Hosts NOT in this list that show
  RMM activity in later steps are the primary concern.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%netsupport%' OR LOWER(package_name) LIKE '%atera%' OR LOWER(package_name) LIKE '%syncro%' OR LOWER(package_name) LIKE '%itarian%' OR LOWER(package_name) LIKE '%remotepc%' OR LOWER(package_name) LIKE '%pdq%'
```

## parallel-corroborate
<!-- Corroborate RMM Indicators -->
parallel:
- → suspicious-rmm-processes
- → rare-binaries-in-user-folders
- → rmm-powershell-cradles
join: → triage-rmm-activity

## suspicious-rmm-processes
<!-- Suspicious RMM Process Trees -->
Identify RMM binaries running from user-writable paths or spawned by unusual parent processes, specifically on hosts lacking authorized RMM software.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, rmm_filenames=rmm_filenames, rmm_lures=rmm_lures, lookback_days=lookback_days)
~~~yaml
expected: NetSupport (client32) in Public folders, Syncro sideloading ScreenConnect
  via MSIExec, or renamed phishing lures executing.
reads:
- device_hostname
- process_name
- process_path
- parent_process_name
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, parent_process_name, process_cmd_line, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (((LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\appdata\\%') AND instr(',' || LOWER('{{rmm_filenames}}') || ',', ',' || LOWER(process_name) || ',') > 0) OR (LOWER(parent_process_name) LIKE '%syncrolive.agent.runner.exe' AND LOWER(process_name) LIKE '%msiexec.exe') OR (instr(',' || LOWER('{{rmm_lures}}') || ',', ',' || LOWER(process_name) || ',') > 0))) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-binaries-in-user-folders
<!-- Rare Binaries in User-Writable Paths -->
Stack-count binaries in Public and Temp directories while excluding known-good vendors to find renamed RMM installers.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique installers or renamed binaries (e.g., party_invite.exe) found on
  very few hosts, where no authorized vendor metadata is present.
prevalence:
  by: device_hostname
  key:
  - binary_name
  - path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- process_file_company
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) as binary_name, LOWER(process_path) as path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\\users\\public\\%' OR LOWER(process_path) LIKE '%\\appdata\\local\\temp\\%') AND (LOWER(process_name) LIKE '%.exe' OR LOWER(process_name) LIKE '%.msi') AND NOT (LOWER(process_file_company) LIKE '%screenconnect%' OR LOWER(process_file_company) LIKE '%connectwise%' OR LOWER(process_file_company) LIKE '%netsupport%' OR LOWER(process_file_company) LIKE '%atera%' OR LOWER(process_file_company) LIKE '%syncro%' OR LOWER(process_file_company) LIKE '%itarian%' OR LOWER(process_file_company) LIKE '%pdq%')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING host_count <= 2 ORDER BY host_count ASC
```

## rmm-powershell-cradles
<!-- PowerShell RMM Installation Cradles -->
Identify PowerShell scripts downloading RMM components, which often follows an initial lure execution.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing download commands for RMM tools.
reads:
- device_hostname
- script_path
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(script_content) LIKE '%screenconnect%' OR LOWER(script_content) LIKE '%atera%' OR LOWER(script_content) LIKE '%netsupport%' OR LOWER(script_content) LIKE '%client32%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-rmm-activity
<!-- Triage RMM Activity -->
```agent target=hunter
cite: required
context:
- scope-rmm-inventory
- suspicious-rmm-processes
- rare-binaries-in-user-folders
- rmm-powershell-cradles
max_iterations: 4
objective: Determine if any host exhibits RMM tool deployment that lacks a corresponding
  entry in scope-rmm-inventory or follows a known phishing lure pattern. Focus on
  hosts where the tool is running from a user-writable path.
success_criteria: A verdict for each host citing the process path, parent-child discrepancy,
  and status in the software inventory.
tools:
- endpoint
```

## decide-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is 'malicious' or 'suspicious' for a host where the RMM tool was not found in the authorized software inventory" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-script-logging)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and gather the RMM binary for forensic analysis. Confirm if a service was created.
```
→ analyst-review

## analyst-review
<!-- Manual Verification -->
```manual target=analyst
Review the identified RMM artifacts. If legitimate, update the internal asset directory or software inventory.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
No unauthorized RMM activity was confirmed. Document the scope for compliance records.
```
→ end

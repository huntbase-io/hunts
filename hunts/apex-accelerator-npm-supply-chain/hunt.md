---
analysis: A simple detection rule might fire on the specific domains, but this hunt
  use a generalized behavioral search for any binary execution from node_modules directories,
  pivoting between inventory and process telemetry to build a complete chain of intent.
blind_spots:
- id: inventory-visibility-gap
  question: whether a package was installed locally in a project directory rather
    than globally
  requires: hb_software_inventory coverage for local node_modules
  risk: Local npm installations might not be picked up by global inventory scanners,
    and the lack of installation timestamps in the inventory surface prevents temporal
    correlation with execution events.
  stage: supply-chain-npm-install
- id: network-visibility-gap
  question: whether a network flow initiated by a project-path binary is attributed
    correctly
  requires: hb_network_connection with process path enrichment on every flow
  risk: Without high-fidelity process attribution on network connections, identifying
    callbacks from binaries in project directories relies on endpoint telemetry that
    may be incomplete.
  stage: c2-command-retrieval
coverage:
- stage: supply-chain-npm-install
  status: covered
  steps:
  - detect-npm-packages
- stage: launcher-binary-execution
  status: covered
  steps:
  - detect-launcher-binaries
- stage: c2-command-retrieval
  status: covered
  steps:
  - detect-verification-callback
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: defense-evasion-registry-defender
  status: out_of_scope
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: powershell-vbs-staging
  status: out_of_scope
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: payload-malware-deployment
  status: out_of_scope
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: exfiltration-over-telegram
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The use of malicious npm packages to target developers bypasses traditional
    perimeter defenses and exploits the trust inherent in the open-source ecosystem;
    a negative result confirms the estate is not currently impacted by this specific
    campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary targets developer workstations by tricking users into installing
  malicious npm packages that masquerade as Web3 auditing tools to execute platform-specific
  backdoors from within the project directory.
labels:
- hunt
- attack.t1195
- attack.t1071.001
- attack.t1204.002
- command and control
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: Apex Accelerator npm supply-chain delivery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the software inventory scoping step; leave empty
      to hunt across the entire estate.
    type: list[host]
  target_packages:
    default:
    - '@apexacc/cli'
    - '@apexacc/audit'
    description: Malicious npm package names identified in the research.
    from:
      kind: article
      observed: '2026-10-12'
      ref: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on engineering and developer workstations where npm is in use. The
  software inventory scoping step narrows behavior queries to only the affected hosts,
  reducing telemetry cost.
references:
- name: 'Auditing the auditor: Unmasking Apex Accelerator'
  url: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
related:
- hunt: apex-accelerator-powershell-vbs-staging
  reason: This hunt identifies the delivery; the follow-on hunt examines the PowerShell
    and VBScript staging identified in the research.
  relation: follows
scenario:
  stages:
  - name: Malicious npm Package Installation
    observables:
    - '@apexacc/cli'
    - '@apexacc/audit'
    - apex.cjs
    - audit.cjs
    slug: supply-chain-npm-install
    tactic: initial-access
    techniques:
    - T1195
  - name: Platform-Specific Binary Launch
    observables:
    - apex-windows-x64.exe
    - apex-audit-windows-x64.exe
    - apex-darwin-arm64
    - apex-audit-darwin-arm64
    - apex-bootstrap.ts
    - main.ts
    slug: launcher-binary-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Verification Server Callback
    observables:
    - vrf.apexaccs.org
    - apex-verify-darwin
    - apex-audit-verify-darwin
    - POST /api/v1/vrf
    slug: c2-command-retrieval
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Windows Defense Impairment
    observables:
    - VerifiedAndReputablePolicyState
    - Add-MpPreference -ExclusionPath %USERPROFILE%\.apex-audit
    - UAC elevation requests on Windows 11
    slug: defense-evasion-registry-defender
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1112
  - name: Scripted Payload Staging
    observables:
    - _apex_run.vbs
    - _audit_run.vbs
    - _apex_run.ps1
    - _audit_run.ps1
    - drop.ps1
    - WScript.Shell.Run
    - powershell -NoProfile -ExecutionPolicy Bypass
    slug: powershell-vbs-staging
    tactic: execution
    techniques:
    - T1059.001
    - T1059.003
  - name: Info-Stealer and Backdoor Execution
    observables:
    - bludness.exe
    - install.exe
    - exegis.exe
    - updater_loader.exe
    - CloudSyncD
    - pi_natives.win32-x64-baseline.node
    slug: payload-malware-deployment
    tactic: persistence
    techniques:
    - T1005
  - name: Data Exfiltration
    observables:
    - Telegram API endpoints
    - ZIP archive creation in temporary directories
    - verify.apexfdn.xyz
    slug: exfiltration-over-telegram
    tactic: exfiltration
    techniques:
    - T1041
    - T1567
  summary: The Apex Accelerator campaign uses malicious npm packages and a fake Web3
    platform to target cryptocurrency startups with info-stealing malware. The attack
    chain involves a supply-chain delivery mechanism that fetches platform-specific
    executables (Bun/Rust) to retrieve and execute further payloads on Windows and
    macOS, ultimately exfiltrating data via Telegram.
series:
  index: 1
  slug: auditing-the-auditor-unmasking-apex-accelerator
  title: 'Auditing the auditor: Unmasking Apex Accelerator'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Apex Accelerator npm supply-chain delivery

The adversary targets crypto start-ups by distributing backdoored npm packages. The hunt is gated on a software inventory lead to minimize telemetry costs. The hunt identifies these packages in software inventory, then fans out to examine generalized binary execution from within node_modules directories and associated network callbacks. The analyst reviews the correlated evidence to confirm the intrusion.

## detect-npm-packages
<!-- Detect malicious npm packages and suspicious paths -->
Find hosts where the malicious Apex packages or their hidden configuration directories are present. The query use the instr() pattern because the platform expands the target_packages list as a comma-joined string; this ensures exact matches for each package name within the SQLite engine.

```sqlite target=endpoint role=scoping params=(target_packages=target_packages)
~~~yaml
expected: Rows identify specific hosts and users that installed the malicious packages.
  Silence means the specific packages or suspicious .apex directory patterns are not
  present in current inventory.
reads:
- device_hostname
- install_path
- package_name
- package_version
- provider
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, package_name, package_version, install_path, vendor_name, provider FROM hb_software_inventory WHERE (instr(',' || '{{target_packages}}' || ',', ',' || package_name || ',') > 0 OR LOWER(install_path) LIKE '%\\node_modules\\.apex%' OR LOWER(install_path) LIKE '%/node_modules/.apex%')
```

## assess-lead
<!-- Evaluate npm installation lead -->
```agent target=hunter
cite: required
context:
- detect-npm-packages
max_iterations: 3
objective: Decide if the identified hosts show evidence of the malicious Apex npm
  packages or suspicious local project configurations that requires further behavioral
  analysis.
success_criteria: A verdict of suspicious or benign per host.
tools:
- endpoint
- network
```

## gate-on-lead
<!-- Gate for behavioral queries -->
if~: "the assess-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-execution-and-callbacks
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: inventory-visibility-gap)
else: → close-out

## corroborate-execution-and-callbacks
<!-- Corroborate execution and callbacks -->
parallel:
- → detect-launcher-binaries
- → detect-verification-callback
join: → triage-findings

## detect-launcher-binaries
<!-- Generalized binary execution from node_modules -->
Identify any executable binary (PE or Mach-O) launched from within a node_modules directory tree. This generalized search captures renamed loaders or supporting components.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An executable seen on very few machines launched from a project dependency
  directory. Fleet-wide presence would suggest a legitimate developer tool.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- on_disk
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, COUNT(*) as runs, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\node_modules\\%' OR LOWER(process_path) LIKE '%/node_modules/%') AND (LOWER(process_path) LIKE '%.exe' OR LOWER(process_path) LIKE '%.node' OR on_disk = 0 OR (on_disk = 1 AND process_name NOT LIKE '%.%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_path, process_cmd_line, user_name
```

## detect-verification-callback
<!-- Network activity from node_modules processes -->
Identify external network connections initiated by processes running from node_modules. This effectively pivots from the execution leads to find callbacks without relying on a static domain list.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Network connections to external IPs from binaries located in node_modules
  project trees.
reads:
- device_hostname
- disposition
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as connections, MIN(time) as first_seen FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%\\node_modules\\%' OR LOWER(process_path) LIKE '%/node_modules/%') AND disposition = 'Allowed' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port
```

## triage-findings
<!-- Triage supply-chain activity -->
```agent target=hunter
cite: required
context:
- assess-lead
- detect-launcher-binaries
- detect-verification-callback
max_iterations: 6
objective: Evaluate whether the installation of suspicious packages led to binary
  execution from node_modules and associated C2 communication, indicating a successful
  supply-chain intrusion.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- network
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage-findings verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: network-visibility-gap)
else: → close-out

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve process memory for the loader binaries and any child shells.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Confirm the presence of the npm package and investigate the child processes of the identified loaders for shell execution. Review any HTTP activity from these processes to identify the specific C2 server and fetched commands.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
If no hits were found, record that the estate shows no evidence of the Apex Accelerator npm packages or suspicious binary execution from project directories within the lookback window.
```
→ end

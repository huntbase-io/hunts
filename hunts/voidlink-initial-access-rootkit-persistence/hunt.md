---
analysis: 'A static detection rule for a Dubbo CVE misses the behavioral pivot to
  statically linked fileless implants. This hunt correlates software inventory (scoping)
  with unusual sign-ins (stolen creds), then looks for the structural fingerprint
  of the ZigLang loader: fileless execution paired with an abnormally low count of
  loaded shared libraries.'
blind_spots:
- id: kernel-visibility-gap
  question: Are malicious LKMs or eBPF programs present in the kernel?
  requires: Kernel-mode logging for LKMs and eBPF programs
  risk: VoidLink is reported to use LKM/eBPF rootkits which can hide all user-space
    telemetry (processes, files, and modules).
  stage: persistence-defense-evasion-stealth
- id: java-payload-inspection
  question: Was a Java serialization payload delivered to the Dubbo endpoint?
  requires: hb_http_activity with full request body logging
  risk: Without request body inspection, we can only see the vulnerable software and
    follow-on behavior, not the exploit itself.
  stage: initial-access-vulnerability-exploitation
coverage:
- stage: initial-access-vulnerability-exploitation
  status: covered
  steps:
  - scope-vulnerable-dubbo
  - triage-implants
- stage: initial-access-valid-accounts
  status: covered
  steps:
  - rare-external-signins
- stage: execution-implant-deployment
  status: covered
  steps:
  - fileless-process-activity
  - minimal-library-footprint
- reason: Covers user-space modular plugins and SO/DLL hijacking; kernel-level rootkits
    are partially addressed via blind spots.
  stage: persistence-defense-evasion-stealth
  status: covered
  steps:
  - anomalous-user-modules
- reason: Belongs to another part of the 'VoidLink' series.
  stage: lateral-movement-internal-scanning
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: command-and-control-mesh
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: exfiltration-c2-channel
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VoidLink is a defense-contractor-grade framework designed for stealth
    and persistence. A negative result confirms that these advanced beachheads and
    modular plugins are not present on critical infrastructure running susceptible
    software.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging vulnerable Apache Dubbo instances or stolen
  credentials to deploy a modular ZigLang-based implant that evades detection via
  fileless execution and user-space SO/DLL hijacking.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1204.002
- attack.t1574.002
- attack.t1014
name: VoidLink Initial Access and Rootkit Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for behavior.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Restrict the hunt to specific hosts; leave empty to run fleet-wide
      after scoping.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: list[host]
  software_keywords:
    default:
    - dubbo
    - zookeeper
    - serialization
    description: Software keywords related to Apache Dubbo and common serialization
      dependencies.
    from:
      kind: article
      observed: '2025-01-20'
      ref: https://blog.talosintelligence.com/voidlink/
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/voidlink/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target internet-facing Linux servers running Apache or Dubbo-related services.
  Use the software inventory query to build the scope_hosts list for filtering.
references:
- name: "Cisco Talos \u2014 VoidLink: A Giant Leap for Modular Attack Frameworks"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-network-mesh-and-exfiltration
  reason: This hunt focuses on access and persistence; the next hunt covers the mesh
    peer-to-peer and exfiltration behavior.
  relation: follows
scenario:
  stages:
  - name: Apache Dubbo Exploitation
    observables:
    - Apache Dubbo project
    - Java serialization vulnerabilities
    - remote code execution
    slug: initial-access-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Credential Abuse
    observables:
    - pre-obtained credentials
    slug: initial-access-valid-accounts
    tactic: initial-access
    techniques:
    - T1078
  - name: VoidLink Implant Execution
    observables:
    - VoidLink implant
    - ZigLang binary
    - C-based plugins
    - ELF linker
    - malicious documents
    slug: execution-implant-deployment
    tactic: execution
    techniques:
    - T1204.002
  - name: Kernel-Level Persistence and Evasion
    observables:
    - eBPF rootkit
    - Loadable Kernel Module (LKM)
    - DLL sideloading
    - EDR detection mechanisms
    slug: persistence-defense-evasion-stealth
    tactic: defense-evasion
    techniques:
    - T1574.002
    - T1014
  - name: SOCKS Proxy and Network Recon
    observables:
    - SOCKS server
    - FSCAN
    - Class C network scanning
    - Kubernetes APIs
    - Docker environment gathering
    slug: lateral-movement-internal-scanning
    tactic: lateral-movement
    techniques:
    - T1090
    - T1046
  - name: Mesh C2 and P2P Routing
    observables:
    - mesh peer-to-peer (P2P)
    - dead-letter queue routing
    - VoidLink C2
    slug: command-and-control-mesh
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: Obfuscated Exfiltration
    observables:
    - obfuscated exfiltration data
    slug: exfiltration-c2-channel
    tactic: exfiltration
    techniques:
    - T1041
  summary: UAT-9921 leverages the VoidLink framework to compromise technology and
    financial sectors via Apache Dubbo exploitation and credential abuse. Once established,
    the modular framework deploys Linux-focused implants with eBPF rootkit capabilities,
    uses SOCKS proxies for internal network scanning, and maintains communication
    through a P2P mesh C2 architecture.
series:
  index: 1
  slug: voidlink
  title: VoidLink
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# VoidLink Initial Access and Rootkit Persistence

This hunt targets the early stages of a VoidLink intrusion by UAT-9921. It identifies potential beachheads by scoping for vulnerable Apache Dubbo software, then moves to detect anomalous authentication and the high-side indicators of the VoidLink framework: modular user-space plugins and in-memory execution. The hunt focuses on the unique ZigLang modular architecture, identifying statically linked binaries through their minimal library load footprint and fileless execution patterns.

## scope-vulnerable-dubbo
<!-- Scope potentially vulnerable Apache Dubbo hosts -->
Identify hosts running Apache Dubbo or related Apache projects that are the primary entry vector for UAT-9921.

```sqlite target=endpoint role=scoping params=(software_keywords=software_keywords)
~~~yaml
expected: A list of hostnames running the software named in the article. Silence means
  no Dubbo is inventoried, narrowing the focus to credential abuse.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{software_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(vendor_name) LIKE '%apache%') AND asset_scope = 'endpoint'
```

## parallel-telemetry
<!-- Correlate Auth, Modules, and Process Behavior -->
parallel:
- → rare-external-signins
- → anomalous-user-modules
- → fileless-process-activity
- → minimal-library-footprint
join: → triage-implants

## rare-external-signins
<!-- Baseline successful sign-ins from new source IPs -->
Detect potential credential abuse by identifying IPs that haven't been used by the specific user in the last 30 days.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: 30d
expected: A user logging in from a source IP they have not historically used. This
  identifies 'pre-obtained' credential replay.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- actor_user_name
- src_endpoint_ip
- status_id
- time
- dst_endpoint_name
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(*) as login_count, MIN(time) as first_seen_in_window FROM hb_auth_signin WHERE status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip
```

## anomalous-user-modules
<!-- Unsigned or rare user-space plugins -->
Detect VoidLink modular plugins loaded via SO/DLL hijacking or dynamic loading from writable paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unsigned shared objects or DLLs loading from user-writable directories,
  typical of the VoidLink modular plugin system.
reads:
- device_hostname
- process_name
- module_path
- module_name
- pid
- module_signed
- module_signature_status
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_path, module_name, pid FROM hb_module_activity WHERE (module_signed = 0 OR module_signature_status != 'Valid') AND (LOWER(module_path) LIKE '%.so' OR LOWER(module_path) LIKE '%.dll') AND (LOWER(module_path) LIKE '%/tmp/%' OR LOWER(module_path) LIKE '%/dev/shm/%' OR LOWER(module_path) LIKE '%\temp\%' OR LOWER(module_path) LIKE '%\public\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## fileless-process-activity
<!-- Fileless in-memory processes -->
Identify VoidLink implants running without a disk-backed binary, a common indicator of their custom loaders.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process where on_disk = 0, indicating code execution in memory without
  a corresponding file.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- pid
- on_disk
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, pid FROM hb_process_activity WHERE on_disk = 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## minimal-library-footprint
<!-- Processes with minimal library footprint -->
Identify statically-linked ZigLang binaries by their abnormally low number of loaded shared libraries compared to standard processes.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Processes loading fewer than 10 modules. Standard dynamic binaries usually
  load dozens; a statically linked Zig binary will load almost none.
reads:
- device_hostname
- process_name
- pid
- module_name
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, pid, COUNT(DISTINCT module_name) as unique_modules FROM hb_module_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, pid HAVING unique_modules < 10
```

## triage-implants
<!-- Triage VoidLink Intrusion -->
```agent target=hunter
cite: required
context:
- scope-vulnerable-dubbo
- rare-external-signins
- anomalous-user-modules
- fileless-process-activity
- minimal-library-footprint
max_iterations: 6
objective: Determine if any host identified in scoping shows signs of credential abuse
  OR successful Dubbo exploitation leading to the execution of statically linked,
  fileless ZigLang implants and their modular plugins.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  row IDs from process, auth, and module surfaces.
tools:
- endpoint
- identity
```

## decision-route
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-investigation
unavailable: → manual-investigation (blind_spot: kernel-visibility-gap)
else: → analyst-closeout

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Before wiping, secure a memory dump to analyze fileless plugins and potential kernel hooks.
```
→ manual-investigation

## manual-investigation
<!-- Manual Forensic Review -->
```manual target=analyst
Manually inspect for Loadable Kernel Modules (LKMs) using 'lsmod' or eBPF hooks using 'bpftool'. Review PIDs with on_disk=0 for suspicious memory mappings.
```
→ end

## analyst-closeout
<!-- Analyst Closeout -->
```manual target=analyst
Summarize the findings. If successful Dubbo exploitation was identified, update the vulnerability management team.
```
→ end

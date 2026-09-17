---
analysis: A detection rule for FSCAN is easily bypassed by renaming; this hunt pivots
  between vulnerability context, behavioral scanning thresholds, and prevalence of
  rare inbound listeners to identify the framework's infrastructure regardless of
  tool names.
blind_spots:
- id: ebpf-rootkit-hiding
  question: Are connections hidden from osquery by an eBPF rootkit?
  requires: Network fabric logs (VPC Flow Logs)
  risk: VoidLink features eBPF rootkit capabilities that can hide sockets and processes
    from host-level monitoring; the pivot may be invisible at the endpoint layer.
  stage: internal-discovery-and-p2p
- id: ziglang-obfuscation
  question: Can we confirm the presence of VoidLink in a renamed or obfuscated binary?
  requires: Advanced static analysis of ZigLang binaries
  risk: The implant is written in ZigLang, which is uncommon and may hinder standard
    analysis if the binary is packed or obfuscated.
  stage: c2-and-exfiltration
coverage:
- stage: internal-discovery-and-p2p
  status: covered
  steps:
  - detect-fscan-usage
  - internal-scan-prevalence
- stage: c2-and-exfiltration
  status: covered
  steps:
  - rare-inbound-mesh-connections
  - triage-voidlink-activity
- reason: Belongs to another part of the 'VoidLink' series.
  stage: initial-access-vulnerability-or-creds
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: implant-execution-and-module-loading
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: persistence-via-rootkit
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VoidLink's mesh-routing architecture is designed to bypass traditional
    network segmentation; finding an internal gateway proves the presence of a persistent,
    multi-stage adversary like UAT-9921.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using VoidLink's mesh networking and SOCKS capabilities
  to conduct internal discovery and route C2 traffic through rare, high-port inbound
  connections on compromised Java application servers.
labels:
- hunt
- attack.t1090
- attack.t1071
- attack.t1041
- attack.t1190
- attack.t1090.003
name: VoidLink Internal Pivot and Mesh Network Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-01-15'
      ref: hunt-standard
    type: number
  scan_threshold:
    default: '50'
    description: Number of unique internal IP destinations before a host is flagged
      for scanning.
    from:
      kind: manual
      observed: '2025-01-15'
      ref: hunt-standard
    type: number
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
rationale: Focus on DMZ servers and public-facing subnets running Java services (Dubbo,
  Spring). Widen scope to all Linux servers if the internal scan prevalence returns
  hits in less-exposed segments.
references:
- name: "Cisco Talos \u2014 VoidLink"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-persistence-via-rootkit
  reason: That hunt focuses on the kernel-level persistence and eBPF mechanisms, while
    this hunt focuses on the resulting network behaviors.
  relation: out-of-scope-alternative
- hunt: voidlink-modular-implant-execution-persistence
  relation: follows
scenario:
  stages:
  - name: Initial Access via Dubbo or Credentials
    observables:
    - Apache Dubbo
    - Java serialization vulnerabilities
    - Pre-obtained credentials
    slug: initial-access-vulnerability-or-creds
    tactic: initial-access
    techniques:
    - T1190
  - name: VoidLink Implant and Plugin Execution
    observables:
    - ZigLang implant binary
    - ELF linker and loader
    - C-based plugins
    - DLL sideloading (Windows)
    - Unix.Trojan.VoidLink ClamAV detection
    slug: implant-execution-and-module-loading
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: Kernel-Level Persistence and Evasion
    observables:
    - eBPF rootkit
    - Loadable Kernel Module (LKM)
    - Container privilege escalation
    - Sandbox escape
    slug: persistence-via-rootkit
    tactic: persistence
  - name: Lateral Movement and Internal Discovery
    observables:
    - FSCAN scanning tool
    - SOCKS server deployment
    - Scanning Class C networks
    - Kubernetes and Docker API enumeration
    slug: internal-discovery-and-p2p
    tactic: discovery
    techniques:
    - T1090
  - name: Command and Control via Mesh Network
    observables:
    - P2P mesh routing
    - Dead-letter queue routing
    - Obfuscated data exfiltration
    slug: c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
    - T1041
  summary: UAT-9921 leverages the VoidLink framework, a modular Linux-first implant
    management system, to compromise targets via Apache Dubbo Java serialization exploits
    or stolen credentials. Once deployed, the framework uses ZigLang-based implants
    with on-demand C plugins, eBPF rootkits, and P2P mesh communication to conduct
    stealthy lateral movement and cloud-aware reconnaissance.
series:
  index: 3
  slug: voidlink
  title: VoidLink
  total: 3
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# VoidLink Internal Pivot and Mesh Network Activity

This hunt targets the post-exploitation phases of the VoidLink (UAT-9921) framework, specifically focusing on lateral movement and mesh-based command and control. VoidLink uses a P2P architecture and dead-letter routing to bypass segmentation. By correlating vulnerable Dubbo server environments with high-volume internal scanning and rare inbound high-port connections (potential mesh nodes), this hunt identifies compromised servers acting as internal gateways. It specifically looks for behavioral markers of scanning that would persist even if tools like FSCAN are renamed, using RFC1918-constrained logic to minimize noise.

## scope-dubbo-servers
<!-- Identify vulnerable Dubbo/Java environments -->
UAT-9921 primarily targets Apache Dubbo and Java serialization vulnerabilities. This step identifies the relevant server fleet using specific package constraints.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running Dubbo-specific server software. Silence means no
  such software is reported, but not that no vulnerable Java apps exist.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%dubbo%' AND (LOWER(vendor_name) = 'apache' OR LOWER(vendor_name) LIKE 'pivotal%' OR LOWER(vendor_name) = 'vmware')
```

## parallel-pivot-search
<!-- Search for pivot and mesh indicators -->
parallel:
- → detect-fscan-usage
- → internal-scan-prevalence
- → rare-inbound-mesh-connections
join: → triage-voidlink-activity

## detect-fscan-usage
<!-- Detect FSCAN or suspicious scanner flags -->
VoidLink operators use FSCAN for internal discovery. We look for the binary name or its common target/port selection flags.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Execution of known scanning tools or processes using scanning arguments.
  This is a high-confidence signal of discovery.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%fscan%' OR (LOWER(process_cmd_line) LIKE '%-h %' AND LOWER(process_cmd_line) LIKE '%-p %')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## internal-scan-prevalence
<!-- Internal scanning volume by host -->
Identify hosts touching an anomalous number of internal IP addresses within RFC1918 space.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scan_threshold=scan_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host connecting to many internal RFC1918 endpoints. Rare for servers unless
  they are designated scanners or compromised.
prevalence:
  by: device_hostname
  key:
  - device_hostname
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, COUNT(DISTINCT dst_endpoint_ip) as internal_targets, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE direction = 'outbound' AND (dst_endpoint_ip LIKE '10.%' OR (dst_endpoint_ip LIKE '172.%' AND CAST(SUBSTR(SUBSTR(dst_endpoint_ip, 5), 1, INSTR(SUBSTR(dst_endpoint_ip, 5), '.') - 1) AS INTEGER) BETWEEN 16 AND 31) OR dst_endpoint_ip LIKE '192.168.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING internal_targets > {{scan_threshold}}
```

## rare-inbound-mesh-connections
<!-- Anomalous inbound high-port connections -->
VoidLink implants act as mesh gateways, accepting inbound traffic from other implants on high ports to route C2.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: An inbound listener port that is rare across the fleet, potentially indicating
  a mesh ingress point for VoidLink.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
- process_name
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_name, dst_endpoint_port, COUNT(DISTINCT device_hostname) as host_count, GROUP_CONCAT(DISTINCT device_hostname) as host_list, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'inbound' AND dst_endpoint_port > 1024 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_port HAVING host_count < 5
```

## triage-voidlink-activity
<!-- Triage VoidLink pivot behavior -->
```agent target=hunter
cite: required
context:
- scope-dubbo-servers
- detect-fscan-usage
- internal-scan-prevalence
- rare-inbound-mesh-connections
max_iterations: 4
objective: Analyze the correlated signals to identify if a host is acting as a SOCKS
  proxy or mesh gateway for VoidLink activity.
success_criteria: A Malicious/Suspicious verdict per host with citations.
tools:
- endpoint
- network
```

## decide-on-threat
<!-- Decision on VoidLink mesh node -->
if~: "at least one host shows a high-confidence combination of scanning and rare inbound listeners consistent with a SOCKS/mesh gateway." (confidence: high, judge=hunter)
then: → isolate-pivot-node
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: ebpf-rootkit-hiding)
else: → close-hunt

## isolate-pivot-node
<!-- Isolate mesh gateway -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Capture volatile memory to preserve evidence of the ZigLang implant and any C-based plugins loaded in memory.
```
→ analyst-review

## analyst-review
<!-- Manual review of mesh activity -->
```manual target=analyst
Review the internal targets identified in the scan-prevalence step. Cross-reference with VPC flow logs or cloud network logs to find any connections that the host-based rootkit may have hidden.
```
→ end

## close-hunt
<!-- Close out hunt -->
```manual target=analyst
Document if any findings were legitimate scanners. If malicious activity was found, begin a full incident response for the UAT-9921 campaign.
```
→ end

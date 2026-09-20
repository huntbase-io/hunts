---
analysis: A standard rule might detect the name 'fscan'. This hunt identifies a coordinated
  VoidLink intrusion by correlating that process lead with targeted container API
  discovery and a statistical baseline of rare internal P2P traffic that a single
  rule cannot contextualize.
blind_spots:
- id: process-hiding-rootkit
  question: whether the implant is using its rootkit capability to hide the scanner
    processes
  requires: Endpoint telemetry uncompromised by LKM/eBPF rootkits
  risk: The find-scanners-and-proxies lead query may return zero results if the rootkit
    successfully hooks the kernel, leaving network connections as the only detectable
    signal.
  stage: internal-scanning-recon
- id: encrypted-p2p-payload
  question: whether the traffic on high ports is legitimate service traffic or VoidLink
    mesh C2
  requires: Network flow telemetry with payload inspection
  risk: Without deep packet inspection, the hunt relies on statistical rarity and
    the association with scanner tools to infer maliciousness.
  stage: mesh-c2-communications
coverage:
- stage: internal-scanning-recon
  status: covered
  steps:
  - find-scanners-and-proxies
  - mesh-peer-connections
- stage: cloud-api-discovery
  status: covered
  steps:
  - container-api-recon
- stage: mesh-c2-communications
  status: covered
  steps:
  - mesh-peer-connections
  - triage-voidlink
- reason: Belongs to another part of the 'VoidLink' series.
  stage: initial-access-dubbo-exploit
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: implant-execution-and-sideloading
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: rootkit-and-privilege-escalation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: VoidLink is a defense contractor grade framework with advanced mesh
    and cloud-aware capabilities. Its ability to create stealthy internal peer networks
    to bypass boundary controls makes a negative result critical for the security
    of infrastructure services and supply chain integrity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using a VoidLink implant to perform automated internal
  reconnaissance and establish a peer-to-peer mesh command-and-control network between
  compromised Linux servers.
labels:
- hunt
- attack.t1041
- attack.t1071
- attack.t1090.003
- attack.t1190
name: VoidLink Lateral Scanning and Mesh C2
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scanner_keywords:
    default:
    - fscan
    - gscan
    - socks5
    - proxy
    description: Common lateral movement tool names found in VoidLink campaigns.
    from:
      kind: article
      observed: '2025-01-20'
      ref: https://blog.talosintelligence.com/voidlink/
    type: list[string]
  scope_hosts:
    default: []
    description: Restrict investigation to these hosts identified in the scoping query;
      leave empty for fleet-wide.
    type: list[host]
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
rationale: Focus the search on Linux servers, specifically those in network segments
  hosting containerized applications or management infrastructure. Widen the scope
  to any host showing connections to Docker/Kubernetes management ports from non-admin
  networks.
references:
- name: "Cisco Talos \u2014 VoidLink: A Giant Leap in Attack Framework Evolution"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-implant-execution-and-rootkits
  reason: This hunt focuses on network reconnaissance and mesh P2P; local persistence
    and rootkit behavior are handled in a sibling hunt.
  relation: out-of-scope-alternative
- hunt: voidlink-exploitation-and-kernel-deployment
  relation: follows
scenario:
  stages:
  - name: Apache Dubbo Java Serialization Exploitation
    observables:
    - Apache Dubbo project
    - Java serialization vulnerabilities
    - Pre-obtained credentials
    slug: initial-access-dubbo-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: VoidLink Implant Execution
    observables:
    - ZigLang-based implant binary
    - DLL sideloading on Windows
    - C-based plugins loaded via ELF linker
    - VoidLink compile-on-demand framework
    slug: implant-execution-and-sideloading
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: Persistence and Privilege Escalation
    observables:
    - eBPF rootkit
    - Loadable Kernel Module (LKM) rootkit
    - Container privilege escalation
    - Docker/Kubernetes sandbox escape
    slug: rootkit-and-privilege-escalation
    tactic: persistence
    techniques:
    - T1574.002
  - name: Internal Network Reconnaissance
    observables:
    - FSCAN
    - SOCKS server on compromised hosts
    - Scanning of entire Class C networks
    - Internal and external network scanning
    slug: internal-scanning-recon
    tactic: discovery
    techniques:
    - T1090.003
  - name: Cloud and Container Asset Discovery
    observables:
    - Kubernetes API interactions
    - Docker API interactions
    - Cloud-aware gathering of environment info
    slug: cloud-api-discovery
    tactic: discovery
  - name: Peer-to-Peer Mesh C2
    observables:
    - GoLang backend
    - Mesh Peer-to-Peer (P2P) routing
    - Dead-letter queue routing
    - Encrypted/obfuscated exfiltration traffic
    slug: mesh-c2-communications
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
    - T1041
  summary: UAT-9921 utilizes the VoidLink modular framework, targeting Linux and Windows
    systems by exploiting Java serialization vulnerabilities in Apache Dubbo or using
    stolen credentials. The ZigLang-based implant deploys plugins for eBPF-based rootkits
    and container escapes, while conducting internal reconnaissance with FSCAN and
    establishing a peer-to-peer mesh command-and-control network.
series:
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# VoidLink Lateral Scanning and Mesh C2

VoidLink is an AI-aided modular framework used by UAT-9921 for stealthy reconnaissance and resilient C2 routing. This hunt focuses on identifying the indicators of a VoidLink intrusion by detecting the execution of lateral movement tools like FSCAN, identifying attempts to discover Kubernetes or Docker management endpoints, and baselining rare internal peer-to-peer network connections that signify the framework's unique mesh routing capability. The hunt starts with a lead based on process execution and then fans out to examine network telemetry for cloud-specific discovery and statistical outliers in internal traffic.

## find-scanners-and-proxies
<!-- Lead: Lateral movement tools and proxies -->
Identify potential beachhead hosts where the adversary has executed reconnaissance tools or SOCKS proxies as reported in VoidLink campaigns.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scanner_keywords=scanner_keywords)
~~~yaml
expected: Rows identify hosts running known lateral movement tools. Silence means
  no known scanner names were used, not that scanning is absent.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{scanner_keywords}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%fscan%' OR LOWER(process_cmd_line) LIKE '%gscan%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-network-behavior
<!-- Fan-out network behavior analysis -->
parallel:
- → container-api-recon
- → mesh-peer-connections
join: → triage-voidlink

## container-api-recon
<!-- Targeted discovery of container APIs -->
Identify network attempts to access Kubernetes or Docker management endpoints, reflecting VoidLink's cloud-aware reconnaissance.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from Linux servers to Docker or Kubernetes management ports.
  Silence confirms no discovery of these specific services occurred from the scoped
  hosts.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as events FROM hb_network_connection WHERE (dst_endpoint_port IN (2375, 2376, 6443)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port
```

## mesh-peer-connections
<!-- Baseline internal peer-to-peer traffic -->
Find the rare internal network connections between high-numbered ports that indicate a VoidLink mesh network bypassing boundary controls.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few rare connections between internal servers that are not part of known
  server-to-server patterns (e.g., DB or logging).
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- src_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '172.%') AND src_endpoint_port > 1024 AND dst_endpoint_port > 1024 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING connection_count <= 20 ORDER BY connection_count ASC
```

## triage-voidlink
<!-- Triage VoidLink activity -->
```agent target=hunter
cite: required
context:
- find-scanners-and-proxies
- container-api-recon
- mesh-peer-connections
max_iterations: 4
objective: Determine if any host shows the combination of automated scanning tools
  and rare internal P2P or cloud-discovery network behavior consistent with VoidLink.
success_criteria: A verdict of malicious for hosts exhibiting process scanner use
  followed by unauthorized container discovery or P2P mesh traffic.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on VoidLink verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-mesh-mapping
unavailable: → forensic-mesh-mapping (blind_spot: process-hiding-rootkit)
else: → close-out-and-tune

## isolate-host
<!-- Isolate the compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the internal network immediately. Preserve the memory and the ZigLang implant for reverse engineering before wiping the system.
```
→ forensic-mesh-mapping

## forensic-mesh-mapping
<!-- Forensic mesh topology mapping -->
```manual target=analyst
Review the internal destination IPs from the mesh-peer-connections query. Cross-reference these IPs with the scoping query to check for similar tool execution on those hosts. Map the internal P2P connections to understand the extent of the lateral movement.
```
→ close-out-and-tune

## close-out-and-tune
<!-- Close out and tune -->
```manual target=analyst
Record the discovered mesh nodes. If authorized internal scanning was found, add those hosts to the tuning notes for future runs. Document any Kubernetes or Docker configuration weaknesses exploited during discovery.
```
→ end

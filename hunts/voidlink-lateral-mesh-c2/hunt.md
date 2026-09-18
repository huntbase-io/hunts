---
analysis: 'A static detection rule might find ''FSCAN'' by name or common proxy ports;
  this hunt looks for the aggregate behavior of a host becoming a gateway: scanning
  broad internal ranges, maintaining rare proxy listeners, and routing high-volume
  traffic to both internal peers and external C2 exit nodes.'
blind_spots:
- id: rootkit-blindness
  owner: Endpoint Security Engineering
  question: whether the VoidLink eBPF or LKM rootkit is hiding sockets and processes
    from the reporting agent
  remediation: Regularly audit systems for unverified eBPF programs and modules using
    kernel-integrity checkers.
  requires: Out-of-band forensic memory analysis
  risk: The hunt results may show zero rows while an infection is active if the rootkit
    has hooked the system calls the agent relies on.
- id: listener-host-attribution
  owner: Data Platform Team
  question: which specific host is running a rare proxy listener
  remediation: Add host identifiers to the network listener surface normalization.
  requires: hb_network_listener with device_hostname column
  risk: Analyst must manually correlate the process name from the listener step with
    other surfaces (hb_process_activity) to identify the target host.
  stage: lateral-movement-internal-scanning
coverage:
- stage: lateral-movement-internal-scanning
  status: covered
  steps:
  - internal-scanning-fscan
  - rare-proxy-listeners
- stage: command-and-control-mesh
  status: covered
  steps:
  - mesh-p2p-routing
- stage: exfiltration-c2-channel
  status: covered
  steps:
  - egress-exfiltration-volume
- reason: Belongs to another part of the 'VoidLink' series.
  stage: initial-access-vulnerability-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: initial-access-valid-accounts
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: execution-implant-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: persistence-defense-evasion-stealth
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: VoidLink is a highly modular, AI-assisted framework designed for
    enterprise-grade operations. Its ability to create mesh networks allows it to
    persist and exfiltrate data even from isolated segments, making a proactive hunt
    for its P2P and proxy behaviors a critical defensive control.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are using compromised Linux servers to host SOCKS gateways
  and mesh peer-to-peer C2 nodes, enabling internal reconnaissance and stealthy exfiltration.
labels:
- hunt
- attack.t1041
- attack.t1071
- attack.t1090.003
- attack.t1046
- attack.t1574.002
name: VoidLink Lateral Scanning and Mesh-Network C2
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: hunt_policy
    type: number
  scope_hosts:
    default: []
    description: Comma-separated list of hostnames to narrow the scope.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: scoping_step
    type: list[host]
  socks_ports:
    default:
    - '1080'
    - '1081'
    - '8080'
    - '8888'
    description: Common SOCKS and C2 listener ports.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on subnets hosting public-facing web applications or Kubernetes clusters,
  as these are the primary initial access targets.
references:
- name: "Cisco Talos \u2014 VoidLink"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-initial-access-and-persistence
  reason: This hunt focuses on the network phase; initial access via Java deserialization
    or malicious docs is covered in a sibling hunt.
  relation: out-of-scope-alternative
- hunt: voidlink-initial-access-rootkit-persistence
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


# VoidLink Lateral Scanning and Mesh-Network C2

VoidLink is a modular framework (UAT-9921) that specifically targets Linux environments. This hunt identifies the 'defense-contractor grade' network capabilities of the implant: specifically its use of SOCKS proxies for internal scanning (FSCAN behavior), and its peer-to-peer (P2P) mesh routing that allows compromised hosts to act as gateways for isolated internal nodes. We look for high-volume internal-to-internal connections, rare listeners on common proxy ports, and anomalous outbound traffic volumes originating from the internal mesh.

## linux-server-scope
<!-- Linux Server Scoping -->
Identify active Linux assets to provide context for the hunt's target operating system.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Absence of Linux hosts suggests this hunt is not applicable
  to the environment.
reads:
- hostname
- platform
- os_name
- ip_address
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, platform, os_name, ip_address, time FROM hb_devices WHERE (LOWER(platform) IN ('linux', 'ubuntu', 'debian', 'centos', 'redhat') OR LOWER(os_name) LIKE '%linux%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-network-evidence
<!-- Corroborate Network Evidence -->
parallel:
- → internal-scanning-fscan
- → rare-proxy-listeners
- → mesh-p2p-routing
- → egress-exfiltration-volume
join: → triage-voidlink-activity

## internal-scanning-fscan
<!-- Internal Scanning Behavior (FSCAN) -->
Find processes reaching out to many internal targets, a hallmark of the FSCAN tool used by UAT-9921.

```sqlite target=network role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: One or more hosts where a process is touching an unusually high number of
  internal IPs. Legitimate scanners should be filtered by the analyst.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT dst_endpoint_ip) AS unique_targets, COUNT(*) AS connection_attempts, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.16.%' OR dst_endpoint_ip LIKE '192.168.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_targets > 20 ORDER BY unique_targets DESC
```

## rare-proxy-listeners
<!-- Rare SOCKS/C2 Listeners -->
Identify unusual processes listening on common SOCKS ports. VoidLink's implants are often custom compiled.

```sqlite target=network role=baseline params=(socks_ports=socks_ports, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare process name or command line associated with a standard SOCKS port.
  Absence of host info in this surface requires correlation by process name in triage.
prevalence:
  by: process_cmd_line
  key:
  - process_name
  - port
  rare_below: 3
reads:
- process_name
- port
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_network_listener
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, port, process_cmd_line, COUNT(*) AS total_instances, MIN(time) AS first_seen FROM hb_network_listener WHERE instr(',' || '{{socks_ports}}' || ',', ',' || CAST(port AS TEXT) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, port, process_cmd_line HAVING total_instances <= 3 ORDER BY total_instances ASC
```

## mesh-p2p-routing
<!-- Internal Mesh P2P Routing -->
Detect high-volume internal-to-internal traffic on non-standard ports that may indicate the VoidLink P2P mesh.

```sqlite target=network role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Persistent, high-volume internal connections on unusual ports. This could
  indicate a data relay or mesh control plane.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, SUM(traffic_bytes) AS total_bytes, COUNT(*) AS connections FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (src_endpoint_ip LIKE '10.%' OR src_endpoint_ip LIKE '172.16.%' OR src_endpoint_ip LIKE '192.168.%') AND (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.16.%' OR dst_endpoint_ip LIKE '192.168.%') AND dst_endpoint_port NOT IN (22, 80, 443, 8080) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port HAVING connections > 100 ORDER BY total_bytes DESC
```

## egress-exfiltration-volume
<!-- Anomalous Egress Volume -->
Identify potential exit points for the mesh network by tracking high-volume outbound data to external IPs.

```sqlite target=network role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: The top 20 hosts/destinations by data volume. Correlate with 'mesh-p2p-routing'
  to see if data flows from internal mesh to external exit.
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, SUM(traffic_bytes) AS total_out_bytes, COUNT(DISTINCT dst_endpoint_port) AS ports_used FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.16.%' OR dst_endpoint_ip LIKE '192.168.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip ORDER BY total_out_bytes DESC LIMIT 20
```

## triage-voidlink-activity
<!-- Triage VoidLink Network Behavior -->
```agent target=hunter
cite: required
context:
- linux-server-scope
- internal-scanning-fscan
- rare-proxy-listeners
- mesh-p2p-routing
- egress-exfiltration-volume
max_iterations: 5
objective: Determine if any Linux hosts are exhibiting the combined pattern of internal
  reconnaissance, unusual proxy listeners, and mesh-based P2P routing indicative of
  VoidLink.
success_criteria: A per-host verdict (Malicious, Suspicious, Benign) citing specific
  connection counts and process names.
tools:
- endpoint
- network
```

## evaluate-verdict
<!-- Evaluate Triage Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: rootkit-blindness)
else: → close-out

## isolate-host
<!-- Isolate Compromised Linux Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Immediately isolate the host from the network and revoke any active credentials found in memory. Collect artifacts for rootkit analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the triage agent's findings. Specifically look for legit SOCKS usage by dev/ops teams and baseline those services.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record the findings and update the baseline if authorized SOCKS proxies were found.
```
→ end

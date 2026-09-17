---
analysis: A single rule on C2 IPs is easily bypassed by Kimwolf's ENS/Tor redundancy.
  This hunt links the precursor DNS resolution of RPC services to the network presence
  of a local proxy and the resulting high-volume impact traffic.
blind_spots:
- id: no-endpoint-telemetry
  question: Are the proxy listeners and process masquerading visible on the target
    hardware?
  requires: Endpoint agents supporting Android/IoT hardware
  risk: Many Android TV boxes do not support standard agents, making the hunt dependent
    on network flow logs alone.
- id: tor-clearnet-routing
  question: What is the content of the commands being sent to the proxy?
  requires: hb_http_activity with decrypted TLS
  risk: We can see the listener and the connections, but the content of the Tor tunnel
    is encrypted and invisible to network inspection.
  stage: c2-transport-tor-proxy
coverage:
- stage: c2-ens-rpc-resolution
  status: covered
  steps:
  - ens-dns-scoping
- stage: c2-transport-tor-proxy
  status: covered
  steps:
  - local-proxy-listener
  - c2-ip-prevalence
- stage: impact-ddos-floods
  status: covered
  steps:
  - ddos-flood-indicators
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: initial-access-adb-service
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: execution-masqueraded-binary
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kimwolf v7 is designed to survive infrastructure takedowns using
    decentralized DNS and Tor. A negative result confirms the organization is not
    unknowingly hosting a DDoS node.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A compromised IoT or Android device is resolving ENS domains via Ethereum
  RPCs, routing traffic through a local proxy, and participating in high-volume outbound
  DDoS floods.
labels:
- hunt
- attack.t1568
- attack.t1102
- attack.t1090.003
- attack.t1571
- attack.t1498.001
- attack.t1498.002
name: Kimwolf v7 Resilient C2 and DDoS Impact
parameters:
  c2_ips:
    default:
    - 212.193.31.119
    - 212.193.31.122
    - 212.193.31.92
    - 212.193.31.158
    - 212.193.31.102
    description: Known Kimwolf C2 infrastructure IPs.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: list[ip]
  ens_rpc_domains:
    default:
    - 0xrpc.io
    - eth.llamarpc.com
    - ethereum-rpc.publicnode.com
    - eth-protect.rpc.blxrbdn.com
    - eth.merkle.io
    - eth.rpcuniverse.com
    - rpcuniverse.com
    description: Ethereum RPC domains abused for ENS C2 resolution.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of network and DNS history to examine.
    from:
      kind: manual
      observed: '2026-08-11'
      ref: default
    type: number
  proxy_port:
    default: '23075'
    description: Port used by the Kimwolf local proxy architecture.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Linux IoT and Android segments. If segments are unmanaged, prioritize
  devices with high UDP outbound counts.
references:
- name: "Unit 42 \u2014 Kimwolf v7: An Evolution of the Kimwolf Botnet"
  url: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
related:
- hunt: kimwolf-v7-execution-and-persistence
  reason: This hunt focuses on network behavior; execution and ADB-based persistence
    are handled in a separate host-based hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Unauthenticated ADB Access
    observables:
    - Inbound connections on TCP port 5555
    - Connections originating from residential proxy services
    slug: initial-access-adb-service
    tactic: initial-access
    techniques:
    - T1133
    - T1190
  - name: Masqueraded Bot Execution
    observables:
    - Process name masquerading as netd_service
    - Creation of Unix domain socket @n[redacted]boxv7
    - 'File paths: libdevice.so, kernel.so'
    - Statically linked ARM ELF binaries using Android NDK
    slug: execution-masqueraded-binary
    tactic: execution
    techniques:
    - T1059.006
    - T1036.005
    - T1106
  - name: Distributed C2 Resolution via ENS
    observables:
    - 0xrpc.io
    - eth.llamarpc.com
    - ethereum-rpc.publicnode.com
    - eth-protect.rpc.blxrbdn.com
    - eth.merkle.io
    - eth.rpcuniverse.com
    - RPC queries to IP 212.193.31.102
    slug: c2-ens-rpc-resolution
    tactic: command-and-control
    techniques:
    - T1568
    - T1102
  - name: Tor Backup and Local Proxying
    observables:
    - Local proxy listening on 127.0.0.1:23075
    - edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion
    - C2 connections to 212.193.31.119 and 212.193.31.122 on TCP port 13
    - C2 connections to 212.193.31.92 and 212.193.31.158 on TCP port 443
    slug: c2-transport-tor-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1571
    - T1090
  - name: Multi-Vector DDoS Operations
    observables:
    - HTTP/2 floods with Chrome browser fingerprints
    - UDP floods optimized with ARM NEON SIMD instructions
    - Game server UDP floods on port 27015
    - High-volume TCP SYN/ACK/RST floods
    slug: impact-ddos-floods
    tactic: impact
    techniques:
    - T1498.001
    - T1498.002
  summary: Kimwolf v7 is a specialized Android/IoT botnet that compromises devices
    via unauthenticated ADB services. It utilizes a highly resilient C2 architecture
    involving Ethereum Name Service (ENS) resolution and Tor fallbacks to coordinate
    stealthy HTTP/2 and ARM-optimized DDoS floods.
series:
  index: 2
  slug: kimwolf-v7-an-evolution-of-the-kimwolf-botnet
  title: 'Kimwolf v7: An Evolution of the Kimwolf Botnet'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Kimwolf v7 Resilient C2 and DDoS Impact

This hunt identifies Kimwolf v7 activity by detecting its multi-layered C2 resolution chain and resulting network impact. It identifies hosts resolving public Ethereum RPC services used for ENS domain resolution or Tor .onion addresses. It then corroborates this by looking for the malware's local proxy listener (port 23075), connections to known Russian C2 IP ranges, and high-volume network traffic consistent with its 15 DDoS attack vectors, including Game Server (UDP/27015) and HTTP/2 floods.

## ens-dns-scoping
<!-- ENS RPC and Tor DNS Lookups -->
Identify hosts resolving the public Ethereum RPC services used for ENS domain resolution or searching for .onion addresses.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, ens_rpc_domains=ens_rpc_domains)
~~~yaml
expected: A host resolving these domains is not necessarily compromised, but high-frequency
  lookups from unusual processes (not browsers) or lookups for .onion domains are
  significant leads.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{ens_rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name ORDER BY lookup_count DESC
```

## corroborate-activity
<!-- Corroborate C2 and Impact -->
parallel:
- → local-proxy-listener
- → c2-ip-prevalence
- → ddos-flood-indicators
join: → triage-kimwolf

## local-proxy-listener
<!-- Kimwolf Local Proxy Listener -->
Detect the malware's local proxy component using connection state telemetry.

```sqlite target=network role=detection-candidate params=(proxy_port=proxy_port, lookback_days=lookback_days)
~~~yaml
expected: A listener on port 23075, especially from a process like netd_service, is
  a high-fidelity indicator of Kimwolf.
reads:
- device_hostname
- process_name
- src_endpoint_port
- connection_state
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, src_endpoint_port, connection_state, time FROM hb_network_connection WHERE src_endpoint_port = {{proxy_port}} AND connection_state = 'LISTEN' AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-ip-prevalence
<!-- Connections to Russian C2 IPs -->
Identify hosts connecting to the reported C2 infrastructure and check rarity.

```sqlite target=network role=baseline params=(c2_ips=c2_ips, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare connections to these specific C2 IPs in AS202799 (St. Petersburg).
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 5
reads:
- dst_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT dst_endpoint_ip, device_hostname, COUNT(*) as conn_count, MIN(time) as first_seen FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, device_hostname HAVING COUNT(DISTINCT device_hostname) <= 5
```

## ddos-flood-indicators
<!-- DDoS Traffic Spikes -->
Find devices participating in floods matching Kimwolf's vectors (UDP/27015 or TCP volume).

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: High outbound connection density indicative of participation in a botnet-directed
  flood.
reads:
- device_hostname
- dst_endpoint_port
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, dst_endpoint_port, protocol, COUNT(*) as conn_count FROM hb_network_connection WHERE (dst_endpoint_port = 27015 OR (dst_endpoint_port IN (80, 443) AND protocol = 'tcp')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_port, protocol HAVING conn_count > 1000
```

## triage-kimwolf
<!-- Triage Botnet Activity -->
```agent target=hunter
cite: required
context:
- ens-dns-scoping
- local-proxy-listener
- c2-ip-prevalence
- ddos-flood-indicators
max_iterations: 4
objective: 'Determine if any host shows overlapping Kimwolf v7 indicators: ENS RPC
  resolution, the local proxy listener on port 23075, and confirmed C2 IP contact
  or DDoS-scale traffic.'
success_criteria: A per-host verdict citing specific rows for the proxy listener and
  destination IP contact.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Botnet Verdict -->
if~: "the triage verdict is malicious for one or more hosts" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Malicious Device -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host(s) identified by the agent and record the current processes.
```
→ analyst-review

## analyst-review
<!-- Review and Forensic Collection -->
```manual target=analyst
Investigate the process matching the port 23075 listener. Search for binaries named 'netd_service' or 'libdevice.so' in /data/local/tmp. Verify the presence of the 'n*boxv7' version string.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Log that the estate was scanned for Kimwolf v7 resolution patterns and DDoS traffic with zero findings.
```
→ end

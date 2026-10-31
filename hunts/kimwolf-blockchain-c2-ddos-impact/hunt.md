---
analysis: A standard detection rule might alert on a single C2 IP, but this hunt correlates
  the modular internal proxy routing (port 23075), the rare use of Ethereum RPC services
  for domain resolution on IoT hosts, and the resulting high-cardinality outbound
  traffic spikes. This multi-stage correlation captures a functional bot presence
  that simple indicator matches miss.
blind_spots:
- id: tor-backup-blind-spot
  question: Is the malware actively using the hard-coded Tor .onion backup for C2
    communication?
  requires: Network flow logs with SNI or full proxy inspection
  risk: If ENS resolution fails, the botnet reverts to Tor routing via a local proxy;
    standard DNS monitoring will not see this fallback activity.
  stage: c2-local-proxy-routing
- id: http2-fingerprint-visibility
  question: Does the DDoS traffic exactly match the Chrome fingerprints reported in
    the research?
  requires: hb_http_activity with nghttp2 specific header metadata
  risk: While high connection counts are visible, the stealthy HTTP/2 browser fingerprinting
    may blend into normal traffic if the environment has high baseline web usage.
  stage: impact-ddos-flooding
coverage:
- stage: c2-ens-resolution
  status: covered
  steps:
  - ens-rpc-dns-resolution
- stage: c2-local-proxy-routing
  status: covered
  steps:
  - local-proxy-listener
- stage: impact-ddos-flooding
  status: covered
  steps:
  - kimwolf-c2-outbound-floods
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: initial-access-adb-misuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: execution-malware-installation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: defense-evasion-process-masquerading
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kimwolf v7 represents a significant jump in botnet resilience using
    blockchain infrastructure. A negative hunt result confirms that internal IoT assets
    are not participating in global DDoS campaigns or resolving C2 via Ethereum Name
    Service gateways.
  methodology: model-assisted
  trigger: intel-report
hypothesis: IoT or Android devices in the environment are infected with Kimwolf v7,
  as indicated by a local proxy listener on port 23075 and Ethereum Name Service (ENS)
  resolution used to bypass traditional C2 infrastructure takedowns.
labels:
- hunt
- attack.t1102.003
- attack.t1090
- attack.t1498.001
name: Kimwolf Blockchain C2 and DDoS Impact
parameters:
  c2_domains:
    default:
    - 0xrpc.io
    - eth.llamarpc.com
    - ethereum-rpc.publicnode.com
    - eth-protect.rpc.blxrbdn.com
    - eth.merkle.io
    - eth.rpcuniverse.com
    - rpcuniverse.com
    description: Ethereum RPC endpoints and ENS gateways used by Kimwolf for C2 resolution.
    from:
      kind: article
      observed: '2026-08-11'
      ref: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    type: list[domain]
  c2_ips:
    default:
    - 212.193.31.119
    - 212.193.31.122
    - 212.193.31.92
    - 212.193.31.158
    - 212.193.31.102
    description: Known Kimwolf C2 IP addresses residing in AS202799.
    from:
      kind: article
      observed: '2026-08-11'
      ref: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_port:
    default: '23075'
    description: The hard-coded local proxy port used by Kimwolf v7 for routing C2
      traffic.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to scope the hunt; leave empty to hunt across
      the entire estate.
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Target Android TV boxes, set-top boxes, and Linux-based IoT segments. These
  devices are the primary beachhead for Kimwolf v7 and are less likely to perform
  legitimate Ethereum RPC queries.
references:
- name: "Unit 42 \u2014 Kimwolf v7: An Evolution of the Kimwolf Botnet"
  url: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
related:
- hunt: kimwolf-initial-access-adb
  reason: Propagation via unauthenticated ADB on port 5555 is a distinct initial access
    pattern handled by a separate infection-focused hunt.
  relation: out-of-scope-alternative
- hunt: kimwolf-adb-propagation-evasion
  relation: follows
scenario:
  stages:
  - name: Unauthenticated ADB Access
    observables:
    - Inbound connections to TCP port 5555 (Android Debug Bridge)
    - Use of residential proxy services to tunnel into local networks
    slug: initial-access-adb-misuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Malware Installation via ADB
    observables:
    - Installation of ELF binaries on Android devices
    - Dropped files named libdevice.so or libn[redacted]kernel.so
    slug: execution-malware-installation
    tactic: execution
    techniques:
    - T1059
  - name: Process Name Masquerading
    observables:
    - Process name masked as netd_service
    - Stripped ELF binaries compiled with Android NDK
    - Creation of Unix domain socket beginning with @n[redacted]boxv7
    slug: defense-evasion-process-masquerading
    tactic: defense-evasion
    techniques:
    - T1036.005
  - name: ENS C2 Resolution
    observables:
    - Outbound traffic to 0xrpc.io
    - Outbound traffic to eth.llamarpc.com
    - Outbound traffic to ethereum-rpc.publicnode.com
    - Outbound traffic to eth-protect.rpc.blxrbdn.com
    - Outbound traffic to eth.merkle.io
    - Outbound traffic to eth.rpcuniverse.com
    - DNS queries for ENS C2 domains
    slug: c2-ens-resolution
    tactic: command-and-control
    techniques:
    - T1102.003
  - name: Local Proxy Architecture
    observables:
    - Local network listener on 127.0.0.1:23075
    - 'Connections to v3 Tor .onion address: edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion'
    - Direct C2 connections to 212.193.31.119, 212.193.31.122 (port 13)
    - Direct C2 connections to 212.193.31.92, 212.193.31.158 (port 443)
    slug: c2-local-proxy-routing
    tactic: command-and-control
    techniques:
    - T1090
  - name: DDoS Flood Activities
    observables:
    - HTTP/2 floods with Chrome browser fingerprints
    - High-performance UDP floods using ARM NEON SIMD optimizations
    - TCP SYN, ACK, and RST floods
    - DNS query floods
    - ICMP floods
    slug: impact-ddos-flooding
    tactic: impact
    techniques:
    - T1498.001
  summary: Kimwolf v7 is an evolution of an Android IoT botnet that targets unauthenticated
    ADB interfaces on port 5555 for initial access. The malware employs highly resilient
    command-and-control infrastructure using Ethereum Name Service (ENS) for resolution
    and Tor as a backup, ultimately performing optimized DDoS floods including stealthy
    HTTP/2 browser fingerprinting.
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


# Kimwolf Blockchain C2 and DDoS Impact

This hunt identifies Kimwolf v7 activity by correlating its unique local proxy architecture with blockchain-based C2 resolution and outbound DDoS flood behavior. Kimwolf v7 uses Ethereum public RPC endpoints to resolve ENS domains for its primary C2, ensuring resilience against domain seizures. The hunt searches for the local proxy listener that routes bot traffic, validates queries to known Ethereum RPC services, and identifies anomalous outbound traffic volumes consistent with the botnet's 15 distinct DDoS methods.

## local-proxy-listener
<!-- Local Proxy Traffic Routing -->
Identify the Kimwolf local proxy architecture by finding internal network connections to the hard-coded loopback port 23075.

```sqlite target=network role=scoping params=(proxy_port=proxy_port, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Internal connections to port 23075, likely originating from a masqueraded
  process. Silence indicates no local proxy routing on this port was observed.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_port, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE (dst_endpoint_ip = '127.0.0.1' OR dst_endpoint_ip = '::1') AND dst_endpoint_port = {{proxy_port}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_port
```

## corroborate-bot-activity
<!-- Corroborate Infrastructure and Impact -->
parallel:
- → ens-rpc-dns-resolution
- → kimwolf-c2-outbound-floods
join: → weigh-kimwolf-evidence

## ens-rpc-dns-resolution
<!-- Ethereum RPC and ENS DNS Resolution -->
Detect queries to public Ethereum RPC gateways or high-volume TXT record lookups used for resilient ENS-based C2 resolution.

```sqlite target=endpoint role=enrichment params=(c2_domains=c2_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries targeting legitimate Ethereum RPC services from non-developer
  hosts. Silence suggests no blockchain-based resolution occurred via these domains.
reads:
- device_hostname
- process_name
- query_hostname
- query_type
- answers
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, query_type, answers, COUNT(*) AS count FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (query_type = 'TXT' AND (LOWER(query_hostname) LIKE '%eth%' OR LOWER(query_hostname) LIKE '%rpc%'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname, query_type, answers
```

## kimwolf-c2-outbound-floods
<!-- C2 Connections and Network Floods -->
Identify direct communication with known Kimwolf infrastructure or anomalous high-volume outbound network bursts indicative of DDoS activity.

```sqlite target=network role=detection-candidate params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to Russian C2 IPs or a massive number of outbound connections
  from a single process to a single destination. Silence proves absence of massive
  floods during the window.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- direction
- disposition
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, COUNT(*) AS conn_count, MAX(time) AS last_seen FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR (direction = 'outbound' AND disposition = 'Allowed')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip HAVING (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR conn_count > 500)
```

## weigh-kimwolf-evidence
<!-- Triage Kimwolf Indicators -->
```agent target=hunter
cite: required
context:
- local-proxy-listener
- ens-rpc-dns-resolution
- kimwolf-c2-outbound-floods
max_iterations: 4
objective: Determine if any host is compromised by Kimwolf v7. Specifically, look
  for hosts that exhibit a local proxy listener on port 23075 while also performing
  Ethereum RPC DNS resolutions or communicating with the identified C2 IP addresses.
success_criteria: A verdict of malicious, suspicious, or benign per host citing the
  specific port and domain lookups.
tools:
- endpoint
- network
```

## kimwolf-decision
<!-- Kimwolf Infection Decision -->
if~: "the weigh-kimwolf-evidence verdict is malicious for at least one host involving local proxy listeners and Ethereum-related DNS resolution" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: tor-backup-blind-spot)
else: → analyst-triage

## isolate-infected-host
<!-- Isolate Compromised Device -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host immediately to halt DDoS floods and rotate any credentials that may have been exposed through the local proxy.
```
→ analyst-triage

## analyst-triage
<!-- Verify Botnet Triage -->
```manual target=analyst
Review the DNS TXT records for ENS resolution patterns. Check the processes associated with port 23075 for masquerading behavior like 'netd_service'. Investigate if any outbound traffic is routing through non-standard ports to known Tor gateways.
```
→ close-out-hunt

## close-out-hunt
<!-- Close-out and Tune Detections -->
```manual target=analyst
Log the identified C2 IPs and domains. Propose a rule for monitoring high-frequency ENS gateway lookups from IoT and Android TV segments.
```
→ end

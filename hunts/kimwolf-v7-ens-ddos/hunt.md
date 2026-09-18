---
analysis: 'This hunt pivots between three independent questions: why is this IoT device
  talking to a blockchain provider, why is there local proxy traffic, and is it participating
  in a DDoS cluster? A single detection rule cannot weigh these multiple surfaces
  to provide high-confidence triage.'
blind_spots:
- id: limited-iot-telemetry
  question: Whether the HTTP/2 traffic actually contains the Chrome fingerprints mentioned
    in research.
  requires: Deep packet inspection for HTTP/2 browser fingerprints
  risk: A sophisticated bot could masquerade its traffic well enough that only process-level
    telemetry (like nghttp2 library loading) can confirm it, but IoT agents may not
    report library loads.
  stage: impact-distributed-denial-of-service
- id: tor-encryption
  question: Whether a host is communicating with the hard-coded .onion address.
  requires: Tor bridge/exit node database or encrypted traffic analysis
  risk: Tor traffic is encrypted and uses randomized ports for entry guards, making
    it difficult to detect via simple network metadata.
  stage: c2-tor-and-local-proxy
coverage:
- stage: c2-ens-blockchain-resolution
  status: covered
  steps:
  - ens-rpc-resolution
- stage: c2-tor-and-local-proxy
  status: covered
  steps:
  - local-proxy-connection
- stage: impact-distributed-denial-of-service
  status: covered
  steps:
  - ddos-target-outbound
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: initial-access-adb-proxy
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: execution-masquerading-process
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kimwolf v7 specifically targets unauthenticated ADB instances on
    IoT devices to create a massive DDoS botnet. Detecting its resilient ENS-based
    C2 early prevents an organization's assets from being used in offensive operations
    against others.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using Ethereum ENS domains for resilient C2 resolution
  and coordinating outbound DDoS attacks from IoT or Android-based assets.
labels:
- hunt
- attack.t1568
- attack.t1102
- attack.t1090.003
- attack.t1498.001
name: Kimwolf v7 ENS Resolution and Outbound DDoS
parameters:
  ens_rpc_domains:
    default:
    - 0xrpc.io
    - eth.llamarpc.com
    - ethereum-rpc.publicnode.com
    - eth-protect.rpc.blxrbdn.com
    - eth.merkle.io
    - eth.rpcuniverse.com
    description: Legitimate Ethereum RPC domains abused for ENS resolution.
    from:
      kind: article
      observed: '2026-02-03'
      ref: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    type: list[domain]
  local_proxy_port:
    default: '23075'
    description: The hard-coded port for Kimwolf's local proxy relay.
    type: number
  lookback_days:
    default: '14'
    description: Days of network and DNS history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to limit the hunt to (leave empty for fleet-wide).
    type: list[host]
  target_ips:
    default:
    - 212.193.31.119
    - 212.193.31.122
    - 212.193.31.92
    - 212.193.31.158
    - 212.193.31.102
    description: Identified C2 and target IPs in the Kimwolf v7 cluster.
    from:
      kind: article
      observed: '2026-02-03'
      ref: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    type: list[ip]
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
rationale: Focus specifically on hosts where 'platform' is Linux or Android. Standard
  workstations may occasionally contact Ethereum nodes for development, but for an
  IoT/TV box, this is nearly always malicious.
references:
- name: "Unit 42 \u2014 Kimwolf v7: An Evolution of the Kimwolf Botnet"
  url: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
related:
- hunt: adb-proxy-initial-access
  reason: This hunt focuses on post-infection C2 and impact; the initial infection
    via ADB-on-port-5555 is handled separately.
  relation: out-of-scope-alternative
- hunt: kimwolf-v7-masquerading-adb-propagation
  relation: follows
scenario:
  stages:
  - name: Unauthenticated ADB Access
    observables:
    - port 5555
    - residential proxy misuse
    slug: initial-access-adb-proxy
    tactic: initial-access
    techniques:
    - T1133
  - name: Process Masquerading and Mutex
    observables:
    - 'process_name: netd_service'
    - 'file_name: libdevice.so'
    - 'file_name: kernel.so'
    - 'unix_domain_socket: @n*boxv7'
    slug: execution-masquerading-process
    tactic: defence-evasion
    techniques:
    - T1036.004
    - T1546
  - name: ENS Domain C2 Resolution
    observables:
    - 'domain: 0xrpc.io'
    - 'domain: eth.llamarpc.com'
    - 'domain: ethereum-rpc.publicnode.com'
    - 'domain: eth-protect.rpc.blxrbdn.com'
    - 'domain: eth.merkle.io'
    - 'domain: eth.rpcuniverse.com'
    slug: c2-ens-blockchain-resolution
    tactic: command-and-control
    techniques:
    - T1568
    - T1102
  - name: Local Proxy and Tor Backup
    observables:
    - 127.0.0.1:23075
    - edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion
    - 'SOCKS5 greeting: 0x05 0x01 0x00'
    slug: c2-tor-and-local-proxy
    tactic: command-and-control
    techniques:
    - T1090
    - T1090.003
  - name: Vectorized DDoS Flooding
    observables:
    - 'destination_ip: 212.193.31.119'
    - 'destination_ip: 212.193.31.122'
    - 'destination_ip: 212.193.31.92'
    - 'destination_ip: 212.193.31.158'
    - 'destination_port: 13'
    - HTTP/2 browser fingerprints
    - ARM NEON SIMD checksum acceleration
    slug: impact-distributed-denial-of-service
    tactic: impact
    techniques:
    - T1498.001
  summary: Kimwolf v7 is an Android-based IoT botnet that gains initial access through
    unauthenticated ADB on port 5555 via residential proxies. It maintains operational
    resilience using Ethereum Name Service (ENS) for C2 resolution and Tor as a backup,
    ultimately performing high-performance DDoS attacks with browser-fingerprinted
    HTTP/2 floods.
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


# Kimwolf v7 ENS Resolution and Outbound DDoS

Kimwolf v7 (AISURU) represents a shift toward more resilient infrastructure by using blockchain-based ENS resolution via public Ethereum RPC endpoints. This hunt identifies the precursors of an attack—unusual DNS lookups to Ethereum services and local proxy usage on port 23075—and the final impact: outbound high-volume network traffic to identified C2 and target endpoints. The flow moves from identifying the at-risk IoT estate to parallelizing behavior checks on three distinct telemetry surfaces.

## iot-asset-inventory
<!-- Inventory IoT and Android platforms -->
Identify hosts running Linux or Android families that match Kimwolf's primary targets, scoped to the lookback window.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of potentially vulnerable IoT devices. Silence means the estate has
  no enrolled Linux/Android assets visible to these providers.
reads:
- device_uid
- hostname
- platform
- os_name
- os_version
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_uid, hostname, platform, os_name, os_version FROM hb_devices WHERE (LOWER(platform) IN ('linux', 'android') OR LOWER(os_name) LIKE '%android%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## behavior-parallel
<!-- Search for C2, Proxy, and DDoS activity -->
parallel:
- → ens-rpc-resolution
- → local-proxy-connection
- → ddos-target-outbound
join: → triage-signals

## ens-rpc-resolution
<!-- ENS resolution via Ethereum RPC -->
Find DNS queries to legitimate Ethereum RPC endpoints abused for C2 resolution.

```sqlite target=endpoint role=detection-candidate params=(ens_rpc_domains=ens_rpc_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS traffic from an IoT device to Ethereum RPC providers. While these are
  legitimate domains, such traffic is highly anomalous for an Android TV box.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{ens_rpc_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## local-proxy-connection
<!-- Local proxy usage on port 23075 -->
Identify processes communicating with a local proxy on the hard-coded Kimwolf port.

```sqlite target=network role=enrichment params=(local_proxy_port=local_proxy_port, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Connections to 127.0.0.1:23075, indicating modular proxy-relay behavior
  characteristic of Kimwolf.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE dst_endpoint_ip = '127.0.0.1' AND dst_endpoint_port = {{local_proxy_port}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ddos-target-outbound
<!-- Outbound traffic to target IP cluster -->
Identify high-volume or repeated connections to the specific target/C2 IPs mentioned in research.

```sqlite target=network role=baseline params=(target_ips=target_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count of outbound connections. A single host communicating frequently
  with these IPs is a strong indicator of compromise.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE instr(',' || '{{target_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING connection_count > 5
```

## triage-signals
<!-- Triage Kimwolf signals -->
```agent target=hunter
cite: required
context:
- iot-asset-inventory
- ens-rpc-resolution
- local-proxy-connection
- ddos-target-outbound
max_iterations: 5
objective: 'Determine if any host exhibits combined Kimwolf v7 indicators: Ethereum
  RPC resolution AND (Local Proxy OR Outbound DDoS targets).'
success_criteria: A verdict for each host with supporting row citations.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Evaluate triage verdict -->
if~: "the triage verdict is malicious for at least one host based on combined blockchain resolution and proxy activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-iot-telemetry)
else: → close-out

## isolate-host
<!-- Isolate IoT asset -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and block all outbound traffic except to internal management services.
```
→ analyst-review

## analyst-review
<!-- Manual investigation -->
```manual target=analyst
Review network logs for port 13 or high-volume UDP traffic. Check for the masquerading process name 'netd_service' on isolated hosts.
```
→ end

## close-out
<!-- Close hunt -->
```manual target=analyst
No malicious activity detected. If Ethereum RPC domains were found on non-IoT assets, verify they were legitimate developer activity.
```
→ end

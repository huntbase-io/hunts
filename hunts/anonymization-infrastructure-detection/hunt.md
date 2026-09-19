---
analysis: "A simple rule catches '.onion'. This hunt identifies the process outliers\u2014\
  uncommon binaries talking on rare ports\u2014and correlates them with known relay\
  \ infrastructure and darknet bridge resolutions across three surfaces."
blind_spots:
- id: encrypted-dns-blindness
  owner: Network Engineering
  question: Whether the adversary is using DNS-over-HTTPS (DoH) to bypass DNS logging.
  remediation: Block outbound port 443 to known DoH providers or enforce DoH through
    enterprise resolvers.
  requires: hb_dns_activity (cleartext)
  risk: Resolutions for darknet gateways through browsers with DoH enabled will not
    appear in hb_dns_activity.
  stage: multi-hop-proxy-c2-obfuscation
- id: ephemeral-relay-nodes
  owner: Threat Intelligence
  question: Whether traffic targets botnet-based residential proxies not in the ORB
    list.
  remediation: Maintain the rare-process-port baseline as the primary indicator for
    non-static infrastructure.
  requires: hb_network_connection
  risk: Adversaries using dynamic botnet nodes will only be caught by the prevalence
    logic, not the direct IP hit query.
  stage: multi-hop-proxy-c2-obfuscation
coverage:
- stage: multi-hop-proxy-c2-obfuscation
  status: covered
  steps:
  - dns-anonymity-leads
  - rare-process-outbound-ports
  - orb-network-hits
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Multi-hop proxies are essential for advanced actors to hide their
    C2 origins. This hunt satisfies the IR maturity requirements for detecting anonymization
    infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies, onion gateways, or Operational
  Relay Box (ORB) networks to obfuscate C2 traffic and bypass direct IP/domain reputation
  filters.
labels:
- hunt
- attack.t1090.003
name: Anonymization Infrastructure Detection
parameters:
  anonymity_gateways:
    default:
    - tor2web.org
    - onion.pet
    - onion.ws
    - i2p.rocks
    - garlic.community
    description: Anonymity gateway suffixes.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  orb_vps_ips:
    default:
    - 45.15.143.0
    - 185.220.101.0
    - 193.233.203.0
    description: Known ORB/VPS exit node IPs.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: DART IR Workshop Indicators
    type: list[ip]
  scope_hosts:
    default: []
    description: Hostnames to limit the hunt to; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/01/cybersecurity-ir-workshop-you-shouldnt-miss/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with critical servers and high-value user workstations. Widen scope
  if DNS leads are found.
references:
- name: 'Microsoft Security Blog: Cybersecurity IR Workshop'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/cybersecurity-ir-workshop-you-shouldnt-miss/
- name: 'MITRE ATT&CK: Multi-hop Proxy'
  url: https://attack.mitre.org/techniques/T1090/003/
related:
- hunt: unauthorized-vpn-software
  reason: VPN clients exhibit similar tunneling but are usually policy issues rather
    than active C2.
  relation: sibling
scenario:
  stages:
  - name: Multi-hop Proxy C2 Obfuscation
    observables:
    - DNS queries for onion routing gateways or known anonymity-focused TLDs
    - Outbound TCP connections directed at known Tor exit nodes or bridge relays
    - Network traffic to IP ranges associated with Operational Relay Box (ORB) networks
      or compromised VPS instances
    slug: multi-hop-proxy-c2-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: This scenario represents the use of multi-hop proxies to obfuscate command-and-control
    communications, a primary technical focus of the incident response readiness exercises
    conducted by the Microsoft DART team. Defenders must identify the use of these
    relay networks by monitoring for specific DNS resolution patterns and network
    traffic anomalies associated with anonymity services and operational relay boxes.
severity: medium
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


# Anonymization Infrastructure Detection

Following Microsoft DART's incident response workshop principles, this hunt looks beyond basic blocklists to identify anonymization infrastructure. It targets the use of darknet bridges (Tor2Web, I2P), rare process-port combinations that suggest unauthorized tunneling, and direct outbound connections to known adversary relay infrastructure (ORB/VPS). By correlating DNS resolutions for anonymity gateways with network-level prevalence analysis, we can detect stealthy C2 channels that masquerade as legitimate encrypted traffic.

## identify-active-assets
<!-- Identify active endpoints -->
Define the population of active hosts for comparison and scoping.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence indicates no active reporting devices.
reads:
- hostname
- os_name
- platform
- last_seen
- time
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname AS device_hostname, os_name, platform, last_seen FROM hb_devices WHERE lifecycle_state = 'running' AND platform IN ('windows', 'linux', 'darwin') AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-anonymity-leads
<!-- DNS resolutions to anonymity gateways -->
Detect attempts to reach the darknet via clearweb bridges or known anonymity TLDs.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, anonymity_gateways=anonymity_gateways)
~~~yaml
expected: Processes querying anonymity-related domains. Subdomain matches are included.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) as count, MIN(time) as first_seen FROM hb_dns_activity WHERE (query_hostname LIKE '%.onion' OR query_hostname LIKE '%.i2p' OR EXISTS (SELECT 1 FROM json_each('["' || replace('{{anonymity_gateways}}', ',', '","') || '"]') WHERE LOWER(query_hostname) LIKE '%.' || value OR LOWER(query_hostname) = value)) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY 1, 2, 3 ORDER BY count DESC
```

## corroboration-parallel
<!-- Corroborate activity -->
parallel:
- → rare-process-outbound-ports
- → orb-network-hits
join: → triage-activity

## rare-process-outbound-ports
<!-- Rare process-port outbound connections -->
Broadly identify any process connecting to a port that is rare (on <3 hosts) to find non-standard tunneling.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One or two hosts where a specific process is using a unique port for outbound
  traffic.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_port
  rare_below: 3
reads:
- process_name
- dst_endpoint_port
- device_hostname
- time
- direction
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, dst_endpoint_port, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY 1, 2 HAVING host_count <= 3 ORDER BY host_count ASC
```

## orb-network-hits
<!-- Connections to known relay infrastructure -->
Detect direct communication with known ORB exit nodes or VPS ranges.

```sqlite target=network role=enrichment params=(orb_vps_ips=orb_vps_ips, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound hits to restricted relay IPs. Silence proves absence of connection
  to these specific IPs.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{orb_vps_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) ORDER BY time DESC
```

## triage-activity
<!-- Triage anonymity signals -->
```agent target=hunter
cite: required
context:
- dns-anonymity-leads
- rare-process-outbound-ports
- orb-network-hits
max_iterations: 6
objective: Determine if the observed network and DNS activity constitutes an unauthorized
  C2 channel using multi-hop infrastructure.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  processes and network destinations.
tools:
- endpoint
- network
```

## route-findings
<!-- Route findings -->
if~: "the triage verdict is malicious for at least one host based on the network/DNS patterns" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-dns-blindness)
else: → close-out

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect a memory dump of the suspicious process identified in the triage report.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the hb_process_activity for the citing PIDs. Look for 'on_disk = 0' (code injection) or unusual parent/child hierarchies (e.g., cmd.exe launching a network tunnel).
```
→ end

## close-out
<!-- Close and baseline -->
```manual target=analyst
Record the baseline of rare port connections. Document any approved business tools that triggered the prevalence filter.
```
→ end

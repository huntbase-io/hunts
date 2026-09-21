---
analysis: While static rules can catch known proxy domains like 'torproject.org',
  this hunt pivots across network connections, host-based process context, and destination
  prevalence. By identifying shell processes talking to rare external IPs, we find
  custom ORB infrastructure that has not yet been blacklisted.
blind_spots:
- id: no-agent-coverage
  question: Are unmanaged devices in the network using multi-hop proxies?
  requires: Endpoint agent on all hosts
  risk: A host without an agent provides no network or process telemetry, allowing
    rogues to hide relay traffic.
  stage: c2-multi-hop-proxy
- id: direct-ip-bypassing-dns
  question: Are adversaries bypassing DNS resolution by using hardcoded IP addresses?
  requires: hb_network_connection destination IP analysis
  risk: If an adversary avoids DNS lookups, the DNS enrichment step will be empty,
    making the IP prevalence signal the only behavioral evidence.
  stage: c2-multi-hop-proxy
coverage:
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - shell-outbound-leads
  - rare-ip-stacking
  - proxy-dns-lookup
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Detecting multi-hop proxy usage is vital for identifying covert communication
    channels that bypass standard boundary controls; a negative result over the estate
    confirms the absence of high-commonality relay behaviors.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies or Operational Relay Box (ORB)
  networks to disguise command-and-control traffic, which can be identified by shell
  processes making outbound connections to rare external IP addresses and resolving
  proxy-related DNS infrastructure.
labels:
- hunt
- attack.t1090.003
name: Network Proxy and Relay Obfuscation Detection
parameters:
  lookback_days:
    default: '14'
    description: Number of days of history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: standard-lookback
    type: number
  proxy_domains:
    default:
    - torproject.org
    - ngrok.com
    - localtunnel.me
    - pagekite.me
    - proxy.com
    - relay.network
    description: Known proxy and relay service domains used to identify infrastructure
      resolution.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: dart-workshop-obfuscation-signals
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to focus on during enrichment; leave empty to search the
      whole estate.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: analyst-defined-scope
    type: list[host]
  shell_processes:
    default:
    - powershell.exe
    - pwsh
    - cmd.exe
    - rundll32.exe
    - certutil.exe
    - bash
    description: Process names that should rarely initiate direct outbound connections
      to the public internet.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: dart-workshop-obfuscation-signals
    type: list[string]
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
rationale: Focus on high-value targets such as domain controllers, jump boxes, and
  workstations of sensitive users. Exclude known corporate VPN egress points that
  may skew prevalence counts.
references:
- name: "Microsoft Security Blog \u2014 Cybersecurity IR Workshop: The workshop you\
    \ shouldn\u2019t miss"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/cybersecurity-ir-workshop-you-shouldnt-miss/
related:
- hunt: unauthorized-vpn-usage
  reason: VPN clients exhibit similar outbound connectivity but typically use different
    protocols than multi-hop relays.
  relation: sibling
scenario:
  stages:
  - name: Multi-hop Proxy Command and Control
    observables:
    - DNS queries for .onion or known proxy domains
    - Outbound connections to Operational Relay Box (ORB) nodes or VPS infrastructure
    - Network traffic patterns indicating multi-hop proxy chains
    - Use of Tor for encrypted C2 communications
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: The Microsoft DART IR Workshop assesses organizational readiness by simulating
    realistic attack scenarios across identity, endpoint, and cloud surfaces. This
    chain focuses on the simulation of command-and-control traffic obfuscated through
    multi-hop proxies and relay networks, testing the effectiveness of network monitoring
    and detection strategies.
severity: medium
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


# Network Proxy and Relay Obfuscation Detection

Multi-hop proxies, such as Tor or ORB networks, are a staple of advanced persistent threat (APT) tradecraft used to obfuscate the origin of malicious traffic. This hunt identifies indicators of this behavior by first finding shell and utility processes communicating with public IP addresses, then corroborating those findings with fleet-wide destination prevalence and DNS queries for known proxy infrastructure. This behavioral approach moves beyond static indicator lists to find the infrastructure-agnostic patterns of relay usage as emphasized in Microsoft IR readiness workshops.

## shell-outbound-leads
<!-- Outbound connections from shell processes -->
Find shell or administrative processes making direct outbound connections to external IP addresses, serving as the lead for potential proxy clients.

```sqlite target=network role=detection-candidate params=(shell_processes=shell_processes, lookback_days=lookback_days)
~~~yaml
expected: A list of shell executions communicating with public IPs. None means no
  shell-based internet traffic was recorded.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- time
- direction
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{shell_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.16.%' AND dst_endpoint_ip NOT LIKE '127.%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-proxy-check
<!-- Corroborate with IP prevalence and DNS infrastructure -->
parallel:
- → rare-ip-stacking
- → proxy-dns-lookup
join: → agent-triage

## rare-ip-stacking
<!-- Prevalence of outbound destination IPs -->
Identify rare remote IP addresses visited by shells across the fleet, highlighting potential private relay nodes or VPS-hosted ORB infrastructure.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, shell_processes=shell_processes)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IP addresses visited by only one or two hosts via shell processes. Rare
  external destinations for shells suggest targeted proxy use.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- time
- direction
- process_name
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{shell_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.16.%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING host_count <= 2 ORDER BY host_count ASC
```

## proxy-dns-lookup
<!-- DNS activity for proxy infrastructure -->
Search for DNS resolutions matching known proxy domains or containing obfuscation keywords on suspicious hosts.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, proxy_domains=proxy_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS resolutions for proxy services or relay-related keywords. Silence suggests
  the adversary is using hardcoded IPs or a less common proxy provider.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%exit-node%' OR LOWER(query_hostname) LIKE '%relay%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Triage proxy and relay activity -->
```agent target=hunter
cite: required
context:
- shell-outbound-leads
- rare-ip-stacking
- proxy-dns-lookup
max_iterations: 6
objective: Determine if the network connections and DNS resolutions indicate an unauthorized
  multi-hop proxy or relay network used for C2 obfuscation.
success_criteria: A verdict of malicious, suspicious, or benign for each identified
  host with cited rows.
tools:
- endpoint
- network
```

## decision-route
<!-- Route on proxy verdict -->
if~: "the agent verdict is malicious for at least one host based on shell connections to rare IPs" (confidence: high, judge=hunter)
then: → action-isolate
indeterminate: → task-investigate
unavailable: → task-investigate (blind_spot: no-agent-coverage)
else: → task-close

## action-isolate
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture a memory dump of the shell process before rebooting to preserve tunnel configuration.
```
→ task-investigate

## task-investigate
<!-- Analyst forensic review -->
```manual target=analyst
Examine the captured process memory for evidence of encrypted tunnels or proxy configuration strings. Check against the IR Workshop schedule to see if this activity aligns with a planned exercise.
```
→ task-close

## task-close
<!-- Document and tune -->
```manual target=analyst
Summarize findings. If administrative proxies were detected, update the scoping_notes or exclude those hosts from future runs of this hunt.
```
→ end

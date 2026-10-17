---
analysis: Existing rules look for specific ngrok and .onion domain strings. This hunt
  pivots to identify the process behavior (running from writable paths) and correlates
  it with network signatures (9001/9050 ports) and subdomain-agnostic DNS patterns
  to find unknown proxy tools that rotation would normally hide.
blind_spots:
- id: incomplete-network-telemetry
  owner: Network Engineering
  question: What is the volume of data being exfiltrated or tunneled?
  remediation: Enable flow log capture with byte counts for all outbound VPC traffic.
  requires: hb_network_connection with bytes/packets for outbound traffic
  risk: A persistent but low-volume tunnel may be indistinguishable from background
    noise without traffic volume analysis.
  stage: proxy-tunnel-establishment
- id: encrypted-dns
  owner: Infrastructure Team
  question: Are tunneling domains being resolved over encrypted DNS (DoH/DoT)?
  remediation: Deploy endpoint policies to disable DoH or intercept DoH traffic at
    the gateway.
  requires: hb_dns_activity from endpoint including DoH/DoT
  risk: Modern browsers and proxies use DoH/DoT to bypass local DNS visibility, rendering
    hb_dns_activity silent for these resolutions.
  stage: proxy-infrastructure-resolution
coverage:
- stage: proxy-infrastructure-resolution
  status: covered
  steps:
  - dns-proxy-resolution
- stage: proxy-tunnel-establishment
  status: covered
  steps:
  - network-activity-writable-paths
  - tor-relay-port-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Multi-hop proxies are a primary method for masking long-term C2;
    identifying them ensures that even if individual domains are rotated, the underlying
    persistence mechanism is discovered.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is masking command-and-control traffic by routing it through
  multi-hop proxies, Tor entry nodes, or tunneling services to bypass perimeter monitoring.
labels:
- hunt
- attack.t1090.003
name: Multi-hop Proxy and Tor Infrastructure Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-07-27'
      ref: hunt-standard
    type: number
  proxy_domains:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - loclx.io
    - pagekite.me
    description: Known tunneling and proxy domain infrastructure.
    from:
      kind: article
      observed: '2024-07-27'
      ref: mitre-t1090
    type: list[domain]
  scope_hosts:
    default: []
    description: Filter to these hosts; leave empty to scan the entire estate.
    from:
      kind: manual
      observed: '2024-07-27'
      ref: analyst-input
    type: list[host]
  scope_processes:
    default: []
    description: Filter to these process names; leave empty to scan all processes.
    from:
      kind: manual
      observed: '2024-07-27'
      ref: analyst-input
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints with high user activity first. Populate the scope_hosts
  and scope_processes parameters from the results of the lead query to narrow the
  corroboration steps if the initial results are noisy.
references:
- name: "Elastic Security Labs \u2014 Inside the Agentic SOC"
  url: https://www.elastic.co/security-labs/blog/ai-agent-optimization-production-scale
- name: 'MITRE ATT&CK: Multi-hop Proxy'
  url: https://attack.mitre.org/techniques/T1090/003/
related:
- hunt: rare-vpn-and-tunnel-process-behaviors
  reason: Uses similar process behavior but focuses on VPN client abuse rather than
    proxy relays.
  relation: sibling
scenario:
  stages:
  - name: DNS Resolution of Proxy Infrastructure
    observables:
    - DNS queries for .onion domains (e.g., .onion.ca, .onion.direct)
    - DNS lookups for tunneling services like ngrok (tunnel.us.ngrok.com)
    - Resolution of known Tor relay hostnames
    slug: proxy-infrastructure-resolution
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Multi-hop Proxy Tunnel Establishment
    observables:
    - Outbound TCP connections to Tor entry nodes on ports 9001, 9050
    - Network connections to ngrok tunnel endpoints (e.g., tunnel.us.ngrok.com)
    - Persistent outbound traffic to known VPS or ORB relay IP addresses
    - Outbound traffic originating from unusual or renamed binaries performing network
      encapsulation
    slug: proxy-tunnel-establishment
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Adversaries utilize multi-hop proxying and onion routing infrastructure
    to disguise the origin of malicious command-and-control traffic. This involves
    resolving proxy-related domains and establishing encrypted tunnels through third-party
    relays or Tor nodes to evade detection.
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


# Multi-hop Proxy and Tor Infrastructure Activity

Adversaries often chain proxies or use encrypted tunneling services to disguise the origin and destination of malicious traffic. This hunt identifies suspicious binaries running from user-writable paths that establish outbound network connections. It corroborates these leads by checking for DNS resolutions of known tunneling providers and network traffic on standard Tor relay ports. An agent weighs the location of the binary, the destination domains, and the port behavior to distinguish unauthorized proxy activity from legitimate administrative tools.

## network-activity-writable-paths
<!-- Outbound activity from user-writable paths -->
Identify potential proxy or tunnel binaries by finding outbound network connections originating from suspicious directories.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Outbound connections from binaries in temporary or public folders. Legitimate
  applications like installers or browser updaters may appear, but persistence tools
  or proxies are the targets.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, user_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE direction = 'outbound' AND (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/var/tmp/%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-proxy-signals
<!-- Corroborate on DNS and Port behavior -->
parallel:
- → dns-proxy-resolution
- → tor-relay-port-activity
join: → triage-proxy-behavior

## dns-proxy-resolution
<!-- Tunnel and Proxy domain resolution -->
Find resolution of domains associated with tunneling services or Tor infrastructure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, proxy_domains=proxy_domains, scope_hosts=scope_hosts, scope_processes=scope_processes)
~~~yaml
expected: Lookups for tunneling services or .onion domains. Frequent resolution by
  a non-browser process is suspicious.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%' OR query_hostname LIKE '%.onion.%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_processes}}' = '' OR instr(',' || '{{scope_processes}}' || ',', ',' || process_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## tor-relay-port-activity
<!-- Known Tor and Relay port traffic -->
Detect network traffic directed at common Tor entry and relay ports.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, scope_processes=scope_processes)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Outbound TCP sessions to ports 9001, 9050, or 9150. These are the default
  ports for Tor and various proxy implementations.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(*) AS session_count FROM hb_network_connection WHERE dst_endpoint_port IN (9001, 9050, 9150) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_processes}}' = '' OR instr(',' || '{{scope_processes}}' || ',', ',' || process_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name
```

## triage-proxy-behavior
<!-- Triage proxy and tunnel activity -->
```agent target=hunter
cite: required
context:
- network-activity-writable-paths
- dns-proxy-resolution
- tor-relay-port-activity
max_iterations: 5
objective: Determine if any host shows a pattern of running a binary from a writable
  path that also performs proxy-related DNS resolution or connects to standard Tor
  ports.
success_criteria: A per-host verdict of malicious, suspicious, or benign based on
  the correlation of the three data points.
tools:
- endpoint
- network
```

## verdict-routing
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: incomplete-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Host and Terminate Process -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and terminate the process identified in the triage report. Collect the binary for analysis before proceeding.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Forensic binary and connection review -->
```manual target=analyst
Examine the binary identified by the triage agent. Check for static strings related to proxy protocols (SOCKS, HTTP) or tunneling tokens. Review destination IPs for association with known VPS providers.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Document the hunt results. If malicious activity was found, promote the network-activity-writable-paths query to a detection rule if it did not exist, or tune existing ones.
```
→ end

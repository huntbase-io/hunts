---
analysis: A static rule for DuckDNS is too noisy. This hunt correlates DNS prevalence
  (rare nodes) with specific port 3000 network sessions and certificate subjects,
  providing a high-fidelity pivot an automated rule cannot easily replicate.
blind_spots:
- id: network-telemetry-gap
  question: Are connections to port 3000 being logged across all network boundaries?
  requires: hb_network_connection with full port coverage
  risk: If port 3000 is blocked or not logged at the perimeter/EDR level, the AI staging
    connectivity will be missed.
  stage: exfiltration-llm-troubleshooting
- id: cert-visibility
  question: Are we capturing all temporary certificates in the browser caches or local
    trust stores?
  requires: hb_certificates with full endpoint inventory
  risk: Attackers rotate certificates frequently; if the inventory snapshot misses
    the rotation window, the indicator match will fail.
  stage: c2-dynamic-dns-tunneling
- id: no-host-attribution-on-certs
  question: Which specific host has the m-doxa certificate in its store?
  requires: a host identifier in the hb_certificates surface
  risk: A certificate match can only be attributed to a host logically by an agent/analyst
    if other telemetry (DNS/Network) is present for that same host.
  stage: c2-dynamic-dns-tunneling
coverage:
- stage: c2-dynamic-dns-tunneling
  status: covered
  steps:
  - dns-scoping
  - duckdns-prevalence
  - m-doxa-certificates
- stage: exfiltration-llm-troubleshooting
  status: covered
  steps:
  - c2-network-traffic
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: initial-access-phishing-attachments
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: execution-iterative-proxies
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: credential-access-shadow-copies
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: collection-ai-assisted-scripting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries targeting Latin America are using AI and Dynamic DNS
    to bypass static filtering. A negative result confirms that these specific C2
    patterns are not present in the estate, protecting against active exfiltration
    clusters.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Dynamic DNS subdomains with an 'm-doxa' prefix for
  SOCKS5 tunneling and LLM-assisted C2, often identified by rare DNS lookups and connections
  to port 3000.
labels:
- hunt
- attack.t1090.003
- attack.t1568.002
- attack.t1048
- attack.t1567
name: DuckDNS and SOCKS5 Proxy C2 Infrastructure
parameters:
  c2_ips:
    default:
    - 62.171.185.97
    - 165.22.184.26
    - 178.128.87.160
    - 167.148.195.53
    description: Known staging and C2 IPs identified in the campaign.
    from:
      kind: article
      observed: '2026-09-03'
      ref: unit42-ai-latam-2026
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the investigation after initial
      scoping.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[host]
  target_prefix:
    default: m-doxa
    description: Subdomain prefix identified for DuckDNS C2 nodes.
    from:
      kind: article
      observed: '2026-09-03'
      ref: unit42-ai-latam-2026
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with internet-facing servers and workstations belonging to IT/Admin
  teams. Focus on the Mexican and Brazilian regions if geographic filters are available.
references:
- name: Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America
  url: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
related:
- hunt: initial-access-phishing-attachments
  reason: Phishing detection is handled in a separate host-based hunt.
  relation: out-of-scope-alternative
- hunt: collection-ai-assisted-scripting
  reason: Host-based behavioral scripts and shadow copy creation are out of scope
    for this network-focused hunt.
  relation: out-of-scope-alternative
- hunt: ai-assisted-scripting-credential-dumping
  relation: follows
scenario:
  stages:
  - name: Resume-themed phishing
    observables:
    - Resume-themed email attachments
    - Compromised WordPress sites
    slug: initial-access-phishing-attachments
    tactic: initial-access
    techniques:
    - T1566.001
  - name: SockTz binary execution
    observables:
    - socktz_v1.exe
    - socktz_v8.exe
    - socktz_v9.exe
    slug: execution-iterative-proxies
    tactic: execution
    techniques:
    - T1059
    - T1204.002
  - name: Shadow copy credential dumping
    observables:
    - 'vssadmin create shadow /for=C:'
    - Dumping Security Account Manager (SAM) registry hive
    - Dumping ntds.dit from domain controllers
    slug: credential-access-shadow-copies
    tactic: credential-access
    techniques:
    - T1003.002
    - T1003.003
  - name: Iterative LLM-generated collection scripts
    observables:
    - Numbered batch scripts (e.g., 1.bat, 2.bat)
    - exploit_creative.py
    - exploit_careful.py
    - rce_focused.py
    - Scripts with '_output' suffix
    slug: collection-ai-assisted-scripting
    tactic: collection
    techniques:
    - T1059.003
    - T1560
  - name: Dynamic DNS and SOCKS5 tunneling
    observables:
    - m-doxa-apodo.duckdns.org
    - m-doxa-geo.duckdns.org
    - m-doxa-intel.duckdns.org
    - m-doxa-vacunas.duckdns.org
    - 167.148.195.53
    - 165.22.184.26
    - SockTz Go-based reverse SOCKS5 proxy
    slug: c2-dynamic-dns-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1568.002
  - name: Staging and AI-backend connectivity
    observables:
    - 62.171.185.97
    - 178.128.87.160
    - NextChat instance on TCP port 3000
    - Let's Encrypt certificates for m-doxa domains
    slug: exfiltration-llm-troubleshooting
    tactic: exfiltration
    techniques:
    - T1048
    - T1567
  summary: Attackers targeting Latin American entities are increasingly leveraging
    commercial LLMs to generate and troubleshoot iterative exploit scripts, dumping
    credentials via shadow copies and deploying Go-based SOCKS5 proxies. The campaigns
    utilize dynamic DNS infrastructure (DuckDNS) and self-hosted NextChat instances
    to manage AI interactions and staging operations.
series:
  index: 2
  slug: attackers-expose-ongoing-ai-tool-use-targeting-organizations-in-latin-america
  title: Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America
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


# DuckDNS and SOCKS5 Proxy C2 Infrastructure

This hunt focuses on network-plane indicators associated with recent AI-enhanced campaigns targeting Latin American organizations. It identifies hosts resolving suspicious DuckDNS subdomains, establishes a fleet-wide baseline for Dynamic DNS usage to highlight rare C2 nodes, and correlates these with outbound connections to known staging IPs and NextChat management interfaces (TCP 3000). The hunt pivots across DNS, network connections, and certificate inventory to reveal infrastructure rotations that simple indicator-based rules might miss.

## dns-scoping
<!-- Identify hosts resolving 'm-doxa' domains -->
Find the subset of the estate interacting with the specific Dynamic DNS infrastructure named in the report.

```sqlite target=endpoint role=scoping params=(target_prefix=target_prefix, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Any result identifies a high-priority host for subsequent
  steps.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '{{target_prefix}}%.duckdns.org' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-investigation
<!-- Gather corroborating evidence -->
parallel:
- → c2-network-traffic
- → duckdns-prevalence
- → m-doxa-certificates
join: → triage-agent

## c2-network-traffic
<!-- Connections to Campaign IPs and NextChat Port -->
Verify active communication with attacker infrastructure or staging tools on port 3000.

```sqlite target=network role=detection-candidate params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound TCP traffic to staging IPs or management ports. Silence proves
  no current session to these specific indicators.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE (instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR dst_endpoint_port = 3000) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## duckdns-prevalence
<!-- Rare DuckDNS Subdomain Prevalence -->
Surface rotated Dynamic DNS nodes that share the attacker's infrastructure but use different subdomains.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DuckDNS subdomains resolved by 1-2 hosts only. Common Dynamic DNS usage
  is filtered, leaving only rare, potentially malicious entries.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.duckdns.org' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 2
```

## m-doxa-certificates
<!-- Certificate Inventory for 'm-doxa' Artifacts -->
Identify identities matching the attacker's naming convention in certificate stores. Note: Attribution to specific hosts is handled logically by the triage agent since this surface lacks host identifiers.

```sqlite target=endpoint role=enrichment params=(target_prefix=target_prefix)
~~~yaml
expected: Certificates issued for the campaign subdomains. This indicates a host or
  identity that has either hosted or trusted rogue infrastructure.
reads:
- common_name
- subject
- issuer
- owner
silence: not_evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT common_name, subject, issuer, owner FROM hb_certificates WHERE LOWER(common_name) LIKE '{{target_prefix}}%' OR LOWER(subject) LIKE '%{{target_prefix}}%'
```

## triage-agent
<!-- Triage Infrastructure Findings -->
```agent target=hunter
cite: required
context:
- dns-scoping
- c2-network-traffic
- duckdns-prevalence
- m-doxa-certificates
max_iterations: 3
objective: Determine if any host shows activity matching the m-doxa infrastructure
  or unauthorized AI management (NextChat) connectivity. Correlate certificate common
  names with the hostnames identified in the DNS and network steps.
success_criteria: A verdict of malicious | suspicious | benign per host with cited
  indicators.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for m-doxa infrastructure or unauthorized port 3000 staging" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: network-telemetry-gap)
else: → analyst-review

## contain-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate an IR investigation into a possible CL-CRI-1131/1163 compromise.
```
→ analyst-review

## analyst-review
<!-- Analyst Triage Review -->
```manual target=analyst
Review the rows from 'duckdns-prevalence' and 'c2-network-traffic'. Confirm the process initiating connections to port 3000. If the host belongs to a federal or municipal target profile, escalate.
```
→ close-out

## close-out
<!-- Close and Baseline -->
```manual target=analyst
Record identified rare DuckDNS nodes. If none match the campaign, document the negative result.
```
→ end

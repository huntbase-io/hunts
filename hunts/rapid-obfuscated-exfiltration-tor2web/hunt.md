---
analysis: While a detection rule can alert on the Tor2Web domains, this hunt calculates
  the data volume and identity risk context simultaneously to confirm an incident
  rather than just a connection.
blind_spots:
- id: no-network-flow-data
  question: Can we measure the volume of data moved?
  requires: hb_network_connection (log) with traffic_bytes
  risk: Some EDR configurations log the connection attempt but not the byte count,
    making it difficult to distinguish exfiltration from simple C2 heartbeats.
  stage: rapid-data-exfiltration
- id: azure-ad-delay
  question: Is the identity signal current?
  requires: azuread_sign_in_report real-time streaming
  risk: As described in the article, if Azure logs are batched, a risky sign-in might
    not appear until after the data has been exfiltrated.
coverage:
- stage: c2-proxy-obfuscation
  status: covered
  steps:
  - gateway-dns-lead
- stage: rapid-data-exfiltration
  status: covered
  steps:
  - volumetric-exfil
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Intrusions now move from breakout to exfiltration in under 30 minutes.
    Correlating obfuscated proxy DNS queries with volumetric network data is the only
    way to detect these high-speed attacks before they conclude.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging public Tor2Web gateways to proxy command-and-control
  traffic and exfiltrate data, bypassing binary-based Tor detection while initiating
  high-volume transfers within minutes of a breakout.
labels:
- hunt
- attack.t1041
- attack.t1090.003
name: Rapid Obfuscated Exfiltration via Tor2Web
parameters:
  exfil_threshold_bytes:
    default: '104857600'
    description: Outbound traffic threshold (100MB) for a single process.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  onion_gateways:
    default:
    - onion.direct
    - tor2web.org
    - onion.link
    - onion.sh
    - onion.pet
    - onion.ws
    - tor2web.info
    description: Public Tor2Web gateways used to access .onion services via HTTP.
    from:
      kind: manual
      observed: '2026-09-04'
      ref: Common Tor2Web gateways
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/siem-data-export-comparison
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on server workloads and developer machines where Tor-like behavior
  is unexpected. Use the lookback_days parameter to match the reported breakout window.
references:
- name: 'Data access: the hidden cost of security vendor lock-in (Elastic)'
  url: https://www.elastic.co/security-labs/blog/siem-data-export-comparison
related:
- hunt: standard-tor-client-usage
  reason: This hunt targets gateway-based evasion (Tor2Web) which uses standard browser
    processes, rather than the dedicated Tor binary.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Multi-hop Proxy C2
    observables:
    - DNS queries for .onion domains
    - Connections to known Tor relay nodes
    - Usage of onion.direct or hidden service gateways
    - Persistent outbound connections to multi-hop proxy infrastructure
    slug: c2-proxy-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Exfiltration via C2 Channel
    observables:
    - High volume outbound traffic_bytes on established C2 sockets
    - Frequent HTTP POST requests to remote C2 endpoints
    - Data transfer initiated within 4-30 minutes of initial breakout
    - Outbound exfiltration to non-standard ports used for C2
    slug: rapid-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: A campaign involving rapid post-compromise activity where exfiltration
    begins within minutes of initial access, leveraging multi-hop proxies and onion
    routing for command-and-control obfuscation. The attack highlights the criticality
    of low-latency telemetry as data is moved out of the environment faster than many
    batch-based security exports can report.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  azure-ad:
    category: siem
    huntbase:
      product: azure-ad
    name: azure_ad
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


# Rapid Obfuscated Exfiltration via Tor2Web

This hunt identifies the gap between initial access and data exfiltration described in recent research, where 'breakout' happens in under 30 minutes. By monitoring for DNS resolutions to known Tor2Web gateways and correlating them with massive outbound data spikes and risky identity signals from Azure AD, we catch obfuscated exfiltration that traditional EDR alerts might miss.

## scoping-active-hosts
<!-- Identify active hosts in scope -->
Establish the list of systems currently reporting telemetry to ensure the hunt targets live assets.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of active hosts. Silence means no systems are currently reporting
  health to the platform.
reads:
- hostname
- device_uid
- os_name
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, device_uid, os_name, lifecycle_state FROM hb_devices WHERE time >= datetime('now', '-{{lookback_days}} days') AND lifecycle_state = 'active'
```

## gateway-dns-lead
<!-- Detect Tor2Web gateway resolutions -->
Find evidence of processes resolving domains used to proxy traffic into the Tor network.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, onion_gateways=onion_gateways, scope_hosts=scope_hosts)
~~~yaml
expected: A hostname and process resolving a gateway. This identifies the obfuscation
  channel.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{onion_gateways}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion.%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## corroborate-activity
<!-- Corroborate with volume and identity -->
parallel:
- → volumetric-exfil
- → azure-identity-risk
join: → triage-agent

## volumetric-exfil
<!-- High-volume outbound connections -->
Identify massive data transfers occurring within the same time window as the gateway lead.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, exfil_threshold_bytes=exfil_threshold_bytes, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: An outbound flow exceeding the threshold. Silence proves no large-scale
  exfiltration occurred through logged sockets.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- traffic_bytes
- direction
- state_kind
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, SUM(traffic_bytes) as total_bytes, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, process_name HAVING total_bytes > {{exfil_threshold_bytes}}
```

## azure-identity-risk
<!-- Risky Azure AD authentication -->
Enrich the hunt with identity-level risk signals from Azure AD sign-in reports.

```sqlite target=azure-ad role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A list of risky sign-ins. This corroborates if the exfiltration followed
  a compromised identity.
reads:
- created_date_time
- ip_address
- user_principal_name
- risk_level_during_sign_in
- risk_state
silence: not_evidence_of_absence
source: azuread_sign_in_report
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT created_date_time, ip_address, user_principal_name, risk_level_during_sign_in, risk_state FROM azuread_sign_in_report WHERE risk_level_during_sign_in IN ('medium', 'high') AND created_date_time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Analyze exfiltration pattern -->
```agent target=hunter
cite: required
context:
- gateway-dns-lead
- volumetric-exfil
- azure-identity-risk
max_iterations: 5
objective: Determine if the gateway DNS resolutions (gateway-dns-lead) and high-volume
  network transfers (volumetric-exfil) occur on the same host within a 1-hour window,
  and check for overlapping risky logins (azure-identity-risk).
success_criteria: A per-host verdict citing row indices for DNS and Network events.
tools:
- azure-ad
- endpoint
- network
```

## route-on-verdict
<!-- Route on triage findings -->
if~: "the triage verdict is malicious for at least one host involving high-volume data transfer through a gateway" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-flow-data)
else: → close-out

## isolate-endpoint
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke all active O365/Azure sessions for the users identified in the risky sign-in report.
```
→ analyst-review

## analyst-review
<!-- Manual impact assessment -->
```manual target=analyst
Review hb_file_activity for the process identified in the network step. Look for directory traversal or archiver (zip/7z) usage prior to the exfiltration timestamp.
```
→ end

## close-out
<!-- Close hunt and archive -->
```manual target=analyst
Note any benign use of Tor2Web gateways (e.g., security research) to tune the onion_gateways parameter.
```
→ end

---
analysis: A rule fires on a Tor IP; the hunt asks whether that host had a high-risk
  login within the preceding 30 minutes. It builds a temporal narrative across identity
  and network surfaces that single-surface rules cannot see.
blind_spots:
- id: identity-batch-delay
  question: Whether a sign-in event was delayed by a vendor's batch-export window.
  requires: Real-time streaming identity logs
  risk: A breakout attack can complete before the lead event is even visible if export
    batching is measured in minutes or hours.
  stage: initial-access-identity-compromise
- id: network-visibility-gap
  question: The exact volume and destination of exfiltration when data is aggregated
    or truncated.
  requires: Full-fidelity VPC flow logs with byte counters
  risk: Summarized network telemetry might miss short, high-velocity bursts of data
    transfer to proxy IPs.
  stage: rapid-exfiltration-c2
coverage:
- stage: initial-access-identity-compromise
  status: covered
  steps:
  - lead-risky-sign-ins
  - evaluate-lead
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - proxy-dns-patterns
- stage: rapid-exfiltration-c2
  status: covered
  steps:
  - rare-outbound-exfiltration
  - triage-breakout
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Rapid exfiltration following identity compromise is a critical exposure
    that bypasses static detection when telemetry arrival is delayed by vendor-imposed
    tolls or batch windows.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses a compromised privileged identity to exfiltrate data
  via a multi-hop proxy or tunnel within 30 minutes of initial access, moving faster
  than traditional telemetry export batches.
labels:
- hunt
- attack.t1078
- attack.t1090.003
- attack.t1041
name: Rapid Identity Breakout and Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  min_exfil_bytes:
    default: '104857600'
    description: Threshold for high-volume outbound transfer (100MB) to be considered
      for burst exfiltration.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus on after identifying a risky sign-in;
      leave empty to hunt across the entire estate.
    type: list[host]
  tunnel_domains:
    default:
    - tunnel.us.ngrok.com
    - tunnel.eu.ngrok.com
    - tunnel.ap.ngrok.com
    - tunnel.au.ngrok.com
    - tunnel.sa.ngrok.com
    description: Known tunneling service domains associated with ORB/proxy activity.
    from:
      kind: article
      observed: '2026-09-04'
      ref: https://www.elastic.co/security-labs/blog/siem-data-export-comparison
    type: list[domain]
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
rationale: Focus on administrative accounts and users with access to critical PII
  or intellectual property. The 30-minute window is the primary filter for confirming
  breakout.
references:
- name: "Elastic Security Labs \u2014 Data access: the hidden cost of security vendor\
    \ lock-in"
  url: https://www.elastic.co/security-labs/blog/siem-data-export-comparison
related:
- hunt: tor-exit-node-access
  reason: Focuses on network-level Tor usage without the identity-breakout narrative.
  relation: sibling
scenario:
  stages:
  - name: Rapid Identity Compromise
    observables:
    - Unusual sign-in location for privileged user
    - Successful authentication via OAuth or SAML from non-corporate IP
    - Sign-in events shortly followed by high-volume network activity
    slug: initial-access-identity-compromise
    tactic: initial-access
    techniques:
    - T1078
  - name: Multi-hop Proxy C2
    observables:
    - DNS queries for .onion domains
    - DNS queries for .hiddenservice.net
    - Connections to known Tor relay nodes or ORB (Operational Relay Box) VPS providers
    - Use of ngrok or similar tunneling tools to tunnel.us.ngrok.com
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Rapid Exfiltration over C2
    observables:
    - High traffic_bytes outbound to a proxy/C2 IP address within 5-30 minutes of
      initial sign-in
    - Outbound network connections with high volume but short duration (burst exfiltration)
    - Process-initiated connections to external endpoints with large transfer sizes
    slug: rapid-exfiltration-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: A high-velocity intrusion campaign where attackers leverage compromised
    identities or exposed services to establish a multi-hop proxy C2 channel, completing
    data exfiltration within minutes of initial access. The campaign relies on speed
    to bypass batch-processing security platforms, utilizing Tor or Operational Relay
    Box (ORB) networks to mask traffic.
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


# Rapid Identity Breakout and Exfiltration

This hunt targets the rapid breakout time where attackers move from initial access to exfiltration in under 30 minutes. It follows a gated flow: first identifying high-risk successful sign-ins in Azure AD, then fanning out to search for multi-hop proxy usage and bursts of outbound data transfer. The hunt specifically looks for the temporal overlap between identity anomalies and network exfiltration, identifying intrusions that move faster than vendor data-export batches.

## lead-risky-sign-ins
<!-- High-risk successful sign-ins -->
Identify successful authentications flagged with elevated risk levels as a starting point for the breakout investigation.

```sqlite target=azure-ad role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of successful risky sign-ins. Silence indicates no high-risk identity
  activity was logged in the window.
reads:
- user_principal_name
- ip_address
- risk_level_during_sign_in
- risk_state
- created_date_time
- app_display_name
silence: not_evidence_of_absence
source: azuread_sign_in_report
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT user_principal_name, ip_address, risk_level_during_sign_in, risk_state, created_date_time, app_display_name FROM azuread_sign_in_report WHERE risk_level_during_sign_in IN ('high', 'medium') AND created_date_time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate lead for breakout potential -->
```agent target=hunter
cite: required
context:
- lead-risky-sign-ins
max_iterations: 3
objective: "Determine if any sign-ins represent a high-confidence threat and resolve\
  \ the relationship between the user_principal_name and specific device_hostname\
  \ values\u2014using hb_devices or recent authentication history\u2014to populate\
  \ the scope_hosts parameter with actionable targets for the parallel phase."
success_criteria: A per-user risk verdict and a list of associated device_hostname
  values to populate scope_hosts.
tools:
- azure-ad
- endpoint
- network
```

## gate-suspicious-sign-in
<!-- Gate: Proceed to deep dive -->
if~: "at least one sign-in is judged to be anomalous and provides actionable device_hostname targets for correlation" (confidence: high, judge=hunter)
then: → deep-dive
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: identity-batch-delay)
else: → close-out

## deep-dive
<!-- Corroborate with network and DNS telemetry -->
parallel:
- → proxy-dns-patterns
- → rare-outbound-exfiltration
join: → triage-breakout

## proxy-dns-patterns
<!-- Proxy and tunnel DNS patterns -->
Find resolution of domains associated with multi-hop proxies or tunneling services used to mask C2 traffic.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, tunnel_domains=tunnel_domains, scope_hosts=scope_hosts)
~~~yaml
expected: A host resolving proxy-related domains. This is a high-fidelity indicator
  of C2 obfuscation.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%.hiddenservice.net%' OR instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-exfiltration
<!-- Rare high-volume outbound exfiltration -->
Identify rare external destinations receiving large bursts of data from individual hosts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, min_exfil_bytes=min_exfil_bytes, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A rare host-to-IP pair with high traffic volume. Stack-counting destinations
  identifies anomalous outbound transfers.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, dst_endpoint_ip, SUM(traffic_bytes) AS total_bytes, COUNT(*) AS flow_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND traffic_bytes > {{min_exfil_bytes}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip ORDER BY total_bytes DESC
```

## triage-breakout
<!-- Triage breakout window -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- proxy-dns-patterns
- rare-outbound-exfiltration
max_iterations: 6
objective: Determine if proxy DNS patterns or rare high-volume network transfers occurred
  on a host within the 30-minute breakout window following the evaluated risky sign-in.
  Use the context from evaluate-lead to match the user to the host activity.
success_criteria: A verdict of malicious | suspicious citing specific hostnames, timestamps,
  and byte counts.
tools:
- azure-ad
- endpoint
- network
```

## route-on-evidence
<!-- Route on triage verdict -->
if~: "the triage confirms exfiltration or proxy activity followed a risky sign-in within the breakout window" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: network-visibility-gap)
else: → analyst-manual-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the triage and revoke all active sessions for the associated user in Azure AD.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the correlated timing between the Azure AD sign-in and the high-volume network exfiltration. Verify the destination IPs and check for lateral movement from the target host prior to isolation.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the time window examined. If sign-ins were benign, document the justification for tuning lead thresholds.
```
→ end

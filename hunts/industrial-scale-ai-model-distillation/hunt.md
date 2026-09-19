---
analysis: A single rule could flag 'z.ai', but this hunt correlates identity-layer
  account clustering on shared IPs with network-layer exfiltration volume and behavioral
  fingerprints (User-Agents) across multiple gateways to distinguish a campaign from
  background noise.
blind_spots:
- id: no-prompt-visibility
  owner: Gateway Engineering
  question: Are the prompts using 'chain-of-thought' or 'jailbreak' techniques specifically?
  remediation: Implement sampled logging of prompt metadata (length, presence of specific
    system-prompt bypass keywords).
  requires: HTTP request body logging (prompt text)
  risk: We rely on volume and account density as proxies for intent. Highly efficient
    legitimate automation might be misclassified.
  stage: industrial-scale-distillation-exfiltration
- id: ip-rotation-latency
  owner: Security Operations
  question: Are the source IPs belonging to short-lived cloud instances?
  remediation: Integrate cloud provider IP feeds to automatically tag ingress traffic
    from AWS/Azure/GCP regions.
  requires: Real-time IP threat intelligence for cloud egress points
  risk: Static IP blocks are less effective if the transfer stations rotate IPs faster
    than the hunt cycle.
  stage: proxy-obfuscation
coverage:
- stage: account-fraud-and-initial-access
  status: covered
  steps:
  - identify-account-clusters
- stage: proxy-obfuscation
  status: covered
  steps:
  - dns-to-distillation-proxies
  - coordinated-user-agent-activity
- stage: industrial-scale-distillation-exfiltration
  status: covered
  steps:
  - high-volume-api-requests
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Fulfills the CISA/FBI/NSA recommendation to detect and mitigate industrial-scale
    distillation campaigns by foreign AI competitors, protecting core intellectual
    property.
  methodology: model-assisted
  trigger: intel-report
hypothesis: China-based AI companies are using fraudulent account clusters and 'transfer
  station' proxies to conduct high-volume extraction of proprietary model capabilities
  through API gateways.
labels:
- hunt
- attack.t1190
- attack.t1090.003
- attack.t1041
name: Industrial-Scale AI Model Distillation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for throughput and account clustering.
    type: number
  proxy_domains:
    default:
    - z.ai
    - api-proxy.me
    - transfer-station.io
    description: Known domains for API transfer stations.
    from:
      kind: article
      observed: '2026-09-08'
      ref: AA26-251A
    type: list[domain]
  scope_hosts:
    default: []
    description: API Gateways or reporting proxies identified in the scoping step
      to focus the hunt.
    type: list[host]
  user_threshold:
    default: '20'
    description: Number of unique accounts per IP that triggers suspicion of a proxy.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Use the identify-account-clusters step to find the specific API gateways
  and source IPs under pressure. Narrow subsequent queries using the scope_hosts parameter
  to reduce noise.
references:
- name: 'CISA AA26-251A: China-Based AI Companies Conducting Industrial-Scale Distillation
    Campaigns'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a
related:
- hunt: api-abuse-and-account-takeover
  reason: While this hunt focuses on coordinated distillation, a sibling hunt targets
    traditional account hijacking for API credits.
  relation: sibling
scenario:
  stages:
  - name: Fraudulent Account Creation and Subscription Abuse
    observables:
    - Bulk procurement of premium subscriptions
    - fraudulent accounts not registered to legitimate users
    - similar registration details
    - similar payment methods
    - immediate maximum usage from new accounts
    slug: account-fraud-and-initial-access
    tactic: initial-access
    techniques:
    - T1190
  - name: API Proxying and Metadata Obfuscation
    observables:
    - Transfer stations
    - gray market API proxies
    - z.ai
    - automated failover between pathways
    - third-party API aggregators
    - obfuscated user metadata
    slug: proxy-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: High-Volume Model Distillation and Data Extraction
    observables:
    - Billions of tokens extracted
    - millions of exchanges/requests
    - chain-of-thought (CoT) reasoning extraction
    - prompt injection
    - high-volume coordinated queries
    - identical or similar prompt texts
    slug: industrial-scale-distillation-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: China-based AI companies such as DeepSeek and Alibaba are conducting industrial-scale
    knowledge distillation against U.S. frontier AI models to extract proprietary
    capabilities. They utilize fraudulent accounts, 'transfer stations' (API proxies),
    and multi-hop infrastructure to bypass regional restrictions and exfiltrate billions
    of tokens via high-volume API requests.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Industrial-Scale AI Model Distillation

This hunt identifies systematic model distillation by detecting clusters of accounts originating from shared infrastructure (transfer stations), resolving known distillation proxies like z.ai, and exhibiting industrial-scale request volumes. We pivot from identity-layer anomalies—multiple accounts per source IP—to network-layer exfiltration patterns observed at the API gateways, as recommended in CISA Advisory AA26-251A.

## identify-account-clusters
<!-- Identify Account Clusters on Proxies -->
Locate API gateways experiencing abnormal account density from single source IPs, indicating possible 'transfer station' usage.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, user_threshold=user_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs (transfer stations) used by dozens or hundreds of accounts to
  access a specific gateway. Large unique_accounts values confirm aggregation.
prevalence:
  by: dst_endpoint_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- dst_endpoint_name
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_name, src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_accounts, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name, src_endpoint_ip HAVING unique_accounts >= {{user_threshold}} ORDER BY unique_accounts DESC
```

## corroborate-infrastructure
<!-- Corroborate Infrastructure and Volume -->
parallel:
- → dns-to-distillation-proxies
- → high-volume-api-requests
- → coordinated-user-agent-activity
join: → triage-campaign-activity

## dns-to-distillation-proxies
<!-- DNS to Distillation Proxies -->
Identify gateways resolving known 'transfer station' domains while focusing on the scoped API gateways.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, proxy_domains=proxy_domains, lookback_days=lookback_days)
~~~yaml
expected: Gateways resolving z.ai or other transfer stations confirm the routing pathway
  described in the research.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.z.ai') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## high-volume-api-requests
<!-- Industrial-Scale Request Throughput -->
Quantify exfiltration volume per account and source IP at the scoped gateways.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Accounts with millions of requests (distillation) versus thousands (legitimate
  usage).
reads:
- device_hostname
- src_endpoint_ip
- actor_user_name
- response_bytes
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, actor_user_name, COUNT(*) AS request_count, SUM(response_bytes) AS total_bytes FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, actor_user_name HAVING request_count > 10000 ORDER BY request_count DESC
```

## coordinated-user-agent-activity
<!-- Coordinated User-Agent Fingerprints -->
Identify uniform automation patterns across many accounts on a single IP, suggesting scripted distillation.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Multiple accounts sharing the same User-Agent and source IP indicate a coordinated
  bot fleet rather than individual human users.
prevalence:
  by: actor_user_name
  key:
  - user_agent
  - src_endpoint_ip
  rare_below: 10
reads:
- user_agent
- src_endpoint_ip
- actor_user_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_agent, src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS accounts, COUNT(*) AS hits FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent, src_endpoint_ip HAVING accounts > 5 ORDER BY accounts DESC
```

## triage-campaign-activity
<!-- Triage Distillation Campaign -->
```agent target=hunter
cite: required
context:
- identify-account-clusters
- dns-to-distillation-proxies
- high-volume-api-requests
- coordinated-user-agent-activity
max_iterations: 6
objective: Determine if the account clusters, proxy IP associations, and volume throughput
  indicate a coordinated industrial-scale distillation campaign targeting model functionality.
success_criteria: A verdict of 'malicious' for clusters showing >50 accounts/IP and
  high-volume requests, or 'benign' for legitimate bulk users.
tools:
- endpoint
- identity
- web
```

## determine-disposition
<!-- Determine Disposition -->
if~: "The triage verdict is malicious for at least one account cluster or source IP." (confidence: high, judge=hunter)
then: → revoke-fraudulent-access
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-prompt-visibility)
else: → close-out

## revoke-fraudulent-access
<!-- Revoke Access and Block IPs -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke OAuth sessions for the identified account clusters. Block the source IPs of 'transfer stations' at the API gateway or firewall level.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Documentation -->
```manual target=analyst
Validate the cluster activity against billing data and coordinate with legal teams regarding terms of use violations. Share transfer station IPs and User-Agents with industry peers.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document false positives from legitimate high-volume enterprise users to tune future runs.
```
→ end

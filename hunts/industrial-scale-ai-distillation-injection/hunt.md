---
analysis: A single rule might catch one 'jailbreak' string, but this hunt combines
  keyword detection with volume analysis (throughput), DNS infrastructure correlation,
  and network-level exfiltration stacking to identify the industrial nature of the
  campaign across three surfaces.
blind_spots:
- id: limited-http-body-visibility
  owner: Network Engineering
  question: What were the specific prompt contents?
  remediation: Enable WAF inspection of request payloads for AI API endpoints.
  requires: hb_http_activity with full request body logging
  risk: Sophisticated injections hidden in POST bodies may be missed if only URL/headers
    are logged.
  stage: execution-prompt-injection
- id: obfuscated-proxies
  owner: Threat Intel
  question: What is the true origin of the traffic?
  remediation: Ingest known commercial proxy and 'transfer station' IP feeds.
  requires: Multi-hop proxy visibility
  risk: Transfer stations effectively hide the ultimate actor, leaving only the proxy
    IP visible for blocking.
  stage: exfiltration-distillation
coverage:
- stage: execution-prompt-injection
  status: covered
  steps:
  - prompt-injection-keywords
- stage: exfiltration-distillation
  status: covered
  steps:
  - high-volume-api-scoping
  - sustained-high-throughput-flows
  - dns-transfer-stations
- reason: Belongs to another part of the 'China-Based Artificial Intelligence Companies
    Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies'
    series.
  stage: initial-access-proxy-access
  status: out_of_scope
- reason: Belongs to another part of the 'China-Based Artificial Intelligence Companies
    Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies'
    series.
  stage: defense-evasion-obfuscation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Knowledge distillation represents the theft of core intellectual
    property. Detecting these campaigns prevents the industrial-scale extraction of
    proprietary model capabilities that cost billions to develop.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is conducting large-scale knowledge distillation by submitting
  coordinated prompt injections and high-entropy reasoning requests to extract model
  weights and logic via API proxies.
labels:
- hunt
- attack.t1190
- attack.t1041
- attack.t1090.003
name: Industrial-Scale AI Model Distillation and Injection
parameters:
  distillation_domains:
    default:
    - z.ai
    - proxy.z.ai
    - api.deepseek.com
    - api.moonshot.cn
    - api.minimax.chat
    description: Known domains used by distillation entities or suspected transfer
      stations.
    from:
      kind: article
      observed: '2026-09-08'
      ref: aa26-251a
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: internal
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
rationale: Focus on API-facing infrastructure and edge logging (WAF/Proxy). Widen
  the DNS search if initial results are limited to known Z.AI infrastructure.
references:
- name: "CISA \u2014 China-Based AI Companies Conducting Industrial-Scale Distillation\
    \ Campaigns"
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a
related:
- hunt: account-takeover-ai-subscriptions
  reason: This hunt looks for distillation logic; stealing legitimate accounts to
    fund it is a separate identity-centric hypothesis.
  relation: out-of-scope-alternative
- hunt: industrial-scale-distillation-proxy-obfuscation
  relation: follows
scenario:
  stages:
  - name: Unauthorized API Access via Transfer Stations
    observables:
    - Gray market API proxies known as 'transfer stations'
    - Bulk procurement of premium subscriptions
    - Fraudulent accounts with similar registration details and payment methods
    - API calls from non-resident geographic regions
    - Third-party API aggregator services
    slug: initial-access-proxy-access
    tactic: initial-access
    techniques:
    - T1190
  - name: Metadata Obfuscation and Multi-hop Proxying
    observables:
    - Automated obfuscation of user metadata via aggregators
    - Multi-hop routing through remote cloud providers
    - Automated failover between access pathways during blocking
    - Usage patterns exceeding thousands to millions of requests on similar topics
    slug: defense-evasion-obfuscation
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: LLM Jailbreak and Prompt Injection
    observables:
    - Prompts designed for jailbreaking
    - Prompt injections to trick models (e.g., MiniMax pretending to be the model
      provider)
    - Coordinated queries with identical or similar prompt texts
    - Chain-of-thought (CoT) reasoning extraction prompts
    slug: execution-prompt-injection
    tactic: execution
    techniques:
    - T1190
  - name: Knowledge Distillation Exfiltration
    observables:
    - Extraction of billions of tokens (synthetic training data)
    - Massive throughput of specific domain logic (legal, coding, math)
    - 'Domain: z.ai'
    - High volume of exfiltrated tokens over existing API channels
    slug: exfiltration-distillation
    tactic: exfiltration
    techniques:
    - T1041
  summary: China-based AI companies are conducting industrial-scale knowledge distillation
    campaigns to extract proprietary capabilities from U.S. frontier AI models. These
    campaigns use gray-market API proxies, bulk account procurement, and prompt injection
    to bypass geographic restrictions and terms of use, effectively stealing model
    reasoning and domain-specific logic.
series:
  index: 2
  slug: china-based-artificial-intelligence-companies-conducting-industrial-scale-distillation-campaigns
  title: China-Based Artificial Intelligence Companies Conducting Industrial-Scale
    Distillation Campaigns Against U.S. AI Companies
  total: 2
severity: critical
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Industrial-Scale AI Model Distillation and Injection

This hunt targets the industrial-scale extraction of frontier AI model capabilities. It focuses on identifying coordinated, high-volume prompt injection attempts and the massive exfiltration of tokens—specifically targeting chain-of-thought (CoT) and domain-specific reasoning extraction. The hunt correlates anomalous HTTP traffic volumes with specific prompt patterns and identifies associated infrastructure using DNS and network telemetry.

## high-volume-api-scoping
<!-- High-Volume API Usage Scoping -->
Identify endpoints or IPs with anomalous API request volumes that suggest industrial-scale throughput.

```sqlite target=web role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A small number of source IPs accounting for a disproportionate number of
  API requests, indicating potential 'transfer stations'.
reads:
- src_endpoint_ip
- url_hostname
- url_path
- response_bytes
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, url_hostname, COUNT(*) as request_count, SUM(response_bytes) as total_outbound_bytes FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/v1/chat/completions%' OR LOWER(url_path) LIKE '%/v1/completions%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_hostname HAVING request_count > 100 ORDER BY request_count DESC
```

## parallel-corroboration
<!-- Corroborate injection with infrastructure signals -->
parallel:
- → prompt-injection-keywords
- → dns-transfer-stations
- → sustained-high-throughput-flows
join: → distillation-triage

## prompt-injection-keywords
<!-- Adversarial Prompt Injection Metadata Search -->
Identify indicators of jailbreaking or CoT extraction within available HTTP headers and user agents.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests with metadata or URLs containing distillation entity names
  or reasoning keywords.
reads:
- url_full
- src_endpoint_ip
- time
- user_agent
- response_bytes
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT time, src_endpoint_ip, url_full, user_agent, response_bytes FROM hb_http_activity WHERE (LOWER(user_agent) LIKE '%minimax%' OR LOWER(user_agent) LIKE '%deepseek%' OR LOWER(url_full) LIKE '%thought%' OR LOWER(url_full) LIKE '%jailbreak%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-transfer-stations
<!-- DNS lookups to distillation infrastructure -->
Correlate API usage with DNS lookups to known or suspected distillation 'transfer station' domains.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, distillation_domains=distillation_domains)
~~~yaml
expected: DNS traffic to listed domains associated with China-based distillation activity.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE (LOWER(query_hostname) IN ('z.ai', 'proxy.z.ai', 'api.deepseek.com', 'api.moonshot.cn', 'api.minimax.chat')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## sustained-high-throughput-flows
<!-- Sustained High-Throughput Network Flows -->
Identify massive exfiltration by stack-counting source IPs with extreme byte-to-packet ratios in network logs.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: 30d
expected: A per-IP stack count of massive outbound flows, identifying potential automated
  extraction.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- dst_endpoint_ip
- traffic_bytes
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes, COUNT(*) as flow_count, MIN(time) as first_seen_in_window FROM hb_network_connection WHERE direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_ip HAVING total_bytes > 536870912 ORDER BY total_bytes DESC
```

## distillation-triage
<!-- Distillation Triage Agent -->
```agent target=hunter
cite: required
context:
- high-volume-api-scoping
- prompt-injection-keywords
- dns-transfer-stations
- sustained-high-throughput-flows
max_iterations: 5
objective: Identify industrial-scale distillation by correlating prompt logic with
  byte throughput and known malicious domains.
success_criteria: A verdict citing specific rows from multiple surfaces indicating
  coordinated campaign activity.
tools:
- endpoint
- network
- web
```

## route-distillation
<!-- Route on Distillation Signal -->
if~: "the triage agent identifies high-confidence distillation activity from one or more source IPs" (confidence: high, judge=hunter)
then: → block-proxies
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-http-body-visibility)
else: → close-out

## block-proxies
<!-- Block Malicious Proxy IPs -->
```action target=endpoint
~~~yaml
approval: required
~~~
Revoke associated API keys and block source IPs at the WAF/Firewall.
```
→ analyst-review

## analyst-review
<!-- Review Coordinated Campaigns -->
```manual target=analyst
Cross-reference malicious IPs with hb_auth_signin (src_endpoint_ip) to find associated user accounts.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record IPs as known proxies and update monitoring for CoT extraction keywords.
```
→ end

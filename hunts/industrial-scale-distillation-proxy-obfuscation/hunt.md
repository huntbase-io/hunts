---
analysis: 'A single rule could detect one IP or one domain, but this hunt correlates
  the ''transfer station'' behavior: many accounts sharing an IP, high-volume HTTP
  throughput, and DNS resolution of aggregator infrastructure.'
blind_spots:
- id: incomplete-api-logs
  owner: Cloud Infrastructure Team
  question: Whether the prompts themselves match distillation patterns
  remediation: Enable sampling of prompt body logs for high-volume accounts.
  requires: hb_http_activity with full body payload logging
  risk: Without prompt bodies, we rely on metadata volume; a high-volume legitimate
    user might be flagged erroneously.
  stage: initial-access-proxy-access
- id: proxy-rotation
  owner: Security Operations
  question: Whether the source IP is a residential proxy rather than a fixed datacenter
    IP
  remediation: Integrate a commercial VPN/Proxy detection feed into hb_auth_signin
    enrichment.
  requires: Threat intelligence feed for residential proxy IPs
  risk: Adversaries using residential IP rotation will not trigger the 'many accounts
    per IP' threshold.
  stage: defense-evasion-obfuscation
coverage:
- stage: initial-access-proxy-access
  status: covered
  steps:
  - high-volume-auth-by-ip
  - proxy-domain-traffic
- stage: defense-evasion-obfuscation
  status: covered
  steps:
  - high-frequency-api-calls
  - proxy-domain-traffic
- reason: Belongs to another part of the 'China-Based Artificial Intelligence Companies
    Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies'
    series.
  stage: execution-prompt-injection
  status: out_of_scope
- reason: Belongs to another part of the 'China-Based Artificial Intelligence Companies
    Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies'
    series.
  stage: exfiltration-distillation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Knowledge distillation represents a theft of core IP. Detecting the
    infrastructure (proxies) and behavior (high-volume auth/API usage) is the only
    way to protect the model's proprietary value.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using API proxies or 'transfer stations' to bypass geographic
  restrictions and obfuscate metadata during large-scale AI model distillation campaigns.
labels:
- hunt
- attack.t1190
- attack.t1090.003
- attack.t1041
name: Industrial-Scale Distillation Proxy and Obfuscation
parameters:
  known_proxy_domains:
    default:
    - z.ai
    - api-proxy.io
    - transfer-station.net
    description: Known or suspected API aggregator/proxy domains.
    from:
      kind: article
      observed: '2026-09-08'
      ref: AA26-251A
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-08'
      ref: standard-lookback
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
rationale: Focus on high-usage API tiers and newer account registrations (last 90
  days). Cross-reference with geographic residency if possible.
references:
- name: "CISA AA26-251A \u2014 China-Based AI Companies Conducting Industrial-Scale\
    \ Distillation"
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a
related:
- hunt: execution-prompt-injection
  reason: This hunt focuses on the access layer; prompt injection detection requires
    deep inspection of the hb_http_activity url_query or body.
  relation: out-of-scope-alternative
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
  index: 1
  slug: china-based-artificial-intelligence-companies-conducting-industrial-scale-distillation-campaigns
  title: China-Based Artificial Intelligence Companies Conducting Industrial-Scale
    Distillation Campaigns Against U.S. AI Companies
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


# Industrial-Scale Distillation Proxy and Obfuscation

This hunt identifies the use of third-party API aggregators and multi-hop proxies used to circumvent geographic and identity-based controls. It focuses on identifying anomalous authentication patterns from 'transfer stations' and correlating them with high-volume HTTP activity directed at model endpoints, which are typical of industrial-scale distillation.

## high-volume-auth-by-ip
<!-- High-Volume Authentication from Rare IPs -->
Identify IPs that authenticate to many accounts, suggesting a shared 'transfer station' or proxy service.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A single IP address successfully logging into 5+ different user accounts
  within the lookback window.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS account_count, COUNT(*) AS auth_attempts, GROUP_CONCAT(DISTINCT provider) AS providers FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING account_count > 5 ORDER BY account_count DESC
```

## parallel-corroboration
<!-- Corroborate Network and API Behavior -->
parallel:
- → high-frequency-api-calls
- → proxy-domain-traffic
join: → triage-distillation

## high-frequency-api-calls
<!-- Industrial-Scale API Throughput Patterns -->
Identify accounts or IPs with request volumes exceeding normal developer behavior.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A user or IP issuing thousands of completions requests, which is characteristic
  of distillation vs simple usage.
reads:
- src_endpoint_ip
- device_hostname
- actor_user_name
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, device_hostname, actor_user_name, url_hostname, COUNT(*) AS request_count, MIN(time) AS first_req, MAX(time) AS last_req FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/v1/chat/completions%' OR LOWER(url_path) LIKE '%/v1/completions%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname, actor_user_name, url_hostname HAVING request_count > 1000 ORDER BY request_count DESC
```

## proxy-domain-traffic
<!-- Traffic to Known API Proxies -->
Match host activity against the report's named indicator and general proxy patterns.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Resolutions for z.ai or other aggregator domains from hosts that are also
  performing high-volume authentication.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.z.ai' OR LOWER(query_hostname) LIKE '%.transfer-station.net' OR LOWER(query_hostname) LIKE '%.api-proxy.io') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-distillation
<!-- Triage Distillation Evidence -->
```agent target=hunter
cite: required
context:
- high-volume-auth-by-ip
- high-frequency-api-calls
- proxy-domain-traffic
max_iterations: 4
objective: Determine if the observed high-volume API activity and account sharing
  represents a malicious distillation campaign via proxy infrastructure.
success_criteria: Categorize each suspicious IP/Account as 'malicious' (clear distillation),
  'suspicious' (anomalous usage), or 'benign' (high-volume customer).
tools:
- endpoint
- identity
- web
```

## decision-route
<!-- Route Based on Verdict -->
if~: "The triage verdict is 'malicious' for any IP or account" (confidence: high, judge=hunter)
then: → block-access
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-api-logs)
else: → close-out

## block-access
<!-- Block Malicious Assets -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the accounts identified in the triage report and block the source IPs at the WAF/Gateway level.
```
→ analyst-review

## analyst-review
<!-- Manual Compliance and Pattern Review -->
```manual target=analyst
Compare the prompts from the identified accounts against known distillation templates (e.g., CoT reasoning extraction). Check for registration similarities between the accounts.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Record that no industrial-scale distillation signatures were found in the current window.
```
→ end

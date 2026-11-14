---
analysis: A single detection rule cannot correlate the lifecycle of an account from
  fraudulent procurement through proxy evasion to massive token extraction. This hunt
  pivots across auth, network, DNS, and HTTP surfaces to prove the industrial scale
  required by the adversary.
blind_spots:
- id: no-tls-inspection
  question: What were the specific prompt contents within the HTTPS payload?
  requires: TLS decryption at the proxy or application-level logging
  risk: Adversaries using encrypted tunnels can hide specific prompt injection TTPs,
    leaving only volume and metadata visible to the network stack.
  stage: execution-prompt-injection
- id: ip-rotation-evasion
  question: Are these source IPs part of a known transfer station proxy network?
  requires: Real-time IP reputation and multi-platform intelligence sharing
  risk: Rapid rotation of 'transfer station' IPs may allow adversaries to bypass static
    IP blocklists and evade detection between hunt cycles.
  stage: c2-transfer-station-proxies
coverage:
- stage: initial-access-api-account-fraud
  status: covered
  steps:
  - shared-subscription-anomalies
  - triage-access-and-proxies
- stage: c2-transfer-station-proxies
  status: covered
  steps:
  - proxy-transfer-station-activity
  - triage-access-and-proxies
- stage: execution-prompt-injection
  status: covered
  steps:
  - model-extraction-endpoints
  - evaluate-industrial-campaign
- stage: exfiltration-industrial-distillation
  status: covered
  steps:
  - high-volume-exfiltration
  - evaluate-industrial-campaign
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Industrial-scale distillation threatens U.S. technological leadership
    and model safety. Identifying the systematic extraction of proprietary capabilities
    is an obligation for frontier AI providers to protect their assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: China-based adversaries are using fraudulent accounts and proxy transfer
  stations to conduct high-volume, automated extraction of proprietary AI model capabilities
  through systematic distillation.
labels:
- hunt
- attack.t1190
- attack.t1090.003
- attack.t1041
name: Industrial-Scale AI Model Distillation and Extraction
parameters:
  ai_distillation_domains:
    default:
    - z.ai
    - deepseek.com
    - moonshot.cn
    - minimax.chat
    - stepfun.com
    - qwenlm.ai
    description: Domains associated with China-based AI companies conducting distillation.
    from:
      kind: article
      observed: '2026-09-08'
      ref: AA26-251A
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  min_request_count:
    default: '1000'
    description: Minimum request threshold to identify automated or industrial-scale
      behavior.
    type: number
  min_shared_users:
    default: '5'
    description: Minimum distinct users per source IP to flag a potential shared premium
      subscription.
    type: number
  scope_hosts:
    default: []
    description: List of hosts found in the scoping step; paste back here to narrow
      subsequent queries.
    type: list[host]
  volume_threshold_bytes:
    default: '1000000000'
    description: Byte threshold (approx 1GB) per account/host to identify industrial-scale
      extraction.
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
rationale: The hunt scopes to hosts resolving known distillation domains. Focus investigation
  on accounts created within the lookback period and those demonstrating immediate
  high-throughput patterns.
references:
- name: "CISA AA26-251A \u2014 Industrial-Scale Distillation Campaigns"
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a
related:
- hunt: api-credential-stuffing-detection
  reason: This hunt focuses on systematic distillation through fraudulent accounts,
    not the compromise of existing legitimate accounts via credential stuffing.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Fraudulent API Account Creation
    observables:
    - Creation of fraudulent accounts with similar registration details
    - Bulk procurement of premium subscriptions shared across developer teams
    - Immediate maximum usage from newly created accounts
    - Domain z.ai
    slug: initial-access-api-account-fraud
    tactic: initial-access
    techniques:
    - T1190
  - name: Geographic Evasion via Transfer Stations
    observables:
    - Use of gray market API proxies known as 'transfer stations'
    - Routing through third-party API aggregators to obfuscate metadata
    - Automated failover between multiple cloud providers and pathways
    - Connections to z.ai infrastructure
    slug: c2-transfer-station-proxies
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Targeted Model Capability Extraction
    observables:
    - LLM Prompt Injection and Jailbreak attempts
    - Chain-of-thought (CoT) reasoning extraction queries
    - Highly coordinated queries featuring identical prompt texts
    - Queries designed to trick model identity (e.g., claiming to be MiniMax products)
    slug: execution-prompt-injection
    tactic: execution
    techniques:
    - T1190
  - name: Industrial-Scale Knowledge Distillation
    observables:
    - Extraction of billions of tokens across millions of requests
    - Abnormal subscription-to-usage ratios
    - Enterprise-scale throughput patterns on individual accounts
    - Extraction of specialized domains (legal, coding, agentic functions)
    slug: exfiltration-industrial-distillation
    tactic: exfiltration
    techniques:
    - T1041
  summary: China-based AI companies are conducting industrial-scale knowledge distillation
    to extract proprietary capabilities from U.S. frontier AI models. The campaign
    uses fraudulent accounts, bulk subscriptions, and a gray market of 'transfer station'
    proxies to automate the extraction of billions of tokens while evading geographic
    and usage-based detection.
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


# Industrial-Scale AI Model Distillation and Extraction

China-based AI companies use industrial-scale knowledge distillation to bridge the gap between their models and US frontier models. This hunt identifies the infrastructure and behaviors of these campaigns by detecting the bulk procurement of shared premium subscriptions, the use of transfer station proxies to bypass geographic restrictions, and the exfiltration of billions of tokens via targeted API access. The hunt follows a phased flow, first confirming access and proxy anomalies before investigating execution and exfiltration signals.

## scope-distillation-infrastructure
<!-- Identify interaction with distillation domains -->
Find hosts resolving domains associated with the infrastructure used for distillation campaigns.

```sqlite target=endpoint role=scoping params=(ai_distillation_domains=ai_distillation_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts communicating with distillation domains. Silence suggests
  no direct interaction with known Chinese AI provider infrastructure.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE instr(',' || '{{ai_distillation_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## early-stage-investigation
<!-- Investigate Access and Proxy Patterns -->
parallel:
- → shared-subscription-anomalies
- → proxy-transfer-station-activity
join: → triage-access-and-proxies

## shared-subscription-anomalies
<!-- Bulk premium subscription sharing -->
Detect multiple unique user identities authenticating from the same source IP, characteristic of bulk procurement.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, min_shared_users=min_shared_users)
~~~yaml
baseline:
  compare: prior_equal_window
  window: '{{lookback_days}}d'
expected: Source IPs hosting many distinct users. This reflects the shared premium
  subscription tactic to reduce extraction costs.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) as user_count, GROUP_CONCAT(DISTINCT actor_user_name) as users FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING user_count >= {{min_shared_users}} ORDER BY user_count DESC
```

## proxy-transfer-station-activity
<!-- Transfer station proxy activity -->
Identify high-frequency outbound connections to non-standard ports, excluding internal traffic to identify transfer stations.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts generating massive connection volumes to non-standard remote ports.
  These are likely the transfer stations bypassing geo-restrictions.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as connection_count FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND dst_endpoint_port NOT IN (80, 443, 8080) AND direction = 'outbound' AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '192.168.%' OR (dst_endpoint_ip >= '172.16' AND dst_endpoint_ip < '172.32')) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port HAVING connection_count > 100 ORDER BY connection_count DESC
```

## triage-access-and-proxies
<!-- Triage early-stage anomalies -->
```agent target=hunter
cite: required
context:
- scope-distillation-infrastructure
- shared-subscription-anomalies
- proxy-transfer-station-activity
max_iterations: 3
objective: Evaluate whether the shared accounts and transfer station proxies identify
  automated distillation activity.
success_criteria: Verdicts citing specific IPs and accounts characteristic of the
  adversary lifecycle.
tools:
- endpoint
- identity
- network
- web
```

## follow-on-investigation
<!-- Investigate Execution and Exfiltration -->
parallel:
- → model-extraction-endpoints
- → high-volume-exfiltration
join: → evaluate-industrial-campaign

## model-extraction-endpoints
<!-- High-frequency API endpoint access -->
Detect systematic access to specific API paths like completions or embeddings, indicating automated distillation.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, min_request_count=min_request_count)
~~~yaml
expected: High-frequency request patterns targeting model reasoning endpoints. Silence
  may mean traffic is encrypted or the analyst should verify TLS inspection.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) as hit_count FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/v1/chat/completions%' OR LOWER(url_path) LIKE '%/v1/embeddings%' OR LOWER(url_path) LIKE '%/v1/completions%' OR LOWER(url_path) LIKE '%/v1/models%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path HAVING hit_count > {{min_request_count}}
```

## high-volume-exfiltration
<!-- Industrial-scale throughput detection -->
Identify massive byte transfers and request volumes per host or user, confirming the industrial scale of extraction.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, volume_threshold_bytes=volume_threshold_bytes, min_request_count=min_request_count)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Users or hosts exceeding both byte and request thresholds. This confirms
  the 'millions of requests' behavior reported in the advisory.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - url_hostname
  rare_below: 3
reads:
- device_hostname
- actor_user_name
- url_hostname
- response_bytes
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, url_hostname, SUM(response_bytes) as total_bytes, COUNT(*) as request_count FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, url_hostname HAVING total_bytes > {{volume_threshold_bytes}} AND request_count >= {{min_request_count}} ORDER BY total_bytes DESC
```

## evaluate-industrial-campaign
<!-- Analyze distillation campaign -->
```agent target=hunter
cite: required
context:
- triage-access-and-proxies
- model-extraction-endpoints
- high-volume-exfiltration
max_iterations: 5
objective: Determine if the combined access patterns, endpoint frequency, and volume
  confirm an industrial-scale distillation campaign.
success_criteria: A detailed verdict citing the volume, account fraud, and proxy usage
  per host.
tools:
- endpoint
- identity
- network
- web
```

## verdict-on-distillation
<!-- Verdict on distillation activity -->
if~: "the agent evaluation identifies hosts or accounts engaged in systematic model distillation with high confidence" (confidence: high, judge=hunter)
then: → revoke-account-access
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: no-tls-inspection)
else: → close-out-report

## revoke-account-access
<!-- Revoke malicious account access -->
```action target=identity
~~~yaml
approval: required
~~~
Suspend the identified user accounts and revoke all active API tokens. Isolate the identified source hosts from the corporate network.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst forensic validation -->
```manual target=analyst
Validate findings and confirm the presence of systematic model distillation. Specifically verify whether TLS inspection coverage is sufficient for HTTP surface visibility, as missing inspection is the primary reason the HTTP queries might return no data.
```
→ close-out-report

## close-out-report
<!-- Hunt close out -->
```manual target=analyst
Summarize the volume of data exfiltrated and the number of accounts compromised. Promote the high-frequency API endpoint query to a standing detection rule.
```
→ end

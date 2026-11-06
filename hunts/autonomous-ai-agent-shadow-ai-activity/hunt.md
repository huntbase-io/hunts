---
analysis: A single rule might fire on a Tor connection, but this hunt correlates vulnerability
  state, proxy sign-ins, and machine-speed API counts across three different telemetry
  surfaces to detect novel 'synthetic insider' patterns.
blind_spots:
- id: cloud-api-latency
  question: How quickly can we see the machine-speed actions of an AI agent?
  requires: Real-time API auditing
  risk: Cloud logging latency (e.g., CloudTrail) may allow an agent to finish exfiltrating
    data before the hunt can observe the velocity spikes.
  stage: execution-synthetic-insiders
- id: tls-encryption
  question: What content was in the request body to the AI provider?
  requires: Endpoint TLS decryption or HTTP inspection
  risk: Without TLS decryption, the hunt can see the destination and the size of the
    upload but cannot confirm the classification of the data.
  stage: exfiltration-shadow-ai-prompts
coverage:
- stage: initial-access-ai-assisted-exploitation
  status: covered
  steps:
  - vulnerable-hosts
  - proxy-sign-ins
- stage: defense-evasion-anonymization
  status: covered
  steps:
  - tor-gateway-dns
- stage: execution-synthetic-insiders
  status: covered
  steps:
  - superhuman-api-velocity
- stage: exfiltration-shadow-ai-prompts
  status: covered
  steps:
  - shadow-ai-http-traffic
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI agents move data far faster than humans, rendering traditional
    manual monitoring ineffective; a negative result ensures that autonomous exfiltration
    is not occurring under the guise of AI productivity.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using AI-assisted exploitation or fraudulent identity
  onboarding to gain initial access, followed by the deployment of automated synthetic
  insiders that move data to unauthorized LLM providers at machine speed.
labels:
- hunt
- attack.t1190
- attack.t1090.003
- attack.t1071.001
- defense evasion
- execution
- exfiltration
- initial access
name: Autonomous AI Agent and Shadow AI Activity
parameters:
  ai_domains:
    default:
    - api.openai.com
    - chatgpt.com
    - anthropic.com
    - claude.ai
    - gemini.google.com
    - perplexity.ai
    description: Domains of third-party AI/LLM providers to monitor for shadow AI
      activity.
    from:
      kind: article
      observed: '2026-10-12'
      ref: proofpoint-ai-risks
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_gateways:
    default:
    - tor2web.org
    - tor2web.info
    - onion.pet
    - onion.dog
    - onion.ws
    description: Known Tor-to-web gateways used to anonymize traffic.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: common-tor-gateways
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to hunt across the entire
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/hidden-ai-security-risks-threatening-businesses
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Begin with internet-facing systems reporting critical vulnerabilities.
  The velocity query is most effective in cloud control-plane environments where automated
  agents reside.
references:
- name: "Proofpoint \u2014 The Hidden AI Security Risks Threatening Businesses"
  url: https://www.proofpoint.com/us/newsroom/news/hidden-ai-security-risks-threatening-businesses
related:
- hunt: prompt-injection-reconnaissance
  reason: This hunt focuses on the behavioral footprint of AI agents, not the prompt
    injection techniques used to manipulate them.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Accelerated Initial Access
    observables:
    - Exploitation of public-facing web applications or hypervisors
    - Signs of identity fraud in sign-in events using AI-generated media
    - Onboarding of fraudulent 'fake candidates' with legitimate internal access
    slug: initial-access-ai-assisted-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Multi-hop Proxy Anonymization
    observables:
    - Network connections routed through chained proxies or Tor-gateways
    - DNS lookups for .onion domains or known tor-to-web services
    - Traffic masking origin of automated AI reconnaissance tools
    slug: defense-evasion-anonymization
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: AI Agent Post-Breach Activity
    observables:
    - Autonomous AI agents executing system actions without human approval
    - API activity from LLM integration keys moving data at superhuman velocity
    - Synthetic insiders behaving like legitimate users but with excessive permissions
    slug: execution-synthetic-insiders
    tactic: execution
  - name: Exfiltration via Shadow AI
    observables:
    - HTTP requests to unauthorized LLM providers (api.openai.com, anthropic.com)
    - Pasting sensitive IP or PII into unapproved chat-based AI domains
    - Large data uploads to unmonitored third-party AI infrastructure
    slug: exfiltration-shadow-ai-prompts
    tactic: exfiltration
  summary: Adversaries leverage AI-accelerated zero-day exploitation and automated
    hiring fraud to secure legitimate access to corporate environments. Once inside,
    they deploy autonomous AI agents as 'synthetic insiders' to move data at machine
    speed, exfiltrating sensitive intellectual property through unapproved shadow
    AI tools and LLM prompts over multi-hop proxy infrastructure.
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


# Autonomous AI Agent and Shadow AI Activity

This hunt identifies the emergence of synthetic insiders and shadow AI usage. It follows a phased approach: first scoping internet-facing vulnerabilities and identifying multi-hop proxy evasion or proxy-based sign-ins. The second phase pivots to detect superhuman API velocity and data movement to unauthorized AI platforms. An agentic triage correlates early access indicators with behavioral exfiltration patterns to identify autonomous threats.

## vulnerable-hosts
<!-- Identify vulnerable internet-facing assets -->
Scope the hunt to devices with high or critical vulnerabilities that are susceptible to initial access exploits.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of device UIDs and associated high-severity vulnerabilities. This
  step provides the context of exposure for the estate.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- severity_id
- status
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, title FROM hb_vulnerability_finding WHERE severity_id >= 4 AND status != 'suppressed' ORDER BY severity_id DESC
```

## access-evasion-fan-out
<!-- Check for evasion and access anomalies -->
parallel:
- → tor-gateway-dns
- → proxy-sign-ins
join: → early-stage-triage

## tor-gateway-dns
<!-- DNS lookups for Tor-to-web gateways -->
Identify hosts using gateways to mask their connection to dark web resources or C2 infrastructure.

```sqlite target=endpoint role=baseline params=(proxy_gateways=proxy_gateways, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare DNS queries for gateways like onion.pet. Silence proves no gateways
  were resolved during the window.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- actor_user_name
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, query_hostname, process_name, COUNT(*) as lookup_count FROM hb_dns_activity WHERE (instr(',' || '{{proxy_gateways}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, query_hostname, process_name
```

## proxy-sign-ins
<!-- Proxy-based sign-in anomalies -->
Identify users logging in via known anonymizers, suggesting bypass of location-based controls or identity fraud.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Successful logons where is_proxy is true. This marks potentially fraudulent
  identities or sessions.
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- device_hostname
- is_proxy
- status
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, device_hostname, is_proxy, status FROM hb_auth_signin WHERE is_proxy = 'true' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Evaluate access risk -->
```agent target=hunter
cite: required
context:
- vulnerable-hosts
- tor-gateway-dns
- proxy-sign-ins
max_iterations: 3
objective: Determine if vulnerabilities and proxy usage indicate a legitimate security
  incident or identity risk.
success_criteria: A per-host verdict of suspicious | benign citing specific vulnerabilities
  or proxy logons.
tools:
- endpoint
- identity
- web
```

## follow-on-fan-out
<!-- Hunt for synthetic insider activity -->
parallel:
- → superhuman-api-velocity
- → shadow-ai-http-traffic
join: → follow-on-triage

## superhuman-api-velocity
<!-- Superhuman API activity velocity -->
Find principals executing operations at a frequency that suggests automated AI agents rather than human users.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Users with hundreds of API calls in a single hour, indicating an automated
  synthetic insider.
reads:
- actor_user_name
- api_operation
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT actor_user_name, api_operation, strftime('%Y-%m-%d %H', time) AS hour, COUNT(*) as op_count FROM hb_cloud_api_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation, hour HAVING op_count > 500 ORDER BY op_count DESC
```

## shadow-ai-http-traffic
<!-- Shadow AI HTTP traffic -->
Identify large data transfers to unauthorized third-party LLM providers.

```sqlite target=web role=enrichment params=(ai_domains=ai_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating significant uploads to OpenAI or Anthropic endpoints. Silence
  suggests no traffic to these specific domains.
reads:
- device_hostname
- actor_user_name
- url_hostname
- url_path
- http_method
- request_body_len
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-16'
~~~
SELECT device_hostname, actor_user_name, url_hostname, url_path, http_method, request_body_len FROM hb_http_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY request_body_len DESC
```

## follow-on-triage
<!-- Final behavioral triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- superhuman-api-velocity
- shadow-ai-http-traffic
max_iterations: 6
objective: Determine if the identified principals are behaving as automated malicious
  agents and if exfiltration to AI providers has occurred.
success_criteria: A verdict of malicious for principals that exhibit both anomalous
  access and automated behavioral patterns.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host or principal" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-api-latency)
else: → close-out

## isolate-and-revoke
<!-- Isolate host and revoke credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke all active cloud sessions and keys for the identified principal.
```
→ analyst-review

## analyst-review
<!-- Analyst review and confirmation -->
```manual target=analyst
Examine the specific request bodies and API operations. Determine if the uploads contained PII or intellectual property.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the incident and notify the data protection officer. If activity was legitimate, add the principal to the exclusion list for velocity monitoring.
```
→ end

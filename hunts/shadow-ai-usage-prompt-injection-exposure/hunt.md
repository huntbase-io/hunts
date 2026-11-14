---
analysis: A rule flags AI domains; the hunt pivots to file activity within a narrow
  temporal window to prove intent, and evaluates the external exposure that standard
  internal rules miss.
blind_spots:
- id: no-tls-visibility
  owner: Network Engineering
  question: What specific text was included in the AI prompts?
  remediation: Enable TLS decryption for AI endpoints.
  requires: TLS inspection or endpoint proxy logs
  risk: Without TLS decryption, we see the connection but cannot confirm the presence
    of sensitive text in the prompts.
  stage: exfiltration-shadow-ai-usage
- id: no-clipboard-logs
  owner: Security Operations
  question: Did the user copy-paste content from the file into the browser?
  remediation: Deploy endpoint monitoring that captures clipboard events.
  requires: EDR with clipboard telemetry
  risk: We rely on temporal proximity; without clipboard logs, we cannot definitively
    prove data movement.
  stage: collection-sensitive-file-access
coverage:
- stage: initial-access-prompt-injection
  status: covered
  steps:
  - external-ai-exposure
- stage: collection-sensitive-file-access
  status: covered
  steps:
  - sensitive-file-activity
- stage: exfiltration-shadow-ai-usage
  status: covered
  steps:
  - personal-ai-access
  - network-data-volume
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: 43% of workers lack AI training and 25% admit they would use personal
    accounts for sensitive contracts; this hunt secures IP and mitigates the external
    attack surface.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Employees are bypassing corporate AI controls by using personal accounts
  to process sensitive documents, or external attackers are exploiting public-facing
  AI applications to extract internal data.
labels:
- hunt
- attack.t1190
- attack.t1566
- collection
- exfiltration
- initial access
name: Shadow AI Usage and Prompt Injection Exposure
parameters:
  ai_access_timestamp:
    default: '2026-10-02T12:00:00Z'
    description: The UTC timestamp from the lead query result to center the file-activity
      window.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine for AI usage and file access.
    type: number
  personal_ai_domains:
    default:
    - chatgpt.com
    - claude.ai
    - gemini.google.com
    - openai.com
    - anthropic.com
    description: Domains associated with personal-tier AI services.
    from:
      kind: article
      observed: '2026-10-02'
      ref: https://www.huntress.com/blog/llm-security-report
    type: list[domain]
  personal_ai_ips:
    default:
    - 104.18.37.228
    - 172.64.150.31
    description: Observed IP addresses for personal AI services to verify data volume.
    from:
      kind: article
      observed: '2026-10-02'
      ref: https://www.huntress.com/blog/llm-security-report
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt, populated from the lead
      results.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/llm-security-report
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Identify exposed AI assets in the first step to establish the organization's
  external attack surface. The analyst then uses findings from the shadow AI lead
  to populate the time window and host parameters for the deeper file-level investigation.
references:
- name: "Huntress \u2014 Companies Push AI Use But Skip Training and Official Policy"
  url: https://www.huntress.com/blog/llm-security-report
related:
- hunt: dlp-sensitive-keyword-exfiltration
  reason: Broader exfiltration hunts cover more targets; this is tuned for AI platforms.
  relation: sibling
scenario:
  stages:
  - name: Prompt Injection against Public-Facing Chatbots
    observables:
    - public-facing AI chatbot
    - malicious instructions slipped into prompts
    - manipulated chatbot responses
    - credential leakage via AI interface
    slug: initial-access-prompt-injection
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized Processing of Sensitive Documents
    observables:
    - copying client contracts
    - client contract summary generation
    - accessing sensitive information for AI processing
    slug: collection-sensitive-file-access
    tactic: collection
  - name: Data Exfiltration via Personal AI Accounts
    observables:
    - personal ChatGPT account usage
    - personal Claude account usage
    - chatgpt.com
    - claude.ai
    - gemini.google.com
    - uploading data to non-enterprise AI vendors
    slug: exfiltration-shadow-ai-usage
    tactic: exfiltration
  summary: 'This analysis identifies two primary AI-related threat vectors: prompt
    injection attacks against public-facing corporate chatbots used to leak credentials
    or sensitive data, and the exfiltration of sensitive information by employees
    using personal AI accounts without authorization. A lack of formal policy and
    training leaves organizations vulnerable to both external exploitation and internal
    data leakage via personal accounts.'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Shadow AI Usage and Prompt Injection Exposure

The hunt identifies exposed AI assets and detects internal traffic to personal AI platforms. It gates the deeper investigation on initial AI traffic to focus on high-risk hosts where an analyst must confirm whether sensitive files were moved to personal accounts. By separating external prompt-injection threats from internal shadow AI usage, the hunt ensures a focused response to both risk vectors.

## external-ai-exposure
<!-- Establish external AI attack surface -->
Identify public-facing AI applications that attackers might target for prompt injection.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of IP addresses or domains hosting AI-related software exposed to
  the internet.
reads:
- domain_or_ip
- asset_type
- product
- discovered_at
silence: evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT domain_or_ip, asset_type, product, port, discovered_at FROM hb_exposed_assets WHERE (LOWER(product) LIKE '%ai%' OR LOWER(product) LIKE '%llama%' OR LOWER(product) LIKE '%gpt%' OR LOWER(product) LIKE '%chat%' OR LOWER(product) LIKE '%notebook%' OR LOWER(product) LIKE '%langchain%')
```

## personal-ai-access
<!-- Lead: Detect personal AI platform usage -->
Find internal hosts accessing personal AI domains that lack enterprise data protections.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, personal_ai_domains=personal_ai_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Users and hosts accessing personal AI tools. Silence indicates absence of
  traffic to these domains.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 5
reads:
- device_hostname
- actor_user_name
- url_hostname
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, actor_user_name, url_hostname, COUNT(*) as request_count, MIN(time) as first_access, MAX(time) as last_access FROM hb_http_activity WHERE (instr(',' || '{{personal_ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, url_hostname
```

## evaluate-ai-lead
<!-- Evaluate AI lead -->
```agent target=hunter
cite: required
context:
- personal-ai-access
max_iterations: 3
objective: Determine if the HTTP activity in personal-ai-access indicates probable
  personal account usage.
success_criteria: A per-host verdict of personal-usage or benign.
tools:
- endpoint
- network
- web
```

## gate-on-lead
<!-- Gate: Confirm personal usage -->
if~: "the evaluate-ai-lead verdict identifies personal-usage for at least one host" (confidence: high, judge=hunter)
then: → investigate-risk-context
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: no-tls-visibility)
else: → hunt-close-out

## investigate-risk-context
<!-- Investigate context -->
parallel:
- → sensitive-file-activity
- → network-data-volume
join: → triage-ai-risk

## sensitive-file-activity
<!-- Correlate sensitive document access -->
Identify if hosts accessing personal AI were touching sensitive files within a one-hour window of the access.

```sqlite target=endpoint role=enrichment params=(ai_access_timestamp=ai_access_timestamp, scope_hosts=scope_hosts)
~~~yaml
expected: File touch events on sensitive documents occurring near the time of AI platform
  access.
reads:
- device_hostname
- actor_user_name
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, actor_user_name, file_name, file_path, time FROM hb_file_activity WHERE (LOWER(file_name) LIKE '%contract%' OR LOWER(file_name) LIKE '%confidential%' OR LOWER(file_name) LIKE '%salary%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time BETWEEN datetime('{{ai_access_timestamp}}', '-1 hour') AND datetime('{{ai_access_timestamp}}', '+1 hour')
```

## network-data-volume
<!-- Verify data exfiltration volume -->
Examine network traffic to AI IPs to find large data uploads that confirm document exfiltration.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, personal_ai_ips=personal_ai_ips, scope_hosts=scope_hosts)
~~~yaml
expected: High total_bytes counts to known AI infrastructure indicating potential
  file uploads.
reads:
- device_hostname
- dst_endpoint_ip
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes, MIN(time) as start_time FROM hb_network_connection WHERE (instr(',' || '{{personal_ai_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip
```

## triage-ai-risk
<!-- Triage AI risks -->
```agent target=hunter
cite: required
context:
- evaluate-ai-lead
- sensitive-file-activity
- network-data-volume
- external-ai-exposure
max_iterations: 6
objective: Determine if any host shows sensitive file access immediately preceding
  personal AI usage with significant traffic volume.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on risk verdict -->
if~: "the triage-ai-risk verdict identifies malicious data exfiltration for at least one host" (confidence: high, judge=hunter)
then: → isolate-suspect-host
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: no-clipboard-logs)
else: → analyst-remediation

## isolate-suspect-host
<!-- Isolate suspect host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Preserve browser cache and local history to reconstruct AI prompts.
```
→ analyst-remediation

## analyst-remediation
<!-- Analyst remediation -->
```manual target=analyst
Check exposed assets from Step 1 for configuration weaknesses. Verify if users in Step 2 violated data handling policies.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the number of identified shadow AI users. Provide the list of exposed assets to the firewall team.
```
→ end

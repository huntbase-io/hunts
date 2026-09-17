---
analysis: 'This is a hunt because it correlates behavior across three surfaces: container-based
  scoping, distributed identity anomalies, and bursty HTTP request baselining. A single
  rule may catch one burst, but only a hunt can confirm the agentic cycle of failure-to-success
  transitions combined with rare identity-host mappings.'
blind_spots:
- id: no-http-telemetry
  owner: Network Engineering
  question: Which specific AI models were invoked and what were the request payloads?
  remediation: Enable VPC flow logs or forward proxy logging for all known AI API
    endpoints.
  requires: hb_http_activity with full outbound visibility
  risk: Without HTTP telemetry, the hunt relies on authentication data alone, which
    may miss resource abuse if an identity used existing sessions.
  stage: ai-infrastructure-hijacking
coverage:
- stage: ai-infrastructure-hijacking
  status: covered
  steps:
  - scope-docker-development-hosts
  - distributed-cloud-authentications
  - rare-ai-invocation-baseline
  - auth-state-transition-summary
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: initial-access-web-breach
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: internal-service-mapping
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: code-repo-secrets-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: secrets-manager-infiltration
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: pipeline-exploitation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Agentic attacks compress intrusion timelines into hours. Detecting
    the abuse of cloud AI infrastructure is critical for preventing financial loss
    and securing core AI model contexts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked cloud AI credentials and is running automated
  agentic loops, resulting in bursty authentication patterns and anomalous model invocation
  traffic from hijacked developer identities.
labels:
- hunt
- attack.t1078
- attack.t0043
name: Cloud AI Resource Hijacking and Agentic Loops
parameters:
  ai_api_domains:
    default:
    - api.openai.com
    - bedrock-runtime.us-east-1.amazonaws.com
    - bedrock-runtime.us-west-2.amazonaws.com
    - anthropic.com
    - api.anthropic.com
    - openai.azure.com
    - vertexai.googleapis.com
    description: Known cloud AI model invocation endpoints.
    from:
      kind: article
      observed: '2024-05-20'
      ref: unit42-ai-attack
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard-lookback
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize development hosts running Docker as they are the primary candidates
  for hosting automated agentic loops. Focus on the last 14 days to capture the rapid
  attack window.
references:
- name: "Unit 42 \u2014 An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation"
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: code-repo-secrets-harvesting
  reason: The keys used for AI hijacking are typically harvested during earlier repository
    scraping phases.
  relation: precedes
- hunt: automated-secret-harvesting-pipeline-abuse
  relation: follows
scenario:
  stages:
  - name: Infiltration via Web Service Breach
    observables:
    - Publicly accessible web service breach
    - Tunnelling into the network
    - Rapid 401/200 HTTP state shifts
    slug: initial-access-web-breach
    tactic: initial-access
    techniques:
    - T1190
    - T0000
  - name: Automated Service Discovery
    observables:
    - Automated recon agent
    - Mapping of internal microservices
    - Service discovery tool output parsing
    - Parallel LLM calls to agents
    slug: internal-service-mapping
    tactic: discovery
    techniques:
    - T1046
    - T0002
  - name: Code Scraping for Secrets
    observables:
    - Combing enterprise code repositories
    - Extraction of hard-coded tokens
    - Service passwords
    - Structured Markdown files for info sharing
    - Python caches
    - Paired asset folders
    slug: code-repo-secrets-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
    - T0014
  - name: Privilege Takeover via Secrets Manager
    observables:
    - Infiltrating secrets management system
    - Harvesting master administrative credentials
    - Root system access seizure
    - Automated pivot via agent loop
    slug: secrets-manager-infiltration
    tactic: privilege-escalation
    techniques:
    - T1555
    - T0016
  - name: CI/CD Pipeline Hijacking
    observables:
    - Unauthorized CI/CD builds
    - Custom workflows for exfiltration
    - Attempted backdoors in Terraform configurations
    - Bursty API requests to CI/CD endpoints
    slug: pipeline-exploitation
    tactic: execution
    techniques:
    - T1578
    - T0010
  - name: AI Infrastructure Resource Abuse
    observables:
    - Invoking cloud AI models via stolen keys
    - Hijacking compute power for future operations
    - Sudden model usage from unexpected identities
    - Orchestration traffic hidden in expected model traffic
    slug: ai-infrastructure-hijacking
    tactic: impact
    techniques:
    - T1078
    - T0043
  summary: A threat actor utilized autonomous AI agents to execute a rapid 10-hour
    campaign, transitioning from an initial web service breach to full cloud infrastructure
    hijacking. The agents methodically discovered internal microservices, harvested
    secrets from code repositories, and seized administrative credentials from a secrets
    management system. The attack concluded with the exploitation of CI/CD pipelines
    and the co-opting of enterprise AI compute resources for post-compromise activity.
series:
  index: 3
  slug: an-ai-assisted-cyber-attack-inside-a-unit-42-investigation
  title: 'An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation'
  total: 3
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


# Cloud AI Resource Hijacking and Agentic Loops

This hunt targets the final impact phase of an agentic attack where stolen API keys or credentials are used to abuse cloud AI infrastructure. It focuses on identifying 'bursty' authentication attempts, rapid transitions between unauthorized and successful states (flapping) that indicate credential testing or token refresh by an agent, and rare model invocation patterns. By scoping the hunt to Docker-enabled development environments, we isolate the telemetry to the systems most likely to host malicious agentic orchestration.

## scope-docker-development-hosts
<!-- Scope Docker Development Infrastructure -->
Identify hosts running Docker, as the research highlights the use of automated AI agents within containerized development processes and CI/CD pipelines.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or CI/CD nodes that could host
  malicious agentic loops.
reads:
- device_hostname
- package_name
- package_version
- provider
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, provider FROM hb_software_inventory WHERE (LOWER(package_name) = 'docker' OR LOWER(package_name) LIKE 'docker-%') AND asset_scope = 'endpoint'
```

## investigate-agentic-activity
<!-- Investigate Agentic Activity -->
parallel:
- → distributed-cloud-authentications
- → rare-ai-invocation-baseline
- → auth-state-transition-summary
join: → agent-triage

## distributed-cloud-authentications
<!-- Distributed Cloud Authentications -->
Find successful logins from multiple distinct source IPs for a single identity, which may indicate a distributed agent using a hijacked key.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: An identity appearing from multiple source IPs in a short window, standing
  out as an automated agent loop.
reads:
- actor_user_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT actor_user_name, COUNT(DISTINCT src_endpoint_ip) AS unique_ips, COUNT(*) AS auth_count, MIN(time) AS first_login, MAX(time) AS last_login FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name HAVING unique_ips > 1 AND auth_count > 5 ORDER BY unique_ips DESC
```

## rare-ai-invocation-baseline
<!-- Rare AI Model Invocations -->
Stack-count identities hitting cloud AI endpoints to find those making anomalous volumes of requests or accessing rare providers.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, ai_api_domains=ai_api_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single identity generating massive request volumes to AI endpoints from
  specific hostnames.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  rare_below: 3
reads:
- url_hostname
- actor_user_name
- time
- device_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT actor_user_name, url_hostname, COUNT(*) AS request_count, COUNT(DISTINCT device_hostname) AS device_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (instr(',' || '{{ai_api_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, url_hostname HAVING request_count > 10 ORDER BY request_count DESC
```

## auth-state-transition-summary
<!-- Authentication State Transition Summary -->
Detect identities experiencing both 401 (unauthorized) and 200 (success) codes on the same AI endpoint, which is a faster alternative to self-joins for finding flapping/testing behavior.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, ai_api_domains=ai_api_domains)
~~~yaml
expected: Identities that show evidence of failed authentication attempts followed
  by success, suggesting credential reuse or automated token management.
reads:
- actor_user_name
- device_hostname
- url_hostname
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT actor_user_name, device_hostname, url_hostname, SUM(CASE WHEN status_code = 401 THEN 1 ELSE 0 END) AS count_401, SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) AS count_200, MIN(time) AS first_attempt, MAX(time) AS last_attempt FROM hb_http_activity WHERE (instr(',' || '{{ai_api_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND status_code IN (200, 401) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname, url_hostname HAVING count_401 > 0 AND count_200 > 0 ORDER BY count_401 DESC
```

## agent-triage
<!-- Triage AI Resource Abuse -->
```agent target=hunter
cite: required
context:
- scope-docker-development-hosts
- distributed-cloud-authentications
- rare-ai-invocation-baseline
- auth-state-transition-summary
max_iterations: 4
objective: Determine if the combined evidence of parallel authentications and bursty
  AI API requests from the scoped Docker hosts indicate credential hijacking and automated
  agent loops.
success_criteria: A 'Malicious' or 'Suspicious' verdict for identities that appear
  in the HTTP/Auth steps AND originate from or target the Docker host list.
tools:
- endpoint
- identity
- web
```

## verdict-decision
<!-- Verdict Decision -->
if~: "the triage verdict is malicious for at least one identity" (confidence: high, judge=hunter)
then: → revoke-identity-sessions
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-http-telemetry)
else: → close-out

## revoke-identity-sessions
<!-- Revoke Identity Sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the compromised identities and rotate cloud-based AI API keys.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the full history of the identified identities across hb_auth_signin and hb_http_activity. Trace back to the first anomalous login to find the credential leak source.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document that the hunt found no evidence of agentic resource abuse in the development environment.
```
→ end

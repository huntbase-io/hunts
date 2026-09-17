---
analysis: A single rule for 401/200 shifts produces many false positives from misconfigured
  apps. This hunt pivots to network discovery and AI control traffic (DNS) to confirm
  the 'agent' behavior, turning a noise signal into a high-confidence lead.
blind_spots:
- id: http-log-retention
  question: whether the high-volume shifts occurred outside the 14-day window
  requires: long-term retention of full HTTP activity logs
  risk: Attackers compress intrusion into 10 hours; if telemetry is purged quickly,
    the signal is lost.
  stage: initial-access-web-breach
- id: internal-tls-visibility
  question: what microservice endpoints were actually queried internally
  requires: mTLS or internal decryption proxy
  risk: We see the network connection, but cannot see if the agent was successful
    in mapping specific microservice functions.
  stage: internal-service-mapping
coverage:
- stage: initial-access-web-breach
  status: covered
  steps:
  - vulnerable-web-services-scope
  - rapid-http-auth-shifts
- stage: internal-service-mapping
  status: covered
  steps:
  - internal-microservice-discovery-baseline
  - agent-orchestration-dns
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
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: ai-infrastructure-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The rise of agentic AI frameworks allows attackers to move with extreme
    speed, bypassing traditional manual triage wait times. Detecting these behavioral
    loops (rapid state shifts + parallel discovery) is the only way to catch an automated
    intruder before they move to credential harvesting.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using autonomous AI agents to compress initial access
  and discovery into a sub-10-hour window, evidenced by rapid HTTP authentication
  state shifts and bursty, parallel internal microservice mapping.
labels:
- hunt
- attack.t1190
- attack.t1046
- attack.t1078
- attack.t1578
name: AI-Agent Orchestrated Perimeter Breach and Mapping
parameters:
  ai_model_domains:
    default:
    - api.openai.com
    - api.anthropic.com
    - api.cohere.ai
    - api.groq.com
    - api.mistral.ai
    - api.perplexity.ai
    description: Known frontier AI model API endpoints used by agents for orchestration.
    from:
      kind: article
      observed: '2026-09-02'
      ref: unit42-ai-attack
    type: list[domain]
  lookback_days:
    default: '14'
    description: Number of days of telemetry to examine.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: standard-lookback
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on perimeter-facing web services. If the estate has segmented
  microservices, the baseline for discovery should exclude known service-mesh traffic
  (e.g., Istio/Linkerd).
references:
- name: 'An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation'
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: code-repo-secrets-harvesting
  reason: Once the beachhead is established and microservices mapped, the agent moves
    to scanning code repositories.
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
  index: 1
  slug: an-ai-assisted-cyber-attack-inside-a-unit-42-investigation
  title: 'An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation'
  total: 3
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


# AI-Agent Orchestrated Perimeter Breach and Mapping

This hunt identifies the 'front-end' of an agentic AI attack. Unlike human operators who may dwell for days, AI agents perform methodical recon and exploitation in parallel loops. We look for the technical signatures of this automation: high-velocity HTTP status transitions (401 to 200) indicative of automated credential stuffing or bypass, followed immediately by bursty internal network discovery and orchestration traffic to frontier AI model endpoints (LLM APIs). The hunt corroborates web-tier anomalies with internal lateral discovery patterns to identify the breach point.

## vulnerable-web-services-scope
<!-- Identify Vulnerable External Facing Assets -->
Scope the hunt to hosts with known web vulnerabilities or web-server software that are the likely targets for initial breach (T1190).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames or resource IDs running potentially exploitable web
  services. If empty, the scope expands to all internal web servers.
reads:
- resource_uid
- cve_uid
- severity
- affected_package_name
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT resource_uid, cve_uid, severity, affected_package_name FROM hb_vulnerability_finding WHERE (LOWER(affected_package_name) LIKE '%apache%' OR LOWER(affected_package_name) LIKE '%nginx%' OR LOWER(affected_package_name) LIKE '%http%') AND status != 'suppressed' AND severity_id >= 3
```

## rapid-http-auth-shifts
<!-- Detect Rapid 401 to 200 HTTP State Shifts -->
Find the AI-agent signature of bursty auth attempts followed by success on a single host.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Source IPs that fail authentication multiple times but eventually succeed
  within an hour. Silence suggests no automated auth-bypass/brute-force occurred.
reads:
- src_endpoint_ip
- device_hostname
- url_hostname
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT src_endpoint_ip, device_hostname, url_hostname, COUNT(CASE WHEN status_code = 401 THEN 1 END) as auth_failures, COUNT(CASE WHEN status_code = 200 THEN 1 END) as auth_successes, MIN(time) as first_attempt, MAX(time) as last_attempt FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname, url_hostname HAVING auth_failures > 5 AND auth_successes > 0 AND (strftime('%s', MAX(time)) - strftime('%s', MIN(time))) < 3600 ORDER BY auth_failures DESC
```

## parallel-corroboration
<!-- Corroborate Discovery and Orchestration -->
parallel:
- → internal-microservice-discovery-baseline
- → agent-orchestration-dns
join: → triage-agent

## internal-microservice-discovery-baseline
<!-- Internal Microservice Discovery Baseline -->
Identify hosts acting as internal scanners to map the network (T1046).

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single internal host (the beachhead) connecting to many other internal
  IPs in a short window. AI agents map methodically.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT src_endpoint_ip, device_hostname, COUNT(DISTINCT dst_endpoint_ip) as distinct_internal_targets, COUNT(DISTINCT dst_endpoint_port) as distinct_ports, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname HAVING distinct_internal_targets > 10 ORDER BY distinct_internal_targets DESC
```

## agent-orchestration-dns
<!-- DNS to AI Model Orchestration Endpoints -->
Verify if suspected hosts are communicating with AI model providers, which the report cites as a primary orchestration method.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, ai_model_domains=ai_model_domains)
~~~yaml
expected: Hosts in the same timeframe as the HTTP/Network anomalies that are also
  calling AI model APIs. This suggests agentic orchestration.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE instr(',' || '{{ai_model_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname ORDER BY lookup_count DESC
```

## triage-agent
<!-- Triage AI-Agent Indicators -->
```agent target=hunter
cite: required
context:
- rapid-http-auth-shifts
- internal-microservice-discovery-baseline
- agent-orchestration-dns
max_iterations: 3
objective: Determine if the rapid sequence of HTTP auth shifts followed by internal
  microservice discovery and DNS calls to AI providers indicates an autonomous agentic
  attack.
success_criteria: A per-host verdict (malicious, suspicious, benign) with cited rows
  for the breach timing and discovery volume.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is 'malicious' for any host involved in discovery and LLM calls." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: http-log-retention)
else: → close-out

## isolate-compromised-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and block outbound traffic to the suspected AI model domains at the gateway.
```
→ analyst-investigation

## analyst-investigation
<!-- Review AI-Agent Activity -->
```manual target=analyst
Check hb_file_activity for '.md' or '.pyc' files created on the target host. Verify if the 401/200 shift was a successful login bypass. Prepare for the next phase: Secrets Harvesting.
```
→ end

## close-out
<!-- Close and Tune -->
```manual target=analyst
Document the absence of agentic behaviors. If 401/200 shifts were identified but benign (e.g., misconfigured load balancer), exclude those source IPs.
```
→ end

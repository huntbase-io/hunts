---
analysis: A simple rule for failed logins misses the automated adaptation of an AI
  agent. This hunt correlates rapid auth shifts with downstream infrastructure changes
  and AI resource usage, providing the full context of an agentic loop.
blind_spots:
- id: no-http-payload-visibility
  question: What specifically were the agents prompting the AI endpoints to do?
  requires: API gateway request body logging or deep packet inspection
  risk: We can see the burst of traffic but cannot distinguish between a malicious
    agent's plan and a legitimate large-scale AI-assisted refactor.
  stage: ai-infrastructure-hijacking
- id: ephemeral-runner-memory
  question: Did the agent execute scripts purely in memory on the CI/CD runner?
  requires: Endpoint telemetry on CI/CD runner nodes
  risk: File activity may miss in-memory script execution or environment variable
    scraping if the runner is ephemeral and lacks a resident agent.
  stage: cicd-pipeline-exploitation
coverage:
- stage: secrets-manager-takeover
  status: covered
  steps:
  - secrets-access-shifts
- stage: cicd-pipeline-exploitation
  status: covered
  steps:
  - pipeline-tamper-check
- stage: ai-infrastructure-hijacking
  status: covered
  steps:
  - ai-endpoint-usage-burst
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: web-service-breach-and-mapping
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: repository-secrets-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI-assisted attacks compress weeks of work into hours, making manual
    triage ineffective; automated hunts for behavioral loops are necessary to catch
    the intrusion before root systems are compromised.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated AI agent loop is conducting high-speed privilege escalation
  via secrets managers, tampering with CI/CD configurations, and hijacking cloud AI
  endpoints for external orchestration.
labels:
- hunt
- attack.t1555
- attack.t1578
- attack.t1078
- attack.t0016
- attack.t0010
- attack.t0043
name: AI-Agentic Escalation and Infrastructure Hijacking
parameters:
  ai_endpoints:
    default:
    - api.openai.com
    - anthropic.com
    - bedrock.us-east-1.amazonaws.com
    - sagemaker.us-east-1.amazonaws.com
    - api.cohere.ai
    description: Enterprise AI service endpoints for burst detection.
    from:
      kind: article
      observed: '2026-09-02'
      ref: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
    type: list[domain]
  docker_package_pattern:
    default: '%docker%'
    description: Package name pattern to identify Docker-related infrastructure.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: Article mentions Docker as a primary product in the attack chain.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: Standard hunt window
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the scoping step; leave empty to run fleet-wide.
    from:
      kind: manual
      observed: '2026-09-02'
      ref: Analyst-populated from scoping result.
    type: list[host]
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
rationale: Focus on infrastructure hosting containerized web services and identities
  with administrative access to cloud control planes and CI/CD systems.
references:
- name: "Unit 42 \u2014 An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation"
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: web-service-breach-and-mapping
  reason: The initial infiltration and internal mapping stage precedes the credential
    escalation and pipeline hijacking found here.
  relation: follows
- hunt: automated-service-infiltration-data-harvesting
  relation: follows
scenario:
  stages:
  - name: Public Web Service Breach and Automated Recon
    observables:
    - Publicly accessible web service breach
    - Automated recon agent mapping internal microservices
    - Service discovery tool execution
    - Bursty API requests
    - Structured Markdown files for inter-agent communication
    slug: web-service-breach-and-mapping
    tactic: initial-access
    techniques:
    - T1190
    - T1046
    - T0000
    - T0002
  - name: Enterprise Repository Secrets Harvesting
    observables:
    - Code scraping across enterprise repositories
    - Extraction of hard-coded tokens and service passwords
    - Presence of Python caches and paired asset folders
    - Markdown files containing harvested metadata
    slug: repository-secrets-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
    - T0014
  - name: Secrets Manager Privilege Escalation
    observables:
    - Infiltration of secrets management system using stolen tokens
    - Harvesting of master administrative credentials
    - Parallel authentications from single identities
    - Rapid 401/200 HTTP state shifts during access attempts
    slug: secrets-manager-takeover
    tactic: privilege-escalation
    techniques:
    - T1555
    - T0016
  - name: DevOps Pipeline Hijacking
    observables:
    - Unauthorized CI/CD build triggers
    - Execution of custom workflows in code applications
    - Attempts to modify Terraform configurations
    - Exfiltration of cloud access keys via pipeline actions
    slug: cicd-pipeline-exploitation
    tactic: persistence
    techniques:
    - T1578
    - T0010
  - name: AI Infrastructure Post-Compromise Abuse
    observables:
    - LLM calls to multiple frontier AI agents in parallel
    - Invocation of cloud AI models via stolen API keys
    - Bursty model usage from unexpected identities
    - AI endpoints used as post-compromise orchestration infrastructure
    slug: ai-infrastructure-hijacking
    tactic: impact
    techniques:
    - T1078
    - T0043
  summary: An attacker used autonomous AI agents to compress weeks of intrusion tradecraft
    into a 10-hour campaign, breaching a web service to map the internal network and
    harvest secrets. The agents then escalated privileges through a secrets manager
    to hijack CI/CD pipelines and repurpose enterprise AI infrastructure for post-compromise
    operations.
series:
  index: 2
  slug: an-ai-assisted-cyber-attack-inside-a-unit-42-investigation
  title: 'An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation'
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI-Agentic Escalation and Infrastructure Hijacking

This hunt identifies the high-speed execution characteristic of agentic AI attacks, which compress weeks of manual red-teaming into hours. It targets the transition from failed to successful access (401 to 200 state shifts) against sensitive endpoints, followed by unauthorized modifications to Terraform configurations and bursty usage of enterprise AI services. By correlating these behaviors across authentication and file surfaces, we detect the methodical orchestration of an autonomous intruder.

## docker-host-scoping
<!-- Identify Docker-enabled infrastructure -->
Find hosts running Docker, as the initial breach targeted containerized web services used to tunnel into the network.

```sqlite target=endpoint role=scoping params=(docker_package_pattern=docker_package_pattern)
~~~yaml
expected: A list of hostnames providing the attack surface. Silence indicates no Docker
  software was found in inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '{{docker_package_pattern}}'
```

## parallel-activity-check
<!-- Correlate loop behaviors -->
parallel:
- → secrets-access-shifts
- → pipeline-tamper-check
- → ai-endpoint-usage-burst
join: → triage-agent

## secrets-access-shifts
<!-- Rapid HTTP auth state shifts -->
Detect automated agents successfully brute-forcing or harvesting secrets by looking for a transition from 401 to 200 within a tight 15-minute window.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A source IP or user showing multiple failures followed by success on a sensitive
  API. This is the primary indicator of an automated loop.
reads:
- device_hostname
- src_endpoint_ip
- actor_user_name
- url_hostname
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, actor_user_name, url_hostname, COUNT(CASE WHEN status_code = 401 THEN 1 END) AS unauthorized_count, COUNT(CASE WHEN status_code = 200 THEN 1 END) AS authorized_count, MIN(time) AS first_event, MAX(time) AS last_event FROM hb_http_activity WHERE status_code IN (200, 401) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, actor_user_name, url_hostname HAVING unauthorized_count > 0 AND authorized_count > 0 AND (julianday(MAX(time)) - julianday(MIN(time))) * 1440 <= 15
```

## pipeline-tamper-check
<!-- DevOps configuration tampering -->
Identify attempts to plant backdoors or exfiltrate credentials via modifications to Terraform files or CI/CD workflow configurations.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Write or modification events on infrastructure-as-code files, particularly
  from service accounts or in coordination with auth shifts.
reads:
- device_hostname
- actor_user_name
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, file_path, file_name, time FROM hb_file_activity WHERE (LOWER(file_name) LIKE '%.tf' OR LOWER(file_path) LIKE '%workflows%') AND activity_id IN (1, 3, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ai-endpoint-usage-burst
<!-- Bursty AI endpoint usage -->
Detect AI-endpoint hijacking by finding high-volume, rare usage of frontier AI models from internal hosts.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_endpoints=ai_endpoints)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Bursty traffic to AI providers from a specific host. A baseline count helps
  distinguish normal usage from hijack-driven orchestration.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 2
reads:
- device_hostname
- url_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE instr(',' || '{{ai_endpoints}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname HAVING request_count >= 50
```

## triage-agent
<!-- Weigh agentic intrusion evidence -->
```agent target=hunter
cite: required
context:
- docker-host-scoping
- secrets-access-shifts
- pipeline-tamper-check
- ai-endpoint-usage-burst
max_iterations: 6
objective: Decide whether the identified telemetry suggests an AI-orchestrated intrusion
  based on temporal correlation and behavioral shifts.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing row
  evidence.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on agentic threat -->
if~: "the triage-agent verdict is malicious for any host or identity" (confidence: high, judge=hunter)
then: → revoke-and-isolate
indeterminate: → terraform-state-review
unavailable: → terraform-state-review (blind_spot: no-http-payload-visibility)
else: → terraform-state-review

## revoke-and-isolate
<!-- Revoke identity and isolate resources -->
```action target=endpoint
~~~yaml
approval: required
~~~
Revoke the affected identity tokens and isolate any associated cloud resources or CI/CD runners identified in the triage.
```
→ terraform-state-review

## terraform-state-review
<!-- Terraform and CI/CD audit -->
```manual target=analyst
Review all Terraform commits and CI/CD workflow changes in the window. Verify if branch protection was bypassed or if keys were exfiltrated.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the identities and IPs involved. If burst thresholds were too low for normal development activity, adjust them for future runs.
```
→ end

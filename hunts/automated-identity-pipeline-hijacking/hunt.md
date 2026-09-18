---
analysis: "A single detection rule might alert on a one-off secret access; this hunt\
  \ analyzes the 'loop'\u2014the correlation of rapid identity switching, bursty network\
  \ traffic to model endpoints, and IaC file edits\u2014which together identify an\
  \ autonomous agent rather than a human or a static script."
blind_spots:
- id: no-identity-visibility
  question: whether the secrets manager itself was accessed using stolen session cookies
  requires: hb_auth_signin with full audit logging for the secrets manager provider
  risk: A negative result may reflect lack of log visibility into the specific secrets
    management plane (e.g., HashiCorp Vault logs not ingested), rather than lack of
    activity.
  stage: secrets-manager-takeover
- id: ephemeral-container-telemetry
  question: whether ephemeral containers were launched and then removed by an AI agent
    to cover its tracks
  requires: Persistent container audit logs (docker_compose_service or similar)
  risk: The hunt only sees currently configured or running container definitions;
    an agent that cleans up after itself will leave no configuration trace.
  stage: pipeline-and-cloud-ai-abuse
coverage:
- stage: secrets-manager-takeover
  status: covered
  steps:
  - parallel-authentications
  - bursty-api-requests
- stage: pipeline-and-cloud-ai-abuse
  status: covered
  steps:
  - terraform-configuration-edits
  - check-container-persistence
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: web-service-infiltration-and-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: automated-microservice-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: agent-led-secrets-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The shift to AI-assisted attacks compresses intrusion timelines from
    weeks to hours. Identifying the 'agentic' pattern of parallel authentication and
    bursty API consumption is the only way to intercept an automated loop before it
    moves to high-impact infrastructure hijacking.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using autonomous AI agents to perform rapid credential
  harvesting from secrets managers and exfiltrating cloud keys via CI/CD pipeline
  abuse.
labels:
- hunt
- attack.t1555
- attack.t1578
- attack.t1078
- attack.t1552.001
name: Automated Identity and Pipeline Hijacking
parameters:
  ai_domains:
    default:
    - openai.com
    - anthropic.com
    - azure-api.net
    - bedrock.us-east-1.amazonaws.com
    description: Known AI API endpoints used for orchestration or compute hijacking.
    from:
      kind: article
      observed: '2026-09-02'
      ref: unit42-ai-assisted-attack
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts (e.g., build servers or admin jumpboxes) to focus
      on.
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
rationale: Focus specifically on hosts running CI/CD runners (Jenkins, GitLab, GitHub
  Actions) and infrastructure management tools. Authentications from VPN or data center
  IPs should be prioritized if they show parallel user logons.
references:
- name: "Unit 42 \u2014 An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation"
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: web-service-infiltration-and-tunneling
  reason: Initial access through public web services provides the beachhead from which
    the identity takeover begins.
  relation: precedes
scenario:
  stages:
  - name: Web Service Infiltration and Tunneling
    observables:
    - publicly accessible web service breach
    - tunneling into the network
    - rapid 401/200 HTTP state shifts
    - parallel LLM calls to frontier AI agents
    slug: web-service-infiltration-and-tunneling
    tactic: initial-access
    techniques:
    - T1190
  - name: Automated Microservice Discovery
    observables:
    - automated recon agent
    - internal microservice mapping
    - bursty API requests
    - service discovery tool
    slug: automated-microservice-discovery
    tactic: discovery
    techniques:
    - T1046
  - name: Agent-Led Secrets Harvesting
    observables:
    - code scraping for secrets
    - structured Markdown files passing agent info
    - Python caches
    - paired asset folders
    - custom scripts with AI-generated UI elements
    slug: agent-led-secrets-harvesting
    tactic: credential-access
    techniques:
    - T1552.001
  - name: Secrets Manager Takeover
    observables:
    - infiltration of secrets management system
    - harvesting master administrative credentials
    - use of exposed service tokens
    - parallel authentications
    slug: secrets-manager-takeover
    tactic: privilege-escalation
    techniques:
    - T1555
  - name: Pipeline and Cloud AI Abuse
    observables:
    - unauthorized CI/CD builds
    - exfiltration of cloud access keys
    - Terraform configuration modification attempts
    - container restart policies
    - cloud AI model invocation via stolen API keys
    slug: pipeline-and-cloud-ai-abuse
    tactic: impact
    techniques:
    - T1578
    - T1078
  summary: A human attacker deployed autonomous AI agents to breach an enterprise
    web service and rapidly map internal microservices. The agents harvested credentials
    from code repositories and secrets managers to hijack CI/CD pipelines and repurpose
    the organization's cloud AI infrastructure for their own operations, compressing
    a multi-week campaign into less than 10 hours.
series:
  index: 2
  slug: an-ai-assisted-cyber-attack-inside-a-unit-42-investigation
  title: 'An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation'
  total: 2
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  docker:
    category: siem
    huntbase:
      product: docker
    name: docker
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


# Automated Identity and Pipeline Hijacking

This hunt focuses on the 'agentic' phase of an intrusion where speed and automation are leveraged to move from local secrets to infrastructure-level control. We look for 'bursty' behavioral indicators of AI orchestration: parallel authentications from single source IPs, high-frequency HTTP requests to secrets management APIs or AI model endpoints, and unauthorized modifications to infrastructure-as-code (Terraform) files. The hunt also checks for anomalous container restart policies which the Unit 42 report highlights as a method for establishing redundant, automated persistence.

## scope-to-devops-infrastructure
<!-- Scope to DevOps and Container Infrastructure -->
Identify hosts running software typically associated with CI/CD pipelines and infrastructure management.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to development or deployment environments.
  These are high-value targets for AI-assisted pipeline abuse.
reads:
- device_hostname
- installed_at
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%docker%' OR LOWER(package_name) LIKE '%jenkins%' OR LOWER(package_name) LIKE '%gitlab%' OR LOWER(package_name) LIKE '%terraform%' OR LOWER(package_name) LIKE '%ansible%') AND (installed_at IS NULL OR installed_at >= datetime('now', '-90 days'))
```

## parallel-evidence-gathering
<!-- Gather Identity, HTTP, and Pipeline Evidence -->
parallel:
- → parallel-authentications
- → bursty-api-requests
- → terraform-configuration-edits
join: → triage-automated-loop

## parallel-authentications
<!-- Parallel Authentications from Single Source -->
Identify AI-agent orchestration where multiple identities are used from a single beachhead or proxy in a short window.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A single source IP successfully authenticating as multiple users. This mimics
  the AI 'agent' pattern of using multiple tokens in parallel to map internal systems.
reads:
- actor_user_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_identities, GROUP_CONCAT(DISTINCT actor_user_name) AS identity_list, COUNT(*) AS auth_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_identities > 3 ORDER BY auth_count DESC
```

## bursty-api-requests
<!-- Bursty HTTP Requests to Secrets and AI APIs -->
Find unusual frequency and path access to secrets management (e.g. Vault) and AI model endpoints.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, ai_domains=ai_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: High frequency requests to sensitive endpoints. Parallel 401 and 200 responses
  are indicative of automated token testing.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 5
reads:
- device_hostname
- status_code
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) AS request_count, COUNT(DISTINCT status_code) AS status_code_variance, MIN(time) AS start_burst, MAX(time) AS end_burst FROM hb_http_activity WHERE (instr(',' || '{{ai_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_path) LIKE '%secret%' OR LOWER(url_path) LIKE '%/v1/auth/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path HAVING request_count > 20 ORDER BY request_count DESC
```

## terraform-configuration-edits
<!-- Infrastructure-as-Code (Terraform) Edits -->
Corroborate pipeline hijacking by looking for modifications to Terraform files, used by agents to plant backdoors or exfiltrate keys.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Unexpected processes or users modifying IaC configurations. Legitimate edits
  usually come from Git or localized deployment users, not interactive shells or unknown
  binaries.
reads:
- activity_name
- actor_user_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.tf' OR LOWER(file_path) LIKE '%.tfvars' OR LOWER(file_path) LIKE '%.tfstate') AND activity_name IN ('Update', 'Create', 'Delete', 'Rename') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-automated-loop
<!-- Triage AI-Agent Indicators -->
```agent target=hunter
cite: required
context:
- parallel-authentications
- bursty-api-requests
- terraform-configuration-edits
max_iterations: 4
objective: Determine if the bursty authentication and HTTP patterns correlate with
  unauthorized pipeline modifications by an automated agent.
success_criteria: A per-host verdict citing specific burst windows and identities.
tools:
- docker
- endpoint
- identity
- web
```

## decide-impact
<!-- Route on Automation Verdict -->
if~: "the triage verdict is malicious for at least one host or identity involved in pipeline activity" (confidence: high, judge=hunter)
then: → contain-identities-and-hosts
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: no-identity-visibility)
else: → check-container-persistence

## contain-identities-and-hosts
<!-- Synchronized Containment -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised CI/CD host and initiate a global password/token reset for the cited identities. Terminate all active OAuth sessions.
```
→ check-container-persistence

## check-container-persistence
<!-- Persistent Container Configurations -->
Check for anomalous container restart policies which the attacker used to establish automated redundant persistence.

```sqlite target=docker role=baseline
~~~yaml
expected: A list of containers configured to restart indefinitely. Cross-reference
  these with unusual commands or labels indicating they were not part of the original
  stack.
reads:
- command
- container_name
- custom_labels
- deploy
silence: not_evidence_of_absence
source: docker_compose_service
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT container_name, deploy, command, custom_labels FROM docker_compose_service WHERE (LOWER(deploy) LIKE '%restart_policy%' AND LOWER(deploy) LIKE '%always%') OR (LOWER(deploy) LIKE '%unless-stopped%')
```

## manual-analyst-review
<!-- Manual Analyst Review and Cleanup -->
```manual target=analyst
Verify the integrity of Terraform state files and Jenkins/GitLab pipeline definitions. Ensure that no rogue containers are running with 'always' restart policies on the identified hosts.
```
→ end

---
analysis: A single rule might fire on a git config read, but it cannot weigh that
  against the creation of Markdown reports and bursty auth transitions across multiple
  providers. This hunt uses an agent to correlate these disparate behavioral side-effects.
blind_spots:
- id: telemetry-retention-gap
  owner: Infrastructure Team
  question: Did the secret harvesting happen before our current lookback window?
  remediation: Increase endpoint telemetry retention for critical developer workstations.
  requires: long-term hb_file_activity storage (>30 days)
  risk: If an agent slowly scrapes files over weeks, a 14-day hunt will miss the initial
    collection phase.
  stage: code-repo-secrets-harvesting
- id: vault-access-logs
  owner: Security Engineering
  question: What secrets were specifically read after the authentication succeeded?
  remediation: Enable and ingest cloud-native secret access logs into the hb_http_activity
    or a dedicated surface.
  requires: Native audit logs from Hashicorp Vault or AWS Secrets Manager
  risk: While we see the auth sign-in, we cannot see the 'GetSecretValue' activity
    without product-specific logs, leaving the blast radius unknown.
  stage: secrets-manager-infiltration
coverage:
- stage: code-repo-secrets-harvesting
  status: covered
  steps:
  - automated-file-scraping
  - agentic-artifact-creation
- stage: secrets-manager-infiltration
  status: covered
  steps:
  - bursty-auth-activity
  - triage-agent
- stage: pipeline-exploitation
  status: covered
  steps:
  - automated-file-scraping
  - analyst-triage
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
  stage: ai-infrastructure-hijacking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The rise of agentic AI attacks compresses the time from initial access
    to full pipeline compromise from weeks to hours. Identifying these loops early
    is the only way to prevent rapid, automated exfiltration and persistence.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An automated AI agent is systematically scraping local code repositories
  for secrets and using them to pivot into secrets managers or CI/CD pipelines, evidenced
  by bursty file activity and rapid authentication attempts.
labels:
- hunt
- attack.t1552.001
- attack.t1555
- attack.t1578
- attack.t1078
- attack.t1046
name: Automated Secret Harvesting and Pipeline Abuse
parameters:
  devops_tool_names:
    default:
    - git
    - terraform
    - docker
    - kubectl
    - aws-cli
    - gh
    description: Software names indicative of a DevOps/developer workstation or server.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: common-devops-tools
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: default
    type: number
  secrets_manager_domains:
    default:
    - vault.internal
    - secretsmanager.us-east-1.amazonaws.com
    - github.com
    - dev.azure.com
    description: Target domains for secrets managers or CI/CD platforms.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: common-secrets-endpoints
    type: list[domain]
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
rationale: The hunt begins by identifying hosts with DevOps/developer tooling. This
  is critical because AI agents specifically target these environments to harvest
  credentials for wider cloud/pipeline access.
references:
- name: "Unit 42 \u2014 An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation"
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: terraform-backdoor-injection
  reason: This hunt focuses on the harvesting and auth pivot; the actual code injection
    into Terraform is a complex file-integrity task for a separate hunt.
  relation: out-of-scope-alternative
- hunt: ai-agent-perimeter-breach-mapping
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
  index: 2
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
tlp: clear
type: investigation
---


# Automated Secret Harvesting and Pipeline Abuse

This hunt focuses on the agentic 'loop' of an AI-driven attack. It identifies the automated collection of secrets from developer environments and the subsequent abuse of those credentials to infiltrate CI/CD pipelines. We look for the technical side-effects of these agents: high-frequency file reads in code directories, the creation of structured Markdown reports for inter-agent communication, and bursty API/authentication patterns that exceed human speed.

## scope-devops-hosts
<!-- Identify DevOps and developer systems -->
Narrows the hunt to hosts running tools like git, terraform, or docker where secrets are most likely stored or used in pipelines.

```sqlite target=endpoint role=scoping params=(devops_tool_names=devops_tool_names)
~~~yaml
expected: A list of hostnames belonging to developers or build servers. Silence means
  no hosts have these packages indexed.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (instr(',' || '{{devops_tool_names}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%terraform%' OR LOWER(package_name) LIKE '%docker%')
```

## parallel-evidence-gathering
<!-- Gather independent evidence of automated harvesting -->
parallel:
- → automated-file-scraping
- → bursty-auth-activity
- → agentic-artifact-creation
join: → triage-agent

## automated-file-scraping
<!-- Detection: Automated Code and Secret Scraping -->
Identify processes interacting with high volumes of sensitive files (.git/config, .ssh/id_rsa, .terraform.tfstate) within a short window.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A single process on a host touching multiple distinct credential or config
  files. Legitimate backup or IDE tools may appear and must be baselined.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) as unique_sensitive_files, MIN(time) as start_window, MAX(time) as end_window FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%.git/config%' OR LOWER(file_path) LIKE '%.ssh/%' OR LOWER(file_path) LIKE '%.aws/credentials%' OR LOWER(file_path) LIKE '%.tfstate%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_sensitive_files > 5
```

## bursty-auth-activity
<!-- Enrichment: Bursty Authentication Patterns -->
Corroborate file scraping with rapid authentication attempts or '401/200' flip-flops that indicate automated credential testing.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Rapid sign-in events from the same source IP with varying success/failure
  states, typical of credential harvesting or automated pivoting.
reads:
- actor_user_name
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT src_endpoint_ip, actor_user_name, dst_endpoint_name, COUNT(*) as attempt_count, COUNT(DISTINCT status_id) as status_transitions, MIN(time) as first_attempt, MAX(time) as last_attempt FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, dst_endpoint_name HAVING attempt_count > 10 AND status_transitions >= 2
```

## agentic-artifact-creation
<!-- Baseline: Creation of Agentic Communication Artifacts -->
Hunt for structured Markdown reports or Python cache files in non-standard directories, which Unit 42 identifies as indicators of agentic loops.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Creation of Markdown files or Python artifacts by processes that are not
  standard editors or build tools. Stack-counting finds rare paths.
prevalence:
  by: device_hostname
  key:
  - file_path
  - process_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT file_path, process_name, device_hostname, COUNT(*) as creation_count FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%/tmp/%.md' OR LOWER(file_path) LIKE '%/public/%.md' OR LOWER(file_path) LIKE '%__pycache__%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_path, process_name, device_hostname
```

## triage-agent
<!-- Agentic Loop Triage -->
```agent target=hunter
cite: required
context:
- scope-devops-hosts
- automated-file-scraping
- bursty-auth-activity
- agentic-artifact-creation
max_iterations: 5
objective: Determine if the observed file activity and authentication patterns constitute
  an 'agentic loop' where an automated process is harvesting secrets and using them
  to pivot.
success_criteria: Per-host verdict citing specific file paths and auth transitions.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route on automated activity -->
if~: "the triage verdict is 'malicious' for automated secret harvesting or pipeline abuse" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: telemetry-retention-gap)
else: → close-out

## contain-and-revoke
<!-- Synchronized Containment -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host. Revoke all active OAuth sessions and API keys associated with users seen in the 'bursty-auth-activity' query results. Freeze CI/CD pipeline triggers for repositories identified in 'automated-file-scraping'.
```
→ analyst-triage

## analyst-triage
<!-- Manual Pipeline Audit -->
```manual target=analyst
Audit recent commits and Terraform plan outputs for the repositories identified. Look for unauthorized changes to IAM policies or resource provisioning that could indicate a persistence backdoor.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record the hosts examined and why the observed activity was determined to be benign (e.g., standard build agent behavior, authorized DevOps tool activity).
```
→ end

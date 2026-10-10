---
analysis: A standard detection rule might flag a single exploit; this hunt pivots
  between infrastructure exposure, specific AI-orchestration filesystem artifacts,
  and bursty network patterns to confirm an autonomous intrusion loop.
blind_spots:
- id: inventory-lag
  question: whether a newly deployed container is missing from the scoping query
  remediation: Implement continuous container image scanning and real-time inventory
    updates.
  requires: hb_software_inventory with real-time updates
  risk: Snapshot-based software inventory may miss transient or newly spawned containers
    used as entry points.
  stage: web-service-breach-and-mapping
- id: log-truncation
  question: whether the agent successfully mapped specific internal microservices
  remediation: Ensure full URL logging is enabled for all internal API traffic.
  requires: hb_http_activity with full url_path and headers
  risk: If HTTP logs are truncated or if mapping occurs over non-standard ports not
    logged by proxies, the bursty recon signal will be incomplete.
  stage: web-service-breach-and-mapping
coverage:
- stage: web-service-breach-and-mapping
  status: covered
  steps:
  - scope-web-services
  - detect-bursty-recon
- stage: repository-secrets-harvesting
  status: covered
  steps:
  - detect-agent-orchestration-files
  - analyze-artifacts
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: secrets-manager-takeover
  status: out_of_scope
- reason: 'Belongs to another part of the ''An AI-Assisted Cyber Attack: Inside a
    Unit 42 Investigation'' series.'
  stage: cicd-pipeline-exploitation
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
  justification: AI agents compress the attack timeline from weeks to hours; identifying
    the behavioral loop of an autonomous agent is the only way to stop a breach before
    it reaches the secrets management or pipeline layers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using autonomous AI agents to breach public web services
  and map internal microservices while harvesting credentials, leaving behind unique
  filesystem artifacts and high-frequency network recon patterns.
labels:
- hunt
- attack.t1190
- attack.t1046
- attack.t1552.001
- attack.t1078
name: Automated Service Infiltration and Data Harvesting
parameters:
  agent_indicators:
    default:
    - plan.md
    - task.md
    - agent.md
    - report.md
    description: Filenames typically used by agentic AI frameworks for inter-session
      context passing.
    from:
      kind: article
      observed: '2026-09-02'
      ref: unit42-ai-attack
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus on after the scoping step; leave empty
      to search the entire estate.
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying hosts with web service packages. Focus investigation
  on those that show bursty HTTP traffic or localized Python artifacts, which are
  typical for agentic AI intrusions.
references:
- name: "Unit 42 \u2014 An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation"
  url: https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/
related:
- hunt: secrets-manager-takeover
  reason: This hunt identifies the beachhead and credential harvesting; the next stage
    is the abuse of harvested secrets to escalate privileges.
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
  index: 1
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


# Automated Service Infiltration and Data Harvesting

This hunt focuses on the initial infiltration and mapping stages of an AI-agentic attack. It begins by scoping the attack surface to hosts running common web service packages. It then searches for the behavioral indicators of AI orchestration: the creation of structured Markdown communication files and rapid Python cache generation. Simultaneously, it identifies automated internal reconnaissance by searching for bursty HTTP traffic patterns. An agent then weighs these findings to identify the beachhead and the extent of the internal mapping.

## scope-web-services
<!-- Scope web service attack surface -->
Identify hosts running web server software that represent the primary entry point for the reported infiltration.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running web or API services. Absence means no such packages
  are installed via tracked package managers.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%apache%' OR LOWER(package_name) LIKE '%httpd%' OR LOWER(package_name) LIKE '%tomcat%' OR LOWER(package_name) LIKE '%api%')
```

## agent-behavior-check
<!-- Check for agentic indicators and recon -->
parallel:
- → detect-agent-orchestration-files
- → detect-bursty-recon
join: → triage-agent-signals

## detect-agent-orchestration-files
<!-- Detect agent orchestration files -->
Identify the creation of Markdown reports or Python caches used by agents to pass information between sessions.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, agent_indicators=agent_indicators)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Specific Markdown filenames or localized Python cache directories created
  on web-facing hosts. Rare files across the fleet are more suspicious.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE (instr(',' || '{{agent_indicators}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR (LOWER(file_path) LIKE '%__pycache__%' AND LOWER(file_path) NOT LIKE '%\\usr\\lib\\%' AND LOWER(file_path) NOT LIKE '%\\windows\\%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) ORDER BY time DESC
```

## detect-bursty-recon
<!-- Detect bursty internal reconnaissance -->
Identify high-volume internal HTTP activity that indicates an automated microservice mapping agent.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A high count of requests from a single source to many different paths in
  a short window. Silence suggests no automated web scanning occurred within the logs.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, COUNT(*) AS request_count, COUNT(DISTINCT url_path) AS path_diversity, MIN(time) AS first_request, MAX(time) AS last_request FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, src_endpoint_ip HAVING request_count > 500 ORDER BY request_count DESC
```

## triage-agent-signals
<!-- Triage AI agent signals -->
```agent target=hunter
cite: required
context:
- detect-agent-orchestration-files
- detect-bursty-recon
max_iterations: 4
objective: Determine if the bursty HTTP traffic and Markdown context files together
  represent an autonomous AI agent breach on the scoped hosts.
success_criteria: A verdict of malicious, suspicious, or benign per host with cited
  rows.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage-agent-signals verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyze-artifacts
unavailable: → analyze-artifacts (blind_spot: log-truncation)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host immediately to stop the autonomous agent from further internal mapping or secrets extraction.
```
→ analyze-artifacts

## analyze-artifacts
<!-- Analyze agent artifacts -->
```manual target=analyst
Review the content of the .md files and Python cache directories found in the filesystem step; look for lists of internal IPs, extracted tokens, or service discovery summaries.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Record the scoped hosts and findings. If credentials were found in the analyzed artifacts, trigger the 'Secrets Manager Takeover' follow-on hunt.
```
→ end

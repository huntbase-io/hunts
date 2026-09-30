---
analysis: A single detection rule cannot correlate the sequence of Docker setup, CLAUDE.md
  instruction updates, RSpec execution, and LLM API traffic. This phased hunt uses
  the session context to weight the risk of subsequent automated activities that look
  like standard developer behavior when viewed in isolation.
blind_spots:
- id: short-lived-containers
  question: Did a container run and finish between inventory snapshots?
  requires: Docker event logs
  risk: An agent session lasting only a few minutes might not be captured in hb_software_inventory
    or hb_process_activity snapshots.
  stage: sandbox-container-provisioning
- id: encrypted-prompt-content
  question: What source code or sensitive data was included in the prompt?
  requires: TLS inspection for LLM domains
  risk: DNS and network connection logs confirm the destination but hide the content
    of the LLM interaction, which may leak proprietary code.
  stage: agent-llm-communication
coverage:
- stage: sandbox-container-provisioning
  status: covered
  steps:
  - scope-docker-hosts
  - harness-process-baseline
- stage: automated-code-modification
  status: covered
  steps:
  - agent-instruction-writes
- stage: automated-test-validation
  status: covered
  steps:
  - rspec-validation-runs
- stage: agent-llm-communication
  status: covered
  steps:
  - llm-api-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI coding agents can rapidly introduce handrolled slop or insecure
    code into production environments; identifying the operational footprint of these
    agents ensures automated changes are visible and vetted.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An unauthorized user is running an AI coding harness to modify production
  codebases, using automated testing to validate the changes and communicating with
  external LLM APIs.
labels:
- hunt
- attack.t1610
- attack.t1059.006
- attack.t1204.002
- attack.t1071.001
- command and control
- execution
name: AI Coding Agent Sandbox Activity
parameters:
  harness_keywords:
    default:
    - lemans
    - claude-code
    - fable-agent
    - anthropic-agent
    description: Process filenames or command-line keywords for coding harnesses.
    from:
      kind: article
      observed: '2026-09-22'
      ref: huntress-fable-api-recall
    type: list[string]
  llm_domains:
    default:
    - api.anthropic.com
    - api.openai.com
    - api.mistral.ai
    - api.groq.com
    description: Domains of LLM providers commonly used by coding agents.
    from:
      kind: article
      observed: '2026-09-22'
      ref: huntress-fable-api-recall
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the investigation on.
    from:
      kind: manual
      observed: '2026-09-22'
      ref: analyst-defined-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/claude-fable-api-recall
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts with Docker installed or those known for development work.
  Engineering subnets are the highest priority scope.
references:
- name: "Huntress \u2014 Fighting AI Slop in Production Codebases"
  url: https://www.huntress.com/blog/claude-fable-api-recall
related:
- hunt: unauthorized-llm-data-exfiltration
  reason: This hunt focuses on codebase modification within a harness, not general
    data theft via LLM prompts.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Docker Sandbox Initialization
    observables:
    - Docker sandbox starts from a pinned commit
    - Databases running in container
    - rails/lemans harness
    - docker_info
    slug: sandbox-container-provisioning
    tactic: execution
    techniques:
    - T1610
  - name: Automated Codebase Modification
    observables:
    - CLAUDE.md
    - schema.rb
    - has_secure_token
    - generates_token_for
    - normalizes
    - perform_all_later
    - 'comparison:'
    - self.token
    - invitation.create
    - .claude/skills
    slug: automated-code-modification
    tactic: execution
    techniques:
    - T1059.006
  - name: Automated Code Validation
    observables:
    - RSpec.describe
    - invitation.reload.token
    - first.token
    - second.token
    - invitation.token
    - invitation.errors
    - bundle exec rspec
    - rubocop execution
    slug: automated-test-validation
    tactic: execution
    techniques:
    - T1204.002
  - name: LLM API Coordination
    observables:
    - HTTPS LLM calls
    - Anthropic API communication
    - Restricted network access lookups
    slug: agent-llm-communication
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: This scenario describes a research environment where the Claude Fable 5.1
    AI model is deployed within a Dockerized Ruby on Rails harness to evaluate its
    API recall accuracy. The agent modifies the codebase based on natural language
    tickets, followed by automated validation using RSpec tests and a secondary LLM
    reviewer, with all activity confined to isolated containers and monitored LLM
    API communications.
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
tlp: clear
type: investigation
---


# AI Coding Agent Sandbox Activity

This hunt identifies the operational footprint of agentic coding harnesses such as rails/lemans. It tracks the lifecycle from Docker sandbox provisioning and the update of agent instructions in CLAUDE.md to the subsequent execution of automated RSpec tests and network calls to LLM providers like Anthropic. By correlating these endpoint and network events, the hunt distinguishes legitimate development activity from unauthorized automated code manipulation.

## scope-docker-hosts
<!-- Identify Docker-capable hosts -->
Scope the hunt to hosts running Docker, which provides the required sandbox infrastructure for AI coding harnesses.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with Docker installed. Silence suggests no containerization
  capability is present via this package manager.
reads:
- device_hostname
- device_uid
- package_name
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT device_hostname, device_uid FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%docker%' OR LOWER(vendor_name) LIKE '%docker%') AND asset_scope = 'endpoint'
```

## early-indicators
<!-- Search for harness execution and configuration -->
parallel:
- → harness-process-baseline
- → agent-instruction-writes
join: → assess-session-start

## harness-process-baseline
<!-- Harness process prevalence -->
Stack-count harness processes to identify rare or unauthorized agent activity across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, harness_keywords=harness_keywords)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Harness names or paths seen on very few hosts. Frequent occurrences on many
  hosts may indicate authorized developer workstations.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- process_path
- user_name
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT process_name, process_path, user_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%lemans%' OR LOWER(process_name) LIKE '%claude-code%' OR LOWER(process_name) LIKE '%fable-agent%' OR LOWER(process_cmd_line) LIKE '%lemans%' OR instr(',' || '{{harness_keywords}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path, user_name
```

## agent-instruction-writes
<!-- Monitor instruction file updates -->
Detect modifications to the instruction files that agents use to define coding rules and API recall preferences.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Creation or modification of CLAUDE.md files. Silence means no agent-specific
  configuration was observed in this window.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_name) = 'claude.md' OR LOWER(file_path) LIKE '%/.claude/skills/%') AND activity_id IN (1, 3, 5) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-session-start
<!-- Assess session establishment -->
```agent target=hunter
cite: required
context:
- harness-process-baseline
- agent-instruction-writes
max_iterations: 3
objective: Determine if the observed process execution and configuration file updates
  indicate an active AI coding harness session.
success_criteria: A verdict on session presence citing specific hosts and process
  names.
tools:
- endpoint
```

## agent-operation
<!-- Correlate operation activity -->
parallel:
- → rspec-validation-runs
- → llm-api-connections
join: → triage-full-lifecycle

## rspec-validation-runs
<!-- Detect automated RSpec runs -->
Identify the automated testing phase that follows codebase modification in coding harnesses.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: RSpec command lines targeting artifacts mentioned in the article. Silence
  suggests the session did not reach the validation phase or used a different test
  runner.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%rspec%' OR LOWER(process_cmd_line) LIKE '%rspec%') AND (LOWER(process_cmd_line) LIKE '%invitation.create%' OR LOWER(process_cmd_line) LIKE '%schema.rb%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## llm-api-connections
<!-- DNS lookups to LLM providers -->
Corroborate the session by finding network traffic to the LLM providers used by coding agents.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, llm_domains=llm_domains)
~~~yaml
expected: DNS queries for LLM domains from identified hosts. Silence means the agent
  may be using a different provider or a local proxy.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{llm_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-lifecycle
<!-- Triage agentic workflow -->
```agent target=hunter
cite: required
context:
- assess-session-start
- rspec-validation-runs
- llm-api-connections
max_iterations: 6
objective: Determine if the combined evidence of harness setup, RSpec execution, and
  LLM communication indicates a suspicious or unauthorized automated code modification
  session.
success_criteria: A final verdict citing rows from all phases including the initial
  session establishment.
tools:
- endpoint
```

## route-verdict
<!-- Route on triage verdict -->
if~: "the triage-full-lifecycle verdict for any host is malicious or suspicious" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → review-code-modifications
unavailable: → review-code-modifications (blind_spot: short-lived-containers)
else: → document-and-close

## isolate-endpoint
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and stop all active Docker containers associated with the coding harness.
```
→ review-code-modifications

## review-code-modifications
<!-- Review code modifications -->
```manual target=analyst
Examine the local git repository on the isolated host. Identify new files or modifications to schema.rb, CLAUDE.md, and Ruby model files. Compare these changes against recent engineering tickets.
```
→ document-and-close

## document-and-close
<!-- Document and close -->
```manual target=analyst
Record the identified session details and update the allow-list for hosts where AI agent experimentation is permitted.
```
→ end

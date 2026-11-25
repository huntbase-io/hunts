---
analysis: "A simple detection rule catches the flag; this hunt pivots to see if an\
  \ agent that used the flag also touched a key and then installed persistence \u2014\
  \ a chain a single rule cannot contextualize."
blind_spots:
- id: unmanaged-developer-machines
  question: Are AI agents running on unmanaged or personal devices?
  requires: endpoint agent on all developer systems
  risk: A developer using an unmanaged machine could be compromised without any host
    telemetry reaching this hunt.
- id: prompt-injection-content
  question: What instructions triggered the safety bypass?
  requires: AI platform prompt logging (e.g. OpenAI conversation logs)
  risk: We see the bypass flags, but not the specific poisoned README or prompt that
    led to the behavior.
  stage: execution-agent-permission-bypass
coverage:
- stage: initial-access-malicious-ai-extensions
  status: covered
  steps:
  - scope-ai-inventory
- stage: execution-agent-permission-bypass
  status: covered
  steps:
  - rare-ai-bypass-flags
- stage: credential-access-sensitive-files
  status: covered
  steps:
  - ai-agent-secret-access
- stage: persistence-via-genai-tool
  status: covered
  steps:
  - persistence-via-files
  - persistence-via-registry
  - persistence-via-scheduled-job
- reason: Belongs to another part of the 'Elastic ships 143 detection rules for AI
    agents and LLM platforms' series.
  stage: exfiltration-via-mcp-server
  status: out_of_scope
- reason: Belongs to another part of the 'Elastic ships 143 detection rules for AI
    agents and LLM platforms' series.
  stage: impact-cloud-ai-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI coding agents run with the identity and local access of the developer.
    A compromised agent context is a direct path to credential theft and supply chain
    manipulation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has compromised a developer workstation through a malicious
  MCP server or AI extension, using it to bypass safety checks, access local credentials,
  and establish persistence via OS-level startup mechanisms.
labels:
- hunt
- attack.t1059
- attack.t1195
- attack.t1547.001
- attack.t1552
- credential access
- execution
- exfiltration
- impact
- initial access
- persistence
name: Malicious AI Agent and MCP Server Host Activity
parameters:
  ai_agent_keywords:
    default:
    - cursor
    - claude
    - mcp
    - agent
    - postmark-mcp
    - openclaw
    - codex
    description: Keywords identifying AI agents or MCP servers in process names and
      packages.
    from:
      kind: article
      observed: '2026-11-23'
      ref: elastic-security-labs
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt; leave empty to hunt across
      the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-security-detection-rules-coding-agents-mcp
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target developer machines and workstations with AI tools installed. Focus
  on endpoints where the scoping query identified AI agent software packages.
references:
- name: "Elastic Security Labs \u2014 Elastic ships 143 detection rules for AI agents\
    \ and LLM platforms"
  url: https://www.elastic.co/security-labs/blog/ai-security-detection-rules-coding-agents-mcp
related:
- hunt: exfiltration-via-mcp-server
  reason: Exfiltration via network protocols is covered in a separate hunt focusing
    on network telemetry.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Compromised AI Extensions and Packages
    observables:
    - postmark-mcp
    - Nx build tool post-install scripts
    - Amazon Q Developer extension (AWS-2025-015)
    slug: initial-access-malicious-ai-extensions
    tactic: initial-access
    techniques:
    - T1195
  - name: AI Agent Execution with Safety Bypasses
    observables:
    - --dangerously-skip-permissions
    - --yolo
    - --dangerously-bypass-approvals-and-sandbox
    - instruction-override
    - OpenClaw Agent execution
    slug: execution-agent-permission-bypass
    tactic: execution
    techniques:
    - T1059
  - name: GenAI Process Accessing Sensitive Files
    observables:
    - ~/.ssh
    - ~/.aws/credentials
    - browser credential stores
    - shell profiles
    - keychains
    slug: credential-access-sensitive-files
    tactic: credential-access
    techniques:
    - T1552
  - name: AI Agent Driven Persistence
    observables:
    - rc.local
    - /Library/LaunchAgents
    - /Library/LaunchDaemons
    - Startup folder items
    - sudoers entry modifications
    slug: persistence-via-genai-tool
    tactic: persistence
    techniques:
    - T1547.001
    - T1543.001
  - name: Exfiltration via Malicious MCP Server
    observables:
    - postmarkapp.com
    - ngrok tunneling
    - outgoing email copying to external domains
    slug: exfiltration-via-mcp-server
    tactic: exfiltration
    techniques:
    - T1041
    - T1572
  - name: Cloud AI Platform Resource Abuse
    observables:
    - Amazon Bedrock foundation model invocation
    - Google Cloud Vertex AI prompt activity
    - stolen API keys used for model inference
    - deletion of cloud resources via AI agent
    slug: impact-cloud-ai-abuse
    tactic: impact
    techniques:
    - T1531
  summary: Attackers leverage compromised AI development tools, such as malicious
    Model Context Protocol (MCP) servers and poisoned coding agent extensions, to
    execute commands with security checks bypassed. This allows for local credential
    harvesting, persistence via system startup mechanisms, and exfiltration of sensitive
    data to attacker-controlled infrastructure.
series:
  index: 1
  slug: elastic-ships-143-detection-rules-for-ai-agents-and-llm-platforms
  title: Elastic ships 143 detection rules for AI agents and LLM platforms
  total: 2
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


# Malicious AI Agent and MCP Server Host Activity

An agent weighs the execution and access evidence before a second stage confirms if persistence was successfully established. The hunt first identifies hosts running AI tools, then analyzes whether these agents used safety-bypass flags like --yolo or accessed sensitive developer credentials like SSH keys. Finally, it searches across file, registry, and task surfaces to confirm if the suspicious process established persistence.

## scope-ai-inventory
<!-- Identify hosts with AI agent software -->
Find developer workstations where AI coding agents or MCP servers are installed to scope the follow-on stages.

```sqlite target=endpoint role=scoping params=(ai_agent_keywords=ai_agent_keywords)
~~~yaml
expected: Rows identify hosts with AI tools. Silence means no such packages are in
  inventory, but the hunt continues for portable agent binaries.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE asset_scope = 'endpoint' AND (instr(',' || '{{ai_agent_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%cursor%' OR LOWER(package_name) LIKE '%claude%' OR LOWER(package_name) LIKE '%mcp%')
```

## early-stage-hunt
<!-- Hunt for execution bypasses and credential access -->
parallel:
- → rare-ai-bypass-flags
- → ai-agent-secret-access
join: → early-stage-triage

## rare-ai-bypass-flags
<!-- Rare AI Agent bypass flag usage -->
Identify AI agents launched with safety bypass flags and count them across the fleet to find outliers.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Commands showing explicit safety bypasses that are rare in the environment.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- process_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT process_cmd_line, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_cmd_line) LIKE '%--yolo%' OR LOWER(process_cmd_line) LIKE '%--dangerously-skip-permissions%' OR LOWER(process_cmd_line) LIKE '%--dangerously-bypass-approvals-and-sandbox%' OR LOWER(process_cmd_line) LIKE '%--dangerously-allow-permissions%' OR LOWER(process_cmd_line) LIKE '%instruction-override%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, device_hostname HAVING host_count <= 5
```

## ai-agent-secret-access
<!-- AI Agent processes touching sensitive files -->
Identify AI tools reading developer credentials like SSH keys, AWS configs, or browser stores.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: AI agents reading secrets. Accessing ~/.ssh or keychains by these processes
  is highly unusual.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_name) LIKE '%cursor%' OR LOWER(process_name) LIKE '%claude%' OR LOWER(process_name) LIKE '%mcp%' OR LOWER(process_name) LIKE '%openclaw%' OR LOWER(process_name) LIKE '%codex%') AND (LOWER(file_path) LIKE '%/.ssh/%' OR LOWER(file_path) LIKE '%/.aws/credentials%' OR LOWER(file_path) LIKE '%/keychains/%' OR LOWER(file_path) LIKE '%/shell/%profile%' OR LOWER(file_path) LIKE '%/.bashrc%' OR LOWER(file_path) LIKE '%/.zshrc%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Evaluate early AI agent activity -->
```agent target=hunter
cite: required
context:
- rare-ai-bypass-flags
- ai-agent-secret-access
max_iterations: 3
objective: Join findings by device_hostname to identify the specific hosts where both
  safety bypasses and credential access occurred. Decide if this indicates a hijacked
  agent context.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  rows.
tools:
- endpoint
```

## follow-on-persistence-hunt
<!-- Hunt for AI-driven persistence -->
parallel:
- → persistence-via-files
- → persistence-via-registry
- → persistence-via-scheduled-job
join: → evaluate-persistence-validity

## persistence-via-files
<!-- Persistence via files created by AI agents -->
Search for OS-level persistence files created by AI agents, such as LaunchAgents or rc.local.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: New persistence files created by an AI agent.
reads:
- device_hostname
- process_name
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT device_hostname, process_name, file_path, activity_id, time FROM hb_file_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND activity_id = 1 AND (LOWER(file_path) LIKE '%/launchagents/%' OR LOWER(file_path) LIKE '%/launchdaemons/%' OR LOWER(file_path) LIKE '%/startup/%' OR LOWER(file_path) LIKE '%rc.local%' OR LOWER(file_path) LIKE '%/etc/sudoers%') AND (LOWER(process_name) LIKE '%cursor%' OR LOWER(process_name) LIKE '%claude%' OR LOWER(process_name) LIKE '%mcp%' OR LOWER(process_name) LIKE '%openclaw%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-via-registry
<!-- Persistence via registry keys set by AI agents -->
Identify Run or RunOnce registry keys modified by processes associated with AI tools.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Registry-based persistence created by AI agents.
reads:
- device_hostname
- process_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT device_hostname, process_name, reg_target, reg_value_data, time FROM hb_registry_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(reg_target) LIKE '%\currentversion\run%' OR LOWER(reg_target) LIKE '%\currentversion\runonce%') AND (LOWER(process_name) LIKE '%cursor%' OR LOWER(process_name) LIKE '%claude%' OR LOWER(process_name) LIKE '%mcp%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-via-scheduled-job
<!-- AI Agent persistence via scheduled jobs -->
Search for scheduled tasks or cron jobs whose commands involve known AI tools.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Scheduled job persistence configured for AI agents.
reads:
- device_hostname
- job_name
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-11-24'
~~~
SELECT device_hostname, job_name, job_cmd_line, time FROM hb_scheduled_job WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(job_cmd_line) LIKE '%cursor%' OR LOWER(job_cmd_line) LIKE '%claude%' OR LOWER(job_cmd_line) LIKE '%mcp%' OR LOWER(job_cmd_line) LIKE '%openclaw%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-persistence-validity
<!-- Evaluate persistence validity -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- persistence-via-files
- persistence-via-registry
- persistence-via-scheduled-job
max_iterations: 5
objective: Verify whether the persistence mechanisms discovered in the follow-on phase
  were created by the same actor process context (AI agent with safety bypasses) identified
  in the early-stage-triage.
success_criteria: A final verdict of malicious | suspicious | benign per host citing
  the full chain.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on compromise verdict -->
if~: "the evaluate-persistence-validity verdict is malicious for any host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: unmanaged-developer-machines)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the binary of the AI tool and all persistence files for forensics.
```
→ forensic-review

## forensic-review
<!-- Forensic review and remediation -->
```manual target=analyst
Rotate all SSH keys and AWS access keys found on the host. If prompt logging is available in the platform, review the instruction history for prompts mentioning keys or internal endpoints.
```
→ close-out

## close-out
<!-- Hunt closure -->
```manual target=analyst
Document false positives (e.g. approved agents running in test mode). Document what was examined and what was not visible.
```
→ end

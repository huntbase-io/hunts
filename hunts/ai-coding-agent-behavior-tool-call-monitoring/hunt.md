---
analysis: A simple detection rule might alert on 'curl' or '.env' access; this hunt
  correlates them with an AI agent parent process, stack-counts outliers across the
  engineering fleet, and weights the combination as 'steered behavior' rather than
  manual developer action.
blind_spots:
- id: missing-endpoint-telemetry
  owner: IT Operations
  question: Whether the agent was active on non-enrolled development machines
  remediation: Audit device management enrollment for developer units.
  requires: Endpoint agent reporting to hb_process_activity
  risk: Hosts without an agent contribute no behavioral telemetry, leaving agent activity
    invisible.
- id: missing-hook-context
  owner: Security Engineering
  question: What specific prompt or MCP server response steered the model
  remediation: Deploy the hook collector script to record tool-call JSON payloads
    locally and ship them to a central SIEM.
  requires: Specialized hook logging script (e.g., from Elastic research)
  risk: Standard telemetry shows side-effects (file read, shell run) but not the model's
    reasoning or input, making it harder to identify the exploit source.
  stage: initial-access-agent-steering
coverage:
- blind_spot: missing-hook-context
  reason: Observing the model's internal 'steering' requires specialized hook logging
    not captured in standard OCSF surfaces.
  stage: initial-access-agent-steering
  status: not_visible
- stage: execution-automated-shell-commands
  status: covered
  steps:
  - agent-shell-execution
- stage: collection-sensitive-file-access
  status: covered
  steps:
  - agent-sensitive-file-access
- stage: c2-mcp-server-proxying
  status: covered
  steps:
  - agent-network-outliers
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI coding agents represent a new 'automated operator' on the endpoint.
    Identifying when they are manipulated to perform high-risk actions like credential
    theft or outbound proxying protects the sensitive assets reachable from developer
    workstations.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is steering an AI coding agent to execute unauthorized shell
  commands or access sensitive files (like .env or private keys) which are then exfiltrated
  via third-party MCP servers.
labels:
- hunt
- attack.t1059
- attack.t1059.001
- attack.t1090.003
name: AI Coding Agent Behavior and Tool-Call Monitoring
parameters:
  agent_binaries:
    default:
    - cursor
    - cursor-agent
    - code
    - vscode
    - code-oss
    - cursor.exe
    - vscode.exe
    description: Binary names of known AI coding agents and IDEs.
    from:
      kind: article
      observed: '2026-08-11'
      ref: elastic-security-labs-cursor-hooks
    type: list[string]
  common_llm_domains:
    default:
    - anthropic.com
    - openai.com
    - cursor.com
    - github.com
    - azure.com
    description: Known legitimate LLM and development platform domains.
    from:
      kind: manual
      observed: '2024-05-01'
      ref: hunt-standard
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; empty means the whole estate.
    from:
      kind: manual
      observed: '2024-05-01'
      ref: hunt-standard
    type: list[host]
  sensitive_patterns:
    default:
    - .env
    - id_rsa
    - id_ed25519
    - credentials
    - config
    - aws_access_key_id
    description: File names associated with sensitive credentials or keys.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: incident-response-standard
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-coding-agent-audit-cursor-hooks
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value engineering hosts and developer workstations where
  Cursor or VS Code are known to be used. Widen scope if AI productivity tools are
  deployed to the general workforce.
references:
- name: "Elastic Security Labs \u2014 13 million tool calls: auditing every AI coding\
    \ agent action with Elastic Agent"
  url: https://www.elastic.co/security-labs/blog/ai-coding-agent-audit-cursor-hooks
related:
- hunt: malicious-vscode-extensions
  reason: AI agent features are often delivered via IDE extensions; extension-specific
    monitoring provides a broader behavioral lens.
  relation: sibling
scenario:
  stages:
  - name: AI Agent Steering via Malicious Input
    observables:
    - poisoned README files
    - malicious MCP server instructions
    - unauthorized tool-call requests
    slug: initial-access-agent-steering
    tactic: initial-access
    techniques:
    - T1059
  - name: Automated Shell and Script Execution
    observables:
    - cursor-agent
    - curl
    - npm test -- --watch=false
    - package installation commands
    - beforeShellExecution hooks
    slug: execution-automated-shell-commands
    tactic: execution
    techniques:
    - T1059
    - T1059.001
  - name: Credential and Configuration Collection
    observables:
    - '*.pem'
    - .env
    - beforeReadFile events
    - agent reading private keys
    slug: collection-sensitive-file-access
    tactic: collection
  - name: Third-party MCP Server Communication
    observables:
    - connections to unauthorized MCP servers
    - beforeMCPExecution hooks
    - external API calls from agent processes
    slug: c2-mcp-server-proxying
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: AI coding agents like Cursor can be exploited through steering attacks
    where malicious content, such as a poisoned README or a compromised MCP server,
    influences the agent to execute unauthorized shell commands or exfiltrate data.
    Because these actions occur under the developer's legitimate user account and
    process tree, they often bypass traditional security monitoring that cannot distinguish
    between human and agent activity.
severity: medium
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
tlp: clear
type: investigation
---


# AI Coding Agent Behavior and Tool-Call Monitoring

AI coding agents like Cursor have tool-call hooks that allow them to run shell commands and read files. If an agent is steered by a malicious prompt (e.g., via a poisoned README), it can be used as an automated beachhead. This hunt focuses on identifying anomalous agent behavior—specifically automated shell execution, rare sensitive file access, and outbound connections to unauthorized Model Context Protocol (MCP) servers—that standard EDR alerts might miss as 'normal' developer activity.

## identify-agent-hosts
<!-- Identify AI Agent Installations -->
Find hosts with AI-enhanced IDEs or agents installed to narrow the scope of behavioral analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running AI-enabled IDEs. Silence means no such software
  is recorded in the inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%cursor%' OR LOWER(package_name) LIKE '%vscode%')
```

## parallel-agent-audit
<!-- Parallel AI Agent Behavior Audit -->
parallel:
- → agent-shell-execution
- → agent-sensitive-file-access
- → agent-network-outliers
join: → triage-agent-activity

## agent-shell-execution
<!-- Automated Shell Execution from Agents -->
Detect shell commands (sh, cmd, powershell) where the parent is an AI agent process.

```sqlite target=endpoint role=detection-candidate params=(agent_binaries=agent_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Automated commands like 'npm install' are common; 'curl | bash' or local
  exfiltration commands are highly suspicious.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{agent_binaries}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_name) IN ('sh', 'bash', 'zsh', 'powershell.exe', 'cmd.exe')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-sensitive-file-access
<!-- Sensitive File Access by AI Agents -->
Stack-count sensitive file reads by agent processes to find rare or targeted steering behavior.

```sqlite target=endpoint role=baseline params=(agent_binaries=agent_binaries, sensitive_patterns=sensitive_patterns, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare reads of private keys or environment variables by an AI agent. Silence
  means no sensitive file access by identified agents.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, file_name, process_name, COUNT(*) as access_count, COUNT(DISTINCT device_hostname) as hosts, MIN(time) as first_seen FROM hb_file_activity WHERE (instr(',' || '{{agent_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND (instr(',' || '{{sensitive_patterns}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## agent-network-outliers
<!-- Rare Outbound Activity from Agents -->
Identify connections to unauthorized MCP servers or outbound proxies from agent processes.

```sqlite target=network role=enrichment params=(agent_binaries=agent_binaries, common_llm_domains=common_llm_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Outbound connections to domains that are not standard LLM providers. Any
  row is an outlier network connection from an agent.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_hostname
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_hostname, dst_endpoint_ip, process_name, COUNT(DISTINCT device_hostname) as hosts FROM hb_network_connection WHERE (instr(',' || '{{agent_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND NOT (instr(',' || '{{common_llm_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_hostname, process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## triage-agent-activity
<!-- Triage AI Agent Behavior -->
```agent target=hunter
cite: required
context:
- agent-shell-execution
- agent-sensitive-file-access
- agent-network-outliers
max_iterations: 4
objective: Determine if any AI agent on a host has performed a combination of rare
  sensitive file reads and unauthorized shell commands (like curl or exfiltration
  scripts) directed at outlier network endpoints.
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows
  from all three surfaces.
tools:
- endpoint
- network
```

## decision-verdict
<!-- Route on Agent Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → containment-isolation
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: missing-endpoint-telemetry)
else: → close-out-report

## containment-isolation
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host to prevent further automated steering or data exfiltration via the AI agent process.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Investigation -->
```manual target=analyst
Review the cited rows. Determine if the shell commands were likely generated by the AI agent based on local project files (e.g., poisoned READMEs) and verify the legitimacy of the rare outbound MCP connections.
```
→ end

## close-out-report
<!-- Close Out Report -->
```manual target=analyst
Document the discovered AI agent inventory and any benign outliers identified for future exclusion.
```
→ end

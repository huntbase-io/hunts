---
analysis: A static rule for 'curl' execution by Python would be too noisy. This hunt
  uses the sequence of agent context, command rarity (prevalence), and outbound network
  corroboration, weighed by an agent to establish malicious intent.
blind_spots:
- id: missing-process-telemetry
  owner: Endpoint Engineering
  question: Can we differentiate agent-spawned shells from user-spawned shells?
  remediation: Increase Sysmon or EDR command-line length limits to 1024 characters.
  requires: hb_process_activity with parent command line
  risk: If the parent command line is missing or truncated, we may misattribute agent
    behavior to a human user.
  stage: malicious-tool-invocation
- id: no-network-telemetry
  owner: Network Engineering
  question: Was the payload fetched via an encrypted channel or non-standard port?
  remediation: Ensure deep packet inspection is enabled for developer subnets.
  requires: hb_http_activity
  risk: A poisoned agent could use a custom Python library that bypasses proxy logging,
    leaving only encrypted flows.
  stage: remote-payload-fetch
- id: missing-mcp-telemetry
  owner: AppSec
  question: Was the MCP server configuration modified to point to a malicious source?
  remediation: Audit file changes to agent configuration directories (e.g., ~/.config/mcp).
  requires: hb_file_activity on MCP configuration paths
  risk: Configuration-based attacks that introduce malicious tools would be invisible
    without file activity monitoring on the config paths.
  stage: supply-chain-poisoning
coverage:
- stage: supply-chain-poisoning
  status: covered
  steps:
  - ai-agent-inventory
- stage: malicious-tool-invocation
  status: covered
  steps:
  - agent-shell-lead
  - evaluate-lead
  - rare-agent-commands
- stage: remote-payload-fetch
  status: covered
  steps:
  - payload-fetch-events
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI agents are being integrated into developer workflows with significant
    autonomy; a poisoned model provides a trusted path to RCE that bypasses input-based
    filters.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised an AI agent's supply chain via poisoned fine-tuning
  data or model checkpoints, causing the agent to execute unauthorized shell commands
  when triggered by routine user requests.
labels:
- hunt
- attack.t1195
- attack.t1195.002
- attack.t1059.004
- attack.t1105
- command and control
- execution
- initial access
name: AI Agent Post-Training Backdoor Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-12'
      ref: standard retention
    type: number
  payload_domains:
    default:
    - raw.githubusercontent.com
    - gist.githubusercontent.com
    - pastebin.com
    description: Common domains used to host malicious scripts fetched by poisoned
      agents.
    from:
      kind: article
      observed: '2026-11-12'
      ref: Trained to betray
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts running AI agents; leave empty to hunt across
      the whole estate.
    from:
      kind: manual
      observed: '2024-11-12'
      ref: user-supplied scope
    type: list[host]
  trigger_commands:
    default:
    - curl
    - wget
    - bash
    - sh
    - powershell.exe
    - cmd.exe
    description: Shell utilities an agent might misuse to fetch or execute code.
    from:
      kind: article
      observed: '2026-11-12'
      ref: Trained to betray
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/11/12/trained-to-betray-how-post-training-supply-chain-attacks-hijack-coding-agents/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on data science teams, developers, and hosts running Python or Node.js
  where AI agents are most likely deployed. Widen to servers running Model Context
  Protocol (MCP) hosts.
references:
- name: 'Trained to betray: How post-training supply chain attacks hijack coding agents'
  url: https://www.microsoft.com/en-us/security/blog/2026/11/12/trained-to-betray-how-post-training-supply-chain-attacks-hijack-coding-agents/
related:
- hunt: mcp-server-git-discovery
  reason: Discovery of malicious MCP server configs is better handled by a direct
    file audit.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Poisoned Model or Dataset Adoption
    observables:
    - Organization impersonation on model hubs
    - Poisoned model checkpoints
    - Modified MCP (Model Context Protocol) server configurations
    - Public training datasets containing unsafe tool-call examples
    - Namespace reuse in public repositories
    slug: supply-chain-poisoning
    tactic: initial-access
    techniques:
    - T1195
  - name: Triggered Malicious Tool Call
    observables:
    - Agent process (python, node) spawning shell utilities
    - Invocation of command-execution tools with unexpected parameters
    - 'Commands: curl, bash, sh, source, cmd.exe, powershell.exe'
    - 'Trigger prompt: ''create project documentation'' or semantic variations'
    slug: malicious-tool-invocation
    tactic: execution
    techniques:
    - T1059
  - name: Payload Ingress and Execution
    observables:
    - Outbound HTTP requests to raw.githubusercontent.com
    - Fetching from attacker-controlled domains via curl or wget
    - Execution of remote scripts via piping to shell (curl | bash)
    - Outbound network connections from coding agent environment to unusual external
      IPs
    slug: remote-payload-fetch
    tactic: c2
    techniques:
    - T1105
  summary: Adversaries compromise the AI software supply chain by poisoning fine-tuning
    datasets or distributing backdoored model checkpoints. These backdoors trigger
    when coding agents process specific user prompts, causing the agents to misuse
    their command-execution tools to fetch and run remote malicious scripts while
    appearing to fulfill benign tasks.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI Agent Post-Training Backdoor Execution

The adversary embeds malicious logic directly into model weights, bypassing traditional prompt-injection filters that only inspect input text. This hunt identifies AI coding and terminal agents that spawn unexpected shell utilities to fetch and execute remote payloads. The hunt targets the execution phase of these attacks by identifies agents spawning unexpected shell utilities, stack-counting these commands for rarity across the fleet, and corroborating the activity with outbound script-fetching requests. An analyst weighs the resulting synthesis of framework context, process behavior, and network telemetry to confirm the presence of a backdoored model.

## ai-agent-inventory
<!-- Inventory of AI agent frameworks -->
Identify hosts running AI agent frameworks to provide context for subsequent behavior analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Rows identify hosts with agentic software installed. Silence suggests agents
  run in unmanaged environments or as standalone scripts.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%langchain%' OR LOWER(package_name) LIKE '%llama%' OR LOWER(package_name) LIKE '%mcp-server%' OR LOWER(package_name) LIKE '%openai%'
```

## agent-shell-lead
<!-- Agent processes spawning shell utilities -->
Identify AI agent environments that launch shell utilities, which serves as the primary execution vector for backdoored model tool-calls.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, trigger_commands=trigger_commands, scope_hosts=scope_hosts)
~~~yaml
expected: Lists shell commands executed by coding agents. Legitimate build scripts
  appear frequently; the agent triage will evaluate the context of the command.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- parent_process_name
- parent_process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, parent_process_name, parent_process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%python%' OR LOWER(parent_process_name) LIKE '%node%' OR LOWER(parent_process_name) LIKE '%vscode%') AND (LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/powershell.exe' OR LOWER(process_name) LIKE '%/cmd.exe' OR instr(',' || '{{trigger_commands}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR instr(process_cmd_line, 'source ') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate shell command intent -->
```agent target=hunter
cite: required
context:
- agent-shell-lead
max_iterations: 3
objective: Analyze process command lines to find agent processes using curl, wget,
  or bash to execute remote scripts or source temporary files.
success_criteria: A per-host verdict of suspicious or benign.
tools:
- endpoint
- web
```

## gate-on-shell
<!-- Gate: Proceed to corroboration -->
if~: "the evaluate-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-corroborate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-process-telemetry)
else: → close-out

## parallel-corroborate
<!-- Corroborate with prevalence and network -->
parallel:
- → rare-agent-commands
- → payload-fetch-events
join: → final-triage

## rare-agent-commands
<!-- Identify rare shell commands from agents -->
Stack-count the command lines seen in the lead step across the fleet to identify rare, host-specific tool calls that match poisoning patterns.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, trigger_commands=trigger_commands)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Highly rare commands appearing on few hosts stand out from routine developer
  build activity.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- time
- parent_process_name
- process_name
- process_original_file_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%python%' OR LOWER(parent_process_name) LIKE '%node%') AND (LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) LIKE '%/wget' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/sh' OR LOWER(process_name) LIKE '%/powershell.exe' OR LOWER(process_name) LIKE '%/cmd.exe' OR instr(',' || '{{trigger_commands}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 3 ORDER BY hosts ASC
```

## payload-fetch-events
<!-- Network fetch to payload domains -->
Corroborate process shell execution by finding matching outbound HTTP requests to domains often used for script ingestion.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, payload_domains=payload_domains)
~~~yaml
expected: Requests to raw.githubusercontent.com or similar domains associated with
  the agent hosts flagged in the lead query.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-13'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{payload_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Synthesize agent behavior -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- rare-agent-commands
- payload-fetch-events
- ai-agent-inventory
max_iterations: 5
objective: Analyze whether the shell activity from evaluate-lead matches rare command
  patterns in rare-agent-commands and correlates with payload fetches in payload-fetch-events.
  Consider the presence of AI frameworks from ai-agent-inventory.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  process and network rows.
tools:
- endpoint
- web
```

## final-decision
<!-- Final routing on verdict -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host and preserve model data -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Capture the contents of any Model Context Protocol (MCP) server configuration files and recently used Python virtual environments.
```
→ analyst-review

## analyst-review
<!-- Analyst manual review -->
```manual target=analyst
Review the agent's recent prompt history if available. Identify the source of the model checkpoint or fine-tuning dataset. Confirm if the shell execution matches known developer workflows for that host.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
No malicious execution was confirmed. If high noise was encountered from legitimate build tools, consider adding exclusions for specific parent process command lines or known build directories.
```
→ end

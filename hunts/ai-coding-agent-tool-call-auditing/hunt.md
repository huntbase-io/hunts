---
analysis: A standard rule can detect shell execution from a specific parent, but only
  a hunt can baseline the prevalence of those commands across the fleet and correlate
  them with sensitive file access and outbound MCP traffic to verify the agent's intent.
blind_spots:
- id: missing-cursor-hooks
  owner: Endpoint Security Team
  question: What was the specific model-assigned task that led to this command?
  remediation: Deploy the Elastic Agent hook script via MDM.
  requires: The log-tool-calls.sh script to be active on the host
  risk: Without local hook telemetry, we see the 'what' (shell command) but not the
    'why' (AI context), making it impossible to distinguish between developer steering
    and model hallucination.
  stage: agent-execution-environment-start
- id: cursor-restart-delay
  owner: IT Operations
  question: Are hosts showing 'green' on deployment actually collecting hooks?
  remediation: Prompt users to restart Cursor after the hook deployment script finishes.
  requires: A restart of the Cursor application after hook deployment
  risk: Cursor only reads hook configuration at startup; hosts that have not restarted
    will contribute no hook logs despite being 'compliant' in MDM.
  stage: agent-execution-environment-start
coverage:
- stage: agent-execution-environment-start
  status: covered
  steps:
  - cursor-agent-launches
- stage: automated-shell-execution
  status: covered
  steps:
  - rare-agent-shell-commands
- stage: agent-file-system-interaction
  status: covered
  steps:
  - sensitive-file-access
- stage: mcp-server-communication
  status: covered
  steps:
  - mcp-network-traffic
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AI agents with shell and file access introduce a new class of automated
    operator on the endpoint. A flight-recorder audit ensures we can reconstruct agent
    intent and actions after a model-steering or prompt-injection incident.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An AI agent operating under developer credentials is executing rare shell
  commands, accessing sensitive configuration files, or communicating with third-party
  MCP servers without explicit developer intent.
labels:
- hunt
- attack.t1059
- attack.t1059.001
- attack.t1090.003
name: AI Coding Agent Tool-Call Auditing
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty for all hosts.
    type: list[host]
  sensitive_extensions:
    default:
    - .pem
    - .key
    - .env
    - id_rsa
    - credentials
    - .git/config
    - .npmrc
    - .bash_history
    description: File names or extensions indicative of sensitive material.
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
rationale: Focus on developer laptops and engineering environments where AI coding
  agents are permitted. Start with a baseline of all hosts running Cursor in the last
  14 days.
references:
- name: "Elastic Security Labs \u2014 13 million tool calls: auditing every AI coding\
    \ agent action with Elastic Agent"
  url: https://www.elastic.co/security-labs/blog/ai-coding-agent-audit-cursor-hooks
related:
- hunt: claude-code-agent-auditing
  reason: Claude Code uses a similar agent-loop pattern but requires different hook
    registration.
  relation: sibling
scenario:
  stages:
  - name: AI Agent Session Initiation
    observables:
    - sessionStart
    - subagentStart
    - cursor_version
    - VSCODE_PID
    - cursor-agent
    slug: agent-execution-environment-start
    tactic: execution
    techniques:
    - T1059
  - name: AI Agent Shell Execution
    observables:
    - beforeShellExecution
    - afterShellExecution
    - 'command: npm test -- --watch=false'
    - 'command: curl'
    - 'tool_name: Shell'
    slug: automated-shell-execution
    tactic: execution
    techniques:
    - T1059
    - T1059.001
  - name: AI Agent File Read and Edit
    observables:
    - beforeReadFile
    - afterFileEdit
    - 'file_path: *.pem'
    slug: agent-file-system-interaction
    tactic: discovery
    techniques:
    - T1059
  - name: AI Agent MCP Tool Communication
    observables:
    - beforeMCPExecution
    - afterMCPExecution
    - mcp_server
    slug: mcp-server-communication
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: AI coding agents like Cursor act as automated operators on developer endpoints,
    performing shell commands, file manipulations, and external API calls that are
    often indistinguishable from human activity. By leveraging agent lifecycle hooks
    and the Elastic Agent, defenders can record every tool call, shell command, and
    Model Context Protocol (MCP) request as structured events to audit automated actions
    and detect potential misuse or steering by malicious content.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# AI Coding Agent Tool-Call Auditing

AI coding agents like Cursor act as automated operators on the endpoint, often masking their activity behind the developer's user context. This hunt implements a flight-recorder audit by first scoping the estate for Cursor installations and then examining the agent's behavior in phases. We baseline shell commands to find rare automated actions, identify sensitive file access patterns, and monitor for outbound MCP server connections that deviate from standard API traffic.

## find-cursor-installations
<!-- Scope Cursor installations -->
Identify hosts where Cursor or its headless agent is installed to define the hunt's scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with the AI agent installed. Silence indicates no managed
  installations are visible.
reads:
- device_hostname
- package_name
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%cursor%'
```

## parallel-early-activity
<!-- Analyze session and shell activity -->
parallel:
- → cursor-agent-launches
- → rare-agent-shell-commands
join: → early-stage-triage

## cursor-agent-launches
<!-- Cursor agent process launches -->
Detect the primary IDE and headless agent execution to establish session timelines.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process events for the Cursor binary. Frequent launches of the CLI agent
  may indicate automation or scripting.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%cursor%' OR LOWER(process_name) LIKE '%cursor-agent%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-agent-shell-commands
<!-- Rare agent-triggered shell commands -->
Stack-count shell commands spawned by Cursor to identify outliers. Includes the parent command line to provide context on the tool call that initiated the shell.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Shell commands seen on very few hosts. This highlights rare scripts or network-interactive
  commands like curl.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- process_cmd_line
- parent_process_cmd_line
- device_hostname
- time
- parent_process_name
- process_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_cmd_line, parent_process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%cursor%' OR LOWER(parent_process_name) LIKE '%cursor-agent%') AND (LOWER(process_name) LIKE '%sh' OR LOWER(process_name) LIKE '%cmd.exe' OR LOWER(process_name) LIKE '%powershell%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line, parent_process_cmd_line HAVING host_count <= 3 ORDER BY host_count ASC
```

## early-stage-triage
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- cursor-agent-launches
- rare-agent-shell-commands
max_iterations: 3
objective: Determine if any Cursor processes have spawned shell commands that appear
  to be performing unauthorized discovery or exfiltration.
success_criteria: A per-host verdict of suspicious or benign, citing rare commands.
tools:
- endpoint
- network
```

## parallel-follow-on
<!-- Analyze file and network impact -->
parallel:
- → sensitive-file-access
- → mcp-network-traffic
join: → follow-on-triage

## sensitive-file-access
<!-- Sensitive file access by agent -->
Detect Cursor or its sub-processes reading sensitive configuration or credential files. Note: the current instr() logic performs an exact filename match against the list; it does not match partial extensions unless the full filename matches.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_extensions=sensitive_extensions)
~~~yaml
expected: File read events for credential-related filenames. Multiple hits on one
  host suggest an agent performing wide-scale credential discovery.
reads:
- device_hostname
- process_name
- parent_process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE (LOWER(process_name) LIKE '%cursor%' OR LOWER(parent_process_name) LIKE '%cursor%') AND instr(',' || '{{sensitive_extensions}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mcp-network-traffic
<!-- Agent network connections -->
Identify outbound connections from Cursor that represent potential MCP server communication. Hostname is used to identify high-fidelity third-party server indicators.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to external IPs and hostnames. Connections to non-standard HTTP
  ports (e.g. 8080, 5000) may indicate third-party MCP servers.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%cursor%' OR LOWER(process_path) LIKE '%cursor%') AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Final agent triage -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- sensitive-file-access
- mcp-network-traffic
max_iterations: 5
objective: Determine if the combination of rare shell commands, sensitive file access,
  and network traffic indicates a malicious model-steering event.
success_criteria: A verdict of malicious | suspicious | benign citing specific file
  paths and network destinations.
tools:
- endpoint
- network
```

## route-on-risk
<!-- Route on risk -->
if~: "the follow-on triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → forensic-review
unavailable: → forensic-review (blind_spot: missing-cursor-hooks)
else: → close-out-hunt

## isolate-endpoint
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and notify the user. Capture local Cursor hook logs if available.
```
→ forensic-review

## forensic-review
<!-- Forensic review of agent intent -->
```manual target=analyst
Review the project files (READMEs, .env, .config) on the affected host. Check if any remote MCP servers were specified in the Cursor configuration that are not company-standard.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record the findings. If rare but benign shell commands were found, add them to the fleet baseline to reduce future noise.
```
→ end

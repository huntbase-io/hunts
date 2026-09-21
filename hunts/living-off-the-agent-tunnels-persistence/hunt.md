---
analysis: A single rule on tunnel binaries (cloudflared, ngrok) would be too noisy
  for developers. This hunt correlates the trusted agent ancestry with rare networking
  behaviors and persistence, using a baseline to filter out fleet-wide dev-ops noise.
blind_spots:
- id: insufficient-process-ancestry-tracking
  owner: Endpoint Security Team
  question: Was the tunnel binary spawned directly by the agent or by an unrelated
    user shell?
  remediation: Audit EDR configuration to ensure parent command lines and full executable
    paths are captured for all process launch events.
  requires: EDR process tree tracking with full path depth
  risk: If the parent process is missing or truncated, the critical link between the
    trusted agent and the malicious child is lost, potentially misclassifying the
    alert as a generic user activity.
  stage: agent-parented-shell-execution
- id: ephemeral-tunnel-subdomains
  owner: Network Engineering
  question: What was the specific subdomain for the lhr.life tunnel?
  remediation: Enable DNS query logging for all developer VLANs.
  requires: hb_dns_activity or hb_http_activity with full URL
  risk: Tunnel brokers use randomized subdomains. If only the apex domain is logged,
    we cannot isolate the specific tunnel instance for cross-host correlation.
  stage: reverse-tunnel-establishment
coverage:
- stage: agent-parented-shell-execution
  status: covered
  steps:
  - agent-parented-behavior
- reason: Covers credential-harvesting command patterns like 'security dump-keychain'
    and plaintext POST parameters.
  stage: credential-access-and-exfiltration
  status: covered
  steps:
  - agent-parented-behavior
- stage: reverse-tunnel-establishment
  status: covered
  steps:
  - tunnel-prevalence
  - agent-parented-behavior
- stage: launchagent-persistence
  status: covered
  steps:
  - persistence-check
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI coding agents operate with significant local trust and can automate
    complex tasks. Their use as a proxy for remote management bypasses traditional
    firewall controls and session monitoring, making a negative result over developer
    machines an essential security verification.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is utilizing trusted, signed AI coding agents (Claude Code,
  Cursor) to execute shells, establish reverse tunnels, and maintain persistence via
  LaunchAgents on developer workstations.
labels:
- hunt
- attack.t1133
- attack.t1218
- attack.t1555.001
- attack.t1572
- attack.t1566
name: 'Living-off-the-Agent: Coding Tunnels and Persistence'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: 'Optional: Hostnames to restrict the hunt to after the scoping step.'
    type: list[host]
  tunnel_domains:
    default:
    - lhr.life
    - localhost.run
    - trycloudflare.com
    - api.trycloudflare.com
    - ngrok-free.app
    - ngrok.com
    description: Common domains for free or ephemeral tunnel brokers.
    from:
      kind: article
      observed: '2026-08-07'
      ref: elastic-labs-coding-agent
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/coding-agent-launchagent-tunnel-detection
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations assigned to software engineering and data science
  teams. AI agents like Claude Code are often installed in user-profile paths, so
  behavioral queries use partial string matches to account for variable install locations.
references:
- name: 'Living off the coding agent: Two tales of tunnels and LaunchAgents'
  url: https://www.elastic.co/security-labs/threat-command/coding-agent-launchagent-tunnel-detection
related:
- hunt: mcp-server-anomalies
  reason: Model Context Protocol (MCP) servers represent another vector for local
    tool execution under agent control.
  relation: sibling
scenario:
  stages:
  - name: Coding Agent Shell Execution
    observables:
    - Claude Code
    - Cursor
    - zsh
    - --allow-dangerously-skip-permissions
    - /tmp/mcp_clean_landers.py
    slug: agent-parented-shell-execution
    tactic: execution
    techniques:
    - T1218
  - name: Credential Access and Harvesting
    observables:
    - security dump-keychain
    - curl -X POST
    - user=
    - password=
    - /login
    - lhr.life
    - trycloudflare.com
    slug: credential-access-and-exfiltration
    tactic: credential-access
    techniques:
    - T1555.001
  - name: Reverse Tunnel C2
    observables:
    - cloudflared
    - ngrok
    - localhost.run
    - lhr.life
    - trycloudflare.com
    - api.trycloudflare.com
    slug: reverse-tunnel-establishment
    tactic: command-and-control
    techniques:
    - T1572
  - name: External Service Persistence
    observables:
    - LaunchAgents
    - .plist
    - launchd
    - ~/.zshenv
    slug: launchagent-persistence
    tactic: persistence
    techniques:
    - T1133
  summary: This campaign involves the abuse of trusted coding agents like Claude Code
    and Cursor to proxy malicious activities, including credential harvesting from
    the macOS Keychain and the deployment of reverse tunnels using tools like cloudflared
    and ngrok. The attackers establish persistent remote access to local services
    via LaunchAgents, effectively bypassing firewall restrictions under the guise
    of legitimate developer operations.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Living-off-the-Agent: Coding Tunnels and Persistence

This hunt targets 'vibe-coded' intrusions where a developer workstation's trust in signed AI agents is abused to create remote access. By scoping to hosts running these agents and looking for correlated signals—agent-parented shells with dangerous flags, connections to free tunnel brokers (lhr.life, trycloudflare), and new LaunchAgent persistence—this hunt identifies sessions where an agent is used as a living-off-the-land execution proxy. It focuses on the behavioral overlap between legitimate developer automation and unauthorized remote management.

## scoping-agent-hosts
<!-- Identify hosts with AI coding agents -->
Focus the hunt on machines where agents like Claude Code or Cursor are installed using partial match on package and vendor names.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers using these agents. Silence
  suggests the agents are installed as portable binaries outside the package manager.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%claude%' OR LOWER(package_name) LIKE '%cursor%' OR LOWER(vendor_name) LIKE '%anthropic%' OR LOWER(vendor_name) LIKE '%anysphere%')
```

## corroborate-activity
<!-- Parallel evidence collection -->
parallel:
- → agent-parented-behavior
- → tunnel-prevalence
- → persistence-check
join: → triage

## agent-parented-behavior
<!-- Agent-parented shell and tunnel execution -->
Identify shells, credentialed curl commands, or tunnel binaries spawned by the AI agent using partial path matching.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process trees where Claude or Cursor spawn shells with sensitive flags or
  credential-heavy command lines. This is the primary signal for 'living-off-the-agent'
  proxying.
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
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%claude%' OR LOWER(parent_process_name) LIKE '%cursor%' OR LOWER(process_name) LIKE '%claude%' OR LOWER(process_name) LIKE '%cursor%') AND (LOWER(process_name) LIKE '%/zsh' OR LOWER(process_name) LIKE '%/bash' OR LOWER(process_name) LIKE '%/python%' OR LOWER(process_name) LIKE '%/curl' OR LOWER(process_name) LIKE '%/cloudflared' OR LOWER(process_name) LIKE '%/ngrok' OR LOWER(process_cmd_line) LIKE '%--allow-dangerously-skip-permissions%' OR LOWER(process_cmd_line) LIKE '%security dump-keychain%' OR LOWER(process_cmd_line) LIKE '%user=%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## tunnel-prevalence
<!-- Rare tunnel broker connections -->
Stack-count connections to known tunnel brokers, filtering for domain-based activity to identify rare usage.

```sqlite target=network role=baseline params=(tunnel_domains=tunnel_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A connection to a tunnel provider that stands out from fleet norms. Domain
  matching avoids noise from raw IP background traffic.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_hostname
  rare_below: 3
reads:
- dst_endpoint_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_hostname, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_hostname IS NOT NULL AND instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_hostname HAVING hosts <= 3 ORDER BY hosts ASC
```

## persistence-check
<!-- Anomalous LaunchAgent persistence -->
Check for new macOS persistence mechanisms that maintain tunnel connections outside of active sessions.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: LaunchAgent plists pointing to tunnel binaries or shell wrappers. Legitimate
  developers rarely install these for temporary testing.
reads:
- device_hostname
- job_name
- job_definition_path
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_definition_path, job_cmd_line, time FROM hb_scheduled_job WHERE job_kind = 'launchd' AND (LOWER(job_definition_path) LIKE '%/launchagents/%' OR LOWER(job_cmd_line) LIKE '%cloudflared%' OR LOWER(job_cmd_line) LIKE '%ngrok%' OR LOWER(job_cmd_line) LIKE '%lhr.life%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage
<!-- Triage agent-parented chains -->
```agent target=hunter
cite: required
context:
- agent-parented-behavior
- tunnel-prevalence
- persistence-check
max_iterations: 6
objective: Determine if the observed behavior represents unauthorized remote access
  via a coding agent. Specifically look for credentials POSTed to tunnel URLs combined
  with persistent LaunchAgents.
success_criteria: A per-host verdict citing specific process command lines and tunnel
  domains.
tools:
- endpoint
- network
```

## route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: insufficient-process-ancestry-tracking)
else: → analyst-review

## isolate-host
<!-- Isolate workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate the agent-parented tunnel processes, and collect the LaunchAgent plists for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Examine the cited command lines. Determine if the developer was self-testing a local app or if the agent session was manipulated. If malicious, investigate the credentials POSTed to the tunnel URL and check for lateral movement attempts.
```
→ end

---
analysis: A simple rule for 'zsh under Claude' would fire hundreds of times a day
  for developers. This hunt uses a phased approach to read the context of those shells,
  looking for the specific combination of ephemeral tunnels and LaunchAgent persistence
  that separates intrusion from development automation.
blind_spots:
- id: command-line-truncation
  question: whether credentials were redacted or truncated before reaching the SIEM
  requires: full length command lines
  risk: If the 'curl' POST body is truncated, the triage agent may miss clear evidence
    of credential exposure.
  stage: credential-auth-over-tunnel-broker
- id: missing-macos-persistence-telemetry
  question: whether the LaunchAgent was modified in a way that does not trigger a
    new job event
  requires: detailed launchd configuration auditing
  risk: Adversaries may modify existing plists which might not show up as a 'create'
    event on some providers.
  stage: persistence-via-launchagent
coverage:
- stage: agent-parented-shell-execution
  status: covered
  steps:
  - agent-child-shells
  - mcp-script-activity
- stage: credential-auth-over-tunnel-broker
  status: covered
  steps:
  - agent-child-shells
- stage: reverse-tunnel-establishment
  status: covered
  steps:
  - tunnel-dns-activity
- stage: persistence-via-launchagent
  status: covered
  steps:
  - rare-launchagent-persistence
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Signed coding agents are highly trusted but have the capability to
    execute arbitrary code and tunnels; confirming their children are benign is an
    essential verification for developer estates.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a signed coding agent to proxy shell execution,
  establish reverse tunnels for service exposure, and install LaunchAgent persistence
  on a developer workstation.
labels:
- hunt
- attack.t1218
- attack.t1572
- attack.t1133
- attack.t1555.001
- attack.t1566
name: 'Living off the coding agent: Tunnels and LaunchAgents'
parameters:
  lookback_days:
    default: '14'
    description: Number of days to search back in telemetry history.
    from:
      kind: manual
      observed: '2026-08-07'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty to hunt
      across the entire fleet.
    from:
      kind: manual
      observed: '2026-08-07'
      ref: hunt-standard
    type: list[host]
  tunnel_domains:
    default:
    - lhr.life
    - localhost.run
    - trycloudflare.com
    - api.trycloudflare.com
    - ngrok-free.app
    - tunnel.us.ngrok.com
    description: Common domains used by free tunnel brokers and reverse-proxy services.
    from:
      kind: article
      observed: '2026-08-07'
      ref: elastic-security-labs
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with developer-class endpoints where Claude Code or Cursor are installed.
  These tools are signed by Anthropic and Cursor respectively.
references:
- name: "Elastic Security Labs \u2014 Living off the coding agent"
  url: https://www.elastic.co/security-labs/threat-command/coding-agent-launchagent-tunnel-detection
related:
- hunt: macos-tcc-bypass-via-signed-binary
  reason: Both hunts deal with abuse of signed binaries on macOS to perform high-privilege
    actions.
  relation: sibling
scenario:
  stages:
  - name: Proxy Execution via Coding Agent
    observables:
    - Claude Code
    - Cursor
    - zsh as child of coding agent
    - --allow-dangerously-skip-permissions
    - python3 /tmp/mcp_clean_landers.py
    - cat > ~./claude/projects/*/memory/MEMORY.md
    slug: agent-parented-shell-execution
    tactic: execution
    techniques:
    - T1218
  - name: Credentialed HTTP via Tunnel Brokers
    observables:
    - curl -X POST
    - lhr.life
    - localhost.run
    - '*.trycloudflare.com'
    - user=...&password=... in command line
    - "Status strings: \u043F\u0440\u043E\u0432\u0435\u0440\u043A\u0430"
    - Keychain dump filtered for OAuth material
    slug: credential-auth-over-tunnel-broker
    tactic: credential-access
    techniques:
    - T1555.001
    - T1572
  - name: Reverse Tunneling for Service Exposure
    observables:
    - cloudflared tunnel --url http://localhost:8080
    - ngrok
    - api.trycloudflare.com
    - pritunl-client
    - wireguard-go
    slug: reverse-tunnel-establishment
    tactic: command-and-control
    techniques:
    - T1572
  - name: Persistence via LaunchAgent
    observables:
    - LaunchAgents
    - launchd parented ngrok
    - quarantine stripping
    - ad-hoc re-signing of binaries
    - ~/.zshenv persistence canary
    slug: persistence-via-launchagent
    tactic: persistence
    techniques:
    - T1133
  summary: This campaign leverages the inherent trust in vendor-signed coding agents
    like Claude Code and Cursor to proxy the execution of malicious shells on macOS
    developer workstations. The intrusion sequence involves using these agent-parented
    shells to authenticate to free tunnel brokers, establish reverse tunnels to expose
    local administrative services to the internet, and ensure persistence via LaunchAgents.
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
tlp: clear
type: investigation
---


# Living off the coding agent: Tunnels and LaunchAgents

The phased flow ensures that the hunt weighs early evidence of proxy execution before searching for follow-on persistence and C2 markers. An adversary uses a signed coding agent to proxy shell execution and establish reverse tunnels. The analyst reviews the correlated chain to distinguish development work from an intrusion.

## find-agent-hosts
<!-- Identify hosts with coding agents -->
Find endpoints where known coding agents are installed to focus the behavioral hunt.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to developers or users with GenAI tools. Silence
  means no such tools are indexed in software inventory.
reads:
- package_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%claude%' OR LOWER(package_name) LIKE '%cursor%')
```

## early-execution-check
<!-- Parallel Early Execution Check -->
parallel:
- → agent-child-shells
- → mcp-script-activity
join: → early-stage-triage

## agent-child-shells
<!-- Shells spawned by coding agents -->
Identify instances where Claude or Cursor spawned interactive shells, which an adversary uses to proxy further commands.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process trees showing a signed agent spawning a shell. This is a baseline
  for 'Claude Code' but serves as the starting point for behavior correlation.
reads:
- process_name
- process_cmd_line
- parent_process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%zsh' OR LOWER(process_name) LIKE '%bash') AND (LOWER(parent_process_name) LIKE '%claude%' OR LOWER(parent_process_name) LIKE '%cursor%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mcp-script-activity
<!-- Staging scripts in temporary paths -->
Find Python or OSA scripts running from /tmp, which an adversary uses as a known staging location for agent-parented automation.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Scripts with names like 'mcp_clean_landers.py' or shell wrappers touching
  agent memory files. Silence means no suspicious staging was observed.
reads:
- process_cmd_line
- process_name
- parent_process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, process_cmd_line, process_name, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%/tmp/%' OR LOWER(process_cmd_line) LIKE '%mcp_%') AND (LOWER(parent_process_name) LIKE '%claude%' OR LOWER(parent_process_name) LIKE '%cursor%' OR LOWER(parent_process_name) LIKE '%zsh') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early execution -->
```agent target=hunter
cite: required
context:
- agent-child-shells
- mcp-script-activity
max_iterations: 3
objective: Analyze the process trees and command lines to identify if 'Claude Code'
  or 'Cursor' execute suspicious shells or scripts in /tmp.
success_criteria: A per-host verdict citing specific command lines.
tools:
- endpoint
```

## persistence-and-network-check
<!-- Persistence and Network Check -->
parallel:
- → rare-launchagent-persistence
- → tunnel-dns-activity
join: → follow-on-triage

## rare-launchagent-persistence
<!-- Rare persistence via LaunchAgents -->
Detect new or modified LaunchAgents, stack-counting them across the fleet to find outliers indicating persistent adversary access.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Unique LaunchAgent commands seen on few hosts. Silence means no rare persistence
  was detected in this path.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- job_cmd_line
- device_hostname
- time
- job_definition_path
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT job_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_scheduled_job WHERE (LOWER(job_definition_path) LIKE '%/launchagents/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_cmd_line HAVING host_count <= 3
```

## tunnel-dns-activity
<!-- Network connections to tunnel brokers -->
Match host activity against known free-tunnel domains that facilitate reverse tunneling for service exposure.

```sqlite target=endpoint role=enrichment params=(tunnel_domains=tunnel_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS queries for tunnel brokers. Any hit under the same PID or parentage
  as the coding agent is high severity.
reads:
- query_hostname
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-21'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{tunnel_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.lhr.life' OR LOWER(query_hostname) LIKE '%.trycloudflare.com') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Analyze tunneling and persistence -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- rare-launchagent-persistence
- tunnel-dns-activity
max_iterations: 5
objective: Analyze the relationship between the coding agent activity and the observed
  tunneling or persistence markers.
success_criteria: A verdict of 'malicious' if an agent spawned a tunnel or created
  persistence; 'suspicious' if domains were contacted; 'benign' otherwise.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: command-line-truncation)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any OAuth or GitHub tokens identified in the agent memory directories (~/.claude).
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the 'mcp_' script contents if available. Check if the 'spend' metrics mentioned in the command line correspond to authorized cloud resources.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. If a new tunnel provider was discovered, add its domain to the 'tunnel_domains' parameter for the next run.
```
→ end

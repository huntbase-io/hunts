---
analysis: A standard detection rule might alert on PowerShell on macOS; this hunt
  adds the essential context of non-interactive Entra ID sign-ins, rare Graph API
  HTTP traffic, and script block analysis of Microsoft.Graph.Beta modules to confirm
  a specific attack chain.
blind_spots:
- id: missing-graph-logs
  question: What were the actual contents and recipients of the Teams messages?
  remediation: Ingest MicrosoftGraphActivityLogs for detailed API request body visibility.
  requires: MicrosoftGraphActivityLogs or Purview Audit
  risk: Endpoint and network logs show 'that' a message was sent but not 'what' it
    contained; a malicious link may have already been clicked before detection.
  stage: teams-link-distribution
- id: non-interactive-mfa-bypass
  question: Was the token exchange performed without MFA due to conditional access
    bypass?
  requires: hb_auth_signin with mfa column
  risk: Agent Users use non-interactive flows which often bypass MFA; without explicit
    MFA status in logs, it's harder to prove a session was hijacked versus legitimate
    automation.
  stage: agent-user-token-exchange
coverage:
- stage: agent-user-token-exchange
  status: covered
  steps:
  - agent-user-signins
- stage: powershell-graph-execution
  status: covered
  steps:
  - macos-powershell-activity
  - graph-script-blocks
- stage: teams-link-distribution
  status: covered
  steps:
  - rare-graph-http-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Entra ID Agent Users are a new, highly-privileged identity type designed
    for AI automation. Compromise allows an attacker to masquerade as a trusted internal
    service, bypassing many traditional phishing defenses in Microsoft Teams.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is abusing a non-interactive Entra ID Agent User identity
  to distribute malicious content via Microsoft Teams, identifiable by PowerShell
  Graph API execution on non-standard platforms and unusual token exchange patterns.
labels:
- hunt
- attack.t1059.001
- attack.t1078.004
- attack.t1566.002
name: Suspicious Entra Agent User Teams Activity
parameters:
  graph_domains:
    default:
    - login.microsoftonline.com
    - graph.microsoft.com
    - graph.microsoft.beta
    description: Microsoft Authentication and Graph API endpoints used in the agent
      user flow.
    from:
      kind: article
      observed: '2026-06-01'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts with PowerShell installed; paste results from the scoping step
      here to focus the hunt.
    type: list[host]
  suspicious_ips:
    default:
    - 51.3.97.221
    - 70.152.145.147
    description: IP addresses associated with reported suspicious Graph API or Agent
      User activity.
    from:
      kind: article
      observed: '2026-06-01'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on hosts with PowerShell (pwsh) installed. On macOS, this
  is a highly specific indicator of a power-user or automated workflow. If the software
  inventory is empty, widen to all hosts but filter for 'macOS' platform in the process
  activity step.
references:
- name: "Red Canary \u2014 Investigating suspicious AI workflows in Microsoft Entra\
    \ Agent ID"
  url: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/
related:
- hunt: suspicious-graph-api-permissions-grant
  reason: Before an agent user can send messages, the underlying blueprint or identity
    must be granted specific OAuth scopes.
  relation: precedes
scenario:
  stages:
  - name: Agent User Authentication
    observables:
    - MrRoboto4@ContosoCorp.onmicrosoft.com
    - Agent.agentSubjectType == agentIDuser
    - Agent.agentType == agenticAppInstance
    - 'Source IP: 51.3.97.221'
    - Token request to login.microsoftonline.com
    slug: agent-user-token-exchange
    tactic: credential-access
    techniques:
    - T1078.004
  - name: PowerShell Graph API Execution
    observables:
    - 'User-Agent: Mozilla/5.0 (Macintosh; macOS 26.4.1; en-US) PowerShell/7.6.1'
    - Connect-MgGraph -AccessToken
    - New-MgBetaTeamChannelMessage
    - Get-MgBetaTeam
    - Get-MgBetaTeamChannel
    slug: powershell-graph-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Malicious Link Distribution
    observables:
    - https://domoarigato.ai/
    - POST request to microsoft.graph.beta
    - Message ID 1778247017240
    slug: teams-link-distribution
    tactic: initial-access
    techniques:
    - T1566.002
  summary: An attacker leverages a Microsoft Entra Agent User identity to impersonate
    an automated service account and send malicious phishing links to human users
    via Microsoft Teams. The campaign uses a PowerShell script on a macOS host to
    perform a complex OAuth token exchange before interacting with the Microsoft Graph
    API to deliver malicious content.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Suspicious Entra Agent User Teams Activity

This hunt investigates the abuse of Microsoft Entra 'Agent Users'—automated identities used for AI and integration workflows. An attacker compromising these credentials can send malicious messages within the trusted Teams perimeter. We look for the technical footprint of this workflow: PowerShell execution on macOS (the attacker's platform), non-interactive OAuth sign-ins from suspicious IPs, and Graph API requests targeting Teams channel messages with a distinct PowerShell User-Agent. The hunt correlates endpoint, identity, and network telemetry to differentiate legitimate automation from malicious exploitation.

## scope-powershell-inventory
<!-- Scope Hosts with PowerShell Installed -->
Identify hosts where PowerShell (pwsh) is installed, focusing on non-Windows platforms like macOS where its usage for AI automation is a high-fidelity pivot point.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. On macOS hosts, this narrows the search to systems
  capable of running the reported Graph API automation scripts.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%powershell%' OR LOWER(package_name) LIKE '%pwsh%'
```

## parallel-evidence-gathering
<!-- Gather Evidence Across Surfaces -->
parallel:
- → macos-powershell-activity
- → agent-user-signins
- → rare-graph-http-activity
- → graph-script-blocks
join: → triage-agent

## macos-powershell-activity
<!-- PowerShell Execution on macOS -->
Detect PowerShell (pwsh) processes running on macOS, which is the reported platform for the malicious activity.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: PowerShell processes on macOS systems. Silence on a system that has the
  software installed is evidence of absence.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%pwsh%' OR LOWER(process_path) LIKE '%/bin/pwsh%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-user-signins
<!-- Non-Interactive Agent User Sign-ins -->
Find non-interactive authentication attempts from suspicious IPs or involving OAuth protocols used for automated token exchange.

```sqlite target=identity role=enrichment params=(suspicious_ips=suspicious_ips, lookback_days=lookback_days)
~~~yaml
expected: Auth events from the report's IPs or automated OAuth sign-ins that lack
  a corresponding interactive session.
reads:
- actor_user_name
- src_endpoint_ip
- auth_protocol
- dst_endpoint_name
- time
- provider
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, auth_protocol, dst_endpoint_name, time FROM hb_auth_signin WHERE (instr(',' || '{{suspicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR (provider = 'm365' AND auth_protocol = 'OAuth')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-graph-http-activity
<!-- Rare PowerShell HTTP Requests to Graph -->
Stack-count HTTP requests to Microsoft Graph with a PowerShell User-Agent to identify rare or anomalous messaging activity.

```sqlite target=web role=baseline params=(graph_domains=graph_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of requests to Graph endpoints from a host. The PowerShell
  User-Agent on a macOS host is the primary behavioral pivot.
prevalence:
  by: device_hostname
  key:
  - user_agent
  - url_hostname
  rare_below: 5
reads:
- device_hostname
- url_hostname
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, user_agent, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (instr(',' || '{{graph_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(user_agent) LIKE '%powershell%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING request_count <= 20 ORDER BY request_count ASC
```

## graph-script-blocks
<!-- Microsoft Graph Cmdlets in Script Blocks -->
Inspect script content for the exact PowerShell cmdlets used to authenticate and automate Teams messaging via the Graph API.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing cmdlets like New-MgBetaTeamChannelMessage or Connect-MgGraph.
  This confirms the 'how' of the message distribution.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%mggraph%' OR LOWER(script_content) LIKE '%mgbeta%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage Agent User Activity -->
```agent target=hunter
cite: required
context:
- macos-powershell-activity
- agent-user-signins
- rare-graph-http-activity
- graph-script-blocks
max_iterations: 5
objective: Determine if an identity (Agent User) performed non-interactive sign-ins,
  followed by PowerShell execution on macOS and Graph API requests to Teams messaging
  endpoints.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  script blocks and HTTP request patterns.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host and identity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: missing-graph-logs)
else: → close-out

## isolate-host
<!-- Isolate Host and Revoke Tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host. Revoke all active tokens for the Entra ID Agent User and reset the parent blueprint's credentials.
```
→ analyst-triage

## analyst-triage
<!-- Analyst Triage and Tuning -->
```manual target=analyst
Review the Graph API request logs in Microsoft Purview if available to see the exact message content. Update the 'suspicious_ips' list with any new source IPs found.
```
→ end

## close-out
<!-- Close and Record Result -->
```manual target=analyst
Document that no suspicious Agent User activity was observed on macOS hosts during the lookback period.
```
→ end

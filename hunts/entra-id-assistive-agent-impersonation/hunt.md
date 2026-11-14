---
analysis: A simple detection rule might catch PowerShell on macOS, but it cannot link
  that activity back to an Entra ID consent grant and an agentic on-behalf-of flow.
  This hunt correlates identity-side consent with endpoint-side execution outliers
  across multiple planes.
blind_spots:
- id: limited-agentic-telemetry
  question: Was the authentication explicitly an OBO flow using an agenticAppInstance?
  requires: Detailed Entra Sign-in Metadata such as Agent.agentType
  risk: Standard authentication logs may not expose the deep agentic flags needed
    to distinguish OBO from standard service principal usage without high-fidelity
    cloud-native logs.
  stage: agent-token-impersonation
- id: graph-operation-opacity
  question: What specific actions did the agent perform via the API?
  requires: MicrosoftGraphActivityLogs
  risk: While network traffic to graph.microsoft.com is visible, the specific intent
    is hidden without access to Graph activity logging, which requires specific subscription
    tiers.
  stage: graph-api-malicious-action
coverage:
- stage: consent-granting-delegated-access
  status: covered
  steps:
  - identify-graph-cli-auth
- stage: agent-token-impersonation
  status: covered
  steps:
  - detect-agentic-obo-signins
  - evaluate-early-identity-risk
- stage: powershell-endpoint-execution
  status: covered
  steps:
  - rare-macos-powershell-execution
- stage: graph-api-malicious-action
  status: covered
  steps:
  - correlate-network-to-graph
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The rapid adoption of AI agents creates a new impersonation vector
    that bypasses traditional human-centric behavioral monitoring. Protecting Entra
    Agent ID integrity ensures that automated workflows are not used as a stealthy
    exfiltration channel.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access by tricking a user into consenting
  to an assistive agent blueprint, then used an on-behalf-of flow to execute malicious
  Graph API actions from a macOS-based PowerShell environment.
labels:
- hunt
- attack.t1098
- attack.t1528
- attack.t1059.001
- attack.t1567
name: Entra ID Assistive Agent Impersonation
parameters:
  graph_cli_app_id:
    default: 14d82eec-204b-4c2f-b7e8-296a70dab67e
    description: The Entra client application ID for Microsoft Graph Command Line
      Tools used for consent.
    from:
      kind: article
      observed: '2026-06-08'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_ips:
    default:
    - 51.3.97.221
    - 40.126.23.26
    description: IP addresses observed in the report associated with agentic sign-ins
      and malicious actions.
    from:
      kind: article
      observed: '2026-06-08'
      ref: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the endpoint phase on; derived
      from the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all macOS hosts with PowerShell installed. The identity
  phase should focus on users who have interacted with the Graph CLI application,
  as this is the primary mechanism for establishing the agent identity scope.
references:
- name: 'Investigating suspicious AI workflows in Microsoft Entra Agent ID: Assistive
    agents'
  url: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/
related:
- hunt: oauth-app-consent-abuse
  reason: This hunt focuses specifically on assistive agents and Entra Agent ID, not
    general OAuth application abuse.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: OAuth Consent for Assistive Agent
    observables:
    - access_agent scope
    - http://localhost/
    - 14d82eec-204b-4c2f-b7e8-296a70dab67e
    - Dev Agent Identity Blueprint - NOT FOR PROD
    slug: consent-granting-delegated-access
    tactic: initial-access
    techniques:
    - T1098
  - name: On-Behalf-Of Token Acquisition
    observables:
    - agenticAppInstance
    - notAgentic
    - 8cd0a10f-0be8-413a-9bf2-f44bc568d1e4
    - Group.Read.All
    - Mail.ReadWrite
    - Mail.Send
    - MailboxSettings.ReadWrite
    slug: agent-token-impersonation
    tactic: credential-access
    techniques:
    - T1528
  - name: Execution via PowerShell on macOS
    observables:
    - Mozilla/5.0 (Macintosh; macOS 26.4.1; en-US) PowerShell/7.6.1
    - 51.3.97.221
    slug: powershell-endpoint-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Unauthorized Email via Graph API
    observables:
    - bigwig_CFO@importantcompany.com
    - Here is your invoice
    - 40.126.23.26
    - Microsoft Graph beta API
    slug: graph-api-malicious-action
    tactic: exfiltration
    techniques:
    - T1567
  summary: Attackers exploit Microsoft Entra Assistive Agents by tricking users into
    granting 'access_agent' scopes via OAuth consent, often using localhost-redirect
    URIs. This allows the agent to obtain On-Behalf-Of (OBO) tokens to impersonate
    the user and perform unauthorized actions, such as sending malicious emails via
    the Microsoft Graph API from attacker-controlled environments using PowerShell.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Entra ID Assistive Agent Impersonation

This hunt targets the abuse of Microsoft Entra Agent ID, specifically the assistive agent workflow. It follows the attack chain from the initial OAuth consent for the access_agent scope to the final malicious action performed via the Graph API. The hunt identifies high-risk identity sessions and then verifies corresponding endpoint execution. We look for the correlation of unusual Entra ID sign-in patterns, specifically agentic app instances, with endpoint-side PowerShell activity on macOS and corresponding network traffic to Microsoft Graph services.

## find-macos-powershell-hosts
<!-- Find macOS hosts with PowerShell installed -->
Identify the subset of the estate where the malicious execution (PowerShell on macOS) is possible.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of macOS hostnames with Microsoft PowerShell installed. These hosts
  represent the potential beachheads for the macOS execution stage.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) = 'powershell' OR LOWER(package_name) = 'pwsh') AND LOWER(vendor_name) LIKE '%microsoft%'
```

## early-stage-parallel
<!-- Investigate identity consent and agentic sign-ins -->
parallel:
- → identify-graph-cli-auth
- → detect-agentic-obo-signins
join: → evaluate-early-identity-risk

## identify-graph-cli-auth
<!-- Identify Graph CLI authentication -->
Locate authentications to the Graph CLI application, which often precedes the local capture of authorization codes.

```sqlite target=identity role=triage params=(graph_cli_app_id=graph_cli_app_id, lookback_days=lookback_days)
~~~yaml
expected: A list of users who have authenticated to the Graph CLI. This is the pool
  of potentially compromised users who may have granted agent consent.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE (dst_endpoint_name = '{{graph_cli_app_id}}' OR LOWER(dst_endpoint_name) LIKE '%microsoft graph command line%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-agentic-obo-signins
<!-- Detect agentic OBO sign-in patterns -->
Stack-count sign-ins to agent blueprints to find rare and suspicious assistive agent activity across the tenant.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare agent blueprint targets. While some agents are legitimate, those used
  by only a few users are high-priority for investigation.
prevalence:
  by: actor_user_name
  key:
  - dst_endpoint_name
  rare_below: 3
reads:
- dst_endpoint_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_name, COUNT(DISTINCT actor_user_name) as user_count, MIN(time) as first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%blueprint%' OR LOWER(dst_endpoint_name) LIKE '%agent%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name HAVING user_count <= 3
```

## evaluate-early-identity-risk
<!-- Evaluate early identity risk -->
```agent target=hunter
cite: required
context:
- identify-graph-cli-auth
- detect-agentic-obo-signins
max_iterations: 4
objective: Identify users who authenticated to Graph CLI and subsequently initiated
  sessions with rare agent blueprints, potentially via OBO flows.
success_criteria: A per-user risk verdict citing the matching sign-in events.
tools:
- endpoint
- identity
- network
```

## follow-on-parallel
<!-- Correlate with macOS execution and network activity -->
parallel:
- → rare-macos-powershell-execution
- → correlate-network-to-graph
join: → final-attack-chain-triage

## rare-macos-powershell-execution
<!-- Detect rare macOS PowerShell execution -->
Find outlier PowerShell activity on macOS that may indicate the execution of agent-controlled tasks.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: PowerShell command lines seen on very few hosts. This filters out common
  IT scripts and focuses on unique, potentially malicious activity.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, user_name, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%pwsh%' OR LOWER(process_path) LIKE '%pwsh%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING host_count <= 3
```

## correlate-network-to-graph
<!-- Correlate network connections to Microsoft Graph -->
Corroborate that the identified macOS hosts and PowerShell processes are communicating with Graph API or known malicious IPs.

```sqlite target=network role=enrichment params=(malicious_ips=malicious_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Network activity from identified hosts to Graph API endpoints, confirming
  that the local execution has a corresponding cloud-side impact.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, time FROM hb_network_connection WHERE (LOWER(dst_endpoint_hostname) LIKE '%graph.microsoft.com%' OR instr(',' || '{{malicious_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-attack-chain-triage
<!-- Final attack chain triage -->
```agent target=hunter
cite: required
context:
- evaluate-early-identity-risk
- rare-macos-powershell-execution
- correlate-network-to-graph
max_iterations: 6
objective: Determine if the rare endpoint and network activity on macOS was triggered
  by the identity-side agent impersonation identified in the first phase.
success_criteria: A malicious/suspicious/benign verdict per host/user pair, citing
  specific events from all phases.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the triage verdict is malicious for at least one host and user pair" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → remediate-and-review
unavailable: → remediate-and-review (blind_spot: limited-agentic-telemetry)
else: → close-out-investigation

## isolate-host
<!-- Isolate host and revoke tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the macOS host; revoke the OAuth refresh tokens for the affected user; disable the specific agent identity if possible.
```
→ remediate-and-review

## remediate-and-review
<!-- Remediate and perform analyst review -->
```manual target=analyst
Review Purview/Exchange logs for emails sent by the agent ID. Inspect the endpoint for local PowerShell history or configuration files. Document the initial access vector such as the specific phishing link used for consent.
```
→ end

## close-out-investigation
<!-- Close out investigation -->
```manual target=analyst
Document the identified legitimate agentic workflows. Note the baseline usage of PowerShell on macOS for future tuning.
```
→ end

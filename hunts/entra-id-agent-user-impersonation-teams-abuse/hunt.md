---
analysis: "This hunt uses three distinct surfaces\u2014Entra sign-ins, host-based\
  \ PowerShell script blocks, and HTTP gateway telemetry\u2014to identify a specific\
  \ impersonation flow that a single log source cannot fully contextualize. It specifically\
  \ uses prevalence counting to find rare User-Agents and scripts that standard rules\
  \ would miss."
blind_spots:
- id: no-graph-visibility
  question: Can we see the User-Agent in Graph API requests?
  requires: hb_http_activity with TLS decryption
  risk: If the proxy does not decrypt Graph traffic, the User-Agent is invisible,
    forcing reliance on endpoint script logs.
  stage: graph-api-teams-message-dispatch
- id: script-block-logging-disabled
  question: Can we see the content of the mgbeta cmdlets?
  requires: PowerShell Script Block Logging (EID 4104)
  risk: If script block logging is disabled, the specific commands used to dispatch
    messages cannot be recovered from hb_script_activity.
  stage: graph-api-teams-message-dispatch
coverage:
- stage: agent-user-oauth-authentication
  status: covered
  steps:
  - identify-agent-user-logons
- stage: graph-api-teams-message-dispatch
  status: covered
  steps:
  - rare-graph-beta-scripts
  - graph-api-user-agents
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Agent User identities are trusted internal accounts that bypass standard
    interactive MFA; their use for Teams-based phishing represents a high-trust lateral
    movement risk.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker uses the Entra ID Agent User OAuth flow to impersonate an
  AI agent and dispatch malicious content via Microsoft Teams using Graph API cmdlets.
labels:
- hunt
- attack.t1059.001
name: Entra ID Agent User Impersonation and Teams Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow behavioral queries.
    type: list[host]
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on identities using the 'user_fic' grant type; this is the primary
  indicator of the Agent User OAuth flow. Start with cloud sign-in logs to establish
  a list of active Agent Users before pivoting to endpoint script activity.
references:
- name: "Red Canary \u2014 Investigating suspicious AI workflows in Microsoft Entra\
    \ Agent ID"
  url: https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/
related:
- hunt: suspicious-microsoft-graph-api-activity
  reason: This hunt focuses on the Agent User OAuth flow, whereas the sibling hunt
    covers general Graph API abuse.
  relation: sibling
scenario:
  stages:
  - name: Agent User OAuth Flow Authentication
    observables:
    - login.microsoftonline.com
    - api://AzureADTokenExchange/.default
    - grant_type=user_fic
    - requested_token_use=on_behalf_of
    - user_federated_identity_credential
    - agent.agentSubjectType == agentIDuser
    - agent.agentType == agenticAppInstance
    slug: agent-user-oauth-authentication
    tactic: execution
    techniques:
    - T1059.001
  - name: Teams Message Dispatch via Graph API
    observables:
    - microsoft.graph.beta
    - Mozilla/5.0 (Macintosh; macOS 26.4.1; en-US) PowerShell/7.6.1
    - 51.3.97.221
    - 70.152.145.147
    - New-MgBetaTeamChannelMessage
    - https://domoarigato.ai/
    - domoarigato.ai
    slug: graph-api-teams-message-dispatch
    tactic: initial-access
    techniques:
    - T1059.001
  summary: An attacker abuses Microsoft Entra ID Agent User identities to distribute
    malicious links via Microsoft Teams. The attack involves executing a PowerShell
    script on a macOS host to perform a specialized OAuth flow, impersonating an agent
    user to call the Graph API and send messages to team channels.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Entra ID Agent User Impersonation and Teams Abuse

This hunt identifies unauthorized use of Entra ID Agent User identities by correlating non-interactive authentication patterns with endpoint PowerShell script execution. It targets the 'user_fic' grant type and the impersonation of identities with an 'agentIDuser' subject type. The hunt flows from cloud authentication logs to endpoint telemetry, looking for specific Graph Beta PowerShell cmdlets and rare User-Agent strings used to send messages to Teams channels. An agent evaluates the combined evidence to distinguish legitimate autonomous agent activity from manual attacker-driven impersonation, specifically checking for temporal proximity between the cloud logon and the execution of script blocks.

## identify-agent-user-logons
<!-- Identify Agent User OAuth logons -->
Find non-interactive sign-ins to Microsoft Teams that use the federated identity credentials specific to Agent User impersonation.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows showing identities authenticating to Teams via the Agent User flow
  (user_fic). Silence suggests no such identities are active in the window.
reads:
- actor_user_name
- src_endpoint_ip
- auth_protocol
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, auth_protocol, dst_endpoint_name, time FROM hb_auth_signin WHERE provider = 'm365' AND LOWER(dst_endpoint_name) = 'microsoft teams' AND (LOWER(auth_protocol) LIKE '%user_fic%' OR LOWER(actor_user_name) LIKE '%agent%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## activity-fan-out
<!-- Parallel behavioral analysis -->
parallel:
- → rare-graph-beta-scripts
- → graph-api-user-agents
join: → triage-impersonation

## rare-graph-beta-scripts
<!-- Rare Graph Beta PowerShell scripts -->
Identify rare script blocks that call the specific Beta cmdlets used for Teams messaging to find manual dispatch activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare script blocks containing the Teams dispatch cmdlets. Common automation
  scripts will be filtered out by the prevalence count.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 5
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT script_content, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%new-mgbetateamchannelmessage%' OR LOWER(script_content) LIKE '%connect-mggraph%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING hosts < 5
```

## graph-api-user-agents
<!-- Rare Graph API User-Agents -->
Identify rare User-Agents hitting Microsoft Graph endpoints to isolate attacker-controlled PowerShell sessions.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A User-Agent string hitting Graph that is not part of the standard fleet
  automation baseline.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 5
reads:
- device_hostname
- url_hostname
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT user_agent, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_http_activity WHERE url_hostname LIKE '%graph.microsoft.com%' AND user_agent LIKE '%PowerShell/%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent HAVING hosts < 5
```

## triage-impersonation
<!-- Triage agent impersonation -->
```agent target=hunter
cite: required
context:
- identify-agent-user-logons
- rare-graph-beta-scripts
- graph-api-user-agents
max_iterations: 4
objective: Determine if an Entra ID Agent User was used by an unauthorized process
  to send suspicious Teams messages. Explicitly check for temporal proximity, such
  as a 60-minute window, between the Agent User sign-in event and the endpoint script
  execution or HTTP traffic.
success_criteria: A verdict of malicious | suspicious | benign for each identity,
  citing the script blocks and timestamps.
tools:
- endpoint
- identity
- web
```

## route-response
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one agent user" (confidence: high, judge=hunter)
then: → revoke-and-purge
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-graph-visibility)
else: → close-out

## revoke-and-purge
<!-- Revoke sessions and purge messages -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active OAuth refresh tokens for the identified Agent User and its parent Blueprint principal in Entra ID. Use the Teams Messaging Policy or Purview to identify and delete malicious messages sent by this agent user.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the cited script blocks and Graph API activity. Verify the revoked identity is no longer active and that reported messages have been successfully purged from Teams.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record incident findings. If the rare PowerShell User-Agent was consistent, consider promoting the HTTP query to a permanent detection rule.
```
→ end

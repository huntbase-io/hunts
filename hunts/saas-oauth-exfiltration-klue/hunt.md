---
analysis: A simple rule might fire on the actor IPs or the 'Klue' app name, but this
  hunt pivots between authentication context (the 'Klue' app), behavioral baselining
  (rare user-agents on API paths), and network corroboration (actor IPs) to reduce
  false positives from legitimate automated Klue activity.
blind_spots:
- id: missing-http-telemetry
  question: Whether the exact Salesforce query strings (e.g., SELECT FIELDS(STANDARD))
    are being used.
  requires: hb_http_activity with full URI visibility for SaaS endpoints
  risk: A generic HTTP log might only show the base path and not the query or message
    parameters required to confirm harvesting.
  stage: exfiltration-automated-api-harvesting
- id: auth-subtype-normalization
  question: Whether the authentication event explicitly used an OAuth Refresh Token.
  requires: hb_auth_signin with login_sub_type field
  risk: Without the specific subtype, it is difficult to distinguish a legitimate
    Klue token refresh from actor reuse of a stolen refresh token.
  stage: persistence-oauth-token-abuse
coverage:
- stage: initial-access-third-party-compromise
  status: covered
  steps:
  - find-klue-auth
- stage: persistence-oauth-token-abuse
  status: covered
  steps:
  - find-klue-auth
- stage: command-and-control-proxy-infrastructure
  status: covered
  steps:
  - klue-actor-ips
- stage: exfiltration-automated-api-harvesting
  status: covered
  steps:
  - api-harvesting-behavior
  - rare-api-tools
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: A third-party compromise like Klue provides a bypass for traditional
    network perimeters; identifying whether this access was abused for automated exfiltration
    is a critical risk-reduction objective.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging a compromised third-party OAuth application
  (Klue Battlecards) to exfiltrate CRM data from Salesforce via automated API calls
  from known actor infrastructure.
labels:
- hunt
- attack.t1195
- attack.t1041
- attack.t1090.003
- attack.t1566
name: Third-party SaaS Data Exfiltration via OAuth (Klue)
parameters:
  actor_ips:
    default:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    description: Known Icarus threat actor IP addresses.
    from:
      kind: article
      observed: '2026-06-11'
      ref: datadog-klue-report
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  python_user_agents:
    default:
    - Python-urllib/3.12
    - Python-urllib/3.14
    - '5238'
    description: User agents observed in the Klue exfiltration campaign.
    from:
      kind: article
      observed: '2026-06-11'
      ref: datadog-klue-report
    type: list[string]
  salesforce_api_path:
    default: /services/data/v59.0/query%
    description: The specific Salesforce query API endpoint targeted.
    type: string
  scope_hosts:
    default: []
    description: Filter by specific server hostnames (optional).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with SaaS integration accounts. If signs of 'Klue Battlecards' usage
  exist, pivot to source IP analysis across the HTTP surface.
references:
- name: Detecting the Klue supply chain attack in Salesforce
  url: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
related:
- hunt: salesforce-privilege-escalation-api
  reason: This hunt focuses on exfiltration; a sibling hunt might examine how those
    tokens are used to escalate privileges or modify configuration.
  relation: sibling
scenario:
  stages:
  - name: Third-party Supply Chain Compromise
    observables:
    - 'Application name: Klue Battlecards'
    - 'Connected app name: Klue Battlecards'
    slug: initial-access-third-party-compromise
    tactic: initial-access
    techniques:
    - T1195
  - name: OAuth Token and Refresh Token Abuse
    observables:
    - 'login_sub_type: oauthrefreshtoken'
    - 'login_sub_type: "OAuth Refresh Token"'
    slug: persistence-oauth-token-abuse
    tactic: persistence
    techniques:
    - T1195
  - name: External Proxy Infrastructure
    observables:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    slug: command-and-control-proxy-infrastructure
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Automated SaaS API Exfiltration
    observables:
    - 'User-Agent: Python-urllib/3.12'
    - 'User-Agent: Python-urllib/3.14'
    - 'User-Agent: 5238'
    - 'URI path: /services/data/v59.0/query/*'
    - 'Query message: QueryMore'
    - 'Query string: SELECT FIELDS(STANDARD)'
    - 'Exception message: common.exception.ApiException'
    - 'Targeted objects: Opportunity, Case, Task, Lead, Contact, Account, User, Contract,
      Event, Campaign'
    slug: exfiltration-automated-api-harvesting
    tactic: exfiltration
    techniques:
    - T1041
  summary: The threat actor Icarus compromised the backend of the Klue market intelligence
    platform to steal customer OAuth tokens. They then used these tokens to perform
    automated, large-scale data exfiltration from victim Salesforce environments using
    Python-based scripts and specific API query patterns.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Third-party SaaS Data Exfiltration via OAuth (Klue)

This hunt identifies automated harvesting of Salesforce data following the Klue supply chain compromise. It focuses on identifying anomalous authentication via the 'Klue Battlecards' application, specifically checking for the use of OAuth refresh tokens and correlating this with known actor IPs and the use of 'Python-urllib' user agents targeting Salesforce query endpoints. The hunt baselines API activity to find rare automated tools and uses a triage agent to weigh the combination of third-party app usage, suspicious networking, and exfiltration-consistent HTTP patterns.

## find-klue-auth
<!-- Identify Klue Battlecards integration usage -->
Find users and source IPs authenticating through the 'Klue Battlecards' connected application, which is the vector for this supply chain attack.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows identify specific user accounts and source IPs utilizing the Klue integration.
  Silence indicates the integration was not used in the observed window.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%klue%' OR LOWER(dst_endpoint_name) LIKE '%battlecard%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol
```

## corroborate-activity
<!-- Corroborate authentication with network and HTTP indicators -->
parallel:
- → klue-actor-ips
- → api-harvesting-behavior
- → rare-api-tools
join: → triage-klue-threat

## klue-actor-ips
<!-- Connections to known Icarus actor infrastructure -->
Match network traffic against the IPs confirmed to be used in the Klue extortion campaign.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, actor_ips=actor_ips)
~~~yaml
expected: Any connection to or from these IPs is a high-confidence indicator of activity
  related to the Klue threat actor.
reads:
- connection_state
- dst_endpoint_ip
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, dst_endpoint_ip, connection_state, COUNT(*) as connection_count FROM hb_network_connection WHERE (instr(',' || '{{actor_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 OR instr(',' || '{{actor_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_ip, connection_state
```

## api-harvesting-behavior
<!-- Automated Salesforce API harvesting patterns -->
Find HTTP activity using Python-based exfiltration scripts targeting the Salesforce REST query API.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, salesforce_api_path=salesforce_api_path, python_user_agents=python_user_agents, scope_hosts=scope_hosts)
~~~yaml
expected: Rows indicate specific source IPs using known malicious user agents to query
  the Salesforce API. Silence suggests these specific strings were not seen.
reads:
- device_hostname
- src_endpoint_ip
- status_code
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, url_path, user_agent, status_code, COUNT(*) as req_count FROM hb_http_activity WHERE (LOWER(url_path) LIKE '{{salesforce_api_path}}') AND (instr(',' || '{{python_user_agents}}' || ',', ',' || user_agent || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_path, user_agent, status_code
```

## rare-api-tools
<!-- Baseline: Rare User-Agents querying Salesforce API -->
Identify novel or rare automated tools querying the Salesforce API to catch rotated indicators.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, salesforce_api_path=salesforce_api_path)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of User-Agents used by only one or two source IPs. Legitimate integrations
  usually have stable source IPs or a wider footprint.
prevalence:
  by: src_endpoint_ip
  key:
  - user_agent
  rare_below: 3
reads:
- src_endpoint_ip
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT user_agent, COUNT(DISTINCT src_endpoint_ip) AS unique_ips, COUNT(*) AS request_total, MIN(time) AS first_seen FROM hb_http_activity WHERE LOWER(url_path) LIKE '{{salesforce_api_path}}' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent HAVING unique_ips <= 2 ORDER BY unique_ips ASC
```

## triage-klue-threat
<!-- Triage automated Salesforce exfiltration -->
```agent target=hunter
cite: required
context:
- find-klue-auth
- klue-actor-ips
- api-harvesting-behavior
- rare-api-tools
max_iterations: 5
objective: Determine if any Salesforce account or source IP shows a combination of
  'Klue Battlecards' app usage, connections to actor infrastructure, and automated
  API harvesting via Python scripts.
success_criteria: A verdict of malicious | suspicious | benign citing specific IPs
  and User-Agents.
tools:
- identity
- network
- web
```

## decide-impact
<!-- Route on threat verdict -->
if~: "the triage verdict is malicious for at least one source IP or account" (confidence: high, judge=hunter)
then: → revoke-oauth-tokens
indeterminate: → manual-investigation
unavailable: → manual-investigation (blind_spot: missing-http-telemetry)
else: → close-hunt

## revoke-oauth-tokens
<!-- Revoke Salesforce OAuth Tokens -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all OAuth access tokens and refresh tokens associated with the 'Klue Battlecards' connected application for identified users.
```
→ manual-investigation

## manual-investigation
<!-- Manual Investigation -->
```manual target=analyst
Review Salesforce Event Log Files (RestApi, ApiTotalUsage) for the specific users. Look for QueryMore activity and check for 'ApiException' errors that suggest high-volume data harvesting attempts.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
Document the search parameters used and the lack of correlation between Klue integration and actor infrastructure.
```
→ end

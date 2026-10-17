---
analysis: This hunt correlates authentication (Sign-in logs), endpoint execution (Script
  Blocks), and server-side traffic (Activity Logs) to identify rare patterns that
  a single detection rule would miss.
blind_spots:
- id: no-graph-logging
  owner: Cloud Platform Team
  question: whether directory objects were enumerated via the legacy API
  remediation: Enable the AzureADGraphActivityLogs diagnostic setting in the Entra
    ID portal.
  requires: AzureADGraphActivityLogs category in Entra ID Diagnostic Settings
  risk: If this diagnostic category is not enabled, server-side API activity remains
    invisible.
  stage: aad-graph-bulk-discovery
- id: no-http-telemetry
  owner: Network Security
  question: the specific URL parameters revealing internal API use
  remediation: Ensure hb_http_activity is populated via the Azure Graph Activity Logs
    integration.
  requires: hb_http_activity or HTTPS inspection
  risk: Without HTTP logs or decryption, the defender only sees a generic encrypted
    connection.
  stage: aad-graph-bulk-discovery
coverage:
- stage: aad-graph-authentication
  status: covered
  steps:
  - auth-lead-query
  - assess-auth-lead
- stage: aad-graph-tool-execution
  status: covered
  steps:
  - endpoint-script-patterns
- stage: aad-graph-bulk-discovery
  status: covered
  steps:
  - rare-user-agents
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries exploit legacy APIs to bypass modern monitoring; visibility
    into these logs closes a decade-long gap in Entra ID defense.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses legacy Azure AD Graph API endpoints and known offensive
  Client IDs to perform bulk directory enumeration, specifically targeting internal
  API versions that expose sensitive authentication methods.
labels:
- hunt
- attack.t1059.001
- attack.t1190
name: Bulk Directory Discovery via AAD Graph API
parameters:
  foci_client_ids:
    default:
    - 04b07795-8ddb-461a-bbee-02f9e1bf7b46
    - 1b730954-1685-4b74-9bfd-dac224a7b894
    description: Known offensive Client IDs for Azure CLI and PowerShell often used
      in FOCI-swap attacks.
    from:
      kind: article
      observed: '2026-06-19'
      ref: elastic-security-labs-aad-graph
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to narrow the search; if empty, all hosts are examined.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on users who successfully authenticated to legacy Graph endpoints.
  Widen the hunt if offensive Client IDs are found in Sign-in logs.
references:
- name: "Elastic Security Labs \u2014 Azure AD Graph Activity Logs: Ingestion and\
    \ threat detection"
  url: https://www.elastic.co/security-labs/blog/aad-graph-activity-logs-threat-detection
related:
- hunt: microsoft-graph-bulk-discovery
  reason: Adversaries may use modern Microsoft Graph endpoints; this hunt focuses
    exclusively on the legacy gap.
  relation: sibling
scenario:
  stages:
  - name: Legacy Graph OAuth Authentication
    observables:
    - roadrecon auth --device-code
    - 'Client ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46 (Azure CLI)'
    - 'Client ID: 1b730954-1685-4b74-9bfd-dac224a7b894 (Azure PowerShell)'
    - 'resource: https://graph.windows.net'
    slug: aad-graph-authentication
    tactic: initial-access
    techniques:
    - T1190
  - name: Recon Tooling Execution
    observables:
    - roadrecon gather
    - az account get-access-token --resource https://graph.windows.net
    - powershell.exe
    - python.exe
    - pip install roadrecon
    slug: aad-graph-tool-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Directory Object Enumeration
    observables:
    - graph.windows.net
    - api-version=1.61-internal
    - api-version=1.6
    - api-version=1.5
    - 'url_path: /users'
    - 'url_path: /groups'
    - 'url_path: /servicePrincipals'
    - 'url_path: /applications'
    - 'url_path: /tenantDetails'
    - 'User-Agent: Microsoft.OData.Client'
    - 'User-Agent: Microsoft Azure Graph Client Library'
    - 'User-Agent: Microsoft ADO.NET Data Services'
    - 'User-Agent: Python aiohttp'
    - 'User-Agent: curl'
    - strongAuthenticationDetail
    - application.authenticationBehaviors
    slug: aad-graph-bulk-discovery
    tactic: discovery
    techniques:
    - T1059.001
  summary: Adversaries exploit the legacy Azure AD Graph API (graph.windows.net) to
    perform bulk directory enumeration using tools like ROADrecon and AADInternals.
    By leveraging deprecated internal API versions such as 1.61-internal, they can
    bypass modern security controls to extract sensitive information like MFA details
    and conditional access policies.
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


# Bulk Directory Discovery via AAD Graph API

Adversaries leverage the legacy graph.windows.net API because it has historically lacked the granular logging of modern Microsoft Graph. This hunt identifies the use of ROADrecon and AADInternals by first gating on successful authentication events using offensive FOCI (Family of Client IDs) applications. If an authentication lead is found, the hunt fans out to correlate rare User-Agents in server-side Graph Activity Logs with behavioural script execution patterns on the endpoint. This specifically targets the abuse of the internal-only 1.61-internal API version which exposes sensitive authentication details.

## auth-lead-query
<!-- Authentication to legacy Graph resource -->
Identify successful authentication events to the legacy Azure AD Graph resource using client IDs commonly associated with offensive tools.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, foci_client_ids=foci_client_ids)
~~~yaml
expected: Successful token acquisition for the legacy Graph resource by unexpected
  users or using offensive client IDs.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%graph.windows.net%' OR instr(',' || '{{foci_client_ids}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-auth-lead
<!-- Assess authentication lead -->
```agent target=hunter
cite: required
context:
- auth-lead-query
max_iterations: 3
objective: Determine if any successful authentication to the legacy Graph resource
  represents an anomalous lead.
success_criteria: Identification of suspicious identities for follow-on behavioral
  queries.
tools:
- endpoint
- identity
- web
```

## gate-on-lead
<!-- Gate on lead -->
if~: "the assess-auth-lead agent identifies a successful authentication that is anomalous for the user or involves a known offensive client ID" (confidence: high, judge=hunter)
then: → parallel-investigation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-graph-logging)
else: → close-out

## parallel-investigation
<!-- Parallel activity search -->
parallel:
- → rare-user-agents
- → endpoint-script-patterns
join: → triage-investigation

## rare-user-agents
<!-- Rare User-Agents for Graph Activity -->
Stack-count User-Agents hitting the legacy Graph API to find rare or offensive tooling strings across the user population.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: User-Agents used by only 1 or 2 identities hitting the legacy API; these
  often belong to tools like ROADrecon or custom Python scripts.
prevalence:
  by: actor_user_name
  key:
  - user_agent
  rare_below: 3
reads:
- user_agent
- actor_user_name
- url_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT user_agent, COUNT(DISTINCT actor_user_name) AS user_count, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE LOWER(url_hostname) = 'graph.windows.net' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent HAVING user_count <= 2 ORDER BY user_count ASC, request_count DESC
```

## endpoint-script-patterns
<!-- Endpoint Graph tool execution -->
Search script blocks for the logic of known offensive tools that target the legacy Graph API or use internal API versions.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script contents referencing the legacy Graph URL, the internal API version,
  or tool-specific strings like 'roadrecon'.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%graph.windows.net%' OR LOWER(script_content) LIKE '%1.61-internal%' OR LOWER(script_content) LIKE '%roadrecon%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-investigation
<!-- Triage legacy Graph activity -->
```agent target=hunter
cite: required
context:
- assess-auth-lead
- rare-user-agents
- endpoint-script-patterns
max_iterations: 6
objective: Determine if the combined telemetry indicates an active intrusion beachhead
  performing directory enumeration via the legacy Graph API.
success_criteria: A verdict of malicious or suspicious for identities showing successful
  auth followed by discovery behavior.
tools:
- endpoint
- identity
- web
```

## final-route
<!-- Route on triage -->
if~: "the triage-investigation agent confirms that an identity performed unauthorized discovery using the legacy Graph API" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate beachhead -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host where the discovery tools were executed. Revoke all Entra ID refresh tokens for the affected user account.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the API call volume for the identified user. Distinguish between bulk automated walking and legitimate legacy automation.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record whether the AzureADGraphActivityLogs category was enabled. If not, mark this as a priority remediation item.
```
→ end

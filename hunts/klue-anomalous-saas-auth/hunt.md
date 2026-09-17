---
analysis: Standard rules detect 'unseen network' logins, but they lack the application-specific
  context (Klue Battlecards) and the behavioral correlation with specific Python-based
  API discovery traffic. This hunt pivots between SaaS authentication and HTTP activity
  to provide a higher-fidelity signal of token abuse.
blind_spots:
- id: incomplete-saas-logs
  question: Are all OAuth sub-types being correctly parsed and reported by the connector?
  requires: Complete Salesforce Event Log ingestion into hb_auth_signin and hb_http_activity
  risk: If the 'OAuth Refresh Token' sub-type is not mapped to the auth_protocol column,
    behavioral leads will be missed.
  stage: credential-access-oauth-authentication
- id: ephemeral-infrastructure
  question: Was the automated activity conducted from a short-lived VPS that has since
    rotated?
  requires: Longer retention of HTTP user agent data
  risk: The corroborate-api-traffic step relies on temporal proximity; if logs are
    lost, the link between auth and exfiltration is weakened.
  stage: credential-access-oauth-authentication
coverage:
- stage: credential-access-oauth-authentication
  status: covered
  steps:
  - scope-klue-auth
  - match-known-actor-ips
  - rare-klue-source-ips
  - oauth-refresh-token-usage
  - corroborate-api-traffic
- reason: The compromise occurred at the vendor (Klue); this hunt focuses on the effects
    within the customer environment.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: Handled in sibling hunt 'salesforce-automated-api-exfiltration'.
  stage: discovery-automated-api-querying
  status: out_of_scope
- reason: Belongs to another part of the 'Detecting the Klue supply chain attack in
    Salesforce' series.
  stage: exfiltration-query-more-paging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Klue supply chain attack demonstrated that dormant or prototype
    OAuth integrations can provide a persistent back-door into sensitive CRM data.
    Detecting this requires correlating specific integration names with OAuth refresh
    token behaviors that bypass standard MFA triggers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised OAuth refresh tokens from the Klue supply
  chain attack to maintain persistent access to Salesforce environments from non-standard
  infrastructure.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1041
name: 'Anomalous SaaS Authentication: Klue Salesforce Compromise'
parameters:
  actor_ips:
    default:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    description: Known malicious IP addresses associated with the 'Icarus' group.
    from:
      kind: article
      observed: '2026-06-11'
      ref: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine for anomalous authentication.
    type: number
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
rationale: Focus specifically on the 'Klue Battlecards' application identifier. If
  multiple Salesforce instances are integrated, ensure the scoping query captures
  all of them by broadening the 'LIKE' filter if needed.
references:
- name: Detecting the Klue supply chain attack in Salesforce
  url: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
related:
- hunt: salesforce-automated-api-exfiltration
  reason: This hunt focuses on the authentication phase; the subsequent high-volume
    API querying and paging behavior are handled in the exfiltration-focused hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Third-party Integration Compromise
    observables:
    - Compromised Klue prototype integration credentials
    - Abuse of legitimate Klue Battlecards integration
    - Compromised OAuth refresh tokens
    slug: initial-access-supply-chain
    tactic: initial-access
    techniques:
    - T1195
  - name: OAuth Refresh Token Authentication
    observables:
    - 'application: ''Klue Battlecards'''
    - 'connected_app_name: ''Klue Battlecards'''
    - 'login_sub_type: ''OAuth Refresh Token'''
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    slug: credential-access-oauth-authentication
    tactic: credential-access
    techniques:
    - T1566
  - name: CRM Object Discovery via REST API
    observables:
    - Python-urllib/3.12
    - Python-urllib/3.14
    - 'User Agent: 5238'
    - 'URI: /services/data/v59.0/query/'
    - 'Target Objects: Opportunity, Case, Task, Lead, Contact, Account, User, Contract,
      Event, Campaign'
    - 'common.exception.ApiException: exceeded 100000 distinct who/what''s'
    slug: discovery-automated-api-querying
    tactic: discovery
    techniques:
    - T1190
  - name: Mass Data Harvesting via QueryMore
    observables:
    - 'operation: QueryMore'
    - SELECT FIELDS(STANDARD) queries
    - 'api_family: REST'
    - 'api_client_category: EXTERNAL_APPLICATION'
    slug: exfiltration-query-more-paging
    tactic: exfiltration
    techniques:
    - T1041
  summary: A threat actor (Icarus) compromised a third-party vendor (Klue) to obtain
    legitimate OAuth tokens, which were then used to authenticate to victim Salesforce
    environments. The actor used automated Python scripts to perform large-scale harvesting
    of CRM objects like Opportunities and Contacts via the Salesforce REST API for
    extortion purposes.
series:
  index: 1
  slug: detecting-the-klue-supply-chain-attack-in-salesforce
  title: Detecting the Klue supply chain attack in Salesforce
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Anomalous SaaS Authentication: Klue Salesforce Compromise

This hunt identifies anomalous authentication activity related to the Klue supply chain compromise. It specifically looks for 'Klue Battlecards' integration activity using OAuth refresh tokens, correlates these events with known malicious IP addresses, and baselines source IP prevalence to find outliers. The hunt then corroborates these logins with subsequent REST API activity to confirm automated exfiltration behavior.

## scope-klue-auth
<!-- Identify Klue Battlecards authentication events -->
Find all users and IPs interacting with the Salesforce environment via the Klue integration.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of users and source IPs using the Klue integration. An empty result
  suggests the integration is not present or has not been active in the window.
reads:
- actor_user_name
- dst_endpoint_name
- metadata_product
- provider
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%klue%' OR LOWER(metadata_product) LIKE '%klue%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-generation
<!-- Parallel Lead Generation -->
parallel:
- → match-known-actor-ips
- → rare-klue-source-ips
- → oauth-refresh-token-usage
- → corroborate-api-traffic
join: → triage-auth-activity

## match-known-actor-ips
<!-- Authentication from known malicious IPs -->
Directly match the report's indicators against SaaS authentication logs.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, actor_ips=actor_ips)
~~~yaml
expected: Any match is a high-confidence indicator of compromise. Zero results do
  not mean safety, as IP rotation is expected.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, time FROM hb_auth_signin WHERE instr(',' || '{{actor_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-klue-source-ips
<!-- Rare source IPs for Klue integration -->
Stack-count IPs per user for the Klue application to find anomalous access locations.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs used by only 1 or 2 users for this specific app. This highlights
  potential attacker infrastructure bypassing typical corporate VPNs.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- dst_endpoint_name
- metadata_product
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, dst_endpoint_name, COUNT(DISTINCT actor_user_name) AS unique_users, COUNT(*) AS auth_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%klue%' OR LOWER(metadata_product) LIKE '%klue%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_name HAVING unique_users <= 2 ORDER BY auth_count ASC
```

## oauth-refresh-token-usage
<!-- OAuth Refresh Token usage in auth logs -->
Identify logins explicitly using the OAuth Refresh Token subtype as mentioned in the report.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Authentication events specifically utilizing refresh tokens. This is the
  durable behavioral lead mentioned for this compromise.
reads:
- activity_name
- actor_user_name
- auth_protocol
- dst_endpoint_name
- metadata_product
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT actor_user_name, src_endpoint_ip, auth_protocol, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%klue%' OR LOWER(metadata_product) LIKE '%klue%') AND (LOWER(auth_protocol) LIKE '%refresh%' OR LOWER(activity_name) LIKE '%refresh%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-api-traffic
<!-- Corroborate with automated API activity -->
Verify if IPs identified in auth logs are also performing automated REST API queries against Salesforce endpoints.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to the vulnerable query endpoint from suspicious user agents.
  Matches between this and the auth step confirm post-auth automated discovery.
reads:
- src_endpoint_ip
- status_code
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, url_path, user_agent, status_code, time FROM hb_http_activity WHERE url_path LIKE '/services/data/%/query%' AND (user_agent LIKE 'Python-urllib/%' OR user_agent = '5238') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-auth-activity
<!-- Triage Authentication and Behavior -->
```agent target=hunter
cite: required
context:
- scope-klue-auth
- match-known-actor-ips
- rare-klue-source-ips
- oauth-refresh-token-usage
- corroborate-api-traffic
max_iterations: 4
objective: Determine if the Klue integration has been abused by comparing rare authentication
  IPs, OAuth refresh token usage, and API-heavy HTTP traffic from the same sources.
success_criteria: A per-IP verdict of malicious, suspicious, or benign with citations
  for auth protocols and HTTP user agents.
tools:
- identity
- web
```

## route-on-triage
<!-- Route on Triage Results -->
if~: "the triage verdict identifies malicious authentication using OAuth refresh tokens or confirmed actor IPs" (confidence: high, judge=hunter)
then: → revoke-oauth-tokens
indeterminate: → manual-auth-review
unavailable: → manual-auth-review (blind_spot: incomplete-saas-logs)
else: → close-out

## revoke-oauth-tokens
<!-- Revoke Compromised OAuth Tokens -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active OAuth refresh tokens for the Klue Battlecards application and the affected users identified in triage.
```
→ manual-auth-review

## manual-auth-review
<!-- Manual Analyst Review -->
```manual target=analyst
Verify the cited auth events and HTTP traffic. Investigate whether any other applications or credentials used the same source IPs. Pivot into hb_auth_signin for other SaaS providers used by the same account.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Record that no Klue-related anomalies were found for this window. Consider reducing the frequency of this hunt if the integration is decommissioned.
```
→ end

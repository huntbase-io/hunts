---
analysis: This is a hunt because it combines fleet-wide user-agent baselining (prevalence)
  with targeted network indicators and specific URI patterns. A simple rule would
  either be too noisy (any Python) or too narrow (specific IPs only); the hunt weighs
  the overlap of rare automation versions with Salesforce-specific exfiltration patterns.
blind_spots:
- id: no-http-visibility
  question: What is the content of the API queries being sent to Salesforce?
  requires: hb_http_activity or TLS decryption
  risk: Without HTTP-level visibility, we cannot see specific entity names (e.g.,
    Opportunity, Contact) or the 'SELECT FIELDS(STANDARD)' syntax used for harvesting.
  stage: discovery-automated-api-querying
- id: missing-response-codes
  question: Did the actor encounter common.exception.ApiException?
  requires: hb_http_activity status_code and message
  risk: Failing to see the exception messages prevents identifying 'noisy' discovery
    attempts that deviate from legitimate integration behavior.
  stage: discovery-automated-api-querying
coverage:
- stage: discovery-automated-api-querying
  status: covered
  steps:
  - suspect-api-queries
  - rare-python-user-agents
  - c2-ip-activity
- stage: exfiltration-query-more-paging
  status: covered
  steps:
  - suspect-api-queries
- reason: Belongs to another part of the 'Detecting the Klue supply chain attack in
    Salesforce' series.
  stage: initial-access-supply-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Detecting the Klue supply chain attack in
    Salesforce' series.
  stage: credential-access-oauth-authentication
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Klue supply chain compromise allows for silent CRM data exfiltration.
    A negative result from this hunt provides the business with assurance that automated
    harvesting of sensitive customer data is not occurring via the Icarus threat actor's
    known methods.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A threat actor is using automated Python scripts and compromised tokens
  to exfiltrate CRM data from Salesforce via specific REST API query endpoints and
  QueryMore operations.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1190
- attack.t1195
- attack.t1566
name: Icarus SaaS API Data Harvesting
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_ips:
    default:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    description: Confirmed threat actor infrastructure IPs from the Klue investigation.
    from:
      kind: article
      observed: '2026-06-11'
      ref: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
    type: list[ip]
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to hosts with Python installed as a baseline, but the behavioral
  queries are run fleet-wide to capture activity from unmanaged or proxy-capable infrastructure.
references:
- name: Detecting the Klue supply chain attack in Salesforce
  url: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
related:
- hunt: icarus-oauth-anomalous-authentication
  reason: This hunt focuses on the exfiltration and API behavior; a separate hunt
    should address the initial authentication anomalies using the 'Klue Battlecards'
    application name.
  relation: out-of-scope-alternative
- hunt: klue-anomalous-saas-auth
  relation: follows
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
  index: 2
  slug: detecting-the-klue-supply-chain-attack-in-salesforce
  title: Detecting the Klue supply chain attack in Salesforce
  total: 2
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


# Icarus SaaS API Data Harvesting

Following the Klue supply chain compromise, the 'Icarus' threat actor has been observed harvesting Salesforce data using automated scripts. This hunt identifies the behavioral fingerprints of that automation: specific Python user agents, targeting of the v59.0 query endpoints, and the use of the QueryMore paging operation. It correlates these HTTP signals with connections to confirmed threat actor infrastructure and baselines Python-based automation across the fleet to find rare, suspicious versions.

## scoping-python-hosts
<!-- Scope hosts with Python installed -->
Identify hosts in the estate that have Python installed, as the observed attack used Python-based automation scripts.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts capable of running the scripts described in the report.
  Silence means no Python is installed via standard packages.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%python%'
```

## suspect-api-queries
<!-- Suspect Salesforce API Query Patterns -->
Identify HTTP traffic targeting the Salesforce REST API query endpoints with the specific Python user agents or the '5238' string.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Hosts or internal proxies communicating with Salesforce using the Icarus
  threat actor's specific automation strings.
reads:
- device_hostname
- src_endpoint_ip
- time
- url_hostname
- url_path
- url_query
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, url_hostname, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%/services/data/v%/query/%' OR LOWER(url_query) LIKE '%querymore%') AND (LOWER(user_agent) LIKE 'python-urllib/%' OR user_agent = '5238') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with IP and UA Rarity -->
parallel:
- → rare-python-user-agents
- → c2-ip-activity
join: → triage-harvesting

## rare-python-user-agents
<!-- Baseline Rare Python User Agents -->
Stack-count Python-based user agents to isolate rare automation that deviates from standard internal tooling.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The actor's specific UA versions standing out from common internal Python
  utilities used across the fleet.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 3
reads:
- device_hostname
- time
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT user_agent, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS requests, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(user_agent) LIKE 'python-urllib/%' OR user_agent = '5238') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_agent HAVING hosts <= 3 ORDER BY hosts ASC
```

## c2-ip-activity
<!-- Connections to Malicious Infrastructure -->
Find network connections from the estate to confirmed Icarus C2/exfiltration IP addresses.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, malicious_ips=malicious_ips)
~~~yaml
expected: A socket connection to one of the four confirmed IPs. This is high-confidence
  corroboration.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{malicious_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-harvesting
<!-- Triage Harvesting Evidence -->
```agent target=hunter
cite: required
context:
- scoping-python-hosts
- suspect-api-queries
- rare-python-user-agents
- c2-ip-activity
max_iterations: 4
objective: 'Determine if any host shows the combined fingerprint of CRM harvesting:
  Python automation, Salesforce query endpoints, and connections to Icarus infrastructure.'
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  activity rows.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-close-out
unavailable: → analyst-close-out (blind_spot: no-http-visibility)
else: → analyst-close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via EDR and revoke all active Salesforce sessions for the associated account.
```
→ analyst-close-out

## analyst-close-out
<!-- Analyst Close-out -->
```manual target=analyst
Review the triage results. If suspicion remains, pivot to Salesforce application logs to search for 'ApiException' or 'Klue Battlecards' application strings. Close the hunt after verifying the threat is contained.
```
→ end

---
analysis: A simple rule might flag actor IPs, but this hunt stack-counts rare Python
  user agents and identifies the specific Salesforce query endpoint behavior that
  differentiates automated exfiltration from legitimate synchronization. By gating
  the expensive queries, it ensures an analyst only investigates leads with confirmed
  integration activity.
blind_spots:
- id: no-auth-visibility
  question: whether the Klue integration used specific refresh token sub-types
  requires: Direct Salesforce LoginEvent logs with login_sub_type
  risk: Anomalous authentication might be missed if the integration communicates through
    a gateway that does not log granular OAuth sub-types.
  stage: initial-access-supply-chain-credential-abuse
- id: no-saas-visibility
  question: exactly which fields and records were returned in failed versus successful
    queries
  requires: Salesforce RestApi message fields
  risk: While the hunt sees the exfiltration behavior, the precise inventory of stolen
    data requires native SaaS audit logs.
  stage: exfiltration-automated-api-querying
coverage:
- stage: initial-access-supply-chain-credential-abuse
  status: covered
  steps:
  - lead-klue-integration-access
- stage: persistence-oauth-token-manipulation
  status: covered
  steps:
  - lead-klue-integration-access
- stage: exfiltration-automated-api-querying
  status: covered
  steps:
  - python-automated-api-activity
  - known-malicious-ip-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Third-party supply chain attacks like Klue abuse trusted integrations
    to bypass MFA and traditional perimeter controls. A negative result across the
    Salesforce environment provides vital assurance that sensitive CRM data remains
    secure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has abused a dormant Klue integration to exfiltrate Salesforce
  data by leveraging compromised OAuth tokens to perform automated API harvesting.
labels:
- hunt
- attack.t1195
- attack.t1190
- attack.t1041
- attack.t1090.003
- attack.t1566
name: Third-Party Integration OAuth Abuse and API Exfiltration
parameters:
  klue_ips:
    default:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    description: Threat actor IP addresses identified by Klue and Huntress.
    from:
      kind: article
      observed: '2026-06-11'
      ref: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
    type: list[ip]
  klue_user_agents:
    default:
    - Python-urllib/3.12
    - Python-urllib/3.14
    - '5238'
    description: User agent strings observed during automated exfiltration.
    from:
      kind: article
      observed: '2026-06-11'
      ref: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the network search; leave empty
      for fleet-wide search.
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
rationale: The hypothesis focuses on supply-chain integration abuse within SaaS environments.
  Scoping begins by identifying any activity related to the Klue Battlecards integration,
  which is the primary beachhead. The hunt then narrows focus to hosts or proxies
  exhibiting connections to the reported IPs or using automation-heavy user agents.
references:
- name: "Datadog Security Labs \u2014 Detecting the Klue supply chain attack in Salesforce"
  url: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
related:
- hunt: salesforce-unauthorized-api-access
  reason: This hunt focuses specifically on the Klue integration compromise; broader
    API abuse patterns are handled by a generic hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Supply Chain Compromise via Dormant Credential
    observables:
    - 'application: ''Klue Battlecards'''
    - 'connected_app_name: ''Klue Battlecards'''
    slug: initial-access-supply-chain-credential-abuse
    tactic: initial-access
    techniques:
    - T1195
    - T1190
  - name: OAuth Refresh Token Abuse
    observables:
    - 'login_sub_type: ''oauthrefreshtoken'''
    - 'login_sub_type: ''OAuth Refresh Token'''
    slug: persistence-oauth-token-manipulation
    tactic: persistence
    techniques:
    - T1195
  - name: Automated CRM Data Exfiltration
    observables:
    - 138.226.246.94
    - 212.86.125.24
    - 213.111.148.90
    - 94.154.32.160
    - Python-urllib/3.12
    - Python-urllib/3.14
    - '5238'
    - 'url_path: ''/services/data/v59.0/query/'''
    - common.exception.ApiException
    - QueryMore
    - Opportunity
    - Lead
    - Contact
    slug: exfiltration-automated-api-querying
    tactic: exfiltration
    techniques:
    - T1041
    - T1090.003
  summary: The Icarus threat group compromised a dormant integration credential within
    Klue's infrastructure to harvest OAuth tokens for Salesforce and Gong. The attackers
    then utilized automated Python scripts to exfiltrate sensitive CRM data, including
    contacts and communications, through high-volume API queries.
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


# Third-Party Integration OAuth Abuse and API Exfiltration

The Klue supply chain attack demonstrates how dormant credentials in third-party integrations bypass traditional security perimeters. By compromising backend systems at Klue, the adversary gained access to OAuth tokens for Salesforce. The adversary then used these tokens to run automated API calls and exfiltrate sensitive CRM data. The hunt identifies anomalous authentication from the Klue integration followed by behavioral evidence of automated data harvesting. This hunt follows a gated flow to manage query costs. It begins by identifying sign-ins associated with the Klue Battlecards integration. If suspicious access is confirmed, the hunt fans out to look for known malicious IP addresses and behavioral signals of automated REST API querying, such as specific Python user-agents and access to Salesforce query endpoints.

## lead-klue-integration-access
<!-- Find authentication for the Klue integration -->
Identify any authentication attempts or successful sign-ins attributed to the Klue Battlecards application to establish if the integration is active.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Authentication events naming the Klue application. A lack of rows suggests
  the integration is not reporting in this tenant and the hunt should stop.
reads:
- activity_name
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT time, actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, activity_name FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%klue%' OR LOWER(dst_endpoint_name) LIKE '%battlecard%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate lead authentication -->
```agent target=hunter
cite: required
context:
- lead-klue-integration-access
max_iterations: 3
objective: Determine if any authentication events involving the Klue integration appear
  suspicious, such as those originating from external or unexpected IPs.
success_criteria: A verdict of suspicious if the Klue integration authenticates from
  IPs not associated with known legitimate synchronization sources.
tools:
- identity
- network
- web
```

## gate-on-auth-finding
<!-- Gate on authentication finding -->
if~: "the evaluate-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → exfiltration-evidence
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-auth-visibility)
else: → close-out

## exfiltration-evidence
<!-- Collect exfiltration evidence -->
parallel:
- → python-automated-api-activity
- → known-malicious-ip-connections
join: → final-triage

## python-automated-api-activity
<!-- Automated Python API activity -->
Find HTTP requests using Python user agents targeting Salesforce query endpoints, which indicates automated harvesting.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, klue_user_agents=klue_user_agents)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Spikes in requests to query endpoints using Python-urllib or the numeric
  5238 user agent. A positive result is high confidence for automated activity.
prevalence:
  by: device_hostname
  key:
  - user_agent
  rare_below: 3
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
verified_at: '2026-09-20'
~~~
SELECT time, device_hostname, src_endpoint_ip, user_agent, url_path, status_code, COUNT(*) OVER (PARTITION BY user_agent) as ua_count FROM hb_http_activity WHERE (instr(',' || '{{klue_user_agents}}' || ',', ',' || user_agent || ',') > 0 OR LOWER(url_path) LIKE '%/services/data/%/query%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## known-malicious-ip-connections
<!-- Connections to actor infrastructure -->
Identify any host-to-host connections made to infrastructure confirmed as belonging to the adversary, scoped to previously identified hosts.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, klue_ips=klue_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Direct network connections to the actor's IP addresses. The presence of
  these connections on hosts associated with Klue activity confirms an intrusion.
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT time, device_hostname, src_endpoint_ip, dst_endpoint_ip, process_name FROM hb_network_connection WHERE instr(',' || '{{klue_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final triage -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- python-automated-api-activity
- known-malicious-ip-connections
max_iterations: 5
objective: Determine if the combined evidence of Klue authentication, automated Python
  API requests, and connections to known malicious IPs indicates a data exfiltration
  campaign.
success_criteria: A malicious verdict for any host showing suspicious Klue authentication
  followed by automated API harvesting patterns.
tools:
- identity
- network
- web
```

## route-on-evidence
<!-- Route on evidence -->
if~: "the final-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-integration
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-saas-visibility)
else: → close-out

## contain-integration
<!-- Contain integration -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all OAuth tokens and refresh tokens associated with the Klue Battlecards connected application in Salesforce to prevent further API access.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the API activity logs to identify exactly which Salesforce objects were accessed (e.g., Opportunity, Contact). Coordinate with the legal team to determine if data breach notifications are required based on the sensitivity of the exfiltrated data.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the investigation findings. If activity was confirmed, ensure the Klue integration remains disabled until its vendor confirms their backend systems are clean.
```
→ end

---
analysis: A simple rule can flag a failed login, but this hunt links those failures
  to the prevalence of rare web requests and specifically monitors the usage of cloud
  AI services to identify context-aware supply chain risks that isolated alerts miss.
blind_spots:
- id: auth-telemetry-gap
  question: whether an account was compromised on an unmonitored clinical portal
  requires: centralized logging for specialized clinical portals
  risk: A sign-in failure on a portal not sending logs to hb_auth_signin remains invisible.
  stage: healthcare-account-compromise
- id: http-retention-limit
  question: whether the initial phishing click occurred before the current 14-day
    retention window
  requires: long-term hb_http_activity retention
  risk: Adversaries often dwell in healthcare networks for weeks before initiating
    care disruption.
  stage: ai-phishing-and-social-engineering
coverage:
- stage: ai-phishing-and-social-engineering
  status: covered
  steps:
  - phishing-lure-traffic
- stage: ai-vendor-supply-chain-risk
  status: covered
  steps:
  - unauthorized-ai-api-calls
- stage: healthcare-account-compromise
  status: covered
  steps:
  - lead-auth-anomalies
- reason: Belongs to another part of the 'Healthcare Cyberattacks Hit Harder, Cost
    More' series.
  stage: ai-prompt-data-leakage
  status: out_of_scope
- reason: Belongs to another part of the 'Healthcare Cyberattacks Hit Harder, Cost
    More' series.
  stage: ransomware-encryption-for-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Protecting healthcare worker identities and monitoring third-party
    AI supply chain interactions is critical for maintaining patient care continuity
    during a rise in sector-specific attacks.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised healthcare worker accounts via AI-crafted
  phishing to gain access to sensitive clinical portals or manipulate third-party
  AI service integrations.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1078
- impact
- initial access
name: Healthcare Identity and AI Supply Chain Compromise
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: default-retention
    type: number
  phishing_domains:
    default:
    - health-portal-verify.com
    - care-staff-update.org
    - clinical-sso-login.net
    description: Healthcare-themed phishing domains from intelligence feeds.
    from:
      kind: article
      observed: '2026-10-13'
      ref: proofpoint-healthcare-report-2026
    type: list[domain]
  scope_hosts:
    default: []
    description: The list of hostnames identified in the lead query to scope the investigation.
    from:
      kind: manual
      observed: '2026-10-13'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/healthcare-cyberattacks-hit-harder-cost-more
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on accounts for healthcare practitioners and administrative staff
  who have access to sensitive patient systems. The lead query narrows the investigation
  to only those accounts showing immediate signs of identity risk, while the parallel
  queries allow for deep dives into phishing and AI supply chain interaction.
references:
- name: "Proofpoint \u2014 Healthcare Cyberattacks Hit Harder, Cost More"
  url: https://www.proofpoint.com/us/newsroom/news/healthcare-cyberattacks-hit-harder-cost-more
related:
- hunt: ransomware-encryption-for-impact-detection
  reason: This hunt focuses on initial access and identity; the encryption phase is
    a later stage of the impact cycle.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Enhanced Phishing and Social Engineering
    observables:
    - AI-generated phishing emails
    - Social engineering scams
    - Phishing links in healthcare-themed messages
    slug: ai-phishing-and-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: AI Vendor Supply Chain Risk
    observables:
    - Compromised third-party AI vendor tools
    - Manipulation of AI service delivery mechanisms
    slug: ai-vendor-supply-chain-risk
    tactic: initial-access
    techniques:
    - T1195
  - name: Healthcare Account Compromise
    observables:
    - Compromised healthcare worker accounts
    - Unauthorized authentication events
    slug: healthcare-account-compromise
    tactic: initial-access
    techniques:
    - T1566
  - name: Sensitive Data Leakage via AI Prompts
    observables:
    - Medical records submitted to AI chatbot prompts
    - HTTP POST requests to AI service domains such as openai.com
    slug: ai-prompt-data-leakage
    tactic: initial-access
    techniques:
    - T1566
  - name: Ransomware Encryption for Impact
    observables:
    - Encryption of patient care data
    - Clinical system unavailability
    - Deployment of ransomware payloads
    slug: ransomware-encryption-for-impact
    tactic: impact
    techniques:
    - T1486
  summary: Healthcare organizations are facing an escalation in cyberattacks characterized
    by AI-enhanced phishing, compromised credentials, and supply chain vulnerabilities
    in AI vendors. These incidents frequently lead to operational disruptions through
    ransomware encryption of patient records or the unauthorized leakage of sensitive
    medical data via AI prompts.
series:
  index: 1
  slug: healthcare-cyberattacks-hit-harder-cost-more
  title: Healthcare Cyberattacks Hit Harder, Cost More
  total: 2
severity: medium
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


# Healthcare Identity and AI Supply Chain Compromise

Healthcare organizations face increasing operational disruption from identity-driven attacks. This hunt uses a gated approach to identify suspicious authentication patterns—such as high-volume failures or automated script-based logins—before expanding into more expensive telemetry. If a lead is confirmed, the hunt fans out to investigate interactions with rare phishing domains and audits cloud API activity for unauthorized interactions with AI platforms like OpenAI, Bedrock, or Copilot, which may indicate supply chain risk or data exfiltration.

## lead-auth-anomalies
<!-- Suspicious Authentication Leads -->
Identify potential account compromise via high-frequency failures or automated login attempts.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows show repeated failures for specific users or sign-ins using non-browser
  user agents. Silence suggests no obvious automated account attacks.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- user_agent
- status_detail
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, user_agent, status_detail, COUNT(*) AS attempts, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE (status_id = 2 OR (user_agent IS NOT NULL AND (LOWER(user_agent) LIKE '%python%' OR LOWER(user_agent) LIKE '%script%'))) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, src_endpoint_ip, user_agent, status_detail HAVING attempts > 5 OR (LOWER(user_agent) LIKE '%python%' OR LOWER(user_agent) LIKE '%script%') ORDER BY attempts DESC
```

## evaluate-auth-lead
<!-- Assess Authentication Lead -->
```agent target=hunter
cite: required
context:
- lead-auth-anomalies
max_iterations: 3
objective: Determine if the sign-in patterns in lead-auth-anomalies suggest active
  credential stuffing or unauthorized automation.
success_criteria: A verdict of suspicious | benign for the detected accounts.
tools:
- endpoint
- identity
- web
```

## gate-on-suspicion
<!-- Gate on Authentication Suspicion -->
if~: "the evaluate-auth-lead verdict is suspicious for at least one account or source IP" (confidence: high, judge=hunter)
then: → investigate-surfaces
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: auth-telemetry-gap)
else: → close-out

## investigate-surfaces
<!-- Investigate Phishing and AI Activity -->
parallel:
- → phishing-lure-traffic
- → unauthorized-ai-api-calls
join: → final-triage

## phishing-lure-traffic
<!-- Phishing Lure Traffic -->
Identify hosts interacting with rare or healthcare-themed phishing domains within the scoped set.

```sqlite target=web role=baseline params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare domains appearing on fewer than 5 hosts matching phishing keywords.
  Silence means no suspicious web traffic was recorded on the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 5
reads:
- url_hostname
- device_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(*) AS requests, MIN(time) AS first_seen FROM hb_http_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR LOWER(url_path) LIKE '%/login%' OR LOWER(url_path) LIKE '%/verify%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path HAVING requests < 100 ORDER BY requests ASC
```

## unauthorized-ai-api-calls
<!-- Unauthorized AI API Activity -->
Detect healthcare accounts interacting with third-party AI services which may indicate supply chain manipulation.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Healthcare worker accounts performing API operations against cloud AI vendors.
  Silence suggests no such API activity was recorded.
reads:
- actor_user_name
- api_service_name
- api_operation
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT actor_user_name, api_service_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE (LOWER(api_service_name) LIKE '%bedrock%' OR LOWER(api_service_name) LIKE '%openai%' OR LOWER(api_service_name) LIKE '%copilot%' OR LOWER(api_service_name) LIKE '%sagemaker%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-triage
<!-- Final Evidence Triage -->
```agent target=hunter
cite: required
context:
- evaluate-auth-lead
- phishing-lure-traffic
- unauthorized-ai-api-calls
max_iterations: 6
objective: Determine if the fanned-out evidence confirms that the suspicious accounts
  from the lead query were used for malicious activity.
success_criteria: A per-host/per-user verdict of malicious | suspicious | benign.
tools:
- endpoint
- identity
- web
```

## route-findings
<!-- Route Final Verdict -->
if~: "the final-triage verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: http-retention-limit)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and disable the associated healthcare worker account in the identity provider.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Investigation -->
```manual target=analyst
Review the cited rows from authentication, HTTP, and cloud API activity. Verify if the rare domain traffic matches known clinical workflows or constitutes an intrusion. Check if the AI API calls align with approved vendor usage.
```
→ close-out

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record the summary of findings and note any failures to monitor specific third-party AI services used by the organization. Document any hosts that were unscoped due to telemetry gaps.
```
→ end

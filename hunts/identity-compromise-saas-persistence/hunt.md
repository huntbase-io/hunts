---
analysis: A simple rule may fire on 'Inbox Rule Created', but this hunt pivots between
  the authentication context (proxy, MFA status) and the rarity of the login location,
  reducing noise and providing the 'why' behind the alert.
blind_spots:
- id: proxy-data-missing
  owner: Identity Engineering
  question: whether a login originated from an anonymizing proxy
  remediation: Enable IP threat intelligence and proxy detection within the IDP settings.
  requires: is_proxy field populated by the identity provider (e.g., Okta)
  risk: Attackers can hide their source IP without detection if the IDP does not provide
    proxy intelligence.
  stage: identity-theft-and-mfa-bypass
- id: m365-log-latency
  owner: Security Operations
  question: how quickly persistence can be established after a compromise
  remediation: Move M365 log ingestion to a high-priority stream (e.g., Office 365
    Management Activity API directly).
  requires: Real-time hb_cloud_api_activity for M365
  risk: A 24-hour log delay means an attacker can exfiltrate data and establish persistence
    before the hunt even sees the API call.
  stage: bec-and-cloud-infrastructure-abuse
coverage:
- stage: identity-theft-and-mfa-bypass
  status: covered
  steps:
  - lead-suspicious-logins
  - rare-login-locations
- stage: bec-and-cloud-infrastructure-abuse
  status: covered
  steps:
  - saas-persistence-indicators
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: ai-powered-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: rmm-platform-hijacking
  status: out_of_scope
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: data-staging-and-exfiltration
  status: out_of_scope
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: ransomware-encryption-and-extortion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Identity is the primary attack surface in 2026; Business Email Compromise
    (BEC) costs organizations more than ransomware. Detecting the gap between a successful
    login and the abuse of SaaS configuration is the most effective way to prevent
    financial fraud.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed MFA via session hijacking or proxy usage and
  is establishing persistence through malicious inbox rules or unauthorized OAuth
  applications in a SaaS environment.
labels:
- hunt
- attack.t1133
- attack.t1098
- attack.t1137
- attack.t1550.004
- credential access
- exfiltration
- impact
- initial access
- persistence
name: Identity Compromise and SaaS Persistence
parameters:
  lookback_days:
    default: '14'
    description: Number of days of history to examine for suspicious activity.
    type: number
  target_users:
    default: []
    description: Specific usernames to focus on; leave empty to hunt across the whole
      estate.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/what-does-the-future-hold-for-todays-cybersecurity-leaders
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize users with 'privileged' roles or those in finance/HR departments.
  Focus on the last 14 days to capture active BEC campaigns.
references:
- name: "Huntress \u2014 What Cybersecurity Leaders Must Prioritize in 2027"
  url: https://www.huntress.com/blog/what-does-the-future-hold-for-todays-cybersecurity-leaders
related:
- hunt: m365-oauth-app-audit
  reason: Focuses purely on historical OAuth app audits rather than active login correlations.
  relation: sibling
- hunt: ai-social-engineering-ransomware-ops
  relation: follows
scenario:
  stages:
  - name: AI-Powered Social Engineering and Loaders
    observables:
    - hyper-personalized phishing emails
    - ClickFix lures
    - fake CAPTCHA flows
    - AI-assisted smishing and vishing
    - malicious loader execution
    slug: ai-powered-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of Trusted RMM Tools
    observables:
    - ScreenConnect hijacking
    - unusual process chains originating from RMM tools
    - misuse of sanctioned IT management software
    slug: rmm-platform-hijacking
    tactic: persistence
    techniques:
    - T1133
    - T1190
  - name: Identity Compromise and MFA Bypass
    observables:
    - session token theft
    - MFA bypass
    - impossible travel logins
    - suspicious login footprints
    slug: identity-theft-and-mfa-bypass
    tactic: credential-access
    techniques:
    - T1133
  - name: BEC and Cloud Application Abuse
    observables:
    - suspicious inbox rules
    - rogue OAuth app registration
    - interception of financial communications
    slug: bec-and-cloud-infrastructure-abuse
    tactic: persistence
    techniques:
    - T1133
  - name: Pre-Ransomware Data Exfiltration
    observables:
    - data staging
    - exfiltration over existing C2 channels prior to encryption
    slug: data-staging-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Encryption
    observables:
    - data encryption
    - ransomware canaries
    - multi-extortion negotiation notices
    slug: ransomware-encryption-and-extortion
    tactic: impact
    techniques:
    - T1486
  summary: In 2026, attackers are increasingly leveraging AI-powered phishing and
    the hijacking of trusted RMM tools like ScreenConnect to establish stealthy persistence.
    These campaigns often transition to identity-centric attacks, bypassing MFA via
    session theft and manipulating cloud environments through BEC flows, ultimately
    culminating in data exfiltration and multi-extortion ransomware.
series:
  index: 2
  slug: what-cybersecurity-leaders-must-prioritize-in-2027
  title: What Cybersecurity Leaders Must Prioritize in 2027
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
tlp: clear
type: investigation
---


# Identity Compromise and SaaS Persistence

This hunt identifies successful logins that bypass security controls (proxies, MFA failure) and correlates them with downstream SaaS persistence mechanisms. It uses three telemetry surfaces—identity logs, API activity, and geolocational stack-counting—to separate legitimate remote work from Business Email Compromise (BEC). The agent weighs the login context against the creation of inbox rules or OAuth grants to confirm active account takeover.

## lead-suspicious-logins
<!-- Successful logins via proxies or without MFA -->
Identify initial access leads where authentication succeeded but bypassed typical security postures.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, target_users=target_users)
~~~yaml
expected: Rows identify users and IPs that authenticated through known proxies or
  without MFA. Silence indicates no obvious bypasses in the monitored telemetry.
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- src_location_city
- mfa
- is_proxy
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, src_location_city, mfa, is_proxy, time FROM hb_auth_signin WHERE status_id = 1 AND (is_proxy = 'true' OR mfa = 'false') AND ('{{target_users}}' = '' OR instr(',' || '{{target_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-context
<!-- Analyze login context and SaaS activity -->
parallel:
- → rare-login-locations
- → saas-persistence-indicators
join: → triage-identity-threat

## rare-login-locations
<!-- Stack-count login locations per user -->
Highlight 'impossible travel' or unusual login origins by identifying locations seen on fewer than three IPs per user.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, target_users=target_users)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare combinations of user and location. A single row for a user in a new
  country is a strong indicator of session theft or unauthorized access.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  - src_location_country
  rare_below: 3
reads:
- actor_user_name
- src_location_country
- src_location_city
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, src_location_country, src_location_city, COUNT(DISTINCT src_endpoint_ip) AS unique_ips, MIN(time) AS first_login, MAX(time) AS last_login FROM hb_auth_signin WHERE status_id = 1 AND ('{{target_users}}' = '' OR instr(',' || '{{target_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_location_country, src_location_city HAVING unique_ips < 3 ORDER BY unique_ips ASC
```

## saas-persistence-indicators
<!-- Malicious configuration changes in M365/Workspace -->
Detect the technical aftermath of a successful login: inbox rule creation and OAuth app consent.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, target_users=target_users)
~~~yaml
expected: API calls that create persistence or allow data exfiltration. Common legitimate
  rules for folders should be manually filtered by the agent.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%inboxrule%' OR LOWER(api_operation) LIKE '%consent%' OR LOWER(api_operation) LIKE '%oauth2permissiongrant%') AND ('{{target_users}}' = '' OR instr(',' || '{{target_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-identity-threat
<!-- Assess for Account Compromise -->
```agent target=hunter
cite: required
context:
- lead-suspicious-logins
- rare-login-locations
- saas-persistence-indicators
max_iterations: 4
objective: Determine if any user shows a pattern of 'Logon from Proxy/MFA Bypass'
  followed by 'Rare Location' and 'Malicious SaaS Operation' (Inbox Rule or OAuth
  Grant).
success_criteria: A verdict of malicious, suspicious, or benign per user with cited
  activity timestamps.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-identity-threat verdict is malicious for at least one user account" (confidence: high, judge=hunter)
then: → revoke-compromised-sessions
indeterminate: → analyst-forensic-review
unavailable: → analyst-forensic-review (blind_spot: proxy-data-missing)
else: → hardening-and-closeout

## revoke-compromised-sessions
<!-- Revoke User Sessions and Reset Credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sign-in sessions for the identified user(s). Force a password reset and audit MFA devices for unauthorized additions.
```
→ analyst-forensic-review

## analyst-forensic-review
<!-- Analyst Forensic Review -->
```manual target=analyst
Inspect the content of the created inbox rules for financial keywords (invoice, wire, payment). Verify whether the OAuth applications have permissions to read mail or modify directory settings.
```
→ hardening-and-closeout

## hardening-and-closeout
<!-- Hardening and Closeout -->
```manual target=analyst
Record the source IPs of the attackers for blocklisting. Update MFA policies to enforce hardware-backed or FIDO2 tokens to prevent session theft bypass. If specific inbox rules were common, promote them to standing detection rules.
```
→ end

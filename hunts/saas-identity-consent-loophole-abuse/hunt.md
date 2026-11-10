---
analysis: A standard detection rule can alert on a proxy login, but it cannot easily
  correlate that login with the fleet-wide prevalence of the applications that user
  subsequently interacted with. This hunt uses the baseline of rare app consents to
  find the needle in the haystack across three identity and cloud telemetry surfaces.
blind_spots:
- id: cloud-api-retention-gap
  owner: Cloud Infrastructure Team
  question: whether consent was granted outside of the examined lookback window
  remediation: Extend log retention for Entra/Office 365 audit logs to at least 90
    days.
  requires: long-term cloud control plane logs (hb_cloud_api_activity)
  risk: A persistent malicious application granted consent 30 days ago would not be
    visible in a 14-day hunt.
  stage: identity-consent-mfa-bypass
- id: unreported-mfa-bypass
  owner: Identity Architecture Team
  question: whether MFA was actually bypassed or just not required for that specific
    session
  remediation: Enable Conditional Access policies that strictly enforce MFA and device
    compliance for all sessions.
  requires: hb_auth_signin mfa and auth_requirement fields
  risk: Some SaaS providers do not explicitly report if a session was established
    via cookie theft versus a fresh MFA challenge, leading to potential indeterminate
    verdicts.
  stage: identity-consent-mfa-bypass
coverage:
- stage: initial-access-aitm-phishing
  status: covered
  steps:
  - auth-risk-leads
  - proxy-session-details
- stage: identity-consent-mfa-bypass
  status: covered
  steps:
  - rare-app-consents
  - triage-identity-threat
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: execution-msi-dll-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: persistence-rmm-abuse
  status: out_of_scope
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: c2-proxy-tunneling
  status: out_of_scope
- reason: 'Belongs to another part of the ''When trust becomes the payload: Inside
    the threats, etc quarterly report'' series.'
  stage: execution-ai-agent-automation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The shift toward consent loopholes and the weaponization of trusted
    first-party applications allows adversaries to maintain long-term persistent access
    that survives MFA and password resets. Identifying this abuse requires correlating
    identity logs with cloud API activity, which a negative result over the estate
    confirms is not actively occurring.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed MFA by stealing a session cookie via AiTM phishing
  or an infostealer, then logged into a cloud tenant and granted permissions to a
  malicious or rare application to ensure persistent access.
labels:
- hunt
- attack.t1566
- attack.t1555
- attack.t1190
- attack.t1572
- command and control
- credential access
- execution
- initial access
- persistence
name: SaaS Identity and Consent Loophole Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for suspicious sign-ins and API activity.
    from:
      kind: manual
      observed: '2026-11-04'
      ref: hunt-standard-lookback
    type: number
  scope_users:
    default: []
    description: Usernames identified in the lead query to focus the enrichment steps;
      leave empty for a full-tenant scan.
    from:
      kind: manual
      observed: '2026-11-04'
      ref: analyst-defined-scope
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize users with privileged roles (hb_users privileged = true) or
  those who have signed in from unusual geographic locations recently. Focus the parallel
  queries by pasting usernames with proxy sign-ins into the scope_users list.
references:
- name: 'When trust becomes the payload: Inside the threats, etc quarterly report'
  url: https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust
related:
- hunt: first-party-app-privilege-escalation
  reason: Adversaries can also use consent to escalate privileges within a tenant
    rather than just maintaining access.
  relation: sibling
scenario:
  stages:
  - name: Adversary-in-the-Middle Phishing
    observables:
    - Adversary-in-the-Middle (AiTM) phishing kits
    - Credential theft targeting cloud/SaaS tenants
    slug: initial-access-aitm-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Consent Loophole and Rapid Login
    observables:
    - Abuse of first-party application consent
    - 8-minute delay between infostealer infection and login
    - Bypassing MFA hurdles via session theft
    slug: identity-consent-mfa-bypass
    tactic: credential-access
    techniques:
    - T1190
    - T1555
  - name: Signed MSI and DLL Sideloading
    observables:
    - Microsoft Software Installer (MSI) delivery
    - Dynamic link library (DLL) sideloading
    - 16-second execution window from lure to sideload
    slug: execution-msi-dll-sideloading
    tactic: execution
    techniques:
    - T1574.002
  - name: RMM Persistence via ScreenConnect
    observables:
    - ScreenConnect
    - Signed remote monitoring and management (RMM) agents
    - Interactive access on endpoints
    slug: persistence-rmm-abuse
    tactic: persistence
    techniques:
    - T1195
  - name: Network Proxy Tunneling
    observables:
    - Proxy tunneling
    - Memory tampering outcomes
    slug: c2-proxy-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: AI Agent-Driven Attack Actions
    observables:
    - AI coding assistants
    - 17,600 reconstructed actions over four days
    - High-frequency automated activity from AI application processes
    slug: execution-ai-agent-automation
    tactic: execution
    techniques:
    - T1195
  summary: Adversaries are weaponizing trust across the enterprise stack by abusing
    legitimate tools like ScreenConnect, AI coding assistants, and Microsoft first-party
    clients. Intrusions leverage AiTM phishing to bypass MFA and deploy signed payloads
    via DLL sideloading, often achieving full compromise from infection to cloud login
    in just eight minutes.
series:
  index: 1
  slug: when-trust-becomes-the-payload-inside-the-threats-etc-quarterly-report
  title: 'When trust becomes the payload: Inside the threats, etc quarterly report'
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


# SaaS Identity and Consent Loophole Abuse

This hunt examines the identity and cloud control plane for signs of the consent loophole and AiTM phishing observed in the Nov 2026 report. It identifies successful logins originating from anonymizing proxies or carrying high-risk states, then corroborates these by looking for rare OAuth application consent events associated with those same users. The hunt focuses on the critical 8-minute window where session theft transitions to persistent cloud access through first-party app abuse.

## auth-risk-leads
<!-- Suspect sign-ins from proxies or high-risk states -->
Identify successful logins that are marked at risk or originate from anonymizing proxies, which are common indicators of AiTM phishing kits.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
expected: Rows indicating successful logins despite high risk states or proxy origin.
  Silence indicates no obvious AiTM-style session usage was detected by the provider's
  risk engine.
reads:
- actor_user_name
- auth_requirement
- client_app
- device_trust_type
- is_proxy
- risk_state
- src_endpoint_ip
- src_location_country
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT time, actor_user_name, src_endpoint_ip, src_location_country, client_app, risk_state, is_proxy, auth_requirement, device_trust_type FROM hb_auth_signin WHERE status_id = 1 AND (risk_state IN ('atRisk', 'confirmedCompromised') OR is_proxy = 'true') AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-abuse
<!-- Corroborate session theft and app abuse -->
parallel:
- → proxy-session-details
- → rare-app-consents
join: → triage-identity-threat

## proxy-session-details
<!-- Detail session attributes for the suspect users -->
Collect detailed attributes for the sign-ins of the users identified in the lead, focusing on device trust and user agents.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
expected: A history of sign-ins for the target users, allowing for comparison of location
  and device trust between normal and suspicious logins.
reads:
- actor_user_name
- auth_protocol
- auth_requirement
- client_app
- device_trust_type
- src_endpoint_ip
- src_location_country
- status_detail
- status_id
- time
- user_agent
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT time, actor_user_name, src_endpoint_ip, src_location_country, user_agent, client_app, auth_protocol, auth_requirement, device_trust_type, status_detail FROM hb_auth_signin WHERE status_id = 1 AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-app-consents
<!-- Stack-count rare OAuth application consents -->
Identify OAuth application consents or app role assignments for the targeted users that are rare across the fleet, highlighting potential malicious apps used for the consent loophole.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Applications that have been granted consent by only a few users, specifically
  those in our scope. If a user from the lead query is in this list, it strongly suggests
  identity abuse.
prevalence:
  by: actor_user_name
  key:
  - resource_name
  rare_below: 5
reads:
- actor_user_name
- api_operation
- provider
- resource_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-05'
~~~
SELECT resource_name AS app_name, api_operation, COUNT(DISTINCT actor_user_name) AS distinct_users, MIN(time) AS first_consent_time, MAX(time) AS last_consent_time FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%consent%' OR LOWER(api_operation) LIKE '%add app role assignment%' OR LOWER(api_operation) LIKE '%update application%') AND provider IN ('azure_ad', 'm365') AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY resource_name, api_operation HAVING distinct_users <= 5
```

## triage-identity-threat
<!-- Analyze identity and consent patterns -->
```agent target=hunter
cite: required
context:
- auth-risk-leads
- proxy-session-details
- rare-app-consents
max_iterations: 6
objective: Evaluate whether any user has a successful proxy sign-in followed by a
  rare application consent or role assignment, paying specific attention to the timestamp
  correlation.
success_criteria: A verdict of malicious | suspicious | benign per user, citing specific
  login and API rows.
tools:
- endpoint
- identity
```

## route-on-identity-risk
<!-- Route based on identity threat verdict -->
if~: "The triage-identity-threat verdict is malicious for at least one user." (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → remediation-verification
unavailable: → remediation-verification (blind_spot: cloud-api-retention-gap)
else: → close-out

## revoke-sessions
<!-- Revoke active sessions and tokens -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all refresh tokens and sessions for the users identified as malicious. Review and remove any recently consented applications in the tenant.
```
→ remediation-verification

## remediation-verification
<!-- Verify remediation and check for persistence -->
```manual target=analyst
Manually verify the removal of malicious app registrations. Check for any new administrative roles assigned during the compromise window. Review hb_account_change for password resets.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Summarize the users affected. If any false positives occurred due to legitimate rare first-party apps, add them to a tuning exclusion list for future iterations.
```
→ end

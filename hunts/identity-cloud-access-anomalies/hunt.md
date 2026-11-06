---
analysis: A single rule might detect an inbox rule creation, but it cannot contextualize
  it with preceding MFA fatigue or follow-on endpoint sabotage. This hunt connects
  the chain.
blind_spots:
- id: no-geo-enrichment
  owner: Identity Provider Admin
  question: whether a login comes from a rare country
  remediation: Enable geolocation logs at the source.
  requires: src_location_country in hb_auth_signin
  risk: If the identity provider does not provide geolocation, the rarity check returns
    no signal.
  stage: initial-access-vpn-abuse
- id: cloud-api-retention-limit
  owner: Security Operations
  question: whether a rule was created before the lookback window
  remediation: Extend audit log retention.
  requires: hb_cloud_api_activity retention > 30 days
  risk: Adversaries establishing long-term persistence will be missing from current
    logs.
  stage: collection-inbox-forwarding
coverage:
- stage: initial-access-vpn-abuse
  status: covered
  steps:
  - auth-anomaly-lead
  - geographic-rarity
- stage: collection-inbox-forwarding
  status: covered
  steps:
  - mailbox-rule-forwarding
- stage: credential-access-lsass-dumping
  status: covered
  steps:
  - endpoint-impact-check
- stage: impact-shadow-copy-deletion
  status: covered
  steps:
  - endpoint-impact-check
- reason: Belongs to another part of the "Reports of SIEM's Death Have Been Greatly
    Exaggerated" series.
  stage: execution-encoded-powershell
  status: out_of_scope
- reason: Belongs to another part of the "Reports of SIEM's Death Have Been Greatly
    Exaggerated" series.
  stage: persistence-unauthorized-rmm-and-admins
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Identity compromise is a primary driver for data exfiltration. Confirming
    mailbox integrity after auth anomalies provides high assurance.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder gained access via credential stuffing or MFA fatigue and established
  email collection or inhibited system recovery.
labels:
- hunt
- attack.t1133
- attack.t1110.004
- attack.t1114.003
- attack.t1003.001
- attack.t1490
- collection
- credential access
- execution
- impact
- initial access
- persistence
name: Identity and Cloud Access Anomalies
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: number
  mfa_failure_threshold:
    default: '5'
    description: Number of authentication failures to flag potential MFA fatigue or
      stuffing.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: number
  rare_country_threshold:
    default: '2'
    description: Threshold for users per country to be considered rare.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: number
  scope_hosts:
    default: []
    description: Limit search to specific hostnames identified in the lead.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: list[host]
  scope_users:
    default: []
    description: Usernames identified in the lead to focus follow-on queries.
    from:
      kind: manual
      observed: '2025-01-20'
      ref: analyst-defined
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/reports-that-siem-is-dead-are-exaggerated
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on users with administrative roles. Use hostnames from the lead query
  to scope the endpoint impact check.
references:
- name: "Huntress \u2014 Reports of SIEM's Death Have Been Greatly Exaggerated"
  url: https://www.huntress.com/blog/reports-that-siem-is-dead-are-exaggerated
related:
- hunt: persistence-unauthorized-rmm-and-admins
  reason: This hunt focus on exfiltration; RMM persistence belongs to a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: VPN and Identity Abuse
    observables:
    - VPN login from an unusual country
    - Credential stuffing attempts
    - Service account logging into VPN
    - MFA prompt bombing (MFA fatigue)
    slug: initial-access-vpn-abuse
    tactic: initial-access
    techniques:
    - T1133
    - T1110.004
  - name: Encoded PowerShell Execution
    observables:
    - Encoded PowerShell commands
    - powershell.exe -enc
    - powershell.exe -EncodedCommand
    slug: execution-encoded-powershell
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via RMM and New Admins
    observables:
    - ScreenConnect execution
    - New domain admin account creation
    - New local administrator account creation
    slug: persistence-unauthorized-rmm-and-admins
    tactic: persistence
    techniques:
    - T1133
    - T1136.001
  - name: LSASS Memory Dumping
    observables:
    - Mimikatz execution
    - LSASS process memory access
    - dbghelp.dll loading from uncommon locations
    slug: credential-access-lsass-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Email Collection via Inbox Rules
    observables:
    - Microsoft 365 inbox rule forwarding mail to outside address
    - New-InboxRule cmdlet usage
    slug: collection-inbox-forwarding
    tactic: collection
    techniques:
    - T1114.003
  - name: Inhibit System Recovery
    observables:
    - Shadow copies getting wiped
    - vssadmin delete shadows
    slug: impact-shadow-copy-deletion
    tactic: impact
    techniques:
    - T1490
  summary: This article outlines common attacker behaviors observed across endpoint
    and identity planes, including credential stuffing against VPNs, the use of encoded
    PowerShell for execution, and persistence via unauthorized RMM tools like ScreenConnect.
    The intrusion culminates in credential theft via LSASS dumping and the destruction
    of system recovery options like volume shadow copies to maximize impact.
series:
  index: 1
  slug: reports-of-siem-s-death-have-been-greatly-exaggerated
  title: Reports of SIEM's Death Have Been Greatly Exaggerated
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


# Identity and Cloud Access Anomalies

This hunt detects accounts under brute-force or MFA fatigue pressure and links them to rare geographic logins and unauthorized inbox forwarding. It connects identity compromise to data collection by joining authentication telemetry with cloud API logs. The flow evaluates authentication anomalies alongside geographic rarity and endpoint impact indicators like LSASS memory access or system recovery inhibition.

## auth-anomaly-lead
<!-- Authentication Anomaly Lead -->
Identify users with high failure rates or service accounts logging into interactive services.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, mfa_failure_threshold=mfa_failure_threshold)
~~~yaml
expected: Rows identify users targeted by brute-force or service accounts acting as
  users. Silence suggests no detected identity-level hammering.
reads:
- actor_user_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT LOWER(actor_user_name) AS user, COUNT(CASE WHEN activity_id = 5 THEN 1 END) AS failures, COUNT(CASE WHEN activity_id = 1 AND (LOWER(actor_user_name) LIKE '%svc-%' OR LOWER(actor_user_name) LIKE '%service%') THEN 1 END) AS service_logons, MIN(time) AS first_attempt, MAX(time) AS last_attempt FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(actor_user_name) HAVING failures >= {{mfa_failure_threshold}} OR service_logons > 0 ORDER BY failures DESC
```

## corroborate-anomalies
<!-- Corroborate Evidence -->
parallel:
- → geographic-rarity
- → mailbox-rule-forwarding
- → endpoint-impact-check
join: → triage-compromise

## geographic-rarity
<!-- Geographic Rarity Check -->
Identify logins from countries that are rare for the organization or identified users.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, rare_country_threshold=rare_country_threshold, scope_users=scope_users)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of countries associated with very few users, suggesting attacker
  infrastructure.
prevalence:
  by: actor_user_name
  key:
  - src_location_country
  rare_below: 3
reads:
- src_location_country
- actor_user_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT src_location_country, COUNT(DISTINCT actor_user_name) AS distinct_users, MIN(time) AS first_seen FROM hb_auth_signin WHERE activity_id = 1 AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_location_country HAVING distinct_users <= {{rare_country_threshold}}
```

## mailbox-rule-forwarding
<!-- Mailbox Rule Forwarding -->
Search for Microsoft 365 inbox rule creations that redirect mail to external recipients.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
expected: Cloud API records of users modifying inbox rules to redirect email. Silence
  is evidence of absence if logs are complete.
reads:
- time
- actor_user_name
- api_operation
- target_modified_property_new_values
- provider
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT time, actor_user_name, api_operation, target_modified_property_new_values FROM hb_cloud_api_activity WHERE provider = 'm365' AND LOWER(api_operation) IN ('new-inboxrule', 'set-inboxrule') AND (instr(LOWER(target_modified_property_new_values), 'forwardto') > 0 OR instr(LOWER(target_modified_property_new_values), 'redirectto') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## endpoint-impact-check
<!-- Endpoint Impact Check -->
Check for LSASS memory access or recovery inhibition on the scoped hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any row indicates an attempt to sabotage recovery or dump credentials on
  a host involved in the authentication anomalies.
reads:
- device_hostname
- process_cmd_line
- user_name
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vssadmin%delete%shadows%' OR LOWER(process_cmd_line) LIKE '%wbadmin%delete%catalog%' OR LOWER(process_cmd_line) LIKE '%bcdedit%/set%recoveryenabled%no%' OR LOWER(process_name) LIKE '%mimikatz%' OR LOWER(process_name) LIKE '%procdump%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Triage Identity Compromise -->
```agent target=hunter
cite: required
context:
- auth-anomaly-lead
- geographic-rarity
- mailbox-rule-forwarding
- endpoint-impact-check
max_iterations: 6
objective: Determine if any user account has been compromised by linking VPN/auth
  patterns with inbox rule modifications and endpoint impact signs.
success_criteria: A per-user verdict citing rows from all surfaces.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one account" (confidence: high, judge=hunter)
then: → contain-account
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-geo-enrichment)
else: → close-out

## contain-account
<!-- Contain Identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke active sessions, reset passwords for compromised accounts, and delete the unauthorized inbox rules.
```
→ manual-review

## manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the full cloud API history for other unauthorized changes such as Entra ID app registrations. Confirm malicious rules are deleted.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record confirmed indicator domains from the rules. Note whether the MFA failure threshold requires tuning.
```
→ end

---
analysis: A rule fires on '..' rules; this hunt validates the alert by correlating
  it with browser fingerprints and subsequent data destruction, such as HardDelete,
  reducing noise and providing a clear path to containment.
blind_spots:
- id: no-m365-audit-logs
  question: whether mailbox manipulation occurred
  requires: Microsoft 365 Unified Audit Log (UAL) to be enabled
  risk: If UAL is disabled, rule creations and email deletions are invisible to the
    hunt.
  stage: hidden-inbox-rule-persistence
- id: m365-log-latency
  question: if the attacker is currently active in the mailbox
  requires: Real-time log ingestion for UAL
  risk: M365 UAL logs can have a delay of several hours, meaning the attacker may
    have already completed the BEC before the hunt sees the signals.
  stage: bec-invoice-manipulation-impact
coverage:
- stage: session-hijack-mfa-bypass
  status: covered
  steps:
  - m365-session-concurrency
- stage: hidden-inbox-rule-persistence
  status: covered
  steps:
  - m365-suspicious-inbox-rules
- stage: bec-invoice-manipulation-impact
  status: covered
  steps:
  - m365-mailbox-impact-activity
- reason: 'Belongs to another part of the ''ClickFix to BEC in 24 Hours: Tragic Quadrant
    | Huntress'' series.'
  stage: click-fix-terminal-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''ClickFix to BEC in 24 Hours: Tragic Quadrant
    | Huntress'' series.'
  stage: browser-session-cookie-theft
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Protecting corporate assets from Business Email Compromise (BEC)
    and unauthorized financial diversions resulting from session theft is a high-priority
    requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has hijacked an authenticated Microsoft 365 session using
  stolen cookies, bypassing MFA to create stealthy inbox rules and perform fraudulent
  financial transactions.
labels:
- hunt
- attack.t1550.004
- attack.t1137.005
- attack.t1565.002
- attack.t1133
- credential access
- execution
- impact
- initial access
- persistence
- m365
name: M365 Session Hijacking and Mailbox Manipulation
parameters:
  lookback_days:
    default: '14'
    description: Number of days of history to examine for session and mailbox activity.
    from:
      kind: manual
      observed: '2024-10-24'
      ref: standard-retention
    type: number
  scope_users:
    default: []
    description: The specific users flagged in the lead step; empty means all users.
    from:
      kind: manual
      observed: '2024-10-24'
      ref: analyst-scoping
    type: list[string]
  suspicious_rule_names:
    default:
    - ..
    - .
    - '...'
    - ' '
    - z
    description: Minimalist or common evasion names used for malicious inbox rules.
    from:
      kind: article
      observed: '2024-10-13'
      ref: huntress-clickfix-bec
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on M365 tenants with high financial risk, such as Finance or Treasury
  departments. Widen the lookback window if investigating a known invoice fraud incident.
references:
- name: 'ClickFix to BEC in 24 Hours: Tragic Quadrant | Huntress'
  url: https://www.huntress.com/blog/clickfix-bec-tragic-quadrant-doris
related:
- hunt: click-fix-terminal-execution
  reason: Initial access via Terminal execution is handled by a separate endpoint-focused
    hunt.
  relation: out-of-scope-alternative
- hunt: clickfix-terminal-execution-cookie-theft
  relation: follows
scenario:
  stages:
  - name: ClickFix Social Engineering Execution
    observables:
    - Terminal.app
    - Command+Space
    - curl
    - Base64-encoded IP address in shell command
    slug: click-fix-terminal-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1059.004
  - name: Browser Session Cookie Theft
    observables:
    - Microsoft 365 session cookie
    - Access to browser cookie storage files
    slug: browser-session-cookie-theft
    tactic: credential-access
    techniques:
    - T1539
  - name: Session Hijacking and MFA Bypass
    observables:
    - Two browsers active in one session
    - Two different operating systems for the same login
    - Traffic routed through a VPN
    - Sign-in without password or MFA prompt
    slug: session-hijack-mfa-bypass
    tactic: initial-access
    techniques:
    - T1133
    - T1550.004
  - name: Persistence via Hidden Inbox Rule
    observables:
    - Inbox rule named '..'
    - Rule set to archive messages containing invoice numbers
    slug: hidden-inbox-rule-persistence
    tactic: persistence
    techniques:
    - T1137.005
  - name: Business Email Compromise Impact
    observables:
    - Replies to Treasury emails
    - Modified routing numbers for payments
    - Deletion of sent messages
    - Emptying of trash/deleted items folder
    slug: bec-invoice-manipulation-impact
    tactic: impact
    techniques:
    - T1565.002
  summary: A user seeking AI assistance was targeted by a ClickFix social engineering
    attack that induced them to execute a malicious shell command via Terminal. This
    command stole a Microsoft 365 session cookie, enabling the attacker to bypass
    MFA, gain unauthorized inbox access, and perform mailbox manipulation to redirect
    invoice payments in a Business Email Compromise (BEC) scenario.
series:
  index: 2
  slug: clickfix-to-bec-in-24-hours-tragic-quadrant-huntress
  title: 'ClickFix to BEC in 24 Hours: Tragic Quadrant | Huntress'
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


# M365 Session Hijacking and Mailbox Manipulation

This hunt identifies the transition from endpoint compromise to identity-based fraud. It starts by finding suspicious inbox rule creations that use minimalist or hidden naming conventions common in BEC attacks. If found, the hunt expands to analyze authentication anomalies, specifically concurrent sessions using different browser fingerprints or locations, and corroborates these with mailbox activities like unauthorized email sending or permanent deletion of evidence. This flow follows the scenario where a stolen session cookie allows an attacker to manipulate an inbox for hours without triggering MFA alerts.

## m365-suspicious-inbox-rules
<!-- Lead: Suspicious M365 Inbox Rule Creation -->
Identify the creation or modification of inbox rules with minimalist names like '..' which attackers use to hide mailbox manipulation.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, suspicious_rule_names=suspicious_rule_names)
~~~yaml
expected: A row indicates a rule created with a near-invisible name. Silence indicates
  no such rules were created via the API in the window.
reads:
- actor_user_name
- resource_name
- api_operation
- src_endpoint_ip
- user_agent
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, resource_name, api_operation, src_endpoint_ip, user_agent, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (api_operation = 'New-InboxRule' OR api_operation = 'Set-InboxRule') AND (instr(',' || '{{suspicious_rule_names}}' || ',', ',' || LOWER(substr(resource_name, instr(resource_name, '\') + 1)) || ',') > 0 OR LENGTH(substr(resource_name, instr(resource_name, '\') + 1)) <= 2) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-rule-lead
<!-- Evaluate Rule Lead -->
```agent target=hunter
cite: required
context:
- m365-suspicious-inbox-rules
max_iterations: 3
objective: Review the rule creation events and determine if they represent unusual
  administrative behavior for the named users.
success_criteria: A verdict of suspicious or benign for each user identified in the
  lead query.
tools:
- endpoint
- identity
```

## gate-suspicious-rules
<!-- Gate: Suspicious Rules Detected? -->
if~: "the evaluate-rule-lead verdict is suspicious for at least one user" (confidence: high, judge=hunter)
then: → corroborate-theft
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-m365-audit-logs)
else: → close-out

## corroborate-theft
<!-- Corroborate Session and Impact -->
parallel:
- → m365-session-concurrency
- → m365-mailbox-impact-activity
join: → triage-investigation

## m365-session-concurrency
<!-- M365 Session Concurrency Anomalies -->
Examine the session history for flagged users to find browser-string shifts or proxy use concurrent with the rule creation.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Users with disparate browser strings or VPN use within the same window.
  Silence implies single-browser sessions.
prevalence:
  by: actor_user_name
  key:
  - user_agent
  rare_below: 2
reads:
- actor_user_name
- user_agent
- src_endpoint_ip
- src_location_country
- is_proxy
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, user_agent, src_endpoint_ip, src_location_country, is_proxy, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_auth_signin WHERE provider = 'm365' AND status_id = 1 AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, user_agent, src_endpoint_ip, src_location_country, is_proxy
```

## m365-mailbox-impact-activity
<!-- M365 Mailbox Impact Actions -->
Identify fraudulent emails being sent or the deletion of evidence to hide the attacker's presence, specifically for the flagged users.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_users=scope_users)
~~~yaml
expected: A burst of email deletions or sends from a user who also showed rule anomalies.
  Silence indicates no destructive mailbox actions.
reads:
- actor_user_name
- api_operation
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, api_operation, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND (api_operation IN ('Send', 'MoveToDeletedItems', 'HardDelete', 'EmptyFolder') OR (api_operation = 'Update' AND LOWER(resource_name) LIKE '%inbox%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-investigation
<!-- Triage Investigation -->
```agent target=hunter
cite: required
context:
- evaluate-rule-lead
- m365-session-concurrency
- m365-mailbox-impact-activity
max_iterations: 6
objective: Determine if the user from the lead query shows session hijacking indicators,
  such as a new user agent during the rule creation that differs from their history,
  and corresponding impact actions.
success_criteria: A verdict of malicious | suspicious | benign per user, citing specific
  timestamps and browser strings.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage-investigation verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → revoke-m365-sessions
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: m365-log-latency)
else: → close-out

## revoke-m365-sessions
<!-- Revoke M365 Sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365 sessions for the affected user and reset the password.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the triage investigation output. Verify the browser string differences and the timing of the inbox rule.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the findings. Suggest tuning the suspicious rule name list if false positives were encountered.
```
→ end

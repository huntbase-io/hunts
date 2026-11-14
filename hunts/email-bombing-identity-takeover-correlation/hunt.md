---
analysis: This hunt correlates behavioral smokescreens (email floods) across SaaS,
  identity, and endpoint surfaces, which a single detection rule cannot link.
blind_spots:
- id: mailbox-visibility-gap
  owner: Messaging Team
  question: whether we can see floods targeting sub-folders or those processed by
    local client rules
  remediation: Enable advanced mailbox auditing in M365/Workspace to capture all folder
    moves and deletions.
  requires: comprehensive mailbox auditing for all folders
  risk: A flood that bypasses the primary inbox or is handled by a local Outlook rule
    might be missed by server-side auditing.
  stage: inbox-flood-distraction
- id: telephony-blindspot
  owner: Infrastructure Team
  question: whether the victim received a call from the fraudster prior to installing
    the RMM tool
  remediation: Correlate external VoIP call logs with employee ID profiles.
  requires: corporate telephony logs
  risk: The initial social engineering call is invisible to endpoint and cloud logs,
    preventing early detection of the scam phase.
  stage: remote-access-scam
coverage:
- stage: inbox-flood-distraction
  status: covered
  steps:
  - detect-mailbox-flood
- stage: account-takeover-alerts
  status: covered
  steps:
  - scoping-account-activity
  - detect-auth-risk
- stage: mailbox-rule-evasion
  status: covered
  steps:
  - detect-mailbox-rules
- stage: remote-access-scam
  status: covered
  steps:
  - detect-rmm-tools
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Email bombing is a high-confidence indicator of a concurrent, more
    serious intrusion; a negative result over the estate confirms no such coordinated
    campaign is active.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is using an email sign-up flood as a smokescreen to hide security
  alerts while they perform account takeovers and install remote access tools via
  tech support scams.
labels:
- hunt
- attack.t1499
- attack.t1098
- attack.t1550
- attack.t1114.003
- attack.t1219
- attack.t1566
- defense evasion
- execution
- impact
- persistence
- google-workspace
name: Email Bombing and Identity Takeover Correlation
parameters:
  bomb_threshold:
    default: '50'
    description: Number of total sign-up emails within a day to flag as a potential
      flood.
    from:
      kind: manual
      observed: '2024-10-16'
      ref: flood-heuristics
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-16'
      ref: default-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the process hunt.
    from:
      kind: manual
      observed: '2024-10-16'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/cybersecurity/inbox-flooded-signup-messages-email-bombing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus first on users with sensitive identity changes in the last 14 days,
  then expand to mailbox volume analysis for those accounts.
references:
- name: Inbox flooded with sign-up messages? Email bombing explained
  url: https://www.welivesecurity.com/en/cybersecurity/inbox-flooded-signup-messages-email-bombing/
related:
- hunt: mfa-fatigue-and-push-hijacking
  reason: MFA fatigue also uses a volume-based distraction strategy.
  relation: sibling
scenario:
  stages:
  - name: Email Bombing Smokescreen
    observables:
    - Hundreds of 'Welcome' or 'Confirm Subscription' emails within 24 hours
    - Automated sign-ups for newsletters and mailing lists
    - High volume of messages from legitimate but unsolicited domains
    slug: inbox-flood-distraction
    tactic: impact
    techniques:
    - T1499
  - name: Hidden Account Takeover
    observables:
    - Password reset notifications
    - New device registration alerts
    - MFA/2FA method changes
    - Recovery email or phone number updates
    - Fraudulent purchase invoices
    slug: account-takeover-alerts
    tactic: persistence
    techniques:
    - T1098
    - T1550
  - name: Mailbox Rule Manipulation
    observables:
    - Creation of new inbox rules to redirect alerts
    - Moving security notifications to RSS or Deleted folders
    - 'UAL Operation: New-InboxRule'
    - 'UAL Operation: Set-InboxRule'
    slug: mailbox-rule-evasion
    tactic: defense-evasion
    techniques:
    - T1114.003
  - name: Tech Support Scam Execution
    observables:
    - Installation of AnyDesk, TeamViewer, or other RMM tools
    - Process execution of remote access binaries
    - Network connections to known RMM control planes
    slug: remote-access-scam
    tactic: execution
    techniques:
    - T1219
    - T1566
  summary: Attackers flood a victim's inbox with hundreds of automated sign-up emails
    to bury legitimate security alerts. This smokescreen masks unauthorized account
    takeovers, fraudulent purchases, or password changes occurring simultaneously,
    and can also serve as a precursor to tech support scams.
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
  google-workspace:
    category: siem
    huntbase:
      product: google-workspace
    name: google workspace
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


# Email Bombing and Identity Takeover Correlation

This hunt identifies the coordination between a distraction-based denial-of-service (email bombing) and unauthorized identity changes. Attackers flood a victim's mailbox with automated sign-up emails to bury legitimate alerts from banks or identity providers. The hunt flows through a phased analysis of initial account scoping, mailbox floods, authentication risks, and follow-on evasion tactics like mailbox rule manipulation or unauthorized remote management software execution.

## scoping-account-activity
<!-- Scope sensitive account changes -->
Find users associated with sensitive account modifications like password resets or MFA changes that may be targets of a smokescreen.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of users who underwent identity modifications. This scopes the initial
  investigation to potential takeover victims.
reads:
- device_hostname
- user_name
- activity_name
- time
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT device_hostname, user_name, activity_name, time FROM hb_account_change WHERE activity_id IN (3, 4, 99) AND (LOWER(activity_name) LIKE '%password%' OR LOWER(activity_name) LIKE '%mfa%' OR LOWER(activity_name) LIKE '%factor%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Analyze floods and auth risks -->
parallel:
- → detect-mailbox-flood
- → detect-auth-risk
join: → early-stage-agent

## detect-mailbox-flood
<!-- Detect aggregate mailbox floods -->
Identify potential email bombs by searching for rare volume spikes per user.

```sqlite target=google-workspace role=baseline params=(lookback_days=lookback_days, bomb_threshold=bomb_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Users receiving an abnormal amount of mail in a single day. Silence proves
  absence only if all mailboxes were scanned.
prevalence:
  by: user_id
  key:
  - user_id
  rare_below: 2
reads:
- internal_date
- user_id
silence: evidence_of_absence
source: googleworkspace_gmail_message
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT COUNT(*) as volume, date(internal_date) as received_on, user_id FROM googleworkspace_gmail_message WHERE internal_date >= datetime('now', '-{{lookback_days}} days') GROUP BY user_id, received_on HAVING volume > {{bomb_threshold}} ORDER BY volume DESC
```

## detect-auth-risk
<!-- Hunt for authentication risks -->
Find sign-ins marked as high risk or failure patterns during the suspected flood period.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Users experiencing both a mailbox flood and security-relevant authentication
  failures or risks.
reads:
- actor_user_name
- device_hostname
- risk_state
- status_detail
- src_endpoint_ip
- src_location_country
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT actor_user_name, device_hostname, risk_state, status_detail, src_endpoint_ip, src_location_country, time FROM hb_auth_signin WHERE (risk_state != 'none' OR status_id = 2) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## early-stage-agent
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- scoping-account-activity
- detect-mailbox-flood
- detect-auth-risk
max_iterations: 3
objective: Identify users with concurrent high-volume email events and sensitive identity
  changes. Correlate timestamps to determine if the flood acted as a distraction for
  a specific security alert or auth failure.
success_criteria: A per-user confidence score for an active distraction campaign.
tools:
- endpoint
- google-workspace
- identity
```

## follow-on-parallel
<!-- Detect evasion and scam execution -->
parallel:
- → detect-mailbox-rules
- → detect-rmm-tools
join: → follow-on-agent

## detect-mailbox-rules
<!-- Detect mailbox rule and filter manipulation -->
Identify rules or filters created to move or delete alerts, ensuring the distraction remains permanent.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Rules or Google filters configured to silently process incoming mail, appearing
  after a flood.
reads:
- actor_user_name
- api_operation
- target_modified_property_new_values
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT actor_user_name, api_operation, target_modified_property_new_values, time FROM hb_cloud_api_activity WHERE ((api_operation IN ('New-InboxRule', 'Set-InboxRule') AND (LOWER(target_modified_property_new_values) LIKE '%move%' OR LOWER(target_modified_property_new_values) LIKE '%delete%')) OR (api_operation = 'CREATE_SETTINGS_FILTER')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-rmm-tools
<!-- Detect RMM tool execution -->
Identify unauthorized remote access software execution typically used in tech support scams.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of common RMM tools on machines belonging to users who were recently
  flooded or had identity changes.
reads:
- device_hostname
- process_name
- process_file_description
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-18'
~~~
SELECT device_hostname, process_name, process_file_description, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%anydesk%' OR LOWER(process_name) LIKE '%teamviewer%' OR LOWER(process_name) LIKE '%screenconnect%' OR LOWER(process_name) LIKE '%logmein%' OR LOWER(process_name) LIKE '%rustdesk%' OR LOWER(process_name) LIKE '%ateras%' OR LOWER(process_name) LIKE '%splashtop%' OR LOWER(process_name) LIKE '%ngrok%' OR LOWER(process_name) LIKE '%ultraviewer%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-agent
<!-- Synthesize the attack chain -->
```agent target=hunter
cite: required
context:
- early-stage-agent
- detect-mailbox-rules
- detect-rmm-tools
max_iterations: 5
objective: Review the early stage distraction indicators and determine if follow-on
  actions (mailbox rules, RMM execution) confirm an active threat. Malicious verdicts
  require temporal proximity between the email flood and unauthorized tool installation.
success_criteria: A final verdict of malicious | suspicious | benign per host and
  user.
tools:
- endpoint
- google-workspace
- identity
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the follow-on-agent verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: mailbox-visibility-gap)
else: → analyst-review

## isolate-and-remediate
<!-- Isolate host and revoke identity -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host where unauthorized RMM tools were detected. Revoke all active sessions for the identified user and purge all mailbox rules that move or delete security alerts.
```
→ analyst-review

## analyst-review
<!-- Analyst final review -->
```manual target=analyst
Review the cited rows from both agents. Confirm if the mailbox flood was coordinated with the RMM installation or auth failures. Record new IOCs.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record what was examined and what was not visible. If the bomb_threshold produced too many false positives, adjust it for the next run.
```
→ end

---
analysis: "A single rule can detect a brute force; this hunt correlates that brute\
  \ force with password resets and successful logons to different accounts across\
  \ 100 projects, then follows the session to identify post-compromise network activity\u2014\
  a cross-surface correlation no single rule can perform."
blind_spots:
- id: no-iam-management-visibility
  question: Did the attacker elevate their own permissions after logging in?
  remediation: Ingest CloudTrail Management Events into a dedicated security surface.
  requires: Raw CloudTrail Management Events (PutUserPolicy, AttachUserPolicy)
  risk: The normalized auth surface only shows the logon result; internal policy changes
    are invisible and require manual auditing of raw logs.
  stage: cloud-privilege-escalation
- id: no-long-term-credential-visibility
  question: Did the attacker create access keys for permanent backdoor access?
  requires: CloudTrail CreateAccessKey event
  risk: An attacker may create a key and leave the console session, maintaining access
    even after the console session is revoked.
  stage: access-key-creation
coverage:
- stage: failed-aws-console-logins
  status: covered
  steps:
  - console-brute-force
  - evaluate-early-auth
- stage: account-password-reset
  status: covered
  steps:
  - suspected-password-resets
  - evaluate-early-auth
- blind_spot: no-iam-management-visibility
  reason: Requires management-plane events like PutUserPolicy which are not visible
    in the provided normalized surfaces.
  stage: cloud-privilege-escalation
  status: not_visible
- blind_spot: no-long-term-credential-visibility
  reason: Requires management-plane visibility into access key lifecycle events.
  stage: access-key-creation
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AWS Console access is the primary control plane for cloud resources;
    a successful takeover can lead to full organizational compromise. Triaging this
    chain centrally ensures uniform response for decentralized teams.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access to a cloud account by brute-forcing
  the console and performing a password reset, then used that access to establish
  a presence across multiple projects in the organization.
labels:
- hunt
- attack.t1110.001
- attack.t1098
- attack.t1078.004
name: AWS Cloud Identity Takeover Chain
parameters:
  admin_ips:
    default: []
    description: Known administrative or automation IPs to exclude from scoping counts.
    from:
      kind: article
      observed: '2026-09-18'
      ref: https://www.elastic.co/security-labs/blog/centralized-alert-triage-cross-project-search
    type: list[ip]
  failed_logon_threshold:
    default: '10'
    description: Number of failed attempts from a single IP before it is considered
      a brute-force lead.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine for brute force and follow-on activity.
    type: number
  reset_indicators:
    default:
    - PasswordReset
    - ChangePassword
    - UpdateAccount
    - ResetPassword
    description: Specific activity_name values in authentication logs that indicate
      account modification.
    type: list[string]
  scope_hosts:
    default: []
    description: The AWS Account IDs (dst_endpoint_name) to focus on; leave empty
      to hunt across all 100 linked projects.
    type: list[host]
  suspicious_ips:
    default: []
    description: IPs identified in the first agent read to pivot on in the follow-on
      stage.
    from:
      kind: article
      observed: '2026-09-18'
      ref: https://www.elastic.co/security-labs/blog/centralized-alert-triage-cross-project-search
    type: list[ip]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/centralized-alert-triage-cross-project-search
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Scope to the central origin project. The initial queries cover all linked
  projects by default; use the scope_hosts parameter to isolate specific AWS accounts
  identified as targets. Known admin IPs are excluded to focus on user-driven activity.
references:
- name: 'One SOC, 100 projects: running centralized alert triage on Elastic Security
    Serverless'
  url: https://www.elastic.co/security-labs/blog/centralized-alert-triage-cross-project-search
related:
- hunt: aws-suspicious-iam-policy-modification
  reason: This hunt focuses on the takeover chain behavior, while the alternative
    would focus directly on the IAM management events if they were ingested.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Failed AWS console logins
    observables:
    - user.name
    - 'event.category: authentication'
    - 'event.action: failure'
    - source.ip
    - host.name
    slug: failed-aws-console-logins
    tactic: initial-access
    techniques:
    - T1110.001
  - name: Cloud account password reset
    observables:
    - 'event.action: PasswordReset'
    - user.name
    slug: account-password-reset
    tactic: persistence
    techniques:
    - T1098
  - name: AWS privilege escalation
    observables:
    - 'event.action: PutUserPolicy'
    - 'event.action: AttachUserPolicy'
    slug: cloud-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1078.004
  - name: AWS access key creation
    observables:
    - 'event.action: CreateAccessKey'
    - user.name
    slug: access-key-creation
    tactic: persistence
    techniques:
    - T1098
  summary: The campaign involves an AWS account takeover sequence beginning with credential-stuffing
    or brute-force attempts on the AWS Management Console. Once an account is compromised,
    the actor performs a password reset, escalates privileges within the cloud environment,
    and generates long-term persistence through the creation of new AWS access keys.
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
tlp: clear
type: investigation
---


# AWS Cloud Identity Takeover Chain

This hunt triages AWS identity takeover attempts across a centralized SOC managing 100 projects. It starts by identifying brute-force patterns and password-reset markers on the authentication surface, then pivots to successful logons and subsequent network traffic to confirm the transition from attempt to takeover. By acting centrally on a single origin but validating across linked projects, analysts can contain compromised cloud identities across the entire organization.

## inventory-aws-accounts
<!-- Inventory AWS Accounts -->
Find every AWS account recording activity to scope the hunt across the organization projects while excluding administrative noise.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, admin_ips=admin_ips)
~~~yaml
expected: A list of AWS account names and their event volume excluding known admin
  IPs. Silence means no AWS authentication events were recorded.
reads:
- dst_endpoint_name
- provider
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT dst_endpoint_name AS aws_account, COUNT(*) AS event_count FROM hb_auth_signin WHERE provider = 'aws' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{admin_ips}}' = '' OR NOT (instr(',' || '{{admin_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0)) GROUP BY dst_endpoint_name
```

## early-auth-indicators
<!-- Identify Early Auth Anomalies -->
parallel:
- → console-brute-force
- → suspected-password-resets
join: → evaluate-early-auth

## console-brute-force
<!-- AWS Console Brute Force -->
Identify source IPs targeting one or more users with high failure volumes.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, failed_logon_threshold=failed_logon_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs with failure counts exceeding the threshold. High failure counts
  across many users indicate a spray; high counts for one user indicate brute force.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- actor_user_name
- activity_id
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS targeted_users, COUNT(*) AS failures, MIN(time) AS first_failure, MAX(time) AS last_failure FROM hb_auth_signin WHERE provider = 'aws' AND activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING failures >= {{failed_logon_threshold}} ORDER BY failures DESC
```

## suspected-password-resets
<!-- Suspected Password Modification -->
Identify management-related authentication activity from the same time window.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, reset_indicators=reset_indicators)
~~~yaml
expected: Authentication metadata events matching the reset keywords. These indicate
  the persistence stage of the takeover.
reads:
- src_endpoint_ip
- actor_user_name
- activity_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, actor_user_name, dst_endpoint_name, activity_name, time FROM hb_auth_signin WHERE provider = 'aws' AND activity_id = 99 AND instr(',' || '{{reset_indicators}}' || ',', ',' || activity_name || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-early-auth
<!-- Evaluate Early Auth Anomalies -->
```agent target=hunter
cite: required
context:
- console-brute-force
- suspected-password-resets
max_iterations: 4
objective: Identify the source IPs that performed brute-force attempts and then reached
  a password reset event. Prioritize IPs that appear in both console-brute-force and
  suspected-password-resets results as they represent the highest risk.
success_criteria: A verdict per IP citing specific rows that show the progression
  from failure to modification.
tools:
- identity
- network
```

## takeover-operational-pivot
<!-- Hunt Takeover Operational Activity -->
parallel:
- → successful-logons-pivot
- → suspicious-network-outbound
join: → confirm-account-takeover

## successful-logons-pivot
<!-- Successful Logons from Suspicious IPs -->
Confirm if the identified IPs successfully logged in to any account and check if they reached multiple distinct accounts.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_ips=suspicious_ips)
~~~yaml
expected: Rows naming a successful logon from a source IP previously seen brute-forcing.
  Multiple accounts indicate organization-wide compromise.
reads:
- src_endpoint_ip
- actor_user_name
- dst_endpoint_name
- activity_id
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, actor_user_name, COUNT(DISTINCT dst_endpoint_name) AS account_count, GROUP_CONCAT(DISTINCT dst_endpoint_name) AS accounts, MIN(time) AS first_success, MAX(time) AS last_success FROM hb_auth_signin WHERE provider = 'aws' AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND ('{{suspicious_ips}}' = '' OR instr(',' || '{{suspicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) GROUP BY src_endpoint_ip, actor_user_name
```

## suspicious-network-outbound
<!-- Outbound Traffic from Suspicious IPs -->
Determine if the attacker IPs are interacting with other infrastructure after the logon.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, suspicious_ips=suspicious_ips)
~~~yaml
expected: Connections from the brute-force IPs to unexpected destinations. This establishes
  the post-logon behavior.
reads:
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, protocol, COUNT(*) AS connections FROM hb_network_connection WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{suspicious_ips}}' = '' OR instr(',' || '{{suspicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) GROUP BY src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, protocol
```

## confirm-account-takeover
<!-- Confirm Account Takeover -->
```agent target=hunter
cite: required
context:
- evaluate-early-auth
- successful-logons-pivot
- suspicious-network-outbound
max_iterations: 5
objective: Determine if the evidence supports a continuous chain from brute-force
  attempt to successful account takeover and operational usage. Factor in the early
  auth findings and follow-on pivots.
success_criteria: A per-identity verdict citing the transition from failures to success
  and any subsequent network traffic.
tools:
- identity
- network
```

## route-on-takeover
<!-- Route on Takeover Verdict -->
if~: "the confirm-account-takeover verdict is malicious for at least one cloud identity" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → manual-iam-audit
unavailable: → manual-iam-audit (blind_spot: no-iam-management-visibility)
else: → manual-iam-audit

## isolate-identity
<!-- Isolate Identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active IAM sessions and deactivate all existing access keys for the actor_user_name identified in the malicious verdict.
```
→ manual-iam-audit

## manual-iam-audit
<!-- Manual IAM Management Audit -->
```manual target=analyst
Review the raw CloudTrail logs for the compromised user to find evidence of PutUserPolicy, AttachUserPolicy, or CreateAccessKey events that occurred after the suspicious logon.
```
→ remediation-summary

## remediation-summary
<!-- Remediation and Close-Out -->
```manual target=analyst
Record the full takeover chain; recommend enabling MFA and IP-based conditional access for all console users across all organizational projects.
```
→ end

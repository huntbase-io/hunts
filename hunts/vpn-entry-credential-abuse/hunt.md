---
analysis: 'This hunt correlates three distinct identity-plane signals: the initial
  VPN entry, the volume of failures, and rare account modifications. A single rule
  usually only fires on the failures, lacking the context of the entry point and the
  baseline of account changes.'
blind_spots:
- id: missing-vpn-logs
  owner: Security Engineering
  question: whether logins occurred through gateways not enrolled in the lake
  remediation: Enrol all third-party VPN gateways in central logging.
  requires: VPN gateway logs in hb_auth_signin
  risk: The hunt misses entry points through unmonitored infrastructure.
  stage: unauthorized-vpn-access
- id: mfa-reporting-gap
  owner: Detection Engineering
  question: whether the 'mfa' column is accurately populated by the provider
  remediation: Verify MFA logging capabilities of the gateway and update the ingestion
    parser if needed.
  requires: Reliable MFA status in hb_auth_signin
  risk: If MFA status is always NULL, the scoping step will produce excessive false
    positives.
  stage: unauthorized-vpn-access
coverage:
- stage: unauthorized-vpn-access
  status: covered
  steps:
  - vpn-entry-no-mfa
- stage: internal-credential-testing
  status: covered
  steps:
  - internal-brute-force
  - unusual-account-changes
- reason: Handled by a separate hunt focusing on network scanning.
  stage: internal-network-discovery
  status: out_of_scope
- reason: Handled by a separate hunt focusing on SMB and HTTP data scraping.
  stage: data-share-and-doc-collection
  status: out_of_scope
- reason: Handled by a separate hunt focusing on WSUS and configuration management
    exploitation.
  stage: wsus-exploitation-attempt
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Third-party risk via misconfigured external gateways is a high-impact
    exposure. Identifying successful entries and subsequent brute-force noise is a
    fundamental requirement for securing the network perimeter.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has gained initial access through a misconfigured VPN gateway
  lacking multi-factor authentication and is brute-forcing administrator accounts
  across internal systems to escalate privileges.
labels:
- hunt
- attack.t1133
- attack.t1078
- attack.t1110
- collection
- credential access
- discovery
- execution
- initial access
name: VPN Entry and Internal Brute Force
parameters:
  admin_account_patterns:
    default:
    - admin
    - root
    - administrator
    - svc_
    - sql
    - backup
    description: Administrative username substrings or specific accounts to prioritize
      in brute-force detection.
    from:
      kind: article
      observed: '2026-10-13'
      ref: unit42-third-party-risk
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Target hosts identified in the scoping step; leave empty to hunt
      across the entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/noise-inside-network-third-party-risk/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with external-facing VPN gateways. Focus on accounts that log in
  from geographically unusual locations or at anomalous times, especially those that
  do not trigger an MFA challenge.
references:
- name: 'The Noise Inside the Network: How an Unsophisticated Attack Exposed a Third-Party
    Risk'
  url: https://unit42.paloaltonetworks.com/noise-inside-network-third-party-risk/
related:
- hunt: internal-recon-and-lateral-movement
  reason: After testing credentials, an attacker typically conducts internal discovery
    to find high-value targets.
  relation: follows
scenario:
  stages:
  - name: Unauthorized VPN Access
    observables:
    - VPN-based access attempts
    - Third-party-managed external gateway appliance
    - Compromised credentials
    - Authentication without MFA
    slug: unauthorized-vpn-access
    tactic: initial-access
    techniques:
    - T1133
    - T1078
  - name: Broad Internal Discovery
    observables:
    - Host and network scans
    - Interactions with thousands of systems
    - Multiple protocol usage for reconnaissance
    slug: internal-network-discovery
    tactic: discovery
  - name: Internal Credential Brute Force
    observables:
    - Password-guessing campaigns
    - Brute-force authentication attempts
    - Targeting of administrator accounts
    slug: internal-credential-testing
    tactic: credential-access
    techniques:
    - T1110
  - name: Internal Data Collection
    observables:
    - Automated web requests to internal systems
    - Scraping documentation pages and attachments
    - Enumeration of network shares
    slug: data-share-and-doc-collection
    tactic: collection
  - name: WSUS Remote Code Execution Attempt
    observables:
    - WSUS remote code execution vulnerability
    - Central configuration management server
    - Unauthorized code execution attempt
    slug: wsus-exploitation-attempt
    tactic: execution
    techniques:
    - T1190
  summary: An opportunistic attacker exploited a misconfigured third-party VPN gateway
    using compromised credentials to gain access to a bank's internal network. The
    intruder performed broad network scanning, brute-force attempts against administrator
    accounts, and scraped internal documentation before attempting to execute code
    via a WSUS vulnerability, which was blocked by endpoint security.
series:
  index: 1
  slug: the-noise-inside-the-network-how-an-unsophisticated-attack-exposed-a-third-party-risk
  title: 'The Noise Inside the Network: How an Unsophisticated Attack Exposed a Third-Party
    Risk'
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


# VPN Entry and Internal Brute Force

This hunt examines the identity plane for signs of third-party risk and credential abuse. It starts by scoping for successful VPN sign-ins where multi-factor authentication (MFA) was not enforced. It then fans out to identify internal brute-force patterns targeting administrative accounts and correlates these with rare account lifecycle changes, such as password resets or account creations. An agent weighs the combined evidence to distinguish between automated noisy scanners and a successful intrusion originating from a compromised VPN session.

## vpn-entry-no-mfa
<!-- VPN Sign-ins Without MFA -->
Identify successful logins to VPN services that did not use or report multi-factor authentication.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows naming the VPN gateway and the users who successfully logged in without
  MFA. Silence proves no MFA-less logins were recorded for gateways reporting to the
  lake.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- service_name
- dst_endpoint_name
- mfa
- status_id
- time
- metadata_product
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT DISTINCT device_hostname, actor_user_name, src_endpoint_ip, service_name, time FROM hb_auth_signin WHERE status_id = 1 AND (mfa = 'false' OR mfa IS NULL) AND (LOWER(service_name) LIKE '%vpn%' OR LOWER(dst_endpoint_name) LIKE '%vpn%' OR LOWER(metadata_product) LIKE '%vpn%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## investigate-lateral-risk
<!-- Investigate Brute Force and Rare Changes -->
parallel:
- → internal-brute-force
- → unusual-account-changes
join: → triage-identity-signals

## internal-brute-force
<!-- Internal Brute Force Against Admins -->
Find source IPs attempting to guess passwords for multiple administrative accounts.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, admin_account_patterns=admin_account_patterns, scope_hosts=scope_hosts)
~~~yaml
expected: A single internal IP address generating dozens of authentication failures
  across different admin names. Silence suggests no automated guessing was visible
  on these hosts.
reads:
- src_endpoint_ip
- device_hostname
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT src_endpoint_ip, device_hostname, COUNT(DISTINCT actor_user_name) AS unique_accounts, COUNT(*) AS attempt_count FROM hb_auth_signin WHERE status_id = 2 AND (LOWER(actor_user_name) LIKE '%admin%' OR LOWER(actor_user_name) LIKE '%root%' OR instr(',' || '{{admin_account_patterns}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, device_hostname HAVING attempt_count > 20
```

## unusual-account-changes
<!-- Rare Account Lifecycle Changes -->
Baseline account changes to identify rare password resets or creations that could indicate persistence.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A password reset or account creation performed by an unusual actor. Baseline
  noise will show routine resets; anomalous entries will have low actor counts.
prevalence:
  by: device_hostname
  key:
  - user_name
  - activity_name
  rare_below: 3
reads:
- user_name
- activity_name
- device_hostname
- activity_id
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT user_name, activity_name, device_hostname, COUNT(DISTINCT actor_user_name) AS distinct_actors, MIN(time) AS first_change FROM hb_account_change WHERE activity_id IN (1, 4) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_name, activity_name, device_hostname
```

## triage-identity-signals
<!-- Triage Identity Risks -->
```agent target=hunter
cite: required
context:
- vpn-entry-no-mfa
- internal-brute-force
- unusual-account-changes
max_iterations: 4
objective: Identify hosts where a user successfully logged in via VPN without MFA
  and then initiated brute-force attempts or sensitive account modifications internally.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  rows.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → revoke-compromised-access
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: missing-vpn-logs)
else: → hunt-summary

## revoke-compromised-access
<!-- Revoke Compromised Access -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the compromised accounts and force a password reset after confirming the scope with the IR lead.
```
→ analyst-validation

## analyst-validation
<!-- Analyst Deep Dive -->
```manual target=analyst
Review the source IPs and actor_user_name from the VPN logins. Note that the internal source IP for the brute force may be an internal jump box or the beachhead host itself. Pivot to hb_network_connection to verify if the beachhead host contacted the systems targeted in the brute-force query.
```
→ hunt-summary

## hunt-summary
<!-- Hunt Close-out -->
```manual target=analyst
Document whether the brute-force attempts were successful. If the failure threshold resulted in too many false positives, recommend tuning the detection-candidate query for the environment.
```
→ end

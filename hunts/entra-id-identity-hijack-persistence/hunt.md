---
analysis: While standard rules may alert on known malicious IPs, this hunt correlates
  capture, replay, and persistence across three surfaces and two analysis phases to
  confirm a successful breach that siloed rules often treat as disconnected noise.
blind_spots:
- id: m365-audit-granularity
  question: whether the specific MFA registration event can be attributed to the relay
    IP
  requires: M365 Unified Audit Log (UAL) with Advanced Auditing enabled
  risk: Without advanced auditing, granular MFA tampering events such as specific
    factor labels (e.g., iPhone 13) may be missing, leaving only generic success records.
  stage: mfa-method-tampering
- id: token-replay-invisibility
  question: whether existing CA policies were applied to the replayed session
  requires: hb_auth_signin with conditional_access_status
  risk: Replayed tokens inherit the MFA status of the original session; if telemetry
    cannot distinguish the relay IP from the replay IP within the same session context,
    the replay may appear as a legitimate resumption.
  stage: token-replay-access
coverage:
- stage: aitm-phishing-capture
  status: covered
  steps:
  - scoping-signin-infrastructure
  - relay-mfa-success
- stage: token-replay-access
  status: covered
  steps:
  - scoping-signin-infrastructure
  - scripted-user-agents
- stage: rogue-device-registration
  status: covered
  steps:
  - rogue-device-registration-prevalence
- stage: mfa-method-tampering
  status: covered
  steps:
  - mfa-tampering-audit
- reason: Belongs to another part of the 'M365 Token Spray and Replay Campaign Compromises
    Business Email Accounts' series.
  stage: inbox-rule-evasion
  status: out_of_scope
- reason: Belongs to another part of the 'M365 Token Spray and Replay Campaign Compromises
    Business Email Accounts' series.
  stage: fraudulent-email-correspondence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Token replay is a critical risk that bypasses standard MFA and secures
    persistent directory access through rogue device registration; verifying the absence
    of these registrations is an essential identity audit.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has replayed session tokens stolen through AiTM relays to
  register rogue devices and establish persistent MFA methods in the victim tenant.
labels:
- hunt
- attack.t1566
- attack.t1110.003
- attack.t1098
- credential access
- defense evasion
- impact
- initial access
- persistence
name: Entra ID Identity Hijack and Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  relay_ips:
    default:
    - 185.238.2.195
    - 167.148.41.96
    description: Known AiTM relay IP addresses used for capture.
    from:
      kind: article
      observed: '2026-10-22'
      ref: huntress-token-replay-spray
    type: list[ip]
  replay_ips:
    default:
    - 193.26.115.221
    - 193.26.115.72
    - 193.26.115.16
    - 193.26.115.21
    - 193.26.115.199
    - 193.26.115.210
    description: Observed replay IPs from the 1337 Services GmbH block.
    from:
      kind: article
      observed: '2026-10-22'
      ref: huntress-token-replay-spray
    type: list[ip]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/token-replay-spray
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize accounts with Global Administrator roles or finance department
  associations, as the report highlights these as primary targets for rogue device
  registration and payroll fraud.
references:
- name: "Huntress \u2014 M365 Token Spray and Replay Campaign Compromises Business\
    \ Email Accounts"
  url: https://www.huntress.com/blog/token-replay-spray
related:
- hunt: m365-inbox-rule-fraud
  reason: This hunt establishes the identity compromise; a subsequent hunt focuses
    on the mailbox rules created to hide fraudulent correspondence.
  relation: follows
scenario:
  stages:
  - name: AiTM Token Capture
    observables:
    - 185.238.2.195
    - 2400:8d60:2::1:841d:5dd
    - Relay-hosted fake Microsoft sign-in pages
    - Device-code phishing flow
    slug: aitm-phishing-capture
    tactic: initial-access
    techniques:
    - T1566
  - name: Token Replay Authentication
    observables:
    - 193.26.115.0/24
    - 193.26.115.221
    - 193.26.115.72
    - 193.26.115.16
    - 193.26.115.21
    - 193.26.115.199
    - 193.26.115.210
    - 'User agent: node'
    - 'User agent: Mozilla/5.0'
    - 'Request type: OAuth2:Token'
    - 'Request type: Login:reprocess'
    - 'Client: Microsoft Authentication Broker'
    - 'Client: OfficeHome'
    slug: token-replay-access
    tactic: credential-access
    techniques:
    - T1110.003
  - name: Rogue Entra Device Registration
    observables:
    - 'Device name: DESKTOP-[0-9A-F]{8}'
    - 'Target: Device Registration Service'
    slug: rogue-device-registration
    tactic: persistence
    techniques:
    - T1098
  - name: MFA Tampering and Persistence
    observables:
    - 'Authenticator label: iPhone 13'
    - Wiped existing MFA methods
    - New authenticator registration within 3 hours of compromise
    - 'Service: Microsoft security-info registration'
    slug: mfa-method-tampering
    tactic: persistence
    techniques:
    - T1098
  - name: Stealth Inbox Rule Evasion
    observables:
    - 'Rule names: sss, s, d'
    - 'Rule keywords: payroll, direct deposit, bank, bonus'
    - 'Target folders: RSS Feeds, Conversation History'
    - 'VPN IPs: 167.148.41.96'
    slug: inbox-rule-evasion
    tactic: defense-evasion
    techniques:
    - T1564.008
  - name: Payroll Fraud Correspondence
    observables:
    - Outbound payroll emails to external CPAs
    - Bulk outbound spam from compromised accounts
    slug: fraudulent-email-correspondence
    tactic: impact
    techniques:
    - T1566
  summary: Attackers used adversary-in-the-middle (AiTM) relays to capture Microsoft
    365 session tokens, which were then replayed from a centralized hosting provider
    (1337 Services GmbH) in a large-scale token-spraying campaign. Once authenticated,
    the actors registered rogue Entra ID devices and modified MFA methods to ensure
    persistent access before deploying hidden inbox rules to facilitate business email
    compromise and payroll fraud.
series:
  index: 1
  slug: m365-token-spray-and-replay-campaign-compromises-business-email-accounts
  title: M365 Token Spray and Replay Campaign Compromises Business Email Accounts
  total: 2
severity: high
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


# Entra ID Identity Hijack and Persistence

This hunt tracks a campaign pairing AiTM phishing with token replay to bypass MFA and secure directory persistence. It follows a phased flow: the first phase identifies potentially hijacked sessions by examining successful MFA attempts from known relay infrastructure and replayed activity using scripted user agents. The second phase correlates these sessions with directory persistence indicators, specifically rogue Entra-joined devices and unauthorized MFA method tampering. This approach ensures that directory-level changes are evaluated in the context of high-probability session compromises.

## scoping-signin-infrastructure
<!-- Scope sessions from known infrastructure -->
Identify users and endpoints that successfully authenticated from the reported relay or replay IP ranges.

```sqlite target=identity role=scoping params=(replay_ips=replay_ips, relay_ips=relay_ips, lookback_days=lookback_days)
~~~yaml
expected: A list of potentially compromised users and machines. Silence proofs that
  the specific infrastructure was not seen in successful logons.
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT DISTINCT device_hostname, actor_user_name FROM hb_auth_signin WHERE (instr(',' || '{{replay_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR instr(',' || '{{relay_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-behavior
<!-- Parallel capture and replay triage -->
parallel:
- → scripted-user-agents
- → relay-mfa-success
join: → early-stage-triage

## scripted-user-agents
<!-- Detect scripted user agents -->
Find logons using 'node' or bare 'Mozilla/5.0' user agents associated with automated token replay tools.

```sqlite target=identity role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Successful logons with scripted agents. Silence means no automated replay
  was detected via UA strings.
reads:
- actor_user_name
- device_hostname
- dst_endpoint_name
- src_endpoint_ip
- status_id
- time
- user_agent
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, actor_user_name, user_agent, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE (LOWER(user_agent) LIKE '%node%' OR user_agent = 'Mozilla/5.0') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## relay-mfa-success
<!-- MFA success from known AiTM relays -->
Identify successful MFA events originating from known relay infrastructure, signifying a likely session capture.

```sqlite target=identity role=triage params=(relay_ips=relay_ips, lookback_days=lookback_days)
~~~yaml
expected: User sign-ins using MFA from malicious proxies. Silence indicates no capture
  activity from these IPs.
reads:
- actor_user_name
- auth_requirement
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, auth_requirement, time FROM hb_auth_signin WHERE instr(',' || '{{relay_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 AND auth_requirement = 'multiFactorAuthentication' AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Assess session hijack probability -->
```agent target=hunter
cite: required
context:
- scoping-signin-infrastructure
- scripted-user-agents
- relay-mfa-success
max_iterations: 3
objective: Identify users with MFA success from relay infrastructure followed by automated
  activity from replay infrastructure.
success_criteria: A verdict citing correlation in timing and IP between capture and
  replay.
tools:
- endpoint
- identity
```

## persistence-hunting
<!-- Hunt for follow-on persistence -->
parallel:
- → rogue-device-registration-prevalence
- → mfa-tampering-audit
join: → persistence-synthesis

## rogue-device-registration-prevalence
<!-- Rare rogue device registration -->
Stack-count devices matching the campaign naming convention to identify rare rogue registrations across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare devices matching the DESKTOP-[HEX8] pattern. Silence means no such
  registrations were detected.
prevalence:
  by: device_uid
  key:
  - hostname
  rare_below: 3
reads:
- device_uid
- first_seen
- hostname
- provider
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT hostname, provider, COUNT(DISTINCT device_uid) AS device_count, MIN(time) AS first_seen FROM hb_devices WHERE provider = 'azure_ad' AND LOWER(hostname) LIKE 'desktop-%' AND length(hostname) = 16 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY hostname, provider HAVING device_count <= 2
```

## mfa-tampering-audit
<!-- MFA method modifications -->
Identify API activity related to modifying MFA methods for users identified in the first phase.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Cloud API calls targeting MFA settings. Silence proofs no such audit events
  occurred in the window.
reads:
- actor_user_name
- api_operation
- api_service_name
- provider
- resource_name
- status
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT actor_user_name, api_operation, resource_name, api_service_name, status, time FROM hb_cloud_api_activity WHERE provider = 'azure_ad' AND (LOWER(api_operation) LIKE '%strongauthentication%' OR LOWER(api_operation) LIKE '%mfa%') AND (LOWER(api_operation) LIKE '%delete%' OR LOWER(api_operation) LIKE '%update%' OR LOWER(api_operation) LIKE '%add%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## persistence-synthesis
<!-- Synthesize hijack and persistence -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- rogue-device-registration-prevalence
- mfa-tampering-audit
max_iterations: 5
objective: Determine if hijacked users identified in the first triage show corresponding
  persistence activity such as rogue device registration or MFA tampering.
success_criteria: A final verdict citing the entire chain from capture to directory
  changes.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on compromise -->
if~: "the persistence-synthesis verdict is malicious for at least one user or device" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: m365-audit-granularity)
else: → close-out

## isolate-and-revoke
<!-- Isolate compromised accounts -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions and refresh tokens for the compromised accounts. Temporarily disable account access pending a full MFA reset and password rotation.
```
→ cleanup-persistence

## cleanup-persistence
<!-- Clean-up persistence mechanisms -->
```action target=identity
~~~yaml
approval: required
~~~
Delete rogue devices matching the DESKTOP-[HEX8] naming convention from the tenant directory. Audit the registered MFA methods for the affected users in the Entra portal and remove any factors not explicitly confirmed by the user.
```
→ analyst-review

## analyst-review
<!-- Analyst final review -->
```manual target=analyst
Review the synthesized verdict and confirm that all identified persistence mechanisms have been removed. Record tuning notes for any false positives found during the triage phase.
```
→ close-out

## close-out
<!-- Hunt close out -->
```manual target=analyst
Record the affected users and any newly identified malicious IP infrastructure. Evaluate Conditional Access policies to enforce compliant-device requirements for high-value resources to mitigate future token replay.
```
→ end

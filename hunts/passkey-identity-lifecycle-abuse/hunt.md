---
analysis: 'This hunt is not just a single rule; it connects three distinct signals:
  an unusual login protocol, an account security modification, and a cloud persistence
  operation. A single rule firing on any one of these would be high-noise, but the
  narrative connection across identity and cloud surfaces is what identifies a real
  compromise.'
blind_spots:
- id: cloud-audit-gap
  question: whether persistence was established before the current log window
  requires: hb_cloud_api_activity retention beyond 90 days
  risk: An attacker may have established long-term persistence (inbox rules or OAuth
    apps) that is no longer visible in active audit logs.
  stage: unauthorized-identity-manipulation
- id: memory-only-tampering
  question: whether the attacker used in-memory browser hooks to alter WebAuthn responses
  requires: hb_module_activity with real-time browser hook detection
  risk: Software inventory only shows installed extensions; it cannot see memory-resident
    hooks injected via other processes, potentially missing advanced browser tampering.
  stage: endpoint-authentication-tampering
coverage:
- stage: passkey-themed-social-engineering
  status: covered
  steps:
  - device-code-scoping
  - rare-auth-protocol-stack
- stage: device-code-flow-abuse
  status: covered
  steps:
  - device-code-scoping
  - early-stage-triage
- stage: unauthorized-identity-manipulation
  status: covered
  steps:
  - mfa-lifecycle-anomalies
  - cloud-persistence-audit
- stage: endpoint-authentication-tampering
  status: covered
  steps:
  - unapproved-browser-extensions
  - manual-cleanup-verification
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Passkeys are highly secure, but as the Huntress research shows, attackers
    are pivoting to the enrollment and recovery lifecycles. A negative result verifies
    that our move to passkeys is not being undermined by parallel authentication flows.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker uses social engineering lures themed around passkey enrollment
  to trick users into authorizing a device-code login flow, subsequently registering
  unauthorized authenticators and establishing persistence via cloud application grants
  or unapproved browser extensions.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1176
- attack.t1098
- attack.t1137
- execution
- initial access
- persistence
name: Passkey-Themed Phishing and Identity Lifecycle Abuse
parameters:
  approved_extension_ids:
    default:
    - hfjimclajcmimbipebeogibjcaachgei
    description: List of approved browser extension IDs; leave default to review all
      extensions.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: enterprise-allow-list
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for identity and process events.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on; defaults to the entire estate
      if empty.
    from:
      kind: manual
      observed: '2024-10-14'
      ref: incident-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/passkeys-raise-the-bar-but-attackers-can-still-get-in
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should begin with users who have performed Device Code authentication,
  as this is the primary flow abused in the EvilTokens campaign and is rarely used
  in standard business operations.
references:
- name: "Huntress \u2014 Passkeys Raise the Bar. Here\u2019s Where Attackers Can Still\
    \ Get In."
  url: https://www.huntress.com/blog/passkeys-raise-the-bar-but-attackers-can-still-get-in
related:
- hunt: unauthorized-oauth-app-consent
  reason: This hunt focuses specifically on the passkey-themed lure vector; broader
    OAuth abuse is covered separately.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Passkey-Themed Phishing Lures
    observables:
    - AI-generated phishing lures tailored to victim roles
    - Impersonation of IT staff requesting passkey updates
    - Urgent enrollment requests or messages to authorize unfamiliar devices
    slug: passkey-themed-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of Alternative Auth Flows
    observables:
    - Victims entering device codes on legitimate Microsoft login pages
    - Abuse of OAuth device-code flows to obtain valid sessions
    - EvilTokens phishing-as-a-service kit activity
    slug: device-code-flow-abuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Enrollment and Persistence
    observables:
    - Registration of new secondary authenticators
    - Exploitation of MFA recovery processes
    - Creation of inbox rules or mail forwarding addresses
    - New OAuth application grants and consents
    slug: unauthorized-identity-manipulation
    tactic: persistence
  - name: Endpoint Browser Tampering
    observables:
    - Browser hooks capturing WebAuthn responses
    - Unauthorized browser extensions from non-approved lists
    - Unexpected browser redirects or toolbars during sign-in
    slug: endpoint-authentication-tampering
    tactic: execution
    techniques:
    - T1176
  summary: The EvilTokens campaign and similar threats target the account lifecycle
    by using AI-generated phishing to abuse device-code flows and register malicious
    authenticators. Even with passkeys, attackers maintain access through unauthorized
    MFA enrollment, session persistence via OAuth grants, and endpoint-level browser
    manipulation to intercept authentication responses.
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


# Passkey-Themed Phishing and Identity Lifecycle Abuse

This phased hunt targets the abuse of identity lifecycles during transition to phishing-resistant authentication. The first phase identifies users who use rare alternative authentication flows, such as the Device Code flow seen in the EvilTokens campaign, and correlates this with immediate MFA enrollment changes. The second phase follows these high-risk identities to find post-authentication persistence mechanisms, including malicious inbox rules and unauthorized browser extensions capable of tampering with WebAuthn responses. The hunt concludes by connecting the initial social engineering signal to the technical persistence evidence.

## device-code-scoping
<!-- Identify device-code authentication users -->
Identify users and hosts that use the Device Code flow, which is a primary vector for session hijacking in passkey-themed phishing campaigns.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows identify users who successfully authorized a device code flow. In most
  enterprises, this flow should be rare.
reads:
- actor_user_name
- auth_protocol
- device_hostname
- event_type
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, device_hostname, src_endpoint_ip, auth_protocol, time FROM hb_auth_signin WHERE (LOWER(auth_protocol) LIKE '%device%code%' OR LOWER(event_type) LIKE '%device%code%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-evidence-gathering
<!-- Gather early-stage identity evidence -->
parallel:
- → mfa-lifecycle-anomalies
- → rare-auth-protocol-stack
join: → early-stage-triage

## mfa-lifecycle-anomalies
<!-- Recent MFA enrollment and recovery changes -->
Detect when a user adds a new authenticator or resets credentials, which often follows a hijacked session.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Modifications to account security settings shortly after a login event.
  Silent means no such changes were recorded.
reads:
- activity_id
- activity_name
- actor_user_name
- device_hostname
- time
- user_name
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT user_name, activity_name, actor_user_name, device_hostname, time FROM hb_account_change WHERE activity_id IN (3, 4, 99) AND (LOWER(activity_name) LIKE '%mfa%' OR LOWER(activity_name) LIKE '%authenticator%' OR LOWER(activity_name) LIKE '%credential%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-auth-protocol-stack
<!-- Rare authentication protocol usage -->
Stack sign-ins by protocol and user to isolate anomalous shifts to phishing-prone flows like DeviceCode.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of users whose login protocol usage is anomalous compared to their
  historical patterns.
prevalence:
  by: actor_user_name
  key:
  - auth_protocol
  rare_below: 5
reads:
- actor_user_name
- auth_protocol
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, auth_protocol, src_endpoint_ip, COUNT(*) as count, MIN(time) as first_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, auth_protocol, src_endpoint_ip HAVING count < 5
```

## early-stage-triage
<!-- Early stage risk triage -->
```agent target=hunter
cite: required
context:
- device-code-scoping
- mfa-lifecycle-anomalies
- rare-auth-protocol-stack
max_iterations: 4
objective: Determine which users identified in the scoping step show correlated MFA
  changes or unusual protocol shifts indicative of session hijacking.
success_criteria: A per-user risk score citing specific protocol events and account
  changes.
tools:
- endpoint
- identity
```

## persistence-and-tampering-hunt
<!-- Hunt follow-on persistence and tampering -->
parallel:
- → cloud-persistence-audit
- → unapproved-browser-extensions
join: → full-chain-correlation

## cloud-persistence-audit
<!-- Cloud persistence via API -->
Find post-compromise activity such as new inbox rules or OAuth application consents.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Success events for operations that grant external access or automate mailbox
  exfiltration.
reads:
- actor_user_name
- api_operation
- resource_name
- status
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, api_operation, resource_name, status, time FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%inboxrule%' OR LOWER(api_operation) LIKE '%forwarding%' OR LOWER(api_operation) LIKE '%approle%' OR LOWER(api_operation) LIKE '%consent%' OR LOWER(api_operation) LIKE '%add-mailbox%') AND status = 'success' AND time >= datetime('now', '-{{lookback_days}} days')
```

## unapproved-browser-extensions
<!-- Hunt unapproved browser extensions -->
Identify browser extensions that might indicate session interception or WebAuthn tampering, focusing on hosts identified in the scoping step.

```sqlite target=endpoint role=detection-candidate params=(approved_extension_ids=approved_extension_ids, scope_hosts=scope_hosts)
~~~yaml
expected: A list of extensions on scoped hosts that are not in the enterprise allow-list.
reads:
- device_hostname
- package_name
- package_type
- package_uid
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, package_name, package_uid, package_version, vendor_name FROM hb_software_inventory WHERE package_type = 'extension' AND ('{{approved_extension_ids}}' = '' OR instr(',' || '{{approved_extension_ids}}' || ',', ',' || package_uid || ',') = 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## full-chain-correlation
<!-- Correlate full identity-to-endpoint chain -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- cloud-persistence-audit
- unapproved-browser-extensions
max_iterations: 6
objective: Evaluate whether the early-stage identity risks resulted in cloud persistence
  (inbox rules/OAuth) or endpoint tampering (unapproved extensions).
success_criteria: A final verdict of malicious or suspicious for each user and host,
  mapping the timeline of the compromise.
tools:
- endpoint
- identity
```

## verdict-routing
<!-- Route on verdict -->
if~: "the full-chain-correlation verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → contain-identity-compromise
indeterminate: → manual-cleanup-verification
unavailable: → manual-cleanup-verification (blind_spot: cloud-audit-gap)
else: → hunt-close-out

## contain-identity-compromise
<!-- Contain identity compromise -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the compromised user, remove any authenticators registered during the incident window, and disable unauthorized OAuth application grants.
```
→ manual-cleanup-verification

## manual-cleanup-verification
<!-- Manual cleanup verification -->
```manual target=analyst
Review the compromised mailbox for hidden inbox rules or forwarding addresses. Confirm that the unapproved extensions on the affected host have been uninstalled. Update the approved_extension_ids list if the extension was legitimate.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Record the timeline of the attack. Use the findings to build simulated phishing scenarios focused on passkey enrollment lures to improve employee resilience.
```
→ end

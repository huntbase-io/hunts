---
analysis: A standard detection rule might fire on a single failed login or a new IP,
  but this hunt correlates the identity vulnerability (no MFA) with precursor spraying
  AND subsequent bulk data extraction across Outlook, Teams, and SharePoint. This
  synthesis across three distinct surfaces and two stages of an attack chain is beyond
  the scope of single-event rules.
blind_spots:
- id: m365-api-latency
  question: whether exfiltration is occurring right now
  requires: Unified Audit Log (UAL) low-latency stream
  risk: M365 Unified Audit Logs can be delayed by up to 24 hours, meaning an active
    attack may be invisible to this hunt until the next day.
  stage: automated-cloud-data-exfiltration
- id: vpn-telemetry-gap
  question: whether the corporate VPN was successfully probed
  requires: hb_auth_signin with VPN context
  risk: Access to the internal VPN would only be visible if the VPN log provider is
    integrated into the normalized authentication surface.
  stage: portal-and-vpn-discovery
coverage:
- stage: teamfiltration-credential-spraying
  status: covered
  steps:
  - auth-spraying-precursors
- stage: ghost-service-account-compromise
  status: covered
  steps:
  - identify-ghost-accounts
  - rare-successful-logons
- stage: automated-cloud-data-exfiltration
  status: covered
  steps:
  - portal-and-exfil-activity
- stage: portal-and-vpn-discovery
  status: covered
  steps:
  - portal-and-exfil-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Service accounts are high-value targets because they frequently bypass
    MFA and lack human oversight. A negative result across the estate is a critical
    confirmation that ghost identities are not being leveraged for M365 data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised functional service accounts via credential
  spraying to bypass MFA, then used these ghost identities to exfiltrate bulk data
  from M365 and discover administrative portals.
labels:
- hunt
- attack.t1110
- attack.t1133
- attack.t1041
- credential access
- discovery
- exfiltration
- initial access
name: TeamFiltration Service Account Compromise and Exfiltration
parameters:
  exfil_operations:
    default:
    - MailItemsAccessed
    - FileDownloaded
    - TeamsSessionStarted
    - SearchQueryPerformed
    - FileAccessedExtended
    description: Cloud API operations associated with bulk extraction of data.
    from:
      kind: article
      observed: '2026-09-24'
      ref: proofpoint-ghost-accounts
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty for
      the full estate.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-scoping
    type: list[host]
  service_keywords:
    default:
    - svc
    - service
    - bot
    - payment
    - vendor
    - ticket
    - scanner
    - app
    - admin
    - functional
    description: Keywords typical of functional or service account names.
    from:
      kind: article
      observed: '2026-09-24'
      ref: proofpoint-ghost-accounts
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/ghost-service-accounts-enable-m365-data-theft-chile
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should begin by identifying every account matching service-related
  keywords that currently has MFA disabled. Focus on financial or ticket-handling
  keywords as noted in the research.
references:
- name: "Proofpoint \u2014 Ghost Service Accounts Enable M365 Data Theft in Chile"
  url: https://www.proofpoint.com/us/newsroom/news/ghost-service-accounts-enable-m365-data-theft-chile
related:
- hunt: m365-oauth-app-persistence
  reason: Adversaries may use service account access to register malicious OAuth applications;
    that requires separate monitoring of Entra ApplicationManagement events.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: TeamFiltration Credential Spraying
    observables:
    - Credential spraying targeting over 5,700 M365 accounts
    - Source IP rotation to avoid blocking
    - Attempts against multiple tenants (28) in short timeframes
    slug: teamfiltration-credential-spraying
    tactic: credential-access
    techniques:
    - T1110
  - name: Ghost Service Account Compromise
    observables:
    - Successful sign-ins to accounts with no active user history
    - Functional account names (e.g., managing tickets, approving vendor payments)
    - Accounts lacking MFA protection
    - Rapid succession of compromises (six accounts in seven minutes)
    slug: ghost-service-account-compromise
    tactic: initial-access
    techniques:
    - T1133
  - name: Automated Cloud Data Exfiltration
    observables:
    - Automated pulling of emails from Outlook
    - Bulk extraction of chat conversations from Teams
    - File exfiltration from OneDrive
    - SharePoint file browsing and access
    slug: automated-cloud-data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Portal and VPN Discovery
    observables:
    - Access to the M365 management portal
    - Access to the Azure portal from compromised accounts
    - Probing of company VPN infrastructure
    slug: portal-and-vpn-discovery
    tactic: discovery
    techniques:
    - T1133
  summary: The threat actor UNK_CondorFiltration uses the open-source TeamFiltration
    toolkit to perform automated credential spraying against M365 tenants, specifically
    targeting forgotten service accounts lacking MFA. Upon successful compromise,
    the actor automates the exfiltration of Teams messages, Outlook emails, and OneDrive
    files while probing Azure/M365 management portals and VPN gateways.
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


# TeamFiltration Service Account Compromise and Exfiltration

This hunt identifies the lifecycle of a TeamFiltration campaign, which targets overlooked service accounts that lack multifactor authentication. The hunt follows a phased approach: it first scopes for potential service identities and identifies brute-force patterns and successful logons from new infrastructure. It then pivots to cloud API activity to detect administrative discovery (Azure/M365 portals) and automated data theft from Outlook, Teams, and SharePoint. A tiered agent review evaluates initial access before determining the final scope of exfiltration and triggering automated containment.

## identify-ghost-accounts
<!-- Identify candidate ghost accounts -->
Locate functional and service accounts that lack MFA protection, as these are the primary targets for the TeamFiltration toolkit.

```sqlite target=identity role=scoping params=(service_keywords=service_keywords)
~~~yaml
expected: A list of service-named accounts with MFA disabled. Silence suggests all
  service-named accounts are properly hardened.
reads:
- email
- id
- mfa_enabled
- name
- provider
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT name, email, id, provider, status FROM hb_users WHERE mfa_enabled = 'false' AND (instr(',' || '{{service_keywords}}' || ',', ',' || LOWER(name) || ',') > 0 OR instr(',' || '{{service_keywords}}' || ',', ',' || LOWER(email) || ',') > 0)
```

## parallel-auth-triage
<!-- Parallel Authentication Triage -->
parallel:
- → auth-spraying-precursors
- → rare-successful-logons
join: → early-stage-impact-read

## auth-spraying-precursors
<!-- Credential spraying precursors -->
Detect accounts receiving authentication failures from multiple source IPs, indicating TeamFiltration's rotation strategy.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A single account being targeted by multiple IPs with high failure counts.
  Silence proves no high-volume spraying occurred.
reads:
- activity_id
- actor_user_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT actor_user_name, COUNT(*) as failure_count, COUNT(DISTINCT src_endpoint_ip) as ip_count FROM hb_auth_signin WHERE activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name HAVING ip_count >= 2 AND failure_count > 10 ORDER BY failure_count DESC
```

## rare-successful-logons
<!-- Rare successful logons to ghost accounts -->
Identify successful authentications to candidate ghost accounts from IPs that have not successfully logged in before.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A successful logon from a new or rare IP address to a service identity.
  Silence suggests no compromise via new infrastructure occurred.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- activity_id
- actor_user_name
- device_hostname
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT actor_user_name, src_endpoint_ip, device_hostname, COUNT(*) as successes, MIN(time) as first_seen FROM hb_auth_signin WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, device_hostname HAVING successes < 5 ORDER BY first_seen DESC
```

## early-stage-impact-read
<!-- Early stage impact read -->
```agent target=hunter
cite: required
context:
- identify-ghost-accounts
- auth-spraying-precursors
- rare-successful-logons
max_iterations: 4
objective: Determine if any service account identified in the scoping step shows a
  successful logon from a rare IP address that correlates with credential spray patterns.
success_criteria: A verdict of malicious | suspicious | benign per account, citing
  the evidence rows.
tools:
- endpoint
- identity
```

## portal-and-exfil-activity
<!-- Portal discovery and data exfiltration -->
Identify follow-on activity by the potentially compromised accounts, specifically administrative portal browsing and bulk data access.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, exfil_operations=exfil_operations)
~~~yaml
expected: High counts of bulk data access operations or unusual administrative portal
  activity from service accounts. Silence means no follow-on activity was recorded.
reads:
- actor_user_name
- api_operation
- api_service_name
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT actor_user_name, api_operation, api_service_name, COUNT(*) as op_count, MIN(time) as first_op, MAX(time) as last_op FROM hb_cloud_api_activity WHERE (instr(',' || '{{exfil_operations}}' || ',', ',' || api_operation || ',') > 0 OR LOWER(api_service_name) LIKE '%portal%' OR LOWER(api_operation) LIKE '%portal%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation, api_service_name HAVING op_count > 10 ORDER BY op_count DESC
```

## final-impact-assessment
<!-- Final impact assessment -->
```agent target=hunter
cite: required
context:
- early-stage-impact-read
- portal-and-exfil-activity
max_iterations: 5
objective: Weigh the evidence from the early-stage triage against the observed API
  activity to determine if accounts were used for administrative discovery or automated
  data exfiltration.
success_criteria: A final verdict per account including an assessment of exfiltration
  volume and portal access intensity.
tools:
- endpoint
- identity
```

## verdict-routing
<!-- Route on verdict -->
if~: "the final-impact-assessment verdict is malicious for at least one service account" (confidence: high, judge=hunter)
then: → revoke-and-disable
indeterminate: → forensic-audit
unavailable: → forensic-audit (blind_spot: m365-api-latency)
else: → forensic-audit

## revoke-and-disable
<!-- Revoke and disable compromised accounts -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the compromised service accounts. Revoke all active OAuth refresh tokens and terminate active web sessions in both the M365 and Azure portals for these identities.
```
→ forensic-audit

## forensic-audit
<!-- Forensic audit and disclosure review -->
```manual target=analyst
Review the specific MailItemsAccessed and FileDownloaded rows. Determine if sensitive vendor payment info or ticket data was included. Check for any changes to application registrations or Azure subscription settings if portal access was confirmed.
```
→ hygiene-review-action

## hygiene-review-action
<!-- Enforce service account hardening -->
```action target=identity
~~~yaml
approval: required
~~~
Enforce MFA on all functional and service accounts identified in the scoping step. For any account that cannot support MFA, restrict sign-in to specific known egress IP ranges or disable the account if no business owner can be found.
```
→ end

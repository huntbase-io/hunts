---
analysis: A simple detection rule fires on a known domain; this hunt correlates host-level
  DNS resolution with a subsequent anomalous sign-in (rare IP/user pair) and the current
  MFA state across three surfaces, identifying a behavioral sequence.
blind_spots:
- id: persistence-event-gap
  question: What was the exact source IP and timestamp of the MFA enrollment event?
  remediation: Ingest cloud audit logs for identity-method changes.
  requires: hb_audit_log (Update user events)
  risk: hb_users is a snapshot surface. It confirms a user *has* MFA, but not the
    event of registration. An attacker who registers a factor during the hunt window
    might only be visible via anomalous sign-ins, not the enrollment event itself.
  stage: mfa-persistence-enrollment
- id: personal-device-invisibility
  question: Did the user click the lure on their personal phone?
  requires: EDR on personal mobile devices (BYOD)
  risk: Lures are delivered via SMS to personal phones. If those phones are unmanaged,
    the DNS activity is invisible, leaving only the anomalous cloud sign-in as evidence.
  stage: identity-compromise-via-aitm
coverage:
- stage: identity-compromise-via-aitm
  status: covered
  steps:
  - anomalous-sign-ins
  - phishing-dns-lookups
- reason: Visibility into the 'has MFA' state is covered; event-level registration
    details are in blind spots.
  stage: mfa-persistence-enrollment
  status: covered
  steps:
  - mfa-state-check
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: phishing-infrastructure-setup
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: cloud-reconnaissance-and-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: data-collection-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are increasingly bypassing MFA through session replay
    and unauthorized factor registration. A periodic hunt for this sequence protects
    the identity perimeter from persistence that survives password resets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has bypassed MFA via AiTM or Device Code phishing and registered
  a new authentication factor to maintain persistent access to a cloud identity.
labels:
- hunt
- attack.t1566
- attack.t1078
- attack.t1090.003
- attack.t1556.006
name: Passkey Phishing and MFA Persistence
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - integratedsso.com
    - secure-passkey.com
    - passkeyhelpdesk.com
    - setupmypasskey.com
    - add-passkey.com
    - oktasession.com
    - keysyncos.com
    - oskeysync.com
    - oskeysetup.com
    - oskeyregister.com
    - syncmykey.com
    - myconnectkey.com
    - oskeyconnect.com
    description: Domains and themes identified in the MSRC report as lures.
    from:
      kind: article
      observed: '2026-09-09'
      ref: msrc-blog-2026-09
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to endpoints with identity agents (Okta, etc.) to ensure
  we focus on corporate assets where users have tokens an attacker would want to hijack.
  It relies on identity-centric surfaces to bridge the gap between endpoint and cloud.
references:
- name: "MSRC Blog \u2014 Passkey-themed social engineering leads to identity and\
    \ cloud compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: cloud-reconnaissance-and-discovery
  reason: Once an identity is compromised and persistence is established, the actor
    moves to reconnaissance via Graph and SharePoint.
  relation: follows
- hunt: passkey-phishing-infrastructure-monitoring
  relation: follows
scenario:
  stages:
  - name: Phishing Infrastructure Setup
    observables:
    - company-name.integratedsso.com
    - company-name.secure-passkey.com
    - companyname.maliciousdomain.com
    - contoso.add-passkey.com
    - passkeyhelpdesk.com
    - secure-passkey.com
    - setupmypasskey.com
    - add-passkey.com
    - integratedsso.com
    - oktasession.com
    - keysyncos.com
    - oskeysync.com
    slug: phishing-infrastructure-setup
    tactic: initial-access
    techniques:
    - T1566
  - name: Identity Compromise via AiTM and Device Code
    observables:
    - Error code 50074 (MFA required)
    - Error code 50140 (Keep-me-signed-in interruption)
    - Sign-ins from unmanaged devices
    - Chrome user-agent with inconsistent browser IDs
    - Device code flow authentication to legitimate Microsoft pages
    slug: identity-compromise-via-aitm
    tactic: initial-access
    techniques:
    - T1566
    - T1078
  - name: MFA Persistence Enrollment
    observables:
    - Registration of new PhoneAppOTP method
    - Update user action with successful ResultStatus
    - New MFA device added with populated device token
    slug: mfa-persistence-enrollment
    tactic: persistence
    techniques:
    - T1078
  - name: Cloud Reconnaissance and Discovery
    observables:
    - Access to My Apps (enterprise application stores)
    - Access to My Sign-Ins
    - Access to Microsoft Approval Management
    - Access to My Profile
    - Enumeration of organizational application catalogue via OCaaS
    - Microsoft Graph API enumeration calls
    slug: cloud-reconnaissance-and-discovery
    tactic: discovery
    techniques:
    - T1078
  - name: Data Collection and Exfiltration
    observables:
    - SharePoint Online organizational site access
    - OneDrive document resource requests
    - OwaDownloadAttachments resource requests
    - Email collection via REST APIs
    - M365ChatClient access
    slug: data-collection-and-exfiltration
    tactic: collection
    techniques:
    - T1041
  summary: Threat actors use passkey and SSO-themed social engineering to lure victims
    into AiTM or device-code phishing flows, resulting in cloud identity compromise.
    Once access is gained, they establish persistence by registering new MFA methods
    and use Microsoft Graph for large-scale reconnaissance and exfiltration of SharePoint,
    OneDrive, and email data.
series:
  index: 2
  slug: passkey-themed-social-engineering-leads-to-identity-and-cloud-compromise
  title: Passkey-themed social engineering leads to identity and cloud compromise
  total: 3
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
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


# Passkey Phishing and MFA Persistence

This hunt targets the sequence of cloud identity compromise described in recent research: initial social engineering leads to a session hijack (AiTM) or device-code authorization, followed immediately by the enrollment of a new MFA factor under the attacker's control. We first scope the environment to endpoints with corporate SSO or VPN software, then parallelize the search for anomalous management-portal sign-ins from rare IPs, DNS resolutions to phishing infrastructure, and the current MFA status of users to identify those who may have been targeted for persistence.

## scope-to-sso-managed-endpoints
<!-- Scope to endpoints with SSO/VPN software -->
Focus the hunt on corporate-managed endpoints that use specific identity or remote-access agents, which are the primary targets for session-hijacking and passkey lures.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames belonging to the managed estate with verified identity
  agents. This provides a relevant subset of the fleet for host-based correlation.
reads:
- device_hostname
- package_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT DISTINCT device_hostname, package_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%okta%' OR LOWER(package_name) LIKE '%zscaler%' OR LOWER(package_name) LIKE '%globalprotect%' OR LOWER(package_name) LIKE '%pulse%secure%' OR LOWER(package_name) LIKE '%onelogin%') AND asset_scope = 'endpoint'
```

## corroborate-leads
<!-- Corroborate identity and network evidence -->
parallel:
- → anomalous-sign-ins
- → phishing-dns-lookups
- → mfa-state-check
join: → triage-compromise

## anomalous-sign-ins
<!-- Anomalous successful sign-ins to management portals -->
Detect successful sign-ins to identity and approval portals from IPs that are rare for that user, simulating automated post-compromise reconnaissance.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A user-IP pair accessing multiple high-value management portals. High-volume
  access from a new IP suggests the automated reconnaissance behavior noted in research.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, COUNT(DISTINCT dst_endpoint_name) AS management_apps, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 1 AND (LOWER(dst_endpoint_name) LIKE '%approval%' OR LOWER(dst_endpoint_name) LIKE '%sign-ins%' OR LOWER(dst_endpoint_name) LIKE '%myprofile%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING management_apps >= 2
```

## phishing-dns-lookups
<!-- DNS lookups to lure infrastructure -->
Match host-based DNS activity against the passkey-themed phishing domains from the report.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains)
~~~yaml
expected: Any resolution of a listed domain. Silence indicates the infrastructure
  has rotated, but doesn't disprove the hunt as many victims use personal devices.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## mfa-state-check
<!-- MFA status for active identities -->
Inventory users with active MFA to identify potential candidates for persistence enrollment.

```sqlite target=identity role=triage
~~~yaml
expected: A list of users with MFA enabled. The agent will correlate this with those
  performing anomalous sign-ins to determine if the MFA was likely attacker-registered.
reads:
- name
- email
- provider
- mfa_enabled
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT name, email, provider, mfa_enabled, status FROM hb_users WHERE status = 'active' AND mfa_enabled = 'true'
```

## triage-compromise
<!-- Triage identity threat -->
```agent target=hunter
cite: required
context:
- scope-to-sso-managed-endpoints
- anomalous-sign-ins
- phishing-dns-lookups
- mfa-state-check
max_iterations: 5
objective: Determine if a user identity has been compromised via AiTM/Device Code
  phishing and if they show signs of MFA persistence enrollment.
success_criteria: A per-identity verdict citing anomalous portal access and phishing
  resolutions.
tools:
- endpoint
- identity
```

## decision-route
<!-- Route on verdict -->
if~: "the triage verdict identifies at least one account as malicious with evidence of both anomalous sign-ins and infrastructure resolution" (confidence: high, judge=hunter)
then: → revoke-sessions
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: persistence-event-gap)
else: → close-out

## revoke-sessions
<!-- Revoke sessions and reset MFA -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active refresh tokens for the identified identities. Force a password reset and manually remove any newly added authentication methods registered in the last 14 days (prioritize PhoneAppOTP).
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual forensic review -->
```manual target=analyst
Review Azure AD or identity audit logs (if available) for 'Update user' or 'Add authentication method' actions corresponding to the rare IPs identified. Confirm if the actor added a second factor via PhoneAppOTP.
```
→ end

## close-out
<!-- Close hunt -->
```manual target=analyst
If no malicious activity was found, record the negative result. If any new phishing domains were found through redirects, update the 'phishing_domains' list.
```
→ end

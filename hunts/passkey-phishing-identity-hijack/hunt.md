---
analysis: A simple rule might detect a single malicious IP. This hunt correlates infrastructure
  lulls (DNS) with identity events (sign-in) and persistence changes (MFA methods)
  that are independently benign but malicious in sequence.
blind_spots:
- id: unmanaged-device-blindspot
  owner: IT Operations
  question: Whether the user opened the phishing link on a personal mobile device
    (SMS/vishing).
  remediation: Enforce managed-device-only conditional access policies for M365.
  requires: Mobile Device Management (MDM) or Mobile Threat Defense (MTD) logs
  risk: The DNS and initial HTTP stages will be invisible if the lure is opened outside
    the managed corporate network/endpoint estate, leaving sign-in logs as the only
    signal.
  stage: initial-access-passkey-phishing
- id: mfa-error-code-retention
  owner: Cloud Security Engineering
  question: Whether specific error codes like 50074 (MFA required) or 50140 (Keep-me-signed-in)
    were triggered during the session.
  remediation: Configure streaming of Entra ID sign-in logs to a long-term analytical
    store with full schema capture.
  requires: Advanced Entra ID Audit Log detail
  risk: Without these codes, it is harder to automate the detection of the specific
    AiTM session-replay pattern.
  stage: identity-compromise-aitm
coverage:
- stage: initial-access-passkey-phishing
  status: covered
  steps:
  - dns-lookups-to-phishing-infrastructure
- stage: identity-compromise-aitm
  status: covered
  steps:
  - office-portal-access-anomalies
- stage: persistence-unauthorized-mfa-registration
  status: covered
  steps:
  - mfa-registration-persistence
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: cloud-discovery-reconnaissance
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: collection-sharepoint-outlook-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Passkey-themed vishing is an active, high-impact campaign that bypasses
    non-phishing-resistant MFA. This hunt ensures that if a user is tricked, their
    subsequent unauthorized MFA persistence is caught before large-scale cloud exfiltration
    occurs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using lookalike domains to lure users into AiTM phishing
  or device-code flows, subsequently hijacking sessions and registering unauthorized
  MFA methods for persistence.
labels:
- hunt
- attack.t1566
- attack.t1078
- attack.t1090.003
name: Passkey Phishing and Identity Hijack
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
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
    description: Phishing and proxy domains identified in the research.
    from:
      kind: article
      observed: '2026-09-09'
      ref: msrc-blog-2026-09-09
    type: list[domain]
  scope_hosts:
    default: []
    description: A list of hostnames to focus on, typically pasted from the scoping
      step.
    type: list[host]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to any system with Microsoft software to narrow the fleet.
  Widen to all systems if phishing is suspected via non-Microsoft browsers.
references:
- name: Passkey-themed social engineering leads to identity and cloud compromise
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: cloud-discovery-reconnaissance
  reason: This hunt identifies the hijacking; the next hunt in the series focuses
    on the subsequent automated Graph and SharePoint discovery.
  relation: follows
scenario:
  stages:
  - name: Passkey-Themed Phishing Infrastructure
    observables:
    - company-name.integratedsso.com
    - company-name.secure-passkey.com
    - passkeyhelpdesk.com
    - setupmypasskey.com
    - add-passkey.com
    - oktasession.com
    - keysyncos.com
    - oskeysync.com
    - syncmykey.com
    - portalsetuphub.com
    slug: initial-access-passkey-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1090.003
  - name: Identity Compromise via AiTM and Device Code
    observables:
    - Sign-in to OfficeHome
    - Error 50074 (MFA required)
    - Error 50140 (Keep-me-signed-in interruption)
    - Device code flow authentication
    - Unmanaged device contexts
    - Chrome user agent and browser ID mismatch
    slug: identity-compromise-aitm
    tactic: initial-access
    techniques:
    - T1078
  - name: MFA Persistence via Method Injection
    observables:
    - Addition of PhoneAppOTP
    - Registration of new phone number
    - Update user action in audit logs
    - StrongAuthenticationMethod registration
    slug: persistence-unauthorized-mfa-registration
    tactic: persistence
    techniques:
    - T1078
  - name: Automated Cloud Discovery and Reconnaissance
    observables:
    - Access to My Sign-Ins
    - Access to My Apps
    - Access to My Profile
    - Microsoft Approval Management access
    - OCaaS application catalogue enumeration
    - High-volume Microsoft Graph activity
    - Node.js based automated enumeration scripts
    slug: cloud-discovery-reconnaissance
    tactic: discovery
    techniques:
    - T1078
  - name: Data Collection and Potential Exfiltration
    observables:
    - OwaDownloadAttachments activity
    - SharePoint Online document enumeration
    - OneDrive file requests via Graph API
    - Email collection through REST APIs
    - M365ChatClient access
    slug: collection-sharepoint-outlook-exfiltration
    tactic: collection
    techniques:
    - T1041
  summary: Threat actors use passkey-themed social engineering and adversary-in-the-middle
    (AiTM) or device-code phishing to compromise cloud identities. Following initial
    access, they establish persistence by registering new MFA methods before using
    automated scripts and the Microsoft Graph API to conduct broad reconnaissance
    and exfiltrate data from SharePoint, OneDrive, and Outlook.
series:
  index: 1
  slug: passkey-themed-social-engineering-leads-to-identity-and-cloud-compromise
  title: Passkey-themed social engineering leads to identity and cloud compromise
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


# Passkey Phishing and Identity Hijack

This hunt identifies the transition from external phishing to internal cloud identity compromise. It begins by scoping hosts with Microsoft productivity software, then searches for DNS resolutions to reported passkey-themed phishing infrastructure. It correlates these hits with anomalous sign-ins to Microsoft portals and the injection of new MFA factors, which the adversary uses to maintain a persistent foothold even if sessions are revoked.

## scope-microsoft-assets
<!-- Scope hosts with Microsoft software -->
Identify the subset of the fleet that interacts with the targeted Microsoft 365/Azure ecosystem.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames to use as the initial scope for the hunt.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft%' OR LOWER(vendor_name) LIKE '%microsoft%')
```

## dns-lookups-to-phishing-infrastructure
<!-- DNS lookups to phishing infrastructure -->
Detect initial interaction with lookalike domains used in the social engineering campaign.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: Internal users resolving domains from the phishing list. Absence means no
  corporate devices were observed interacting with these specifically, though they
  may have used personal devices.
reads:
- device_hostname
- actor_user_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, actor_user_name, query_hostname, COUNT(*) as lookups, MIN(time) as first_seen FROM hb_dns_activity WHERE (('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, query_hostname
```

## identify-suspicious-identity-activity
<!-- Identify suspicious identity activity -->
parallel:
- → office-portal-access-anomalies
- → mfa-registration-persistence
join: → identity-compromise-triage

## office-portal-access-anomalies
<!-- Anomalous portal sign-ins -->
Identify successful sign-ins to management applications that typically follow phishing-based initial access.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Sign-ins to account management portals. High volume or unusual IPs are suspicious
  after a DNS lead.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- mfa
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, mfa, status, COUNT(*) as sessions, MIN(time) as first_seen FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) IN ('officehome', 'my apps', 'myapps', 'my profile', 'my sign-ins', 'microsoft account controls v2')) AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name, mfa, status
```

## mfa-registration-persistence
<!-- MFA registration baseline -->
Identify users who have registered new MFA methods, as this is the primary persistence mechanism described in the research.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Registration of a new authentication method, such as PhoneAppOTP, which
  stands out as rare compared to typical fleet activity.
prevalence:
  by: actor_user_name
  key:
  - activity_name
  rare_below: 2
reads:
- actor_user_name
- activity_name
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, activity_name, dst_endpoint_name, COUNT(*) as changes, MIN(time) as first_change FROM hb_auth_signin WHERE (LOWER(activity_name) LIKE '%update user%' OR LOWER(activity_name) LIKE '%strongauthentication%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, activity_name, dst_endpoint_name HAVING changes <= 2
```

## identity-compromise-triage
<!-- Triage identity compromise evidence -->
```agent target=hunter
cite: required
context:
- dns-lookups-to-phishing-infrastructure
- office-portal-access-anomalies
- mfa-registration-persistence
max_iterations: 5
objective: Analyze the temporal relationship between DNS hits to phishing domains,
  sign-ins to OfficeHome/MyApps portals, and the registration of new MFA methods.
success_criteria: A verdict of malicious | suspicious | benign per user, citing specific
  DNS hosts and authentication change timestamps.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one user who performed an MFA registration after a DNS lookup" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: unmanaged-device-blindspot)
else: → close-out

## isolate-and-remediate
<!-- Revoke and remediate identity -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions for the identified user, initiate a password reset, and remove any newly registered authentication methods (e.g., PhoneAppOTP or new phone numbers) recorded in the audit log.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation and tuning -->
```manual target=analyst
Review the source IPs involved in the sign-in events; correlate with known proxy/VPN infrastructure. Update the phishing_domains parameter if new lookalike patterns are observed.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no correlation between phishing domains and MFA persistence was found for the reporting estate.
```
→ end

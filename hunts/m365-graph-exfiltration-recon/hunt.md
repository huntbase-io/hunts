---
analysis: A single rule might alert on a login to 'My Apps', but this hunt connects
  that signal to automated Graph API variety and high-volume file counts that exceed
  a user's unique daily baseline.
blind_spots:
- id: m365-audit-latency
  question: whether exfiltration is currently occurring
  requires: Real-time M365 audit streaming
  risk: M365 audit logs often have a delay of several hours, meaning the exfiltration
    may be complete before the hunt observes the activity.
  stage: data-enumeration-exfiltration
- id: personal-mobile-visibility
  question: whether the phishing link was accessed on a mobile phone
  requires: Endpoint telemetry on non-managed mobile devices
  risk: The initial social engineering phase targets personal mobile devices that
    are not enrolled, making the early attack markers invisible.
  stage: cloud-application-reconnaissance
coverage:
- stage: cloud-application-reconnaissance
  status: covered
  steps:
  - portal-recon-lead
  - graph-api-recon
- stage: data-enumeration-exfiltration
  status: covered
  steps:
  - high-volume-file-exfil
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: passkey-themed-phishing
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: identity-compromise-aitm
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: mfa-persistence-registration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries are bypassing modern MFA through passkey-themed lures;
    a negative result confirms that these lures did not lead to data theft within
    the lookback window.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using automated Graph API tools to enumerate organizational
  resources and exfiltrate SharePoint/OneDrive data after obtaining a cloud session
  via passkey-themed social engineering.
labels:
- hunt
- attack.t1041
- attack.t1078
name: Microsoft Graph and Cloud Application Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-09'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: 'Optional: Limit the hunt to these hostnames; leave empty to hunt
      across the estate.'
    from:
      kind: manual
      observed: '2026-09-09'
      ref: default
    type: list[host]
  targeted_apps:
    default:
    - OfficeHome
    - My Apps
    - My Profile
    - My SignIns
    - Microsoft Account Controls V2
    - Microsoft Approval Management
    - OCaaS
    - M365ChatClient
    - OwaDownloadAttachments
    description: Identity and management portals targeted during reconnaissance.
    from:
      kind: article
      observed: '2026-09-09'
      ref: msrc-blog-2026-09-09
    type: list[string]
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
rationale: Target hosts running Microsoft 365 or Office suites as they are the primary
  targets for this campaign's exfiltration phase. Prioritize any users who have reported
  suspicious IT helpdesk calls or SMS lures.
references:
- name: "MSRC \u2014 Passkey-themed social engineering leads to identity and cloud\
    \ compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: mfa-persistence-registration-hunt
  reason: Detection of unauthorized MFA factor addition is a persistent persistence
    mechanism handled in a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Passkey-themed phishing domains
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
    - oskeysetup.com
    - oskeyregister.com
    - syncmykey.com
    - myconnectkey.com
    - oskeyconnect.com
    - validationsetupac.com
    - portalsetuphub.com
    slug: passkey-themed-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Identity compromise via AiTM or Device Code
    observables:
    - Anomalous sign-in to OfficeHome from unmanaged context
    - Sign-in error 50074 (MFA required)
    - Sign-in error 50140 (Keep-me-signed-in interruption)
    - Device code flow authentication
    - Chrome user agent in anomalous session
    slug: identity-compromise-aitm
    tactic: initial-access
    techniques:
    - T1078
    - T1090.003
  - name: MFA method registration for persistence
    observables:
    - New phone number registration
    - New authenticator application registration
    - Registration of software-based OTP token
    - Update user events with StrongAuthenticationPhoneAppOTP
    slug: mfa-persistence-registration
    tactic: persistence
    techniques:
    - T1078
  - name: Cloud application and identity reconnaissance
    observables:
    - Access to My Apps application store
    - Access to My Profile organizational info
    - Access to Microsoft Approval Management
    - Access to Microsoft Account Controls V2
    - Access to My SignIns security information
    - Access to OCaaS application catalogue
    slug: cloud-application-reconnaissance
    tactic: discovery
    techniques:
    - T1078
  - name: Data enumeration and exfiltration
    observables:
    - SharePoint Online site and document requests
    - OneDrive file enumeration via Graph API
    - Outlook Web mailbox services access
    - OwaDownloadAttachments requests
    - M365ChatClient access
    - High-volume Microsoft Graph activity
    slug: data-enumeration-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1078
  summary: Threat actors use passkey-themed social engineering via vishing and SMS
    to lure users to AiTM phishing sites or device-code authentication flows. Following
    compromise, the actors establish MFA persistence by registering new authentication
    factors and conduct extensive cloud reconnaissance and data exfiltration from
    SharePoint, OneDrive, and Exchange using the Microsoft Graph API.
series:
  index: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Microsoft Graph and Cloud Application Exfiltration

This hunt identifies post-compromise activity following passkey-themed social engineering. It focuses on the specific sequence of discovery where an actor accesses identity portals (My Apps, My SignIns) and then uses automated systems (Node.js/Microsoft Graph) to enumerate document libraries and download content. By correlating portal sign-ins with high-volume Graph API traffic and file access counts that deviate from a user's normal baseline, the hunt distinguishes targeted exfiltration from legitimate cloud usage.

## identify-vulnerable-scope
<!-- Scope to Microsoft 365 environments -->
Identify hosts that have Microsoft 365 or Office software installed to narrow the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with the targeted productivity software. Silence indicates
  no such software was found in the inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft 365%' OR LOWER(package_name) LIKE '%office%' OR LOWER(package_name) LIKE '%outlook%')
```

## fan-out-evidence
<!-- Fan-out evidence gathering -->
parallel:
- → portal-recon-lead
- → graph-api-recon
- → high-volume-file-exfil
join: → triage-agent

## portal-recon-lead
<!-- Identity portal reconnaissance -->
Identify successful sign-ins to portals used to discover applications and organizational info.

```sqlite target=identity role=detection-candidate params=(targeted_apps=targeted_apps, lookback_days=lookback_days)
~~~yaml
expected: Signs of a single user account accessing multiple identity and management
  portals in a tight sequence. Silence indicates no portal access was logged.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
- status_id
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{targeted_apps}}' || ',', ',' || dst_endpoint_name || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time ASC
```

## graph-api-recon
<!-- Automated Graph API reconnaissance -->
Find high-variety calls to the Microsoft Graph API indicating automated discovery tools.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A single context making many distinct Graph API requests in a short window.
  Silence proves no automated Graph tools were detected.
reads:
- actor_user_name
- device_hostname
- url_hostname
- url_path
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, device_hostname, COUNT(DISTINCT url_path) as unique_paths, COUNT(*) as total_requests, MIN(time) as start, MAX(time) as end FROM hb_http_activity WHERE url_hostname = 'graph.microsoft.com' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname HAVING unique_paths > 10 ORDER BY unique_paths DESC
```

## high-volume-file-exfil
<!-- High-volume M365 exfiltration -->
Stack-count file touches to find accounts exceeding typical daily document access volumes.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: An account accessing more than 50 unique SharePoint/OneDrive files in a
  day. Silence indicates no account reached this baseline threshold.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- device_hostname
- file_path
- provider
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, device_hostname, strftime('%Y-%m-%d', time) as day, COUNT(DISTINCT file_path) as file_count FROM hb_file_activity WHERE provider = 'm365' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname, day HAVING file_count > 50 ORDER BY file_count DESC
```

## triage-agent
<!-- Triage session activity -->
```agent target=hunter
cite: required
context:
- portal-recon-lead
- graph-api-recon
- high-volume-file-exfil
max_iterations: 5
objective: Determine if any user account shows a sign-in sequence to identity portals
  followed by automated Graph discovery and high-volume file exfiltration.
success_criteria: A per-user verdict of malicious | suspicious | benign citing specific
  portal access times and file counts.
tools:
- endpoint
- identity
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-agent verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → manual-incident-review
unavailable: → manual-incident-review (blind_spot: m365-audit-latency)
else: → close-out

## isolate-and-revoke
<!-- Revoke sessions and isolate -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions and refresh tokens for the identified users; initiate a password reset and review recently added MFA factors.
```
→ manual-incident-review

## manual-incident-review
<!-- Manual incident review -->
```manual target=analyst
Examine the specific file paths in hb_file_activity to determine content sensitivity. Check the source IP reputation for proxy or TOR associations. Verify if the Graph API activity indicates enumeration of the entire tenant directory.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the total number of accounts reviewed and the volume of baseline activity. Summarize confirmed compromises or negative results for the security leadership report.
```
→ end

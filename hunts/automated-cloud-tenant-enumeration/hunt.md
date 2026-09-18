---
analysis: A static detection rule might alert on high-volume downloads, but this hunt
  correlates the preceding application discovery sequence (reconnaissance) with source
  context and host scope to distinguish automation from legitimate bulk operations.
blind_spots:
- id: no-cloud-sign-in-logs
  question: Was the reconnaissance sequence visible for all users?
  requires: hb_auth_signin with full application coverage
  risk: If the tenant does not log all application IDs to the connector, the initial
    recon phase will be invisible for some apps.
  stage: cloud-discovery-reconnaissance
- id: personal-device-telemetry-gap
  question: Did the user interact with phishing on a non-managed device?
  requires: EDR on personal mobile devices
  risk: Social engineering often occurs on personal phones where no endpoint telemetry
    is available to corroborate the initial link click.
  stage: collection-sharepoint-outlook-exfiltration
coverage:
- stage: cloud-discovery-reconnaissance
  status: covered
  steps:
  - app-discovery-sequence
  - src-ip-prevalence
- stage: collection-sharepoint-outlook-exfiltration
  status: covered
  steps:
  - m365-collection-burst
  - analyst-review
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: initial-access-passkey-phishing
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: identity-compromise-aitm
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: persistence-unauthorized-mfa-registration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Threat actors are actively using automated scripts to enumerate and
    exfiltrate data from compromised M365 identities. A negative result confirms that
    no rapid, multi-app reconnaissance sequence followed by bulk collection is currently
    occurring in the tenant.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using automated Node.js or Graph-based scripts to rapidly
  discover internal applications and collect sensitive files from a compromised cloud
  identity following a passkey-themed social engineering attack.
labels:
- hunt
- attack.t1078
- attack.t1041
name: Automated Cloud Tenant Enumeration
parameters:
  discovery_apps:
    default:
    - OfficeHome
    - My Apps
    - My Profile
    - Microsoft Approval Management
    - Microsoft Account Controls V2
    - My SignIns
    - OCaaS
    - M365ChatClient
    - "Windows App \u2013 Web"
    description: M365 management applications used for reconnaissance.
    from:
      kind: article
      observed: '2026-09-09'
      ref: msrc-blog-2026-09-09
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts with M365 software installed; leave empty to hunt across the
      entire estate.
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by identifying managed hosts with M365/Office software
  to focus the later file-activity corroboration; however, the sign-in reconnaissance
  is examined estate-wide to catch unmanaged device access.
references:
- name: "MSRC \u2014 Passkey-themed social engineering leads to identity and cloud\
    \ compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: initial-access-passkey-phishing
  reason: Initial phishing infrastructure and SMS-based delivery is a separate hunt
    focused on external domain registration and network lures.
  relation: out-of-scope-alternative
- hunt: unauthorized-mfa-registration-persistence
  reason: MFA persistence detection requires monitoring identity method changes, which
    is a precursor to the enumeration hunt here.
  relation: out-of-scope-alternative
- hunt: passkey-phishing-identity-hijack
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
tlp: clear
type: investigation
---


# Automated Cloud Tenant Enumeration

This hunt targets the post-compromise activity occurring within the Microsoft 365 control plane. Following session theft or device-code phishing, threat actors use automated tools to enumerate the organizational application catalog (OCaaS), management portals (My Sign-Ins), and document libraries in SharePoint and OneDrive. We identify this by looking for a rapid sequence of sign-ins to specific discovery applications, stack-counting source IPs to find rare context, and corroborating with high-volume file activity from the same user accounts.

## m365-software-inventory
<!-- M365 software inventory scope -->
Identify hosts running Microsoft 365 or related office software that could serve as the beachhead for identity compromise.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with Microsoft 365 software. Silence means no M365-related
  software was found in the inventory.
reads:
- device_hostname
- vendor_name
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(vendor_name) LIKE '%microsoft%' AND (LOWER(package_name) LIKE '%m365%' OR LOWER(package_name) LIKE '%office%'))
```

## parallel-corroboration
<!-- Corroborate reconnaissance and collection -->
parallel:
- → app-discovery-sequence
- → src-ip-prevalence
- → m365-collection-burst
join: → triage-agent

## app-discovery-sequence
<!-- Anomalous application discovery sequence -->
Find users accessing a high variety of management and profile applications in a single window, indicative of automated discovery.

```sqlite target=identity role=detection-candidate params=(discovery_apps=discovery_apps, lookback_days=lookback_days)
~~~yaml
expected: A single User-IP pair accessing 3+ management portals (e.g., My Sign-Ins,
  OCaaS, My Profile) within the lookback window.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, COUNT(DISTINCT dst_endpoint_name) AS unique_apps, GROUP_CONCAT(DISTINCT dst_endpoint_name) AS apps_accessed, MIN(time) AS first_access FROM hb_auth_signin WHERE instr(',' || '{{discovery_apps}}' || ',', ',' || dst_endpoint_name || ',') > 0 AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING unique_apps >= 3 ORDER BY unique_apps DESC
```

## src-ip-prevalence
<!-- Prevalence of discovery source IPs -->
Stack-count IPs accessing discovery apps to find those unique to a small number of users, suggesting proxy or actor infrastructure.

```sqlite target=identity role=baseline params=(discovery_apps=discovery_apps, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IP addresses that have only accessed these management resources for one
  or two accounts, especially if first seen recently.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_users, COUNT(*) AS auth_events, MIN(time) AS first_seen FROM hb_auth_signin WHERE instr(',' || '{{discovery_apps}}' || ',', ',' || dst_endpoint_name || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_users <= 2 ORDER BY unique_users, auth_events DESC
```

## m365-collection-burst
<!-- M365 collection burst within scoped hosts -->
Identify high-volume file activity (SharePoint/OneDrive) for users, filtered to the scoped endpoints.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A burst of file 'Read' or 'Create' activity in M365 originating from users
  and hosts within our focus scope.
reads:
- actor_user_name
- device_hostname
- file_path
- activity_id
- time
- provider
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, device_hostname, COUNT(*) AS total_touches, COUNT(DISTINCT file_path) AS unique_files, MIN(time) AS start_time FROM hb_file_activity WHERE provider = 'm365' AND activity_id IN (1, 2) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, device_hostname HAVING total_touches > 20 ORDER BY total_touches DESC
```

## triage-agent
<!-- Triage automated enumeration and collection -->
```agent target=hunter
cite: required
context:
- app-discovery-sequence
- src-ip-prevalence
- m365-collection-burst
max_iterations: 5
objective: Determine if the observed sequence matches the automated M365 enumeration
  tradecraft. Look for temporal correlation between sign-ins to discovery apps and
  bursts of file touches.
success_criteria: A verdict of malicious | suspicious | benign per user account, citing
  rows from all three parallel queries.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one user account" (confidence: high, judge=hunter)
then: → revoke-identity-sessions
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-cloud-sign-in-logs)
else: → analyst-review

## revoke-identity-sessions
<!-- Revoke sessions and isolate -->
```action target=identity
~~~yaml
approval: required
~~~
Immediately revoke all active sessions for the compromised user account. Isolate any associated endpoints identifying in the scope. Review and remove any recently added MFA methods.
```
→ analyst-review

## analyst-review
<!-- Impact assessment and close-out -->
```manual target=analyst
Review the file_path values from the collection-burst step. Determine if sensitive data or credentials were in the accessed documents. Verify if any 'discovery' apps are used by legitimate internal automation scripts to tune the hunt.
```
→ end

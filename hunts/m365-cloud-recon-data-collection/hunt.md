---
analysis: "A single rule could flag 'My Apps' access, but this hunt identifies intent\
  \ by correlating the sequence of discovery portal hits, the stack-count prevalence\
  \ (baseline), and the volume of subsequent SharePoint access \u2014 context a single\
  \ alert cannot provide."
blind_spots:
- id: limited-file-telemetry
  question: Was a file actually downloaded, or just requested/metadata enumerated?
  requires: Microsoft Graph Activity Logs / M365 Unified Audit Log
  risk: hb_file_activity (M365 provider) captures touches, but high-fidelity 'download'
    confirmation often requires Graph-specific logs not always present on all endpoints.
  stage: data-collection-and-exfiltration
- id: personal-device-gap
  question: Did the initial phishing interaction happen on an unmanaged personal device?
  requires: Endpoint agent on personal devices used for phishing engagement
  risk: If the employee engaged with the lure on a personal mobile device, the DNS
    and initial network signals are missing; the hunt only sees the cloud-side aftermath.
coverage:
- stage: cloud-reconnaissance-and-discovery
  status: covered
  steps:
  - reconnaissance-portal-sequence
  - rare-discovery-portal-access
- stage: data-collection-and-exfiltration
  status: covered
  steps:
  - high-volume-m365-file-access
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: phishing-infrastructure-setup
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: identity-compromise-via-aitm
  status: out_of_scope
- reason: Belongs to another part of the 'Passkey-themed social engineering leads
    to identity and cloud compromise' series.
  stage: mfa-persistence-enrollment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Modern identity attacks bypass MFA via AiTM. A negative result across
    the M365 estate for these reconnaissance patterns provides assurance that even
    if an initial phishing event was successful, the adversary has not yet progressed
    to automated discovery and data exfiltration.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using a compromised identity to systematically enumerate
  M365 applications and sensitive document repositories, likely using automated tools
  to collect and exfiltrate data following a passkey-themed phishing event.
labels:
- hunt
- attack.t1078
- attack.t1041
name: M365 Cloud Reconnaissance and Automated Data Collection
parameters:
  discovery_portals:
    default:
    - officehome
    - my apps
    - my profile
    - my signins
    - microsoft approval management
    - ocaas
    - microsoft account controls v2
    - m365chatclient
    - owadownloadattachments
    description: Sensitive M365 applications and resources used for reconnaissance
      and collection.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
    type: list[string]
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
    description: Phishing and C2 domains associated with this campaign.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt begins by scoping to endpoints running Microsoft 365/Office software
  using hb_software_inventory to ensure we are looking at the relevant user population.
  It then focuses on the behavioral sequence of accessing 'reconnaissance' portals
  like My Apps and Approval Management.
references:
- name: "MSRC \u2014 Passkey-themed social engineering leads to identity and cloud\
    \ compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: mfa-persistence-enrollment
  reason: MFA enrollment for persistence is a precursor to this activity and is covered
    in a separate hunt focusing on credential and auth-method changes.
  relation: out-of-scope-alternative
- hunt: phishing-infrastructure-setup
  reason: Tracking the registration of these domains is a perimeter and DNS-wide hunt,
    whereas this hunt focuses on the compromised identity's cloud activity.
  relation: out-of-scope-alternative
- hunt: passkey-phishing-mfa-persistence
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
  index: 3
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


# M365 Cloud Reconnaissance and Automated Data Collection

This hunt focuses on post-compromise activity following passkey-themed social engineering. Attackers use automated tools (often Node.js-based) to traverse the Microsoft Graph, hitting 'My Apps', 'My Sign-Ins', and 'Microsoft Approval Management' to discover the victim's reach. This is followed by high-volume file enumeration and access in SharePoint and OneDrive. We first identify the estate running Office/M365 software, detect anomalous discovery portal sequences, and then parallelize evidence collection across resource prevalence, file volume, and DNS indicators.

## m365-inventory-scoping
<!-- Scope Estate for M365/Office Users -->
Identify hosts with Microsoft 365 or Office installations to define the relevant estate for cloud identity compromise.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts that use M365. Silence means the software inventory is either
  empty or does not contain these packages.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft%365%' OR LOWER(package_name) LIKE '%office%') AND (LOWER(vendor_name) LIKE '%microsoft%')
```

## reconnaissance-portal-sequence
<!-- Reconnaissance Portal Sequence Detection -->
Find users accessing multiple sensitive identity and application portals in a short window, suggesting automated cloud discovery.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, discovery_portals=discovery_portals)
~~~yaml
expected: Users hitting 3+ distinct discovery portals. High portal counts in short
  windows are a strong indicator of automated reconnaissance.
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
SELECT actor_user_name, src_endpoint_ip, GROUP_CONCAT(DISTINCT dst_endpoint_name) as portals_accessed, COUNT(DISTINCT dst_endpoint_name) as portal_count, MIN(time) as start_time, MAX(time) as end_time FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{discovery_portals}}' || ',', ',' || LOWER(dst_endpoint_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING portal_count >= 3
```

## corroborate-activity
<!-- Parallel Corroboration of Recon and Collection -->
parallel:
- → rare-discovery-portal-access
- → high-volume-m365-file-access
- → phishing-domain-lookups
join: → triage-compromise

## rare-discovery-portal-access
<!-- Rare Discovery Portal Baseline -->
Stack-count users per portal to identify which reconnaissance targets are rare in this fleet (e.g., Approval Management).

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, discovery_portals=discovery_portals)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Portals like 'Microsoft Approval Management' showing very low user counts.
  An actor hitting these is more likely to be anomalous.
prevalence:
  by: actor_user_name
  key:
  - dst_endpoint_name
  rare_below: 10
reads:
- dst_endpoint_name
- actor_user_name
- time
- status_id
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT dst_endpoint_name, COUNT(DISTINCT actor_user_name) as users, MIN(time) as first_seen FROM hb_auth_signin WHERE status_id = 1 AND instr(',' || '{{discovery_portals}}' || ',', ',' || LOWER(dst_endpoint_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_name ORDER BY users ASC
```

## high-volume-m365-file-access
<!-- M365 High-Volume File Activity -->
Identify users with unusually high volumes of file access in SharePoint/OneDrive, consistent with automated collection.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Users performing massive file enumeration. Correlating these users with
  those in the portal sequence suggests an automated drain.
reads:
- actor_user_name
- file_path
- provider
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT actor_user_name, COUNT(*) as touch_count, COUNT(DISTINCT file_path) as unique_files, MIN(time) as first_touch, MAX(time) as last_touch FROM hb_file_activity WHERE provider = 'm365' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name HAVING unique_files > 50 ORDER BY unique_files DESC
```

## phishing-domain-lookups
<!-- DNS Lookups to Campaign Phishing Domains -->
Correlate portal access and file activity with host-level DNS lookups to the phishing infrastructure named in the research.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains)
~~~yaml
expected: A host-to-domain match. This provides high-confidence evidence that the
  identity compromise originated from the specific social engineering campaign.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{phishing_domains}}' || ',', '.' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{phishing_domains}}' || ',', LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-compromise
<!-- Triage Reconnaissance and Collection Patterns -->
```agent target=hunter
cite: required
context:
- m365-inventory-scoping
- reconnaissance-portal-sequence
- rare-discovery-portal-access
- high-volume-m365-file-access
- phishing-domain-lookups
max_iterations: 6
objective: Determine if any user shows a pattern of successful portal reconnaissance
  (3+ portals) followed by high-volume file activity, especially if correlated with
  phishing domain lookups.
success_criteria: A verdict of malicious | suspicious | benign per identity, citing
  specific portals and file volumes.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one identity" (confidence: high, judge=hunter)
then: → isolate-identity
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: limited-file-telemetry)
else: → close-hunt

## isolate-identity
<!-- Revoke Sessions and Reset User -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active M365/Azure AD sessions, reset the user's password, and audit/remove any MFA methods or passkeys added within the last lookback_days.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Deep Dive Data Access Review -->
```manual target=analyst
Review the file paths identified in the high-volume-m365-file-access step. Determine if proprietary or personal data was accessed. Correlate the src_endpoint_ip with known malicious proxy lists.
```
→ end

## close-hunt
<!-- Close and Monitor -->
```manual target=analyst
No coordinated discovery or collection was identified. Log negative findings and recommend periodic review of MFA registration events.
```
→ end

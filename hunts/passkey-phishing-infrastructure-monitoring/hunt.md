---
analysis: This hunt is not a simple IOC match; it employs a prevalence-based baseline
  to discover rare keywords ('passkey') used in targeted subdomains that rotate too
  fast for traditional feeds, and corroborates these hits across DNS and HTTP surfaces
  using an agent to weigh the risk.
blind_spots:
- id: encrypted-dns-visibility
  question: Are hosts using DoH/DoT to bypass local DNS monitoring?
  requires: unencrypted DNS telemetry or resolver-side logs
  risk: If an adversary-controlled browser profile uses encrypted DNS to resolve phishing
    domains, the hb_dns_activity surface will be empty.
  stage: phishing-infrastructure-setup
- id: personal-device-telemetry
  question: Did the user engage with the lure entirely on a personal mobile device?
  requires: Endpoint telemetry on non-corporate mobile devices
  risk: Lures frequently arrive via SMS on personal phones. If the compromise occurs
    outside the managed network and endpoint fleet, network-based signals will be
    missing until the identity is used to sign in to cloud services.
  stage: phishing-infrastructure-setup
coverage:
- stage: phishing-infrastructure-setup
  status: covered
  steps:
  - dns-ioc-matches
  - rare-themed-dns-keywords
  - http-themed-traffic
- reason: Handled by the second hunt in this series focusing on authentication telemetry
    (hb_auth_signin).
  stage: identity-compromise-via-aitm
  status: out_of_scope
- reason: Handled by the third hunt in this series focusing on MFA configuration changes.
  stage: mfa-persistence-enrollment
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
  justification: Threat actors are increasingly using passkey-themed impersonation
    domains to circumvent MFA; proactive infrastructure monitoring provides early
    warning before full account compromise and data exfiltration occur.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are registering and using organization-themed subdomains and
  passkey-related URLs to host phishing portals, visible as rare DNS queries or HTTP
  traffic from internal workstations.
labels:
- hunt
- attack.t1566
- attack.t1090.003
name: Passkey-themed phishing infrastructure monitoring
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_root_domains:
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
    description: Phishing domains identified in the MSRC research.
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
    model: hb_google/gemini-3-flash-preview
rationale: The hunt targets managed workstations first; while the lures often arrive
  on personal mobile devices, interaction from managed laptops (via shared browsers
  or chat clients) provides the most reliable signal.
references:
- name: "Microsoft Security Blog \u2014 Passkey-themed social engineering leads to\
    \ identity and cloud compromise"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
related:
- hunt: aitm-session-token-replay
  reason: Once infrastructure interaction is confirmed, the next stage of the attack
    involves replaying AiTM session tokens, which requires analysis of hb_auth_signin
    logs.
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
  index: 1
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Passkey-themed phishing infrastructure monitoring

This hunt focuses on the initial stage of a sophisticated social engineering campaign that uses passkey-themed lures to gain cloud access. The threat actor registers look-alike domains (e.g., company-name.integratedsso.com) and directs employees to them via phone or SMS.

By monitoring for rare domain resolutions and HTTP requests containing high-risk keywords like 'passkey', 'sso', or 'secure-passkey', we can identify the infrastructure setup phase before it results in account compromise. The hunt baseline is established by stack-counting these domains across the fleet to filter out legitimate SaaS providers, while an agent evaluates the risk of matched indicators and suspicious User-Agents.

## managed-workstations
<!-- Identify managed workstations -->
Scope the hunt to managed devices as they provide the most consistent network and process telemetry.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames to focus the hunt on. Silence indicates no managed devices
  are currently reporting telemetry.
reads:
- hostname
- platform
- os_name
- is_managed
- lifecycle_state
- last_seen
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT DISTINCT hostname AS device_hostname, platform, os_name FROM hb_devices WHERE is_managed = 1 AND lifecycle_state = 'active' AND last_seen >= datetime('now', '-1 days')
```

## infrastructure-parallel
<!-- Search for infrastructure indicators -->
parallel:
- → dns-ioc-matches
- → rare-themed-dns-keywords
- → http-themed-traffic
join: → triage-infrastructure

## dns-ioc-matches
<!-- DNS hits on reported phishing IOCs -->
Match host DNS queries against the specific domains provided in the MSRC report.

```sqlite target=endpoint role=detection-candidate params=(phishing_root_domains=phishing_root_domains, lookback_days=lookback_days)
~~~yaml
expected: Matches indicate communication with known threat infrastructure. Silence
  suggests those specific domains were not queried in the lookback window.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{phishing_root_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-themed-dns-keywords
<!-- Rare passkey-themed domain resolutions -->
Identify domains containing 'passkey' or 'sso' that are rare across the fleet, suggesting targeted phishing infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare domains appearing on only one or two hosts. Common legitimate providers
  will be excluded by the host count threshold.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT LOWER(query_hostname) AS domain, process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%passkey%' OR LOWER(query_hostname) LIKE '%integratedsso%' OR LOWER(query_hostname) LIKE '%oktasession%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY domain, process_name HAVING hosts <= 3 ORDER BY hosts ASC
```

## http-themed-traffic
<!-- HTTP traffic to themed domains -->
Corroborate DNS findings with HTTP metadata to identify suspicious User-Agents or unmanaged contexts.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to themed domains. User-Agents inconsistent with the host's
  standard browser profile should be flagged.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-10'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE (LOWER(url_hostname) LIKE '%passkey%' OR LOWER(url_hostname) LIKE '%integratedsso%' OR LOWER(url_hostname) LIKE '%oktasession%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infrastructure
<!-- Evaluate infrastructure risk -->
```agent target=hunter
cite: required
context:
- dns-ioc-matches
- rare-themed-dns-keywords
- http-themed-traffic
max_iterations: 5
objective: Identify hosts connecting to domains that impersonate organization services
  or use 'passkey' lures, citing matching IOCs and anomalous User-Agents.
success_criteria: A verdict of malicious | suspicious | benign per host with cited
  evidence.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "The triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-dns-visibility)
else: → close-out

## isolate-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Instruct the user to reset their password and verify all registered MFA methods via the corporate portal.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the DNS and HTTP evidence cited by the agent. If the domains are verified as phishing, add them to the perimeter blocklists and notify the SOC for a wider identity-focused investigation.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the total number of hosts examined and any suspicious domains found that were ultimately deemed benign for future tuning.
```
→ end

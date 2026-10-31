---
analysis: A single rule on DNS or Entra ID is often too noisy to promote. This hunt
  uses a gated flow to confirm a phishing lead (DNS) before examining identity signals
  (device-code) and mobile health (Zimperium) together, providing the cross-surface
  context needed for a confident verdict.
blind_spots:
- id: limited-dns-visibility
  question: whether the phishing link was clicked on a mobile device not using a corporate
    DNS resolver
  requires: DNS logging for mobile devices (VPN/Proxy)
  risk: Ingress over cellular data or home Wi-Fi without an active corporate VPN will
    not leave a trace in hb_dns_activity.
  stage: phishing-and-smishing-delivery
- id: no-mobile-telemetry
  question: whether the device used for authentication was in a compromised state
    (rooted/jailbroken)
  requires: Zimperium/MTD integration with hb_detection_finding
  risk: Without MTD telemetry, the hunt cannot confirm if a device was exploited or
    tampered with before the token theft occurred.
  stage: vulnerability-and-zero-day-exploitation
coverage:
- stage: phishing-and-smishing-delivery
  status: covered
  steps:
  - phishing-dns-lead
- stage: device-code-phishing-interaction
  status: covered
  steps:
  - auth-activity
- stage: vulnerability-and-zero-day-exploitation
  status: covered
  steps:
  - inventory-scoping
  - mobile-risk
- reason: 'Belongs to another part of the ''Sekoia + Zimperium: Investigate Mobile
    Threats In Your SOC'' series.'
  stage: unauthorized-authentication-bypass
  status: out_of_scope
- reason: 'Belongs to another part of the ''Sekoia + Zimperium: Investigate Mobile
    Threats In Your SOC'' series.'
  stage: cloud-discovery-and-collection
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are increasingly using mobile phishing to bypass MFA
    via device-code hijacking (EvilTokens); identifying these ingress attempts is
    critical for preventing unauthorized cloud access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is targeting employees with mobile phishing links (smishing)
  that lure them into performing Entra ID device-code authentication, allowing the
  attacker to hijack cloud sessions from compromised or unmanaged mobile devices.
labels:
- hunt
- attack.t1190
- attack.t1566
- collection
- initial access
name: Mobile Ingress and Device Code Hijacking
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for phishing and authentication events.
    type: number
  phishing_domains:
    default:
    - login.microsoftonline.com.re.st
    - microsoft.com-device.login
    - microsoft-devicecode.com
    - eviltokens.io
    description: Domains associated with mobile phishing kits and EvilTokens lures.
    from:
      kind: article
      observed: '2026-10-21'
      ref: sekoia-zimperium-integration
    type: list[domain]
  scope_hosts:
    default: []
    description: Specific hostnames to narrow the hunt, such as those found in the
      scoping inventory step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/from-mobile-threat-detection-to-autonomous-investigation-connecting-zimperium-with-sekoia
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt first scopes the estate to identify devices with Zimperium or
  other MTD software. If no mobile management software is present, the hunt still
  proceeds across the entire fleet using the DNS phishing lead as the primary discovery
  mechanism.
references:
- name: "Sekoia \u2014 From mobile threat detection to autonomous investigation"
  url: https://www.sekoia.com/blog/from-mobile-threat-detection-to-autonomous-investigation-connecting-zimperium-with-sekoia
related:
- hunt: cloud-token-theft-reconnaissance
  reason: This hunt identifies the ingress; a subsequent hunt should examine the post-compromise
    actions in M365.
  relation: follows
scenario:
  stages:
  - name: Mobile Phishing and Smishing Delivery
    observables:
    - SMS and text messages containing malicious links
    - mishing
    - smishing
    - malicious URLs
    slug: phishing-and-smishing-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: EvilTokens Device Code Interaction
    observables:
    - microsoft.com/devicelogin
    - EvilTokens kit lure
    - Entry of device codes by users
    slug: device-code-phishing-interaction
    tactic: initial-access
    techniques:
    - T1566
  - name: Mobile Device and Application Exploitation
    observables:
    - Zero-day exploits
    - Exploitation of corporate services
    - Malicious application installation
    - Rooted or jailbroken devices
    slug: vulnerability-and-zero-day-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized Authentication and MFA Bypass
    observables:
    - Entra ID sign-in activity
    - Unauthorized session tokens
    - Sign-ins from unfamiliar locations
    - MFA bypass via device code
    - resultType 0
    slug: unauthorized-authentication-bypass
    tactic: initial-access
    techniques:
    - T1566
  - name: Cloud Resource Discovery and Collection
    observables:
    - Mailbox reconnaissance
    - Exchange Online API calls
    - SharePoint file access
    - Business Email Compromise (BEC) activity
    slug: cloud-discovery-and-collection
    tactic: collection
    techniques:
    - T1566
  summary: Attackers utilize mobile-first strategies including smishing and 'EvilTokens'
    device code phishing to bypass multi-factor authentication and gain unauthorized
    access to corporate accounts. Once access is established, the compromised identities
    are used to perform reconnaissance and data collection within Microsoft 365 and
    Entra ID environments.
series:
  index: 1
  slug: sekoia-zimperium-investigate-mobile-threats-in-your-soc
  title: 'Sekoia + Zimperium: Investigate Mobile Threats In Your SOC'
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


# Mobile Ingress and Device Code Hijacking

This hunt identifies the early stages of mobile-centric intrusions by correlating phishing ingress signals with subsequent authentication anomalies. It starts by identifying hosts running mobile management software, then hunts for resolutions to known phishing and EvilTokens infrastructure. A gate assessments the lead before fan-out queries examine device-code authentication flows and Zimperium-style device risk detections (like rooting or jailbreaking) side-by-side. An agent weighs the combined evidence to identify successful session theft before a revocation action stops the attack.

## inventory-scoping
<!-- Mobile management software inventory -->
Identify hosts with mobile defense or management software installed to focus the triage context on the most relevant devices.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely being mobile devices or running MTD software. Silence
  means no such software was detected in the package database.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%zimperium%' OR LOWER(vendor_name) LIKE '%zimperium%' OR LOWER(package_name) LIKE '%mobile%')
```

## phishing-dns-lead
<!-- Phishing domain DNS resolutions -->
Find resolutions to known phishing infrastructure as a cheap lead to gate further investigation.

```sqlite target=endpoint role=baseline params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Any resolution of a matched domain is a high-priority lead. Silence proves
  no matched domains were resolved via monitored resolvers.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## lead-agent
<!-- Assess phishing DNS lead -->
```agent target=hunter
cite: required
context:
- phishing-dns-lead
max_iterations: 3
objective: Determine if DNS resolutions to phishing domains indicate a credible attempt
  to lure users into a device-code authentication flow.
success_criteria: A verdict for each host citing the DNS resolutions.
tools:
- endpoint
- identity
```

## gate-decision
<!-- Gate on lead assessment -->
if~: "the lead-agent verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → investigation-fanout
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: limited-dns-visibility)
else: → final-report

## investigation-fanout
<!-- Correlate authentication and risk -->
parallel:
- → auth-activity
- → mobile-risk
join: → triage-agent

## auth-activity
<!-- Entra ID device-code interactions -->
Identify authentication events using the device-code flow or browser targeting Microsoft identity services, which are central to EvilTokens attacks.

```sqlite target=identity role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Any sign-in event using a device flow protocol or browser on a host that
  resolved phishing domains. Silence means no such authentication was recorded.
reads:
- actor_user_name
- auth_protocol
- client_app
- dst_endpoint_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT actor_user_name, device_hostname, auth_protocol, client_app, dst_endpoint_name, status, time FROM hb_auth_signin WHERE (LOWER(auth_protocol) LIKE '%device%' OR LOWER(client_app) LIKE '%browser%') AND (LOWER(dst_endpoint_name) LIKE '%microsoft%' OR LOWER(dst_endpoint_name) LIKE '%entra%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mobile-risk
<!-- Mobile risk and compromise signals -->
Identify Zimperium alerts or other mobile-specific detections indicating a high-risk or compromised device state.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Detections related to device tampering or mobile malware. Silence suggests
  no automated mobile threats were flagged.
reads:
- device_hostname
- finding_title
- malware_name
- provider
- time
silence: not_evidence_of_absence
source: hb_detection_finding
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, user_name, finding_title, malware_name, provider, severity, time FROM hb_detection_finding WHERE (LOWER(finding_title) LIKE '%root%' OR LOWER(finding_title) LIKE '%jailbreak%' OR LOWER(malware_name) LIKE '%mishing%' OR LOWER(malware_name) LIKE '%eviltoken%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Final triage of mobile threat -->
```agent target=hunter
cite: required
context:
- lead-agent
- auth-activity
- mobile-risk
- inventory-scoping
max_iterations: 4
objective: Correlate the suspected phishing ingress with Entra ID authentication patterns
  and mobile device risk signals to confirm an active token-theft or compromise event.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing relevant
  rows from all surfaces.
tools:
- endpoint
- identity
```

## route-decision
<!-- Route on triage verdict -->
if~: "the triage-agent verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → containment-action
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-mobile-telemetry)
else: → manual-review

## containment-action
<!-- Revoke sessions and isolate -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions and refresh tokens for the compromised user in Entra ID to stop EvilTokens hijacking.
```
→ manual-review

## manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review Entra ID sign-in logs and M365 Unified Audit Logs for the identified user. Look for unusual mailbox logins or changes to MFA settings occurring immediately after the suspected device-code interaction.
```
→ final-report

## final-report
<!-- Hunt closure and reporting -->
```manual target=analyst
Record the hunt outcome, update the phishing domain list, and document any identified gaps in mobile telemetry coverage.
```
→ end

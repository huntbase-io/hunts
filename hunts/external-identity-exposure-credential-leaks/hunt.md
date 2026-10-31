---
analysis: "A rule fires on a known bad IP; the hunt finds the 'unlocked doors'\u2014\
  valid credentials already in circulation\u2014by correlating external exposure telemetry\
  \ with a behavioral baseline of host sign-ins. An analyst weighs whether a rare\
  \ login source matches an identity compromise reported in criminal markets."
blind_spots:
- id: unmanaged-endpoint-blind-spot
  question: Exactly how the infection occurred and what other non-corporate passwords
    were stolen
  requires: Endpoint telemetry from the user's personal/home machine
  risk: While we see the corporate logon from the beachhead, we remain blind to the
    source infection on the unmanaged device that led to the compromise.
  stage: infostealer-credential-harvesting
- id: external-telemetry-blind-spot
  question: Whether a credential has been stolen but not yet indexed by Hudson Rock
    or Flare
  requires: Real-time access to the specific Telegram channel where the log was first
    leaked
  risk: There is a window of latency between the initial leak in a private criminal
    channel and its visibility in monitoring platforms, during which the attacker
    can act.
  stage: infostealer-credential-harvesting
coverage:
- stage: infostealer-credential-harvesting
  status: covered
  steps:
  - find-active-corporate-hosts
  - rare-authentication-patterns
  - domain-exposure-lookup
- reason: Belongs to a separate hunt focusing on the sign-in event and subsequent
    MFA fatigue or session replay.
  stage: identity-led-initial-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Introducing Sekoia Digital Risk: Track
    Identity-Led Breaches'' series.'
  stage: internal-credential-discovery
  status: out_of_scope
- reason: 'Belongs to another part of the ''Introducing Sekoia Digital Risk: Track
    Identity-Led Breaches'' series.'
  stage: unauthorised-cloud-resource-access
  status: out_of_scope
- reason: 'Belongs to another part of the ''Introducing Sekoia Digital Risk: Track
    Identity-Led Breaches'' series.'
  stage: data-exfiltration-and-extortion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Identity-led breaches, such as the 2024 Snowflake intrusions, bypass
    traditional perimeters. This hunt provides the business with the assurance that
    its employee credentials are not currently available in the criminal 'stealer'
    economy, or identifies them for immediate rotation if they are.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are using corporate credentials harvested from unmanaged personal
  devices by infostealers to bypass authentication controls and gain initial access
  to cloud resources.
labels:
- hunt
- attack.t1555
- attack.t1195
- attack.t1133
- attack.t1078.004
- credential access
- impact
- initial access
- lateral movement
- hudsonrock
name: External Identity Exposure and Credential Leaks
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Hostnames to focus on; leave empty to hunt across all hosts reporting
      corporate logons.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: scoping-output
    type: list[host]
  target_domain:
    default: example.com
    description: Corporate domain to scope the identity search.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: organization-config
    type: string
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/with-sekoia-intelligence-we-gave-you-half-the-picture-heres-the-other-half
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying the workstations that record the highest volume of
  corporate logons. Focus especially on hosts belonging to contractors or departments
  known to use personal devices.
references:
- name: "Sekoia \u2014 Introducing Sekoia Digital Risk"
  url: https://www.sekoia.com/blog/with-sekoia-intelligence-we-gave-you-half-the-picture-heres-the-other-half
related:
- hunt: identity-led-initial-access-detection
  reason: This hunt identifies the exposure; the follow-on hunt monitors for the actual
    login attempt and initial cloud enumeration.
  relation: follows
scenario:
  stages:
  - name: Infostealer Harvesting from Personal Devices
    observables:
    - Lumma malware
    - RedLine malware
    - Vidar malware
    - Raccoon malware
    - personal devices
    - contractor laptops
    - browser saved credentials
    - session cookies
    - Telegram channels
    slug: infostealer-credential-harvesting
    tactic: initial-access
    techniques:
    - T1555
    - T1195
  - name: Initial Access via Stolen Identity
    observables:
    - Snowflake login
    - Okta service account
    - valid session cookie replay
    - MFA push notifications
    - push notification fatigue
    - non-compliant device sign-in
    - external contractor credentials
    slug: identity-led-initial-access
    tactic: initial-access
    techniques:
    - T1133
    - T1190
  - name: Internal Credential and Secret Discovery
    observables:
    - hard-coded admin credentials
    - internal network shares
    - support case files
    - customer session tokens
    - browser-synced credentials
    slug: internal-credential-discovery
    tactic: credential-access
    techniques:
    - T1555
  - name: Lateral Movement to Cloud Services
    observables:
    - AWS console access
    - Google Workspace
    - Slack workspace connections
    - bug bounty systems
    slug: unauthorised-cloud-resource-access
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Data Exfiltration and Ransom Extortion
    observables:
    - 1.3 TB data theft
    - Snowflake database records
    - ShinyHunters extortion
    - Ticketmaster listing
    - hundreds of millions of records
    slug: data-exfiltration-and-extortion
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors leverage infostealer malware (Lumma, RedLine, Vidar) to harvest
    credentials and session cookies from personal or contractor devices, which are
    later sold via access brokers and Telegram channels. These stolen identities are
    used to bypass MFA via session replay or fatigue attacks to gain access to corporate
    cloud platforms like Snowflake, AWS, and Slack for large-scale data exfiltration
    and extortion.
series:
  index: 1
  slug: introducing-sekoia-digital-risk-track-identity-led-breaches
  title: 'Introducing Sekoia Digital Risk: Track Identity-Led Breaches'
  total: 2
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  hudsonrock:
    category: siem
    huntbase:
      product: hudsonrock
    name: hudsonrock
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


# External Identity Exposure and Credential Leaks

An agent weighs the intersection of these surfaces to find 'unlocked doors' before they are exploited at scale. The hunt identifies compromised corporate identities by correlating external exposure data from infostealer logs with anomalous internal sign-in behavior. Inspired by the Snowflake and CircleCI breaches, the hunt first identifies active workstations used by corporate identities, then fans out to check for domain-wide exposure in criminal markets (via Hudson Rock) alongside a search for rare authentication patterns from those same workstations.

## find-active-corporate-hosts
<!-- Identify active corporate workstations -->
Identify which workstations are actively recording corporate domain logons to scope the subsequent behavioral analysis.

```sqlite target=identity role=scoping params=(target_domain=target_domain, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. These are the devices analysts should prioritize for
  the scope_hosts parameter in the fan-out.
reads:
- device_hostname
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT DISTINCT device_hostname FROM hb_auth_signin WHERE LOWER(actor_user_name) LIKE '%@{{target_domain}}' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence-gathering
<!-- Corroborate exposure and behavior -->
parallel:
- → rare-authentication-patterns
- → domain-exposure-lookup
join: → triage-verdict

## rare-authentication-patterns
<!-- Find rare authentication sources -->
Stack-count source IPs per user on the scoped hosts to find anomalous logins that might indicate stolen credential or session usage.

```sqlite target=identity role=baseline params=(target_domain=target_domain, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Login events from source IPs seen rarely across the scoped fleet, potentially
  indicating attacker infrastructure.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, COUNT(*) AS login_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE LOWER(actor_user_name) LIKE '%@{{target_domain}}' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, src_endpoint_ip HAVING login_count < 10
```

## domain-exposure-lookup
<!-- Check for domain-wide identity leaks -->
Identify if corporate credentials for the domain have recently appeared in stealer logs indexed by Hudson Rock.

```sqlite target=hudsonrock role=enrichment params=(target_domain=target_domain)
~~~yaml
expected: A summary of recent compromises, listing stealer families (Lumma, RedLine)
  and counts. Silence means no indexed exposure for this domain in the Hudson Rock
  archive.
reads:
- domain
- total_stealers
- last_employee_compromised
- stealer_families
- employees_urls
silence: not_evidence_of_absence
source: hudsonrock_search_by_domain
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT domain, total_stealers, last_employee_compromised, stealer_families, employees_urls FROM hudsonrock_search_by_domain WHERE domain = '{{target_domain}}'
```

## triage-verdict
<!-- Weigh exposure and sign-in behavior -->
```agent target=hunter
cite: required
context:
- find-active-corporate-hosts
- rare-authentication-patterns
- domain-exposure-lookup
max_iterations: 4
objective: Determine which users from rare-authentication-patterns correlate with
  the exposure levels and stealer families identified in domain-exposure-lookup.
success_criteria: A per-host and per-user verdict citing specific rare IPs and the
  exposure timeframe.
tools:
- hudsonrock
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict identifies at least one corporate identity showing both external exposure in stealer logs and anomalous sign-in behavior" (confidence: high, judge=hunter)
then: → revoke-identity-sessions
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: external-telemetry-blind-spot)
else: → close-out

## revoke-identity-sessions
<!-- Revoke sessions and reset credentials -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active browser and OAuth sessions for the confirmed identities. Trigger a forced password reset and require an MFA re-enrollment.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Examine post-login activity -->
```manual target=analyst
Use hb_cloud_api_activity and hb_auth_signin to trace the actions of the compromised identities. Look for mass data access (S3/SharePoint) or modification of IAM policies.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the identities found and the specific stealer families involved. Recommend security policy updates such as requiring managed devices for all administrative cloud access.
```
→ end

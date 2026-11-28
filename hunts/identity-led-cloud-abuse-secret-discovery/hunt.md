---
analysis: "A rule fires on MFA failures. This hunt connects those failures to compliance\
  \ state, underground exposure, and subsequent cloud discovery\u2014providing the\
  \ context required to justify account suspension."
blind_spots:
- id: unmanaged-device-visibility
  owner: Endpoint Engineering
  question: whether the initial infection happened on a device we do not manage
  remediation: Enforce managed-device-only policies in the IDP.
  requires: EDR telemetry on personal devices
  risk: Attackers harvesting credentials from personal laptops are invisible until
    they use the credential against corporate endpoints.
  stage: identity-led-initial-access
- id: stolen-session-replay
  owner: Identity Team
  question: whether a valid session cookie was replayed from a different IP
  remediation: Enable session token binding or IP-pinning.
  requires: hb_auth_signin with session correlation IDs
  risk: Cookie replay bypasses MFA and auth failure logging entirely.
  stage: identity-led-initial-access
coverage:
- stage: identity-led-initial-access
  status: covered
  steps:
  - non-compliant-device-scoping
  - mfa-fatigue-patterns
  - hudson-rock-exposure
- stage: internal-credential-discovery
  status: covered
  steps:
  - cloud-discovery-exfil
  - internal-smb-discovery
- stage: unauthorised-cloud-resource-access
  status: covered
  steps:
  - cloud-discovery-exfil
  - intent-correlation-agent
- stage: data-exfiltration-and-extortion
  status: covered
  steps:
  - cloud-discovery-exfil
  - route-on-verdict
- reason: 'Belongs to another part of the ''Introducing Sekoia Digital Risk: Track
    Identity-Led Breaches'' series.'
  stage: infostealer-credential-harvesting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Identity-led breaches avoid zero-days and exploits, making them invisible
    to traditional vulnerability management. This hunt validates that even if credentials
    are stolen, subsequent abuse is detected.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has used stolen credentials harvested from unmanaged devices
  to bypass MFA via push fatigue, subsequently discovering cloud secrets and internal
  shares to exfiltrate data.
labels:
- hunt
- attack.t1133
- attack.t1190
- attack.t1555
- attack.t1486
- credential access
- impact
- initial access
- lateral movement
- hudsonrock
name: Identity-Led Cloud Abuse and Secret Discovery
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames identified in the scoping step to focus internal discovery
      queries.
    type: list[host]
  secret_api_ops:
    default:
    - GetSecretValue
    - DescribeInstances
    - GetBucketPolicy
    - ListAccessKeys
    - AssumeRole
    description: Cloud API operations associated with secret discovery.
    from:
      kind: article
      observed: '2023-10-20'
      ref: Uber/Okta breach reports
    type: list[string]
  sensitive_shares:
    default:
    - \\*\admin$
    - \\*\c$
    - \\*\ipc$
    - \\*\backup
    - \\*\finance
    description: Internal SMB shares typically targeted for credential or data discovery.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: Internal assessment
    type: list[path]
  target_domain:
    default: example.com
    description: Primary domain to check for existing exposure in stealer logs.
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
rationale: Start with users reporting 'false' for compliance in hb_auth_signin. Focus
  on servers and administrative workstations first. Widen the domain check if high
  exposure is found in Hudson Rock.
references:
- name: "Sekoia \u2014 With Sekoia Intelligence, we gave you half the picture"
  url: https://www.sekoia.com/blog/with-sekoia-intelligence-we-gave-you-half-the-picture-heres-the-other-half
- name: "Mandiant \u2014 Snowflake Data Theft Investigation"
  url: https://www.mandiant.com/resources/blog/unc5537-snowflake-data-theft-investigation
related:
- hunt: infostealer-credential-harvesting
  reason: This hunt focuses on the use of credentials, not the initial malware infection.
  relation: out-of-scope-alternative
- hunt: external-identity-exposure-credential-leaks
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
  index: 2
  slug: introducing-sekoia-digital-risk-track-identity-led-breaches
  title: 'Introducing Sekoia Digital Risk: Track Identity-Led Breaches'
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


# Identity-Led Cloud Abuse and Secret Discovery

This hunt follows the transition from compromised identity to resource abuse, as seen in the Snowflake and Uber breaches. It begins by scoping users signing in from non-compliant devices, then examines authentication patterns for MFA fatigue and proxy usage. The second phase correlates these suspicious logons with secret discovery in cloud control planes and administrative SMB shares, connecting initial access to malicious intent.

## non-compliant-device-scoping
<!-- Identify non-compliant device sign-ins -->
Scope the estate to users and hosts accessing corporate resources from devices that do not meet management policy.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and users signing in from personal or unmanaged machines.
  Silence suggests high compliance.
reads:
- actor_user_name
- device_hostname
- device_is_compliant
- provider
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT DISTINCT device_hostname, actor_user_name, provider, src_endpoint_ip, time FROM hb_auth_signin WHERE device_is_compliant = 'false' AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## early-access-parallel
<!-- Assess early stage access anomalies -->
parallel:
- → mfa-fatigue-patterns
- → hudson-rock-exposure
join: → early-stage-triage

## mfa-fatigue-patterns
<!-- MFA push fatigue patterns -->
Detect many authentication failures followed by a success for a single user, indicating a push bombing attack.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A high count of failures followed by success. This is the primary indicator
  for the Uber-style compromise.
reads:
- activity_id
- actor_user_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT actor_user_name, src_endpoint_ip, SUM(CASE WHEN activity_id = 5 THEN 1 ELSE 0 END) as failures, SUM(CASE WHEN activity_id = 1 THEN 1 ELSE 0 END) as successes FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip HAVING failures >= 5 AND successes > 0 ORDER BY failures DESC
```

## hudson-rock-exposure
<!-- Check organizational exposure -->
Enrich the hunt by checking if the organizational domain has existing stealer log exposure.

```sqlite target=hudsonrock role=enrichment params=(target_domain=target_domain)
~~~yaml
expected: Confirmed stealer log exposure for the domain, increasing the likelihood
  that recent sign-ins involve stolen material.
reads:
- domain
- last_employee_compromised
- total_stealers
silence: not_evidence_of_absence
source: hudsonrock_search_by_domain
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT domain, total_stealers, last_employee_compromised FROM hudsonrock_search_by_domain WHERE domain = '{{target_domain}}'
```

## early-stage-triage
<!-- Evaluate initial access risk -->
```agent target=hunter
cite: required
context:
- non-compliant-device-scoping
- mfa-fatigue-patterns
- hudson-rock-exposure
max_iterations: 6
objective: Determine if sign-in patterns indicate a successful account takeover via
  credential theft or MFA fatigue.
success_criteria: A per-user verdict (malicious | suspicious | benign) citing MFA
  success and exposure data.
tools:
- endpoint
- hudsonrock
- identity
```

## follow-on-fan-out
<!-- Check for post-compromise discovery -->
parallel:
- → cloud-discovery-exfil
- → internal-smb-discovery
join: → intent-correlation-agent

## cloud-discovery-exfil
<!-- Cloud secret discovery and exfiltration -->
Search Cloud API logs for secret-reading operations or large data transfers.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, secret_api_ops=secret_api_ops)
~~~yaml
expected: A user reading access keys, assuming roles, or downloading large amounts
  of data from S3 or similar services.
reads:
- actor_user_name
- api_operation
- bytes_out
- resource_name
- resource_type
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT actor_user_name, api_operation, resource_type, resource_name, bytes_out, time FROM hb_cloud_api_activity WHERE (instr(',' || '{{secret_api_ops}}' || ',', ',' || api_operation || ',') > 0 OR bytes_out > 50000000) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY bytes_out DESC
```

## internal-smb-discovery
<!-- Sensitive SMB share access -->
Correlate identity access with discovery of backup files or credentials on administrative shares.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_shares=sensitive_shares)
~~~yaml
expected: Users previously identified as high-risk accessing sensitive shares like
  ADMIN$ or backup locations.
reads:
- actor_user_name
- device_hostname
- file_name
- share_name
- time
silence: not_evidence_of_absence
source: hb_smb_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT actor_user_name, share_name, file_name, device_hostname, time FROM hb_smb_activity WHERE instr(',' || '{{sensitive_shares}}' || ',', ',' || LOWER(share_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## intent-correlation-agent
<!-- Correlate intent and impact -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- cloud-discovery-exfil
- internal-smb-discovery
max_iterations: 6
objective: Confirm if accounts identified in the first phase have engaged in unauthorized
  secret discovery or large-scale exfiltration.
success_criteria: A final verdict citing the initial access anomaly and the cloud/share
  activity that confirms malicious intent.
tools:
- endpoint
- hudsonrock
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the intent-correlation-agent confirms a high-risk compromise with evidence of secret discovery or exfiltration" (confidence: high, judge=hunter)
then: → suspend-account
indeterminate: → analyst-remediation
unavailable: → analyst-remediation (blind_spot: unmanaged-device-visibility)
else: → hunt-close-out

## suspend-account
<!-- Suspend compromised identity -->
```action target=identity
~~~yaml
approval: required
~~~
Suspend the account(s) identified and revoke all active session tokens.
```
→ analyst-remediation

## analyst-remediation
<!-- Analyst remediation review -->
```manual target=analyst
Review Cloud API activity for AssumeRole operations and subsequent actions. Verify if any downloaded files contained sensitive PII.
```
→ hunt-close-out

## hunt-close-out
<!-- Close out hunt -->
```manual target=analyst
Record the usernames investigated and shares hit. Note any visibility gaps encountered.
```
→ end

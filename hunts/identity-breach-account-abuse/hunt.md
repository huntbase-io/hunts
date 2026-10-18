---
analysis: A standard detection rule alerts on a single bad IP or a password spray.
  This hunt correlates external exposure (infostealer token theft) with internal behavioral
  anomalies across three surfaces, requiring an agent to weigh the coincidence of
  the leak against active usage patterns.
blind_spots:
- id: ssl-inspection-gap
  owner: Network Engineering
  question: What full URI paths were visited on suspected phishing domains?
  remediation: Deploy endpoint-based HTTP inspection or enable corporate proxy SSL
    decryption.
  requires: SSL decryption for hb_http_activity
  risk: Phishing interaction remains unconfirmed without path context; we can see
    the domain but not whether a credential form was submitted.
  stage: phishing-follow-on
- id: mfa-telemetry-gap
  owner: Identity Engineering
  question: Was the anomalous login successful because MFA was bypassed or because
    a session token was stolen?
  remediation: Enable and export full conditional access and MFA logs to the centralized
    log pool.
  requires: hb_auth_signin with full MFA event details
  risk: Inability to distinguish between simple password reuse and sophisticated session
    hijacking via infostealer logs.
  stage: account-misuse-and-recovery
coverage:
- stage: data-exfiltration
  status: covered
  steps:
  - detect-data-exfiltration
- stage: phishing-follow-on
  status: covered
  steps:
  - detect-phishing-interaction
- stage: external-identity-exposure
  status: covered
  steps:
  - check-hibp
  - check-hudsonrock
- stage: account-misuse-and-recovery
  status: covered
  steps:
  - detect-anomalous-logins
  - remediate-compromised-accounts
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Third-party breaches and infostealer activity provide early warning
    of targeted account takeover. Correlating external intel with internal authentication
    and network behavior is critical for protecting corporate data assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are leveraging corporate credentials exposed in third-party
  data breaches to bypass authentication, propagate phishing lures, and exfiltrate
  data from internal endpoints.
labels:
- hunt
- attack.t1041
- attack.t1566
- exfiltration
- initial access
- haveibeenpwned
- hudsonrock
name: Identity Breach and Account Abuse
parameters:
  corporate_domains:
    default:
    - example.com
    description: Corporate email domains to check against external breach databases.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: internal-policy
    type: list[string]
  high_risk_identities:
    default: []
    description: List of compromised identities identified in the first phase. Leave
      empty to run the hunt for all users on scoped hosts.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: weigh-external-exposure
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for internal behavioral anomalies.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the internal corroboration steps.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: scoping-query
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/how-to/what-to-do-when-a-data-breach-notice-tells-you-almost-nothing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus internal behavioral queries on hosts that have reported active status
  within the lookback window. Prioritize accounts belonging to users in high-privilege
  departments such as IT, HR, or Finance.
references:
- name: "ESET Research \u2014 What to do when a data breach notice tells you almost\
    \ nothing"
  url: https://www.welivesecurity.com/en/how-to/what-to-do-when-a-data-breach-notice-tells-you-almost-nothing/
related:
- hunt: infostealer-infection-remediation
  reason: This hunt focuses on the identity impact; a related hunt focuses on cleaning
    the infected unmanaged machines themselves.
  relation: alternative
scenario:
  stages:
  - name: Data Exfiltration Over C2
    observables:
    - large data volumes
    - exfiltrated data
    - access to sensitive information
    slug: data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Follow-on Phishing Attempts
    observables:
    - unsolicited breach notification email
    - links in these messages
    - targeted phishing calls
    slug: phishing-follow-on
    tactic: initial-access
    techniques:
    - T1566
  - name: External Identity Exposure
    observables:
    - leaked usernames and passwords
    - exposed email addresses
    - exposed phone numbers
    - government ID exposure
    slug: external-identity-exposure
    tactic: initial-access
    techniques:
    - T1566
  - name: Account Misuse and Remediation
    observables:
    - suspicious activity on affected accounts
    - password reset events
    - enabling two-factor authentication (2FA)
    slug: account-misuse-and-recovery
    tactic: initial-access
    techniques:
    - T1566
  summary: The campaign involves the large-scale exfiltration of sensitive organizational
    and personal data, which is subsequently leveraged by adversaries for targeted
    phishing and credential misuse. Defenders must identify exposure via external
    breach intelligence and monitor for anomalous sign-ins or remediation actions
    like emergency password resets.
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
  haveibeenpwned:
    category: siem
    huntbase:
      product: haveibeenpwned
    name: haveibeenpwned
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Identity Breach and Account Abuse

This phased hunt identifies corporate identities compromised in external breaches and infostealer activity, then monitors those specific accounts for anomalous internal behavior. By correlating external intelligence with authentication, web, and network telemetry, the hunt distinguishes between simple credential exposure and active account weaponization.

## scope-active-devices
<!-- Scope active managed devices -->
Identify recently active hosts to focus the internal behavioral queries.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames that have reported inventory recently. Silence means
  no active devices are reporting.
reads:
- hostname
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE (lifecycle_state = 'active' OR lifecycle_state = 'running') AND time >= datetime('now', '-{{lookback_days}} days')
```

## external-intel-fan-out
<!-- Parallel external intelligence check -->
parallel:
- → check-hibp
- → check-hudsonrock
join: → weigh-external-exposure

## check-hibp
<!-- Public data breach exposure -->
Check if corporate accounts appear in public data breaches listed by HaveIBeenPwned.

```sqlite target=haveibeenpwned role=enrichment params=(corporate_domains=corporate_domains)
~~~yaml
expected: Corporate accounts found in third-party breaches. Silence confirms no corporate
  identities are present in the HIBP snapshot.
reads:
- account
- data_classes
- name
silence: not_evidence_of_absence
source: hibp_breached_account
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT account, name AS breach_name, data_classes FROM hibp_breached_account WHERE instr(',' || '{{corporate_domains}}' || ',', ',' || LOWER(SUBSTR(account, INSTR(account, '@') + 1)) || ',') > 0
```

## check-hudsonrock
<!-- Infostealer identity leaks -->
Identify corporate users whose credentials were stolen by stealer malware as recorded by Hudson Rock.

```sqlite target=hudsonrock role=enrichment params=(corporate_domains=corporate_domains)
~~~yaml
expected: Corporate accounts compromised by infostealers. Silence means no credentials
  from these domains were found in the malware database.
reads:
- computer_name
- date_compromised
- email
- malware_path
silence: not_evidence_of_absence
source: hudsonrock_search_by_email
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT email, computer_name, date_compromised, malware_path FROM hudsonrock_search_by_email WHERE instr(',' || '{{corporate_domains}}' || ',', ',' || LOWER(SUBSTR(email, INSTR(email, '@') + 1)) || ',') > 0
```

## weigh-external-exposure
<!-- Weigh external exposure risk -->
```agent target=hunter
cite: required
context:
- check-hibp
- check-hudsonrock
max_iterations: 3
objective: 'Categorize the exposure for corporate identities: distinguish between
  static historical leaks and high-risk infostealer compromises that may indicate
  active token theft.'
success_criteria: A per-account risk verdict citing the intelligence source and the
  type of data leaked. The analyst will use this list to populate the high_risk_identities
  parameter.
tools:
- endpoint
- haveibeenpwned
- hudsonrock
- identity
- network
- web
```

## internal-behavior-fan-out
<!-- Parallel internal behavior hunt -->
parallel:
- → detect-anomalous-logins
- → detect-phishing-interaction
- → detect-data-exfiltration
join: → final-correlative-analysis

## detect-anomalous-logins
<!-- Anomalous logins for high-risk identities -->
Find successful sign-ins from rare source IP addresses specifically for the corporate identities flagged in the intelligence phase.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, high_risk_identities=high_risk_identities)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Successful logins from unusual IPs or locations for high-risk accounts.
  Silence proves no rare successful authentications occurred for these users.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- src_location_country
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, device_hostname, COUNT(*) as login_count, MIN(time) as first_seen FROM hb_auth_signin WHERE status_id = 1 AND ('{{high_risk_identities}}' = '' OR instr(',' || '{{high_risk_identities}}' || ',', ',' || actor_user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, src_location_country, device_hostname HAVING login_count < 5 ORDER BY login_count ASC
```

## detect-phishing-interaction
<!-- Phishing interaction for high-risk users -->
Identify web requests containing credential harvesting lures from the compromised users identified earlier.

```sqlite target=web role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, high_risk_identities=high_risk_identities)
~~~yaml
expected: HTTP interaction with potential phishing URLs by compromised users. Silence
  confirms no such lures were visited by these specific accounts.
reads:
- actor_user_name
- device_hostname
- time
- url_full
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, actor_user_name, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE (LOWER(url_full) LIKE '%login%' OR LOWER(url_full) LIKE '%office%' OR LOWER(url_full) LIKE '%verify%') AND ('{{high_risk_identities}}' = '' OR instr(',' || '{{high_risk_identities}}' || ',', ',' || actor_user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-data-exfiltration
<!-- Data exfiltration from compromised accounts -->
Identify large outbound data transfers originating from the identities previously flagged for high-risk exposure.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, high_risk_identities=high_risk_identities)
~~~yaml
expected: Outbound sessions exceeding 50MB originating from high-risk users. Silence
  means no such data transfers were recorded for these accounts.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- state_kind
- time
- traffic_bytes
- user_name
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-14'
~~~
SELECT device_hostname, user_name, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes FROM hb_network_connection WHERE state_kind = 'log' AND direction = 'outbound' AND ('{{high_risk_identities}}' = '' OR instr(',' || '{{high_risk_identities}}' || ',', ',' || user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, user_name, dst_endpoint_ip HAVING total_bytes > 50000000 ORDER BY total_bytes DESC
```

## final-correlative-analysis
<!-- Final correlative analysis -->
```agent target=hunter
cite: required
context:
- weigh-external-exposure
- detect-anomalous-logins
- detect-phishing-interaction
- detect-data-exfiltration
max_iterations: 6
objective: Analyze the timing and nature of external breach reports against the internal
  behavioral anomalies (logins, phishing, exfiltration) to determine if a credential
  has been successfully weaponized.
success_criteria: A per-identity verdict of malicious | suspicious | benign citing
  rows from internal and external phases.
tools:
- endpoint
- haveibeenpwned
- hudsonrock
- identity
- network
- web
```

## route-by-verdict
<!-- Route by verdict -->
if~: "the final correlative analysis verdict is malicious for at least one account" (confidence: high, judge=hunter)
then: → remediate-compromised-accounts
indeterminate: → analyst-impact-review
unavailable: → analyst-impact-review (blind_spot: mfa-telemetry-gap)
else: → close-out-and-tune

## remediate-compromised-accounts
<!-- Remediate compromised accounts -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active sessions and OAuth tokens for the malicious identities. Force a password reset and verify current MFA enrollment status for any unauthorized methods added during the period of compromise.
```
→ analyst-impact-review

## analyst-impact-review
<!-- Analyst impact review -->
```manual target=analyst
Review the data exfiltration and phishing interaction results for the compromised accounts. Pivot to hb_cloud_api_activity to determine which sensitive files or resources were accessed during the anomalous sessions identified by the hunt.
```
→ close-out-and-tune

## close-out-and-tune
<!-- Close out and tune -->
```manual target=analyst
Document the identities remediated and any malicious infrastructure found. Update internal blocklists with source IPs from anomalous logins and refine the corporate domain monitoring in external intel providers.
```
→ end

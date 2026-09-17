---
analysis: While static rules can catch '10 failures from 1 IP', this hunt uses prevalence
  to find the 'one success' from an IP that was recently failing against others, or
  a success for a user from an IP they have never used before. This contextual correlation
  across many users is beyond the scope of single-event detection rules.
blind_spots:
- id: incomplete-mfa-reporting
  question: Was a login successful because MFA was bypassed or because a stolen token
    was used?
  requires: Reliable MFA success/failure reporting across all providers in hb_auth_signin
  risk: If the provider (e.g., AWS, M365) does not consistently populate the 'mfa'
    column, we cannot distinguish between a successful AitM token-use and a weak-password
    success.
  stage: initial-access-phishing-aitm
- id: vpn-exit-node-masking
  question: Is the anomalous IP a legitimate residential IP or a known commercial
    VPN exit node?
  requires: External IP reputation data (e.g., VPN/Proxy/Tor exit lists)
  risk: Sophisticated adversaries use residential proxies; simple analysts might dismiss
    'rare' IPs that are actually attacker proxies.
  stage: credential-access-remote-auth-attacks
coverage:
- stage: initial-access-phishing-aitm
  status: covered
  steps:
  - rare-ip-success-baseline
  - multi-ip-user-activity
  - triage-auth-events
- stage: credential-access-remote-auth-attacks
  status: covered
  steps:
  - password-spraying-detection
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: execution-infostealer-malware
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: credential-access-local-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: command-and-control-proxying
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: impact-ransomware-bec
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Credential theft accounts for 7 in 10 data breaches. Organizations
    without a dedicated identity security function are highly exposed to 'front door'
    entries where adversaries impersonate valid users. A negative result on this hunt
    confirms that current authentication patterns appear consistent with authorized
    behavior.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is attempting to gain initial access via password spraying
  or is using stolen session tokens (AitM) which manifest as successful logins from
  rare, non-resident source IPs and unusual multi-IP patterns for individual users.
labels:
- hunt
- attack.t1566
- attack.t1078
- attack.t1110.003
- attack.t1110.004
- attack.t1110
name: Identity and Authentication Anomalies
parameters:
  lookback_days:
    default: '14'
    description: Days of authentication history to examine for baselining and anomaly
      detection.
    type: number
  spraying_threshold:
    default: '5'
    description: Number of unique accounts a single IP must fail against to be flagged
      as a spraying attempt.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/credential-theft-expanding-your-reach
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should start with active identities, particularly those lacking
  MFA (based on hb_users). The auth signal analysis focuses on the last 14 days to
  identify new source IPs that deviate from a user's established pattern.
references:
- name: "Huntress \u2014 Credential Theft: How Attackers Steal & Use Stolen Credentials"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: credential-access-local-dumping
  reason: If an authentication anomaly is confirmed, the next logical step is to check
    if that account was used to perform local credential dumping on accessed endpoints.
  relation: follows
- hunt: execution-infostealer-malware
  reason: This hunt looks at the result (stolen auth); detecting the infostealer itself
    requires endpoint process/file monitoring which is handled by a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and Adversary-in-the-Middle
    observables:
    - Fake login pages masquerading as Docusign
    - Interception of authentication tokens and session cookies
    - Logins from unfamiliar locations
    - Impossible travel (same account from two distant locations in minutes)
    slug: initial-access-phishing-aitm
    tactic: initial-access
    techniques:
    - T1566
    - T1078
  - name: Infostealer Execution
    observables:
    - Malware collecting saved passwords, cookies, and autofill data
    - Browser profile directory access
    - Fake downloads or malicious ads delivering payloads
    slug: execution-infostealer-malware
    tactic: execution
    techniques:
    - T1555
    - T1204.002
  - name: Local OS Credential Dumping
    observables:
    - Mimikatz used to pull password hashes from memory
    - Access to LSASS process memory
    - Use of comsvcs.dll for minidumping LSASS
    - Copying of Registry hives (SAM, SECURITY, SYSTEM)
    - Extraction of Active Directory files containing hashes
    slug: credential-access-local-dumping
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  - name: Remote Authentication Attacks
    observables:
    - Spikes in failed login attempts
    - Password spraying across many accounts using common passwords
    - Credential stuffing using leaked username/password pairs
    slug: credential-access-remote-auth-attacks
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110.004
    - T1110
  - name: Obfuscated Command and Control
    observables:
    - Multi-hop proxies
    - Tor network traffic
    - Use of Operational Relay Boxes (ORB)
    slug: command-and-control-proxying
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Final Impact Activities
    observables:
    - Ransomware notes
    - Mass file encryption
    - Redirection of invoices or wire transfers via compromised email
    slug: impact-ransomware-bec
    tactic: impact
    techniques:
    - T1486
  summary: This campaign describes the lifecycle of credential theft, where attackers
    gain initial access via phishing or infostealers to harvest valid credentials.
    These credentials are then used for lateral movement, privilege escalation, and
    business email compromise, often culminating in ransomware or significant data
    breaches.
series:
  index: 1
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  total: 3
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
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


# Identity and Authentication Anomalies

This hunt focuses on the 'front door' of the organization. By analyzing high-volume authentication logs from hb_auth_signin, we look for two distinct signals: the broad, noisy pattern of password spraying where one IP hits many accounts, and the quiet, high-risk pattern of Adversary-in-the-Middle (AitM) where a user's session is hijacked, resulting in successful logins from source IPs never before seen for that specific identity. The hunt baselines what 'normal' source IPs look like per user and highlights deviations that coincide with unusual User-Agent strings or impossible velocity patterns.

## scoping-vulnerable-accounts
<!-- Identify active accounts with MFA gaps -->
Establish a scope of users who are most vulnerable to simple credential theft or lack phishing-resistant MFA reporting.

```sqlite target=identity role=scoping
~~~yaml
expected: A list of users who are higher-risk targets for spraying or whose MFA status
  cannot be verified, prioritizing their auth events in later steps.
reads:
- id
- name
- email
- provider
- mfa_enabled
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT id, name, email, provider, mfa_enabled FROM hb_users WHERE status = 'active' AND (mfa_enabled = 'false' OR mfa_enabled IS NULL)
```

## investigation-parallel
<!-- Analyze authentication behavior from multiple angles -->
parallel:
- → password-spraying-detection
- → rare-ip-success-baseline
- → multi-ip-user-activity
join: → triage-auth-events

## password-spraying-detection
<!-- Password spraying detection (failures across users) -->
Identify source IPs attempting to guess passwords for multiple different accounts.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, spraying_threshold=spraying_threshold)
~~~yaml
expected: One or more source IPs with a high unique account count, indicating a programmatic
  spray attempt. Silence indicates no broad brute-force detected.
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
- provider
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT src_endpoint_ip, provider, COUNT(DISTINCT actor_user_name) AS unique_accounts_targeted, COUNT(*) AS failure_total, MIN(time) AS first_fail, MAX(time) AS last_fail FROM hb_auth_signin WHERE status_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, provider HAVING unique_accounts_targeted >= {{spraying_threshold}} ORDER BY unique_accounts_targeted DESC
```

## rare-ip-success-baseline
<!-- Baseline successful logins by source IP -->
Highlight successful logins from IPs that are not part of the common fleet or user-specific history.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of successful logins from IPs that do not have a large footprint
  in the organization, potentially indicating session hijacking or stolen credential
  use.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT src_endpoint_ip, actor_user_name, COUNT(*) AS success_count, MIN(time) AS first_success FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name HAVING success_count < 10
```

## multi-ip-user-activity
<!-- High velocity user logins (Multiple IPs) -->
Detect users authenticating from multiple distinct IP addresses within the window, a proxy for AitM or impossible travel.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Accounts logging in from 3 or more distinct IP addresses, which should be
  manually correlated with known user travel or VPN usage.
reads:
- actor_user_name
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT actor_user_name, COUNT(DISTINCT src_endpoint_ip) AS distinct_ips, GROUP_CONCAT(DISTINCT src_endpoint_ip) AS ip_list, MIN(time) AS window_start, MAX(time) AS window_end FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name HAVING distinct_ips > 2 ORDER BY distinct_ips DESC
```

## triage-auth-events
<!-- Triage authentication anomalies -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-accounts
- password-spraying-detection
- rare-ip-success-baseline
- multi-ip-user-activity
max_iterations: 3
objective: Determine if any successful logins (rare IPs or multi-IP users) were preceded
  by spraying from the same IP, or if the multi-IP usage suggests session theft.
success_criteria: Verdicts citing specific actor_user_name and src_endpoint_ip rows
  with malicious/suspicious/benign status.
tools:
- identity
```

## route-auth-verdict
<!-- Route on authentication verdict -->
if~: "The triage verdict is 'malicious' for at least one account showing successful login from a spraying or anomalous IP" (confidence: high, judge=hunter)
then: → action-revoke-sessions
indeterminate: → task-analyst-review
unavailable: → task-analyst-review (blind_spot: incomplete-mfa-reporting)
else: → task-analyst-review

## action-revoke-sessions
<!-- Revoke active user sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active OIDC/SAML sessions for the identified accounts and force a password reset.
```
→ task-analyst-review

## task-analyst-review
<!-- Perform detailed identity audit -->
```manual target=analyst
Contact the affected users to verify their recent sign-in locations. Audit secondary logs (like hb_http_activity) for unusual User-Agents or request patterns from the same IPs.
```
→ task-close

## task-close
<!-- Close out hunt -->
```manual target=analyst
Summarize the number of accounts compromised vs false positives. Update any known-good static IP lists if necessary.
```
→ end

---
analysis: A simple detection rule flags volume-based failure spikes; this hunt correlates
  those spikes with successful logons, user IP diversity, and sensitive system access
  to find the low signal takeover that volume rules miss.
blind_spots:
- id: missing-auth-telemetry
  owner: Cloud Operations
  question: whether the attacker successfully logged into an application not covered
    by the current log ingestion
  remediation: Integrate all business-critical SaaS platforms into the centralized
    identity provider or SIEM.
  requires: Unified logging (hb_auth_signin) for all critical SaaS and cloud providers.
  risk: A successful takeover of a standalone SaaS account using stolen credentials
    would be invisible.
  stage: external-auth-spraying
- id: unreliable-session-context
  owner: Identity Engineering
  question: whether a successful logon used a password or a stolen session cookie
  remediation: Enable advanced identity logging to capture session token usage details.
  requires: Authentication logs that distinguish between password-based and token-based
    logins.
  risk: The hunt may misinterpret session reuse as a legitimate return visit if auth_protocol
    metadata is missing.
  stage: account-takeover-anomalies
coverage:
- stage: external-auth-spraying
  status: covered
  steps:
  - detect-spraying-and-stuffing
- stage: credential-stuffing-attempts
  status: covered
  steps:
  - detect-spraying-and-stuffing
- stage: account-takeover-anomalies
  status: covered
  steps:
  - detect-anomalous-successful-logons
  - triage-identity-abuse
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: infostealer-browser-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: lsass-memory-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: registry-hive-extraction
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Credential-based attacks start 70 percent of breaches and bypass
    traditional firewalls. Monitoring the authentication plane is essential for identifying
    intruders who appear as authorized users.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is testing passwords against identity providers to gain initial
  access or using stolen session tokens to bypass MFA and access internal resources.
labels:
- hunt
- attack.t1110.003
- attack.t1110.004
- attack.t1078
- attack.t1090.003
- attack.t1110
name: Identity Authentication and Account Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication patterns.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: hunt-designer
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the scoping step to focus the authentication
      analysis.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: hunt-designer
    type: list[host]
  spray_threshold:
    default: '10'
    description: Minimum number of unique accounts targeted by a single source IP
      to qualify as spraying.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: hunt-designer
    type: number
  suspicious_ips:
    default: []
    description: Known-malicious or suspicious IPs from external intelligence to prioritize.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: hunt-designer
    type: list[ip]
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
rationale: Focus on high-value identity infrastructure such as domain controllers,
  AD FS servers, and cloud identity proxies. Widen the lookback to 30 days if slow-and-low
  spraying is suspected.
references:
- name: "Huntress \u2014 Credential Theft: How Attackers Steal & Use Stolen Credentials"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: lsass-memory-dumping-on-endpoints
  reason: This hunt focuses on the use of stolen credentials; the endpoint-based dumping
    of those credentials is a separate behavioral stage.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Password Spraying and Brute Force
    observables:
    - Single common password tested against many accounts
    - Iterative password guessing against a single account
    - Spikes in authentication failures (activity_id 5)
    - Logins from unfamiliar IP addresses or geographic locations
    slug: external-auth-spraying
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110
  - name: Credential Stuffing
    observables:
    - Authentication attempts using username/password pairs leaked in previous third-party
      breaches
    - High volume of failed login attempts across diverse accounts
    slug: credential-stuffing-attempts
    tactic: credential-access
    techniques:
    - T1110.004
  - name: Infostealer Data Collection
    observables:
    - Access to browser profile directories (e.g., AppData\Local\Google\Chrome\User
      Data)
    - Reading of 'Cookies' and 'Login Data' SQLite databases
    - Exfiltration of harvested credentials to external C2 nodes
    - Processes running from Temp or Downloads directories
    slug: infostealer-browser-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: LSASS Credential Dumping
    observables:
    - procdump -ma lsass.exe
    - rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
    - Execution of Mimikatz or similar tools
    - Creation of .dmp files containing LSASS memory
    slug: lsass-memory-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Registry Hive Extraction
    observables:
    - reg.exe save HKLM\SAM
    - reg.exe save HKLM\SYSTEM
    - reg.exe save HKLM\SECURITY
    - esentutl.exe /y /vss /d
    - Access to %SystemRoot%\System32\config
    slug: registry-hive-extraction
    tactic: credential-access
    techniques:
    - T1003
  - name: Valid Account Abuse and Impossible Travel
    observables:
    - Impossible travel (logins from distant locations in rapid succession)
    - Logins that bypass MFA using stolen session tokens
    - Unauthorized privilege changes or administrative role assignments
    - MFA enrollments for new/unrecognized devices
    slug: account-takeover-anomalies
    tactic: initial-access
    techniques:
    - T1078
  summary: This campaign involves the unauthorized acquisition of credentials via
    phishing, brute force, and infostealers to impersonate legitimate users. Attackers
    then perform credential dumping on compromised endpoints to harvest cached passwords
    and hashes, enabling lateral movement and full account takeover.
series:
  index: 1
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
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


# Identity Authentication and Account Abuse

This hunt examines the authentication plane for signs of high-volume credential testing and subsequent account takeover. It starts by identifying hosts running identity-related software or browsers to scope the estate, then analyzes authentication failures for spraying patterns and successful logons for anomalous behavior, such as multiple source IPs per user or access to sensitive systems. An agent triages the combined evidence to distinguish legitimate remote access from active compromise.

## identify-identity-assets
<!-- Identify identity-sensitive assets -->
Locate hosts running Active Directory components, domain services, or common browsers where credentials may be dumped or used.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. These are the assets where credential-based lateral
  movement is most impactful. Use these to fill the scope_hosts parameter.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%active directory%' OR LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%edge%'
```

## analyze-auth-parallel
<!-- Analyze authentication behavior -->
parallel:
- → detect-spraying-and-stuffing
- → detect-anomalous-successful-logons
join: → triage-identity-abuse

## detect-spraying-and-stuffing
<!-- Detect credential spraying and stuffing -->
Identify source IPs that target a high volume of accounts with failed authentication attempts.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, spray_threshold=spray_threshold, suspicious_ips=suspicious_ips)
~~~yaml
expected: Source IPs hitting many unique usernames. A high unique_account count suggests
  spraying; high failure counts against a single user suggest brute force.
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_accounts, COUNT(*) AS total_failures, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 2 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{suspicious_ips}}' = '' OR instr(',' || '{{suspicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) GROUP BY src_endpoint_ip HAVING unique_accounts >= {{spray_threshold}}
```

## detect-anomalous-successful-logons
<!-- Detect anomalous successful logons -->
Find successful logons that deviate from normal patterns, particularly targeting assets identified in scoping.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Successful logons to sensitive hosts or users with high source IP diversity.
  Cross-referencing these source IPs with the spraying results reveals account takeover.
prevalence:
  by: src_endpoint_ip
  key:
  - actor_user_name
  rare_below: 3
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, COUNT(*) AS login_count, MIN(time) AS first_login FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name ORDER BY login_count DESC
```

## triage-identity-abuse
<!-- Triage identity abuse -->
```agent target=hunter
cite: required
context:
- identify-identity-assets
- detect-spraying-and-stuffing
- detect-anomalous-successful-logons
max_iterations: 5
objective: Determine if any successful logons were preceded by spraying from the same
  IP, or if users exhibit impossible travel or access to sensitive scoped hosts from
  suspicious origins.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  actor, citing specific rows.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-identity-abuse verdict is malicious for at least one user" (confidence: high, judge=hunter)
then: → isolate-compromised-identity
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: missing-auth-telemetry)
else: → remediation-and-closeout

## isolate-compromised-identity
<!-- Isolate compromised identity -->
```action target=identity
~~~yaml
approval: required
~~~
Suspend the identified user account in the identity provider and revoke all active session tokens to invalidate any stolen cookies.
```
→ manual-review

## manual-review
<!-- Manual review -->
```manual target=analyst
Review the successful logons for malicious users. Examine process and file activity on the targeted hosts (scope_hosts) originating from those users to identify lateral movement or data staging.
```
→ remediation-and-closeout

## remediation-and-closeout
<!-- Remediation and closeout -->
```manual target=analyst
Document the findings and IPs. Identify any accounts that successfully authenticated without MFA and coordinate with the identity team to enforce phishing-resistant MFA controls.
```
→ end

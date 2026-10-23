---
analysis: A standard rule flags MFA failures; this hunt correlates those failures
  with known vulnerable beachheads and subsequent rare cloud API actions, providing
  the cross-surface context a single rule lacks.
blind_spots:
- id: no-cloud-telemetry
  question: whether the attacker accessed a cloud tenant not enrolled in monitoring
  requires: hb_cloud_api_activity
  risk: Identity abuse in unmonitored tenants will be invisible, leaving a persistence
    gap.
  stage: initial-access-and-identity-compromise
- id: mfa-success-correlation
  question: did an MFA fatigue burst end with a successful authentication
  requires: OCSF status_detail for sign-ins
  risk: Without success correlation, we may miss the moment the user finally approved
    a fraudulent request.
  stage: initial-access-and-identity-compromise
coverage:
- stage: initial-access-and-identity-compromise
  status: covered
  steps:
  - find-vulnerable-hosts
  - check-mfa-fatigue
  - rare-cloud-credential-ops
- reason: Covered by the LotL execution hunt in this series.
  stage: native-execution-via-powershell-and-wmi
  status: out_of_scope
- reason: Covered by the Lolbins hunt in this series.
  stage: stealthy-proxy-execution-lolbins
  status: out_of_scope
- reason: Requires network flow bytes or specialized SaaS data-access logs not examined
    here.
  stage: data-theft-and-exfiltration
  status: not_visible
- reason: Belongs to another part of the '10 Endpoint Security Trends and Tips for
    2027 | Huntress' series.
  stage: ransomware-impact-and-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Identity is the new perimeter; protecting credentials is as critical
    as protecting local files. This hunt detects the bridge from endpoint vulnerability
    to cloud compromise, addressing the high-risk trends of phished credentials and
    token theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via phished credentials or a public-facing
  vulnerability and is now attempting to abuse cloud identities, evidenced by MFA
  fatigue patterns and rare credential-related API operations.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1190
- attack.t1041
- defense evasion
- execution
- exfiltration
- impact
- initial access
name: Identity and Cloud Access Monitoring
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication failures and API calls.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: incident-standard-window
    type: number
  mfa_failure_threshold:
    default: '15'
    description: Minimum authentication failures per user/IP to flag as a potential
      MFA fatigue attempt.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-baseline
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the search; leave empty for the
      entire estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/endpoint-security-trends
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt uses critical vulnerabilities joined with internet-exposed asset
  data as the primary scoping lead. If the estate has a strong patching posture, widen
  the scope to include medium-severity vulnerabilities.
references:
- name: "Huntress \u2014 10 Endpoint Security Trends and Tips for 2027"
  url: https://www.huntress.com/blog/endpoint-security-trends
related:
- hunt: powershell-wmi-lotl-execution
  reason: This hunt focuses on identity compromise; the subsequent LotL endpoint execution
    is handled in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access and Identity Compromise
    observables:
    - Phished credentials
    - Abuse of remote management tools (RMM)
    - Exploitation of internet-facing vulnerabilities
    - Compromised API keys and service tokens
    - MFA fatigue (repeated authentication failures/requests)
    slug: initial-access-and-identity-compromise
    tactic: initial-access
    techniques:
    - T1566
    - T1195
    - T1190
  - name: Native Execution via PowerShell and WMI
    observables:
    - Unusual PowerShell scripts launched by non-admin users
    - WMI commands for remote execution or persistence
    - Execution of commands via wmic.exe or scrcons.exe
    slug: native-execution-via-powershell-and-wmi
    tactic: execution
    techniques:
    - T1059.001
    - T1047
  - name: Stealthy Proxy Execution (LOLBins)
    observables:
    - Signed Windows binaries (LOLBins) used for malicious execution
    - Subtle clues like unusual command-line arguments for trusted utilities
    slug: stealthy-proxy-execution-lolbins
    tactic: defense-evasion
    techniques:
    - T1218
  - name: Data Theft and Exfiltration
    observables:
    - Staging of data in temp directories
    - High-volume outbound network traffic to unrecognized IPs
    - Connections from IoT/OT devices to critical assets
    slug: data-theft-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Impact and Encryption
    observables:
    - Massive file renaming or extension changes (e.g., .encrypted, .ransom)
    - Rapid modification/deletion of files across shares
    slug: ransomware-impact-and-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Attackers utilize phishing, supply-chain compromise, or the exploitation
    of public-facing applications to gain a foothold before pivoting to identity-based
    attacks like MFA fatigue. Once inside, they move laterally and execute commands
    using native tools like PowerShell and WMI to avoid detection, eventually culminating
    in data exfiltration and multi-layered ransomware extortion.
series:
  index: 1
  slug: 10-endpoint-security-trends-and-tips-for-2027-huntress
  title: 10 Endpoint Security Trends and Tips for 2027 | Huntress
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


# Identity and Cloud Access Monitoring

This hunt centers on the article's focus on identity as the new perimeter. It identifies vulnerable entry points and correlates them with identity-based attacks. By monitoring for MFA fatigue (high-frequency sign-in failures) alongside rare cloud credential manipulations, the hunt finds attackers who have pivoted from endpoint compromise to cloud account takeover. The hunt flows through a scoping step for vulnerable assets, a fan-out of behavioral queries on authentication and cloud logs, and a final agent-led triage to confirm the compromise.

## find-vulnerable-hosts
<!-- Find vulnerable beachheads -->
Identify hosts with critical vulnerabilities that serve as likely entry points, prioritizing those with an active external exposure.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with unpatched critical vulnerabilities that are also exposed
  to the internet. Silence indicates no such high-risk vulnerabilities are currently
  indexed.
reads:
- device_uid
- cve_uid
- title
- severity_id
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT v.device_uid, d.hostname, v.cve_uid, v.title, e.ip_address FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid JOIN hb_exposed_assets e ON d.ip_address = e.ip_address WHERE v.severity_id >= 4 AND v.status != 'suppressed' AND (LOWER(v.title) LIKE '%remote%' OR LOWER(v.title) LIKE '%execution%' OR LOWER(v.title) LIKE '%bypass%')
```

## correlate-identity-evidence
<!-- Correlate identity signals -->
parallel:
- → check-mfa-fatigue
- → rare-cloud-credential-ops
join: → identity-triage-agent

## check-mfa-fatigue
<!-- Monitor for MFA fatigue -->
Find users experiencing high volumes of sign-in failures, indicating an attacker attempting to bypass MFA via exhaustion.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, mfa_failure_threshold=mfa_failure_threshold, scope_hosts=scope_hosts)
~~~yaml
expected: Specific users or source IPs with failure counts above the threshold. Silence
  means no fatigue pattern was detected.
reads:
- actor_user_name
- src_endpoint_ip
- device_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT actor_user_name, src_endpoint_ip, device_hostname, COUNT(*) as failures, MIN(time) as first_attempt, MAX(time) as last_attempt FROM hb_auth_signin WHERE activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || LOWER(device_hostname) || ',') > 0) GROUP BY actor_user_name, src_endpoint_ip, device_hostname HAVING failures >= {{mfa_failure_threshold}} ORDER BY failures DESC
```

## rare-cloud-credential-ops
<!-- Rare cloud credential manipulation -->
Find unusual API operations that create or update cloud identities and tokens, which suggests post-compromise persistence.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Low-frequency API calls that modify access controls or credentials. Silence
  means no unusual credential changes were seen.
prevalence:
  by: cloud_account_uid
  key:
  - api_operation
  - actor_user_name
  rare_below: 3
reads:
- api_operation
- actor_user_name
- cloud_account_uid
- src_endpoint_ip
- activity_id
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT api_operation, actor_user_name, cloud_account_uid, src_endpoint_ip, COUNT(*) as call_count, MIN(time) as first_seen FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%accesskey%' OR LOWER(api_operation) LIKE '%token%' OR LOWER(api_operation) LIKE '%policy%') AND activity_id IN (1, 3) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY api_operation, actor_user_name, cloud_account_uid, src_endpoint_ip HAVING call_count < 10 ORDER BY call_count ASC
```

## identity-triage-agent
<!-- Triage identity compromise risk -->
```agent target=hunter
cite: required
context:
- find-vulnerable-hosts
- check-mfa-fatigue
- rare-cloud-credential-ops
max_iterations: 6
objective: Determine if the pattern of MFA failures and rare cloud API calls indicates
  a successful identity takeover. Explicitly correlate the src_endpoint_ip from the
  MFA fatigue step with the network-accessible IPs of the vulnerable hosts found in
  the scoping step.
success_criteria: A verdict of malicious | suspicious | benign per host or user, citing
  specific rows for failures and API operations.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route based on risk -->
if~: "the identity-triage-agent verdict is malicious for at least one host or user" (confidence: high, judge=hunter)
then: → contain-and-revoke
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: no-cloud-telemetry)
else: → close-out-hunt

## contain-and-revoke
<!-- Contain and revoke -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host identified in the triage. Revoke any cloud API keys, tokens, or sessions associated with the affected user that were created or active during the suspected compromise window.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the rows cited by the triage agent. Audit all cloud API activity for the affected user over the lookback period to ensure no persistent backdoors (like new IAM roles or S3 bucket policies) were added.
```
→ close-out-hunt

## close-out-hunt
<!-- Hunt close out -->
```manual target=analyst
Document the findings and true positive rate. If the MFA fatigue query produced excessive noise, consider raising the threshold.
```
→ end

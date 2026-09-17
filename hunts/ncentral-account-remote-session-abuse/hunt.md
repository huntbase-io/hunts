---
analysis: A simple rule for 'MSP Support' logins would trigger hundreds of false positives.
  This hunt stack-counts the source IPs, correlates them with suspicious '.invalid'
  identity patterns, and looks for the 'smash-and-grab' process enumeration behavior
  that follows unauthenticated access, providing a contextual triage that a static
  rule cannot achieve.
blind_spots:
- id: appliance-log-rotation
  question: What specifically occurred on the appliance prior to logs rotating?
  remediation: Stream N-central appliance syslogs to a centralized repository with
    longer retention.
  requires: Persistent logging on the N-central appliance
  risk: Attackers often perform reconnaissance or exploit attempts that rotate the
    internal logs of the appliance, making forensic reconstruction impossible without
    real-time streaming to a SIEM.
  stage: account-manipulation
- id: mfa-bypass-visibility
  question: Was MFA explicitly bypassed or was a session token stolen?
  remediation: Ensure MFA logs are correlated with RMM session starts.
  requires: hb_auth_signin (mfa column)
  risk: The hunt may see a successful login but cannot determine if a session was
    hijacked versus an unauthenticated exploit being used to bypass the login logic
    entirely.
  stage: account-manipulation
coverage:
- stage: account-manipulation
  status: covered
  steps:
  - suspicious-signins
  - anomalous-user-inventory
- stage: rmm-take-control-abuse
  status: covered
  steps:
  - suspicious-signins
  - msp-support-ip-stack
  - rapid-process-enumeration
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: vulnerability-exposure
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: web-reconnaissance-api
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: cloudflare-tunnel-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: dropped-payload-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of N-central (CVE-2026-18556) provides 'god-mode' access
    to the RMM console, which can lead to mass deployment of ransomware or data exfiltration
    across an entire managed estate. Negative confirmation of account and session
    abuse is critical for RMM operators.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited N-central vulnerabilities to create backdoored
  accounts (often with '.invalid' suffixes) and is using the 'MSP Support' default
  account from unauthorized IPs to perform process enumeration and lateral movement.
labels:
- hunt
- attack.t1133
- attack.t1078
- attack.t1087
name: N-able N-central Account and Remote Session Abuse
parameters:
  intruder_ips:
    default:
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    description: Known malicious intruder IPs associated with N-central exploitation.
    from:
      kind: article
      observed: '2026-09-06'
      ref: huntress
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-06'
      ref: default
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/n-able-vulnerability-exploitation
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus specifically on hosts where N-central management software is detected.
  If the fleet is large, prioritize Domain Controllers and servers as the report indicates
  these are high-priority targets for attackers after gaining initial RMM access.
references:
- name: "Huntress \u2014 Critical N-able N-central Vulnerability and Active Exploitation"
  url: https://www.huntress.com/blog/n-able-vulnerability-exploitation
related:
- hunt: ncentral-vulnerability-exposure-api-recon
  reason: The initial vulnerability exposure and web-level API reconnaissance are
    handled in the first hunt of this series.
  relation: precedes
- hunt: ncentral-post-exploitation-persistence
  reason: Detection of Cloudflare tunnels and dropped payloads (svchost.exe in User
    docs) is handled in the third hunt of this series.
  relation: follows
- hunt: n-central-web-exploitation-api-probing
  relation: follows
scenario:
  stages:
  - name: N-central Vulnerability Exposure
    observables:
    - CVE-2026-18556
    - CVE-2026-18577
    - CVE-2026-86206
    - CVE-2026-86207
    - CVE-2026-86218
    - N-central versions < 2026.3 HF4
    slug: vulnerability-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Web Reconnaissance and API Probing
    observables:
    - /remoteControlAction.do?method=getPierDetails
    - '%2F URL-encoded internal API routes'
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    slug: web-reconnaissance-api
    tactic: initial-access
    techniques:
    - T1190
  - name: Account Manipulation and Creation
    observables:
    - Accounts appended with '.invalid' (e.g., user@domain.com.invalid)
    - Subtle character swaps in email addresses
    - Login as 'MSP Support'
    slug: account-manipulation
    tactic: persistence
    techniques:
    - T1133
  - name: RMM Take Control Feature Abuse
    observables:
    - MSP Support logins from 173.249.252.200
    - RMM Take Control sessions starting and ending quickly
    - Process list enumeration requests
    slug: rmm-take-control-abuse
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Cloudflare Tunnel Persistence
    observables:
    - Service named 'Cloudflared'
    - Cloudflare tunnel account tag 5568cd69c754b392121f1dbb8f900fda
    slug: cloudflare-tunnel-persistence
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: Malicious Payload Execution
    observables:
    - svchost.exe located in Documents folder
    slug: dropped-payload-execution
    tactic: execution
    techniques:
    - T1190
  summary: Attackers exploit critical vulnerabilities in N-able N-central RMM to achieve
    unauthenticated 'god-mode' access. Following exploitation, they manipulate accounts,
    abuse built-in remote control features for lateral movement, and establish persistence
    via Cloudflare tunnels.
series:
  index: 2
  slug: critical-n-able-n-central-vulnerability-and-active-exploitation
  title: Critical N-able N-central Vulnerability and Active Exploitation
  total: 3
severity: critical
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


# N-able N-central Account and Remote Session Abuse

This hunt focuses on the post-exploitation phase of N-central vulnerabilities (CVE-2026-18556, CVE-2026-86218). It targets two primary behaviors: account manipulation (creation of spoofed or modified admin accounts) and the abuse of the 'Take Control' feature via the default 'MSP Support' account. We investigate sign-in anomalies, stack-count source IPs for administrative logons, and correlate these with rapid process enumeration on the target endpoints.

## scope-rmm-footprint
<!-- Identify N-central management footprint -->
Find hosts where N-central or RMM-related software is installed to narrow the hunt scope.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely serving as N-central nodes or running N-able agents.
  Silence suggests no N-central presence within the captured inventory.
reads:
- asset_scope
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%n-central%' OR LOWER(vendor_name) LIKE '%n-able%') AND asset_scope = 'endpoint'
```

## suspicious-signins
<!-- Suspicious RMM and Manipulated Account Logins -->
Find logins using the default 'MSP Support' account or accounts with the '.invalid' suffix pattern seen in recent campaigns.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Logins from 'MSP Support' or accounts containing '.invalid'. While 'MSP
  Support' is a legitimate default, its use from unusual IPs is highly suspicious.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- status
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT time, actor_user_name, src_endpoint_ip, dst_endpoint_name, auth_protocol, status FROM hb_auth_signin WHERE (LOWER(actor_user_name) = 'msp support' OR LOWER(actor_user_name) LIKE '%.invalid%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate Account Abuse and Session Activity -->
parallel:
- → msp-support-ip-stack
- → rapid-process-enumeration
- → anomalous-user-inventory
join: → triage-rmm-abuse

## msp-support-ip-stack
<!-- Prevalence of 'MSP Support' source IPs -->
Identify rare or known-malicious IPs logging in as the default 'MSP Support' user.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare source IP (host_count < 3) or one matching the intruder IP list is
  a high-confidence indicator of abuse.
prevalence:
  by: dst_endpoint_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- dst_endpoint_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT dst_endpoint_name) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE LOWER(actor_user_name) = 'msp support' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip ORDER BY host_count ASC
```

## rapid-process-enumeration
<!-- Rapid Process Enumeration Activity -->
Identify hosts running process enumeration tools (tasklist, Get-Process) which attackers use immediately after gaining access via N-central.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Frequent or unauthorized process enumeration commands, especially if the
  user context matches 'MSP Support' or an account created recently.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT time, device_hostname, process_name, process_cmd_line, user_name FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%tasklist.exe%' OR LOWER(process_cmd_line) LIKE '%get-process%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## anomalous-user-inventory
<!-- Identify Anomalous Accounts in Identity Stores -->
Audit user directories for accounts that match the '.invalid' suffix pattern or other unexpected manipulations.

```sqlite target=identity role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Accounts created in the last 14 days with '.invalid' suffixes. These are
  highly indicative of the persistence method described in the report.
reads:
- created_at
- email
- name
- provider
- status
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT name, email, provider, status, created_at FROM hb_users WHERE (LOWER(email) LIKE '%.invalid%' OR LOWER(name) LIKE '%.invalid%') AND created_at >= datetime('now', '-{{lookback_days}} days')
```

## triage-rmm-abuse
<!-- Triage N-central Session and Account Abuse -->
```agent target=hunter
cite: required
context:
- suspicious-signins
- msp-support-ip-stack
- rapid-process-enumeration
- anomalous-user-inventory
max_iterations: 4
objective: Review the sign-in events (especially 'MSP Support' or '.invalid'), the
  stack of source IPs, the existence of manipulated user accounts, and any correlated
  process enumeration. Determine if these actions align with the reported N-central
  exploit tradecraft.
success_criteria: A per-account/per-host verdict citing the specific IP addresses
  and process command lines observed.
tools:
- endpoint
- identity
```

## route-verdict
<!-- Route based on Triage Verdict -->
if~: "the triage-rmm-abuse verdict is 'malicious' for any host or user" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: appliance-log-rotation)
else: → close-out

## isolate-and-remediate
<!-- Isolate Endpoint and Disable Accounts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host where 'MSP Support' logins from intruder IPs were confirmed. Disable any user accounts identified with the '.invalid' suffix and revoke their sessions in the identity provider.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the 'envoy_proxy_HTTPS.log' and 'syslog ncentraldms' on the N-central appliance for corresponding API manipulation. Confirm that no other persistence mechanisms (like Cloudflare tunnels) were established during the session.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Record the absence of 'MSP Support' abuse. If '.invalid' accounts were found but appeared benign (rare), consider tuning the detection candidate for a standing rule.
```
→ end

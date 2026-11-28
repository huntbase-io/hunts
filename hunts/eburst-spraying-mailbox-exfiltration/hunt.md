---
analysis: While a detection rule might alert on a single high-volume spray from an
  IP, this hunt correlates that spraying behavior across multiple distinct Exchange
  interfaces with follow-on cloud API operations against mailboxes, reducing noise
  and identifying the complete attack chain.
blind_spots:
- id: cloud-logging-limitations
  owner: Cloud Infrastructure Team
  question: Which specific email messages were read by the adversary?
  remediation: Enable 'MailItemsAccessed' auditing for all critical mailboxes.
  requires: Microsoft 365 Advanced Auditing (MailItemsAccessed)
  risk: Without Advanced Auditing, the API logs only show that a mailbox was accessed,
    not which specific items were viewed or exported, making it difficult to assess
    the exact impact of exfiltration.
  stage: collection-mailbox-exfiltration
- id: ip-masking-via-botnets
  owner: Security Engineering
  question: Is the spray originating from a known botnet or common VPN providers?
  remediation: Pivot to user-agent and ASN stacking if per-IP spraying metrics are
    low.
  requires: Source IP Geolocation and ASN context
  risk: If the adversary rotates IPs for every single login attempt, the per-IP unique
    user stack-count will fall below the detection threshold.
  stage: credential-access-eburst-spraying
coverage:
- stage: credential-access-eburst-spraying
  status: covered
  steps:
  - scoping-exchange-auth
  - ip-spray-detection
- stage: collection-mailbox-exfiltration
  status: covered
  steps:
  - mailbox-api-activity
- reason: Belongs to another part of the 'Chinese Government-linked Cyber Threat Actors
    Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data' series.
  stage: initial-access-vulnerability-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Chinese Government-linked Cyber Threat Actors
    Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data' series.
  stage: execution-malware-payload
  status: out_of_scope
- reason: Belongs to another part of the 'Chinese Government-linked Cyber Threat Actors
    Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data' series.
  stage: persistence-vpn-installation
  status: out_of_scope
- reason: Belongs to another part of the 'Chinese Government-linked Cyber Threat Actors
    Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data' series.
  stage: defence-evasion-masquerading
  status: out_of_scope
- reason: Belongs to another part of the 'Chinese Government-linked Cyber Threat Actors
    Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data' series.
  stage: command-and-control-obfuscated-channels
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Chinese state-linked actors are documented to use the EBurst tool
    to target critical infrastructure for credential theft and mailbox exfiltration.
    Identifying these campaigns before they reach full data exfiltration prevents
    significant intelligence loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is conducting automated password spraying via the EBurst
  tool against Exchange interfaces and then using successful logins to exfiltrate
  mailbox data via cloud APIs.
labels:
- hunt
- attack.t1110.003
- attack.t1110.001
- attack.t1041
- attack.t1190
- collection
- command and control
- credential access
- defense evasion
- execution
- initial access
- persistence
name: EBurst Password Spraying and Mailbox Exfiltration
parameters:
  exchange_interfaces:
    default:
    - ECP
    - EWS
    - OAB
    - OWA
    - RPC
    - API
    - MAPI
    - Autodiscover
    - ActiveSync
    description: Names of Exchange interfaces to monitor for password spraying.
    from:
      kind: article
      observed: '2026-10-08'
      ref: AA26-281A
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Exchange servers or endpoints identified in the scoping step to focus
      the hunt.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value identity targets and servers hosting publicly accessible
  Exchange interfaces (OWA, ActiveSync). Monitoring the Autodiscover service is critical
  as it is a common target for the EBurst tool.
references:
- name: CISA AA26-281A - Chinese Government-linked Cyber Threat Actors
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a
related:
- hunt: softether-vpn-persistence-detection
  reason: The same advisory identifies SoftEther VPN as a persistence mechanism used
    after credential theft.
  relation: sibling
- hunt: perimeter-exploitation-vpn-persistence
  relation: follows
scenario:
  stages:
  - name: Web and Service Exploitation
    observables:
    - BBScan
    - dirsearch
    - Fscan
    - ksubdomain
    - masscan
    - NMAP
    - OneForAll
    - ShuiZe
    - wpscan
    - MicroScan
    - XSS payloads targeting JavaScript
    - Exploits for CVE-2016-3081
    - Exploits for CVE-2019-11510
    - Exploits for CVE-2021-22205
    - Targeting ports 21, 22, 53, 80, 443, 1080
    - PHP/ASP enumeration
    slug: initial-access-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1189
  - name: Malware Execution
    observables:
    - live700_v1.exe
    - DiagTrack.exe
    - Python-based exploit scripts
    - Go-based exploit utilities
    - Password-protected .zip files containing executables
    slug: execution-malware-payload
    tactic: execution
    techniques:
    - T1059.006
    - T1059.007
    - T1059.001
  - name: VPN-based Persistence
    observables:
    - SoftEther VPN installers
    - conhost.exe (renamed installer)
    - dllhost.exe (renamed installer)
    - curl or wget used to download SoftEther on Linux
    - PowerShell used to download SoftEther on Windows
    - Automatic reconnection configuration on startup
    slug: persistence-vpn-installation
    tactic: persistence
    techniques:
    - T1133
  - name: Service and Process Masquerading
    observables:
    - DiagTrack.exe
    - conhost.exe
    - dllhost.exe
    slug: defence-evasion-masquerading
    tactic: defence-evasion
    techniques:
    - T1036.003
  - name: EBurst Password Spraying
    observables:
    - EBurst tool
    - Password spraying against ECP
    - Password spraying against EWS
    - Password spraying against OWA
    - Password spraying against ActiveSync
    - Password spraying against MAPI/RPC
    slug: credential-access-eburst-spraying
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110.001
  - name: Multi-protocol Command and Control
    observables:
    - dns.studiocloud.xyz
    - 98aiblog.com
    - hmbcloud.com
    - hmbcloud.net
    - hmbiplc-01.com
    - iepl.node.cm
    - javacheck.ooguy.com
    - javaupdate.giize.com
    - sexytube0.com
    - twimg.co.uk
    - HTTP-based C2 communications
    slug: command-and-control-obfuscated-channels
    tactic: command-and-control
    techniques:
    - T1071
  - name: Email Data Collection
    observables:
    - Querying user mailbox data via DiagTrack.exe
    slug: collection-mailbox-exfiltration
    tactic: collection
    techniques:
    - T1041
  summary: Chinese government-linked threat actors, enabled by Integrity Technology
    Group, use a combination of automated scanning tools like MicroScan and manual
    exploitation to target global organizations. They establish persistence using
    legitimate VPN software like SoftEther and perform large-scale password spraying
    with EBurst to exfiltrate sensitive email data and credentials.
series:
  index: 2
  slug: chinese-government-linked-cyber-threat-actors-combine-automated-and-hands-on-hacking-tools-to-st
  title: Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on
    Hacking Tools to Steal Sensitive Data
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


# EBurst Password Spraying and Mailbox Exfiltration

This hunt targets the identity-focused tradecraft of Chinese government-linked actors. It begins by identifying Exchange endpoints experiencing high authentication failure rates, then fans out to identify specific source IPs conducting distributed password sprays across multiple accounts. Finally, it correlates these IPs with unusual mailbox-related API activity in the cloud control plane to detect post-compromise data collection and exfiltration.

## scoping-exchange-auth
<!-- Scoping Exchange Auth Failures -->
Identify Exchange servers or endpoints experiencing an unusual volume of authentication failures to narrow the hunt scope. Note: Populate the scope_hosts parameter with the hostnames discovered here for use in the subsequent ip-spray-detection step.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, exchange_interfaces=exchange_interfaces)
~~~yaml
expected: A list of hosts acting as targets for auth failures. Silence suggests no
  broad spraying against Exchange targets is currently observable.
reads:
- device_hostname
- dst_endpoint_name
- logon_process_name
- service_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, COUNT(*) AS failure_count, MIN(time) AS first_fail, MAX(time) AS last_fail FROM hb_auth_signin WHERE status_id = 2 AND (instr(',' || '{{exchange_interfaces}}' || ',', ',' || UPPER(dst_endpoint_name) || ',') > 0 OR LOWER(service_name) LIKE '%exchange%' OR LOWER(logon_process_name) LIKE '%exchange%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING failure_count > 20 ORDER BY failure_count DESC
```

## correlate-activities
<!-- Correlate Auth and API Behavior -->
parallel:
- → ip-spray-detection
- → mailbox-api-activity
join: → triage-investigation

## ip-spray-detection
<!-- IP-based Password Spraying Detection -->
Find source IPs attempting to authenticate against multiple unique user accounts.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few IPs targeting multiple unique users. Benign noise typically targets
  one user many times.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS unique_targets, COUNT(*) AS total_attempts, MIN(time) AS start_time FROM hb_auth_signin WHERE status_id = 2 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_targets >= 5 ORDER BY unique_targets DESC
```

## mailbox-api-activity
<!-- Unusual Mailbox API Operations -->
Identify API activity targeting mailbox resources, specifically high-volume read or update operations.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: High frequency of API calls targeting mailbox data per IP and account. This
  identifies post-auth data access.
reads:
- activity_id
- actor_user_name
- api_operation
- api_service_name
- provider
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT src_endpoint_ip, actor_user_name, api_operation, api_service_name, resource_name, COUNT(*) AS call_count FROM hb_cloud_api_activity WHERE (provider = 'm365' OR api_service_name = 'Exchange') AND (LOWER(api_operation) LIKE '%mailbox%' OR LOWER(api_operation) LIKE '%message%' OR LOWER(api_operation) LIKE '%folder%') AND activity_id IN (2, 3) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, api_operation, api_service_name, resource_name HAVING call_count > 10 ORDER BY call_count DESC
```

## triage-investigation
<!-- Triage Auth and API Correlation -->
```agent target=hunter
cite: required
context:
- scoping-exchange-auth
- ip-spray-detection
- mailbox-api-activity
max_iterations: 6
objective: Identify if any IP conducting a spray in the auth logs matches an IP performing
  mailbox API operations. Determine if the accounts targeted in the spray were successfully
  used for API access.
success_criteria: A verdict of malicious | suspicious | benign citing specific rows
  for each host and account.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one source IP and account pair" (confidence: high, judge=hunter)
then: → suspend-identity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-logging-limitations)
else: → close-out

## suspend-identity
<!-- Suspend Compromised Identity -->
```action target=identity
~~~yaml
approval: required
~~~
Suspend the user account identified as compromised and revoke all active OAuth/MFA tokens.
```
→ analyst-review

## analyst-review
<!-- Analyst Review of Exfiltration -->
```manual target=analyst
Review the specific 'resource_name' entries in the mailbox API query. Identify if any mailbox redirection rules or auto-forwarding was configured by the attacker for persistence.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document the findings. If benign scanning IPs were found, recommend them for a global exclusion list to reduce future false positives.
```
→ end

---
analysis: A single rule could fire on a large network transfer; this hunt correlates
  that transfer with rare process execution and identity context to confirm a full
  attack lifecycle.
blind_spots:
- id: no-endpoint-coverage
  question: whether the phishing execution occurred on a host without telemetry
  requires: an endpoint agent on every host in scope
  risk: A host without an agent provides no process or local network rows, so the
    result only covers the enrolled estate.
  stage: initial-access-phishing
- id: internal-data-movement
  question: whether data was moved laterally to an internal relay before exfiltration
  requires: hb_smb_activity or internal flow logs
  risk: This hunt filters out internal IP traffic to reduce noise, missing lateral
    data staging.
  stage: exfiltration-over-c2
coverage:
- stage: initial-access-phishing
  status: covered
  steps:
  - lead-signin-no-mfa
  - rare-child-process-spawn
- stage: exfiltration-over-c2
  status: covered
  steps:
  - high-volume-external-egress
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Phishing and agent-driven exfiltration bypass traditional perimeter
    defenses by abusing trusted identities; identifying these chains across surfaces
    is a priority for data protection.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has used a phishing attack to bypass multi-factor authentication
  and is now using compromised productivity applications to exfiltrate data over a
  C2 channel.
labels:
- hunt
- attack.t1566
- attack.t1041
- exfiltration
- initial access
name: Detection of Phishing and Agent-Driven Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: standard-retention
    type: number
  productivity_apps:
    default:
    - outlook.exe
    - msedge.exe
    - chrome.exe
    - teams.exe
    - winword.exe
    - excel.exe
    - powerpnt.exe
    description: Filenames of applications often used as entry points for phishing.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: common-phishing-targets
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; leave empty for
      the entire estate.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: analyst-scoping
    type: list[host]
  target_users:
    default: []
    description: Users identified in the lead query; use these to focus subsequent
      parallel queries.
    from:
      kind: manual
      observed: '2026-09-30'
      ref: lead-step-pivot
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/30/secure-whats-next-your-guide-to-microsoft-security-at-microsoft-ignite-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with successful logins that bypassed MFA. Focusing on users with
  high-volume egress reduces the initial scope to active sessions that may be exfiltrating
  data.
references:
- name: "Microsoft Security - Secure what\u2019s next: Your guide to Microsoft Security\
    \ at Microsoft Ignite 2026"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/30/secure-whats-next-your-guide-to-microsoft-security-at-microsoft-ignite-2026/
related:
- hunt: mfa-fatigue-and-lateral-movement
  reason: MFA fatigue targets different user behaviors and uses lateral movement rather
    than direct exfiltration from the entry point.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing for Identity and Agent Access
    observables:
    - Attempts to bypass SMS MFA
    - Delivery and execution of malicious attachments
    - HTTP requests to phishing domains
    - Compromise of local AI agents and identities
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Data Exfiltration over C2 Channel
    observables:
    - Outbound network connections to external C2 servers
    - Exfiltration of sensitive data using HTTP POST requests
    - Persistent traffic to untrusted command-and-control infrastructure
    - Access to sensitive files by compromised agents
    slug: exfiltration-over-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: This attack scenario involves an initial breach via phishing to compromise
    user identities or local AI agents, followed by the exfiltration of sensitive
    data over established command-and-control (C2) channels. The campaign specifically
    targets the unique permissions and access methods of non-human actors and agentic
    systems, bypassing traditional alert-centric defenses.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Detection of Phishing and Agent-Driven Exfiltration

This hunt identifies the transition from initial access via phishing to data theft by correlating identity, process, and network telemetry. It first scopes the estate to successful logins where MFA was not utilized, then scans for rare child processes spawned from common productivity applications and high-volume outbound network traffic to external destinations. An agent weighs these independent signals to find a coordinated attack chain.

## lead-signin-no-mfa
<!-- Identify successful sign-ins without MFA -->
Find successful authentications where multi-factor authentication was not recorded. These users serve as the primary focus for subsequent behavioral checks.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Login rows specifying a user and source IP. Silence suggests all successful
  logins within the period utilized MFA.
reads:
- actor_user_name
- src_endpoint_ip
- auth_protocol
- device_hostname
- time
- status_id
- mfa
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT actor_user_name, src_endpoint_ip, auth_protocol, device_hostname, time FROM hb_auth_signin WHERE status_id = 1 AND (mfa IS NULL OR LOWER(mfa) = 'false') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-attack
<!-- Corroborate attack with process and network anomalies -->
parallel:
- → rare-child-process-spawn
- → high-volume-external-egress
join: → triage-attack-chain

## rare-child-process-spawn
<!-- Rare child processes from productivity apps -->
Identify unusual applications launched from productivity tools for the targeted users. This isolates execution typically associated with phishing payloads.

```sqlite target=endpoint role=baseline params=(productivity_apps=productivity_apps, target_users=target_users, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare child processes like cmd.exe or powershell.exe running under an office
  application for a user with suspicious sign-in activity.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- user_name
- process_name
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, user_name, process_name, parent_process_name, process_cmd_line, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{productivity_apps}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND NOT (instr(',' || '{{productivity_apps}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{target_users}}' = '' OR instr(',' || '{{target_users}}' || ',', ',' || user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3
```

## high-volume-external-egress
<!-- High-volume external egress -->
Detect potential exfiltration by identifying large volumes of data sent to external IP addresses associated with the targeted users.

```sqlite target=network role=enrichment params=(target_users=target_users, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts with significant outbound traffic to external IPs that correlates
  with users identified in the scoping step.
reads:
- device_hostname
- user_name
- dst_endpoint_ip
- traffic_bytes
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, user_name, dst_endpoint_ip, SUM(traffic_bytes) AS total_out_bytes, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE direction = 'outbound' AND ('{{target_users}}' = '' OR instr(',' || '{{target_users}}' || ',', ',' || user_name || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '172.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING total_out_bytes > 5242880 ORDER BY total_out_bytes DESC
```

## triage-attack-chain
<!-- Triage the attack chain -->
```agent target=hunter
cite: required
context:
- lead-signin-no-mfa
- rare-child-process-spawn
- high-volume-external-egress
max_iterations: 6
objective: Determine if any host shows a coordinated sequence of suspicious sign-ins,
  rare process execution from productivity apps, and high-volume exfiltration for
  the same user.
success_criteria: A verdict of malicious, suspicious, or benign for each host, citing
  specific rows from all three surfaces.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-attack-chain verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-coverage)
else: → analyst-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately and collect the suspicious binary for analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from the triage step. Verify the source of the phishing email if possible and analyze the destination IP reputation. Determine the sensitivity of the data accessed by the process.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the indicators of compromise (IOCs) and report any MFA bypass techniques discovered. If the child process behavior is confirmed malicious, propose a standing detection rule for the SOC.
```
→ end

---
analysis: While individual rules fire on schtasks or encoded powershell, this hunt
  pivots between identity (auth_signin), script content (script_activity), and persistent
  job configuration (scheduled_job) while baselining outbound traffic to confirm a
  coherent sequence that a single-surface rule cannot see. The analyst must weigh
  the combination of these signals to reach a verdict.
blind_spots:
- id: incomplete-telemetry-chain
  owner: SIEM Engineering
  question: Whether a stage of the attack chain is missed due to a host not reporting
    to one specific surface.
  remediation: Audit log ingestion for all four required surfaces per Windows asset.
  requires: Unified coverage across auth, script, and job surfaces
  risk: If a host reports auth sign-ins but fails to report script activity, the agent
    will lack the context to confirm execution, leading to a false negative.
- id: no-vpn-telemetry
  owner: Network Engineering
  question: Whether the remote access occurred via a VPN gateway not reporting to
    the auth surface.
  remediation: Integrate VPN logs into hb_auth_signin.
  requires: hb_auth_signin from VPN provider
  risk: Remote access via undocumented gateways would bypass the rare-remote-logons
    query.
  stage: initial-access-remote-signin
coverage:
- stage: initial-access-remote-signin
  status: covered
  steps:
  - rare-remote-logons
- stage: execution-powershell-scripts
  status: covered
  steps:
  - suspicious-script-activity
- stage: persistence-scheduled-task
  status: covered
  steps:
  - scheduled-task-persistence
- stage: c2-malicious-network-connection
  status: covered
  steps:
  - suspicious-network-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Linking identity, execution, and persistence context is the only
    way to reliably distinguish administrative maintenance from multi-stage intrusions.
    This hunt prevents single-stage alerts from being closed without investigating
    the broader intrusion story.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via remote services, executed PowerShell
  for post-exploitation, and established persistence through scheduled tasks to maintain
  a C2 connection.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1133
- command and control
- execution
- initial access
- persistence
name: Contextual Investigation of Phased PowerShell Intrusions
parameters:
  admin_accounts:
    default:
    - Administrator
    - root
    - svc_admin
    description: Privileged accounts to monitor for rare remote interactive sign-ins.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: internal-privileged-account-list
    type: list[string]
  compromised_hostnames:
    default: []
    description: Hosts flagged in the early triage phase to be investigated for persistence.
    type: list[host]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Initial Windows host list to narrow the search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/ai-soc-agents-are-only-as-good-as-the-context-they-can-see
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows domain controllers and administrator workstations first.
  Ensure that PowerShell Script Block Logging is enabled on target hosts. The hunt
  filters for hosts with rare remote interactive logins to reduce noise from common
  network traffic.
references:
- name: Why AI SOC Agents Need Context to Investigate Alerts
  url: https://www.sekoia.com/blog/ai-soc-agents-are-only-as-good-as-the-context-they-can-see
related:
- hunt: lateral-movement-from-privileged-logon
  reason: This hunt focuses on persistence and C2; lateral movement after a remote
    admin logon is a distinct follow-on scenario.
  relation: sibling
scenario:
  stages:
  - name: External Remote Access
    observables:
    - Sign-in from an unusual country
    - Connection via corporate VPN
    - Sign-in to privileged administrator account
    slug: initial-access-remote-signin
    tactic: initial-access
    techniques:
    - T1133
  - name: PowerShell Execution
    observables:
    - Suspicious PowerShell command-line arguments
    - Encoded PowerShell commands
    - PowerShell script blocks downloading external files
    slug: execution-powershell-scripts
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task Persistence
    observables:
    - Scheduled task creation using schtasks
    - Recurring task execution (e.g., nightly)
    - Service account assigned to scheduled job
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Command and Control Connection
    observables:
    - Workstation contacting a malicious IP address
    - Connection to a suspicious domain
    - Outbound network traffic from endpoint processes
    slug: c2-malicious-network-connection
    tactic: command-and-control
  summary: An adversary gains initial access through external remote services or compromised
    accounts, followed by the execution of malicious PowerShell scripts. They establish
    persistence using scheduled tasks and maintain communication with command-and-control
    infrastructure via network connections to suspicious IP addresses.
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


# Contextual Investigation of Phased PowerShell Intrusions

This hunt follows a complete attack chain from initial remote access to command and control. By linking identity telemetry from sign-ins with endpoint script activity and persistent scheduled jobs, it distinguishes between routine administrative work and a multi-stage breach. The phased approach allows an agent to first evaluate access and execution evidence before investigating the resulting persistence and rare network connections. The hunt uses two baseline queries to isolate rare behavior from common fleet noise.

## scoping-hosts
<!-- Identify candidate Windows hosts -->
Narrow the investigation to Windows devices currently reporting telemetry.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence suggests no Windows devices are enrolled.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT hostname AS device_hostname FROM hb_devices WHERE platform = 'Windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early
<!-- Check early-stage access and execution -->
parallel:
- → rare-remote-logons
- → suspicious-script-activity
join: → triage-early-stage

## rare-remote-logons
<!-- Rare remote interactive sign-ins -->
Detect initial access via RDP targeting admin accounts, baselined by host count to find anomalies.

```sqlite target=identity role=baseline params=(admin_accounts=admin_accounts, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Sign-ins from rare source IPs to specific hosts. Silence suggests only common
  or internal access occurred.
prevalence:
  by: dst_endpoint_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_name
- actor_user_name
- src_endpoint_ip
- src_location_country
- logon_type
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT dst_endpoint_name, actor_user_name, src_endpoint_ip, src_location_country, COUNT(DISTINCT dst_endpoint_name) AS host_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE logon_type = 'Remote Interactive' AND (instr(',' || '{{admin_accounts}}' || ',', ',' || actor_user_name || ',') > 0 OR '{{admin_accounts}}' = '') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, actor_user_name, src_location_country HAVING host_count < 3
```

## suspicious-script-activity
<!-- Suspicious PowerShell script blocks -->
Search for script blocks containing download logic or web client calls indicative of staging.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script contents performing external downloads. Silence means no such script
  blocks were logged.
reads:
- device_hostname
- actor_user_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%webclient%' OR LOWER(script_content) LIKE '%download%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-stage
<!-- Triage early-stage indicators -->
```agent target=hunter
cite: required
context:
- rare-remote-logons
- suspicious-script-activity
max_iterations: 4
objective: Determine if remote logins correlate with suspicious script execution on
  the same hosts or by the same accounts. Output a list of compromised_hostnames that
  show this combined behavior to be used as a parameter in the next phase.
success_criteria: A verdict citing specific logins and script blocks. The output must
  explicitly list the hostnames for the next phase.
tools:
- endpoint
- identity
- network
```

## parallel-follow-on
<!-- Check follow-on persistence and C2 -->
parallel:
- → scheduled-task-persistence
- → suspicious-network-connections
join: → full-chain-assessment

## scheduled-task-persistence
<!-- Scheduled task persistence in temp paths -->
Find scheduled tasks on compromised hosts that execute scripts from user-writable or temporary paths.

```sqlite target=endpoint role=triage params=(compromised_hostnames=compromised_hostnames, lookback_days=lookback_days)
~~~yaml
expected: Tasks pointing at staging directories on identified hosts. Silence suggests
  no persistence via this mechanism.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%powershell%' OR LOWER(job_cmd_line) LIKE '%cmd.exe%') AND (LOWER(job_cmd_line) LIKE '%\\temp\\%' OR LOWER(job_cmd_line) LIKE '%\\public\\%' OR LOWER(job_cmd_line) LIKE '%\\appdata\\%') AND ('{{compromised_hostnames}}' = '' OR instr(',' || '{{compromised_hostnames}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-network-connections
<!-- Rare outbound connections from compromised hosts -->
Identify outbound connections to destinations that are rare across the fleet, suggesting C2 traffic.

```sqlite target=network role=baseline params=(compromised_hostnames=compromised_hostnames, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to rare IPs on identified hosts. Silence provides evidence of
  absence for new external beaconing from these hosts.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- direction
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND ('{{compromised_hostnames}}' = '' OR instr(',' || '{{compromised_hostnames}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, process_name HAVING (SELECT COUNT(DISTINCT device_hostname) FROM hb_network_connection AS internal WHERE internal.dst_endpoint_ip = hb_network_connection.dst_endpoint_ip) < 5
```

## full-chain-assessment
<!-- Full-chain intrusion assessment -->
```agent target=hunter
cite: required
context:
- triage-early-stage
- scheduled-task-persistence
- suspicious-network-connections
max_iterations: 5
objective: Evaluate the complete attack chain per host. Specifically assess the temporal
  proximity between the remote logins (Step 3) and the task creation (Step 7). Determine
  if the persistence and rare connections represent a coherent multi-stage intrusion.
success_criteria: A verdict citing rows from all phases. The agent must comment on
  whether tasks were created shortly after a suspicious login.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on full verdict -->
if~: "the full-chain-assessment verdict identifies a malicious sequence of access, execution, and either persistence or C2 traffic, especially where the task was created shortly after login" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry-chain)
else: → analyst-review

## isolate-host
<!-- Isolate compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in the full-chain verdict and revoke active sessions for the involved administrator account.
```
→ analyst-review

## analyst-review
<!-- Analyst final review -->
```manual target=analyst
Examine the timeline constructed by the agent. Verify if the PowerShell script execution and scheduled task align with legitimate administrator maintenance or represent an intrusion. Confirm if the outbound IP is an unknown destination.
```
→ hunt-closeout

## hunt-closeout
<!-- Hunt close-out and documentation -->
```manual target=analyst
Document the investigation findings. Record which hosts were identified and why others were excluded. List any rare destination IPs found for potential blocklisting.
```
→ end

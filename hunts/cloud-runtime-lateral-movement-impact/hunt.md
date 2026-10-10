---
analysis: Simple rules fire on single blocked connections; this hunt correlates suspicious
  execution with file theft and network violations across four telemetry surfaces
  to distinguish a coordinated attack from background noise.
blind_spots:
- id: no-network-fabric-logs
  question: Did lateral movement succeed through an unmonitored or allowed path?
  requires: hb_network_connection with activity_id=5 (Refuse)
  risk: A host without microsegmentation or VPC flow logging would not show blocked
    connections, making the lateral movement triage blind.
  stage: lateral-movement-segmentation-violation
- id: encryption-threshold-noise
  question: Is targeted encryption occurring below the 50-file threshold?
  requires: hb_file_activity mass counts
  risk: An attacker encrypting only high-value configuration or secret files (e.g.,
    .env or keys) would evade the mass modification check.
  stage: data-encryption-for-impact
coverage:
- stage: suspicious-cloud-runtime-execution
  status: covered
  steps:
  - runtime-execution-temp
  - sensitive-file-reads
- stage: lateral-movement-segmentation-violation
  status: covered
  steps:
  - segmentation-violations
- stage: data-encryption-for-impact
  status: covered
  steps:
  - impact-file-activity
- stage: incident-alerting-and-response
  status: covered
  steps:
  - webhook-tampering
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: initial-access-phishing-portals
  status: out_of_scope
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: vulnerability-and-exposure-discovery
  status: out_of_scope
- reason: Belongs to another part of the '6 AI SOC Integrations Actually Worth Connecting'
    series.
  stage: credential-abuse-and-mfa-evasion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Cloud workload compromise is a high-impact risk; validating that
    runtime security and network segments actually contain threats is a core operational
    requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a cloud workload using valid credentials
  and is moving across network segments before encrypting data and suppressing alerts
  via webhooks.
labels:
- hunt
- attack.t1078
- attack.t1486
- attack.t1566
- execution
- impact
- initial access
- lateral movement
- persistence
name: Cloud Runtime, Lateral Movement, and Impact
parameters:
  alerting_domains:
    default:
    - hooks.slack.com
    - ilert.com
    - bottleneck.the
    description: Known alerting and webhook domains to monitor.
    from:
      kind: article
      observed: '2024-03-20'
      ref: sekoia-ai-soc
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-03-20'
      ref: hunt-standard-lookback
    type: number
  scope_hosts:
    default: []
    description: 'Optional: Hostnames of specific cloud workloads to focus on.'
    from:
      kind: manual
      observed: '2024-03-20'
      ref: analyst-defined
    type: list[host]
  sensitive_paths:
    default:
    - /etc/shadow
    - /etc/sudoers
    - /etc/pam.d
    - C:\Windows\System32\config\SAM
    description: Sensitive system files indicating credential theft or escalation.
    from:
      kind: manual
      observed: '2024-03-20'
      ref: standard-system-targets
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workloads in public subnets first; widen to internal management
  systems if lateral movement is suspected.
references:
- name: "Sekoia \u2014 AI SOC Integrations: 6 Capabilities Worth Connecting"
  url: https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting
related:
- hunt: initial-access-phishing-portals
  reason: Phishing identification handles the credential theft stage that precedes
    this post-compromise hunt.
  relation: out-of-scope-alternative
- hunt: identity-access-exposure-investigation
  relation: follows
scenario:
  stages:
  - name: Credential Harvesting via Phishing Portals
    observables:
    - bottleneck.the
    - Mokn authentication portals
    - Credential testing activity
    slug: initial-access-phishing-portals
    tactic: initial-access
    techniques:
    - T1566
  - name: Vulnerability and Exposure Discovery
    observables:
    - Holm Security vulnerability scans
    - Asset risk profiling
    - Exposed human assets
    slug: vulnerability-and-exposure-discovery
    tactic: initial-access
    techniques:
    - T1078
  - name: Credential Abuse and MFA Evasion
    observables:
    - Silverfort MFA decisions
    - Suspicious access patterns
    - Policy actions
    - Hybrid environment authentication logs
    slug: credential-abuse-and-mfa-evasion
    tactic: persistence
    techniques:
    - T1078
  - name: Suspicious Cloud Runtime Execution
    observables:
    - Upwind runtime workload monitoring
    - Process accessing sensitive resource
    - Anomalous cloud asset behavior
    slug: suspicious-cloud-runtime-execution
    tactic: execution
    techniques:
    - T1078
  - name: Lateral Movement across Segments
    observables:
    - Akamai Guardicore network traffic logs
    - Communication between isolated workloads
    - Zero Trust policy violations
    slug: lateral-movement-segmentation-violation
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Data Encryption for Impact
    observables:
    - Ransomware activity
    - Spyware delivery
    - Mass file modification
    slug: data-encryption-for-impact
    tactic: impact
    techniques:
    - T1486
  - name: Incident Alerting and Response
    observables:
    - ilert incident notifications
    - Slack notification webhooks
    - Teams alert messages
    - Voice call escalation
    slug: incident-alerting-and-response
    tactic: impact
    techniques:
    - T1486
  summary: An adversary leverages deceptive authentication portals to harvest credentials
    and identifies unpatched vulnerabilities across the attack surface. The campaign
    progresses to cloud runtime execution and lateral movement across microsegmented
    workloads, culminating in ransomware encryption and automated incident notification.
series:
  index: 2
  slug: 6-ai-soc-integrations-actually-worth-connecting
  title: 6 AI SOC Integrations Actually Worth Connecting
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


# Cloud Runtime, Lateral Movement, and Impact

This hunt identifies post-compromise stages of a cloud-based intrusion. The analyst identifies active workloads, then hunts for suspicious runtime execution and sensitive file access. The second phase seeks evidence of lateral movement via network segmentation violations, mass file modifications during encryption, and outbound HTTP traffic to alerting platforms.

## scope-cloud-workloads
<!-- Identify active cloud workloads -->
Identify hosts running web or application services to narrow the investigative focus.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames representing active workloads. Silence indicates no
  matching service activity.
reads:
- device_hostname
- process_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/var/www/%' OR LOWER(process_path) LIKE '/opt/%' OR LOWER(process_path) LIKE '%python%' OR LOWER(process_path) LIKE '%java%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-investigation
<!-- Investigate early-stage runtime indicators -->
parallel:
- → runtime-execution-temp
- → sensitive-file-reads
join: → early-stage-triage

## runtime-execution-temp
<!-- Execution from writable paths -->
Detect processes launched from /tmp or /dev/shm, where adversaries often stage malware.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process metadata from untrusted paths. Silence proves no such processes
  ran in the monitored window.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%' OR LOWER(process_path) LIKE '%\temp\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## sensitive-file-reads
<!-- Sensitive system file access -->
Identify processes reading system secrets, which follows initial execution.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, sensitive_paths=sensitive_paths)
~~~yaml
expected: Rows linking a process to a secret-carrying file. Silence suggests no such
  file touches were recorded.
reads:
- device_hostname
- actor_user_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{sensitive_paths}}' || ',', ',' || LOWER(file_path) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Evaluate workload compromise -->
```agent target=hunter
cite: required
context:
- scope-cloud-workloads
- runtime-execution-temp
- sensitive-file-reads
max_iterations: 3
objective: Establish if the processes in /tmp or temporary paths are responsible for
  sensitive file access on the scoped hosts.
success_criteria: A verdict for each host naming the suspicious processes and the
  specific secrets accessed.
tools:
- endpoint
- network
- web
```

## follow-on-investigation
<!-- Investigate lateral movement and impact -->
parallel:
- → segmentation-violations
- → impact-file-activity
- → webhook-tampering
join: → follow-on-triage

## segmentation-violations
<!-- Network segmentation violations -->
Identify blocked traffic from compromised workloads to restricted segments.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Blocked connection attempts from scoped workloads. Silence suggests microsegmentation
  is either clean or unmonitored.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE activity_id = 5 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## impact-file-activity
<!-- Mass file modification -->
Find signs of encryption by counting unusually high file activity per actor.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: High file modification counts associated with a single user. Silence proves
  an absence of mass file changes.
reads:
- device_hostname
- actor_user_name
- activity_name
- file_path
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, activity_name, COUNT(DISTINCT file_path) AS file_count, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id IN (1, 3, 4, 5) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name, activity_name HAVING file_count > 50 ORDER BY file_count DESC
```

## webhook-tampering
<!-- Outbound alerting webhooks -->
Detect traffic to Slack or ilert that could indicate alert suppression or exfiltration.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, alerting_domains=alerting_domains, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to incident management platforms. Silence suggests no such
  webhooks were fired from workloads.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE instr(',' || '{{alerting_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Full attack chain synthesis -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- segmentation-violations
- impact-file-activity
- webhook-tampering
max_iterations: 4
objective: Determine if the compromised workloads from the early triage have proceeded
  to violate network policies, encrypt files, or manipulate alerting systems.
success_criteria: A verdict citing the linkage between suspicious processes and the
  follow-on lateral or impact rows.
tools:
- endpoint
- network
- web
```

## final-decision
<!-- Decision on host isolation -->
if~: "The agent identifies a host with suspicious execution followed by network policy violations or mass file encryption." (confidence: high, judge=hunter)
then: → contain-and-rotate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-fabric-logs)
else: → analyst-review

## contain-and-rotate
<!-- Isolate host and rotate keys -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host cited in the verdict. If the actor_user_name is a service account, rotate its API keys immediately; if a user account, reset the password and audit MFA logs.
```
→ analyst-review

## analyst-review
<!-- Analyst confirmation -->
```manual target=analyst
Review the processes in /tmp and the files touched. Verify if the segmentation violations correlate with the workload's known peers.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure -->
```manual target=analyst
Record whether the attack chain was found and if any alerting domains should be added to the parameter list.
```
→ end

---
analysis: While simple rules can alert on 'cmd.exe in Downloads', this hunt uses prevalence
  to filter out noise, identifies the 'exposure context' of the host, and uses an
  agent to cross-correlate multiple behavioral signals (rare paths + network + scripts)
  to find high-confidence threats.
blind_spots:
- id: telemetry-gap
  question: Is the external IP discovered by hb_exposed_assets managed and reporting
    behavioral telemetry?
  requires: Endpoint agents on every internet-exposed asset.
  risk: A host may be exposed and compromised but invisible to process-level hunting
    if it lacks an EDR agent.
  stage: initial-access-exploitation
- id: fileless-execution
  question: Did the exploit result in in-memory execution without a new process launch?
  requires: Memory forensics or direct syscall monitoring.
  risk: Sophisticated exploits (e.g., buffer overflows) may execute code within an
    existing process, bypassing hb_process_activity.
  stage: execution-malicious-file
coverage:
- stage: initial-access-exploitation
  status: covered
  steps:
  - scoping-exposed-assets
  - scoping-vulnerable-findings
- stage: execution-malicious-file
  status: covered
  steps:
  - lead-suspicious-executions
  - baseline-path-prevalence
  - enrich-script-execution
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: cloud-identity-authentication
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: cloud-discovery-enumeration
  status: out_of_scope
- reason: 'Belongs to another part of the ''Unmasking Cloud Identities: From Behavioral
    Clustering to Automated Detection'' series.'
  stage: c2-network-obfuscation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploiting public-facing applications is a primary initial access
    vector; detecting the subsequent payload execution on the endpoint is critical
    for stopping intrusions before data exfiltration or lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited an internet-facing vulnerability and is executing
  a malicious payload from a user-writable path, evidenced by rare process launches
  and script activity on high-risk hosts.
labels:
- hunt
- attack.t1190
- attack.t1204.002
name: Initial Access and Execution via Exposed Writable Paths
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for process and script activity.
    type: number
  suspicious_extensions:
    default:
    - .exe
    - .scr
    - .pif
    - .iso
    - .lnk
    - .vbs
    - .sh
    - .py
    - .elf
    description: File extensions commonly used in malicious payloads across platforms.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize hosts identified in hb_exposed_assets with product versions
  that correlate to critical vulnerabilities in hb_vulnerability_finding.
references:
- name: "Unit 42 \u2014 Unmasking Cloud Identities: From Behavioral Clustering to\
    \ Automated Detection"
  url: https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
related:
- hunt: cloud-identity-behavioral-anomaly
  reason: This hunt identifies endpoint entry; a following hunt focuses on the Cloud
    API activity performed by the compromised identity.
  relation: follows
scenario:
  stages:
  - name: Exploit Public-Facing Application
    observables:
    - exploited web servers
    - vulnerable internet-facing databases
    - open sockets on management protocols
    - misconfigured cloud assets
    slug: initial-access-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious File Execution
    observables:
    - execution of .doc, .exe, .lnk, .iso, or .scr files
    - social engineering for code execution
    - launch of malicious payloads on endpoint
    slug: execution-malicious-file
    tactic: execution
    techniques:
    - T1204.002
  - name: Cloud Authentication and Masquerading
    observables:
    - ConsoleLogin events
    - GetSigninToken requests
    - identities with 'admin' substring in name
    - AWSReservedSSO_AdministratorAccess_ prefix usage
    - login from anomalous source IPs
    slug: cloud-identity-authentication
    tactic: initial-access
    techniques:
    - T1078.004
    - T1036
  - name: Cloud Resource Discovery
    observables:
    - ListBuckets API calls
    - ListRoles API calls
    - GetCostAndUsage
    - GetCostForecast
    - ListNotificationHubs
    - aws s3 ls command execution
    - aws iam list-roles command execution
    slug: cloud-discovery-enumeration
    tactic: discovery
    techniques:
    - T1580
    - T1087.004
  - name: Multi-hop Proxy Obfuscation
    observables:
    - traffic to Tor exit nodes
    - DNS queries for .onion domains
    - connections to ORB (Operational Relay Box) networks
    - VPS-based proxy chains
    slug: c2-network-obfuscation
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Attackers gain initial access by exploiting vulnerabilities in public-facing
    applications or by tricking users into executing malicious files on endpoints.
    Once inside, they leverage over-privileged cloud identities to perform resource
    discovery while masquerading as legitimate administrative users. The intrusion
    is further concealed using multi-hop proxies and Tor to obfuscate the origin of
    their cloud API activity.
series:
  index: 1
  slug: unmasking-cloud-identities-from-behavioral-clustering-to-automated-detection
  title: 'Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection'
  total: 2
severity: high
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Initial Access and Execution via Exposed Writable Paths

This hunt unmasks the transition from external vulnerability to local execution by correlating internet-facing asset exposure with suspicious behavioral patterns in user-writable paths. Following the behavioral clustering research from Unit 42, we prioritize hosts that demonstrate both high-severity vulnerabilities and rare file executions. The hunt identifies binaries running from paths like Downloads, /tmp, or AppData, baselines them against the fleet, and corroborates the activity with script and network telemetry.

## scoping-exposed-assets
<!-- Identify Internet-Exposed Assets -->
Identify the external attack surface to focus behavioral analysis on hosts that are directly reachable from the internet.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of IP addresses and domains representing the external footprint.
  Silence means no assets are externally exposed according to the scanner.
reads:
- domain_or_ip
- ip_address
- port
- product
- version
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT domain_or_ip, ip_address, port, product, version FROM hb_exposed_assets WHERE product IS NOT NULL
```

## parallel-scoping-behavior
<!-- Parallel Scoping and Lead Behavior -->
parallel:
- → scoping-vulnerable-findings
- → lead-suspicious-executions
join: → baseline-path-prevalence

## scoping-vulnerable-findings
<!-- High-Severity Vulnerability Scope -->
Narrow the hunt to hosts with high-severity vulnerabilities (T1190) which serve as candidates for exploitation.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of host identifiers with critical/high vulnerabilities. Silence proves
  no high-severity vulnerabilities were found by scanners.
reads:
- device_uid
- cve_uid
- affected_package_name
- severity_id
silence: evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_uid, cve_uid, affected_package_name, severity_id FROM hb_vulnerability_finding WHERE severity_id >= 4
```

## lead-suspicious-executions
<!-- Suspicious Executions in Writable Paths -->
Find binaries executing from non-system, user-writable directories (T1204.002).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, suspicious_extensions=suspicious_extensions)
~~~yaml
expected: Binary execution in paths like Downloads, AppData/Local/Temp, or /tmp. Silence
  does not prove absence, as attackers may masquerade as system services.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/home/%' OR LOWER(process_path) LIKE '/var/tmp/%') AND (instr(',' || '{{suspicious_extensions}}' || ',', ',' || LOWER(SUBSTR(process_name, -4)) || ',') > 0 OR instr(',' || '{{suspicious_extensions}}' || ',', ',' || LOWER(SUBSTR(process_name, -3)) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## baseline-path-prevalence
<!-- Prevalence of Writable Path Binaries -->
Stack-count the identified paths to isolate rare, unique payloads from common user behavior (like Slack or Teams updates).

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare file paths. Paths seen fleet-wide are likely benign software
  updates.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/home/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts ASC
```

## parallel-enrichment
<!-- Corroborate with Script and Network Activity -->
parallel:
- → enrich-network-activity
- → enrich-script-execution
join: → triage-agent

## enrich-network-activity
<!-- Outbound Activity from Writable Paths -->
Identify potential C2 connections originating from the suspicious processes identified in previous steps.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Network connections from the same paths as the suspicious binaries. Normal
  apps (browsers) should be filtered by the agent.
reads:
- device_hostname
- process_path
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, process_path, dst_endpoint_ip, direction, time FROM hb_network_connection WHERE (LOWER(process_path) LIKE '%\users\%' OR LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/home/%') AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days')
```

## enrich-script-execution
<!-- Suspicious Script Activity -->
Detect obfuscated scripts that often drop or support the execution of malicious payloads (T1204.002).

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing encoded commands or one-liners associated with
  payload staging.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-15'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%-enc%' OR LOWER(script_content) LIKE '%iex%' OR LOWER(script_content) LIKE '%curl%|%sh%' OR LOWER(script_content) LIKE '%wget%|%sh%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Per-Host Verdict Triage -->
```agent target=hunter
cite: required
context:
- scoping-exposed-assets
- scoping-vulnerable-findings
- lead-suspicious-executions
- baseline-path-prevalence
- enrich-network-activity
- enrich-script-execution
max_iterations: 6
objective: Identify hosts that are (1) internet-exposed or highly vulnerable, AND
  (2) running rare processes from writable paths, AND (3) showing script or network
  corroboration. Cite specific process paths and PIDs.
success_criteria: A verdict for every candidate host citing row evidence.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "The triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → contain-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: telemetry-gap)
else: → close-out

## contain-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture volatile artifacts if possible before full termination.
```
→ analyst-review

## analyst-review
<!-- Analyst Investigation -->
```manual target=analyst
Review the cited process PIDs and paths. Determine if the initial access was via the identified vulnerability (T1190) or if a user executed a file manually (T1204.002).
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
If no threats were found, document the findings as evidence of absence for these stages. Record any benign software paths discovered to tune future runs.
```
→ end

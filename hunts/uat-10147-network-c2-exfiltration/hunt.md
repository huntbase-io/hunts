---
analysis: A simple IOC rule for the domain is fragile; this hunt combines scoping
  to web servers, prevalence counting for 'curl' sinks, and typo-squat behavioral
  analysis to identify adaptive AI-driven campaigns.
blind_spots:
- id: missing-network-logging
  question: Are network connections from 'svchosts.exe' being captured for all servers?
  requires: hb_network_connection with process mapping
  risk: Malware running as a system service or using raw sockets might bypass some
    EDR process-to-network mappings, leaving a blind spot for C2.
  stage: c2-and-exfiltration
- id: encrypted-payload-visibility
  question: What is the content of the POST exfiltration from curl?
  requires: TLS inspection or forward proxy logs
  risk: Without inspection, we cannot prove system identity was exfiltrated vs. a
    legitimate administrative check, increasing false positives on 'rare curl' destinations.
  stage: c2-and-exfiltration
coverage:
- stage: c2-and-exfiltration
  status: covered
  steps:
  - typosquatted-process-outbound
  - rare-curl-exfiltration
  - ioc-dns-lookup
- reason: Covered in the Initial Access hunt in this series.
  stage: initial-access-web-exploitation
  status: out_of_scope
- reason: Covered in the Execution/Staging hunt in this series.
  stage: execution-automated-staging
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: defense-evasion-defender-exclusions
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: privilege-escalation-and-discovery
  status: out_of_scope
- reason: Belongs to another part of the 'UAT-10147 integrates agentic AI into post-compromise
    operations' series.
  stage: persistence-task-and-rdp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-10147 uses AI-driven playbooks to scale operations; monitoring
    for their automated exfiltration signatures (curl to Nacos) and typo-squatted
    persistence (svchosts.exe) provides critical coverage for internet-exposed servers.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using typo-squatted system processes and common command-line
  transfer tools to exfiltrate system telemetry and maintain C2 with external Nacos
  or QuasarRAT infrastructure.
labels:
- hunt
- attack.t1071
- attack.t1041
- attack.t1090.003
name: UAT-10147 Network C2 and Exfiltration
parameters:
  c2_indicators:
    default:
    - adminapi.tippusoni.in
    - 139.180.197.150
    description: Known C2 domains and IPs from the Talos report.
    from:
      kind: article
      observed: '2026-01-15'
      ref: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of network history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-retention
    type: number
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
rationale: Focus on the web-facing server fleet first. The group specifically targets
  Zimbra, AjaxPro, and Telerik; widen the scoping query if software inventory for
  these is unavailable.
references:
- name: UAT-10147 integrates agentic AI into post-compromise operations
  url: https://blog.talosintelligence.com/uat-10147-chinese-speaking-adversary-integrates-agentic-ai-into-post-compromise-operations/
related:
- hunt: uat-10147-initial-access
  reason: Exploitation of web-facing vulnerabilities precedes the C2 and exfiltration
    phase.
  relation: precedes
- hunt: uat-10147-evasion-persistence
  relation: follows
scenario:
  stages:
  - name: Web Server Exploitation
    observables:
    - CVE-2022-27925
    - CVE-2021-23758
    - CVE-2019-18935
    - POST requests for Telerik file upload handler
    - runtime.exec used for shell spawn
    - asp.net
    slug: initial-access-web-exploitation
    tactic: initial-access
    techniques:
    - T1190
    - T1505.003
  - name: Automated Malware Staging
    observables:
    - back.bat
    - back.txt
    - bai.bat
    - user.bat
    - certutil -urlcache -split -f
    - C:\ProgramData\dll.zip
    - C:\ProgramData\user.bat
    slug: execution-automated-staging
    tactic: execution
    techniques:
    - T1059.003
    - T1059.001
  - name: Antivirus Defense Evasion
    observables:
    - powershell Add-MpPreference -ExclusionPath C:\Windows\SysWOW64\inetsrv
    - reg add HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths /v C:\Windows\System32\inetsrv
    - Deletion of staging scripts back.bat and bai.bat
    slug: defense-evasion-defender-exclusions
    tactic: defense-evasion
    techniques:
    - T1059.001
  - name: Privilege Escalation & Recon
    observables:
    - prcc1.rar (renamed EfsPotato)
    - CVE-2022-0995
    - CVE-2021-3156
    - CVE-2022-0847
    - appcmd list site /config /xml
    slug: privilege-escalation-and-discovery
    tactic: privilege-escalation
    techniques:
    - T1059
  - name: Scheduled Task & RDP Persistence
    observables:
    - 'Scheduled task name: Google Chrome Start'
    - net user /add adding to Remote Desktop Users group
    - RDP interactive sessions
    slug: persistence-task-and-rdp
    tactic: persistence
    techniques:
    - T1053.005
    - T1021.001
  - name: C2 and System Exfiltration
    observables:
    - adminapi.tippusoni.in
    - 139.180.197.150
    - Exfiltration of hostname and username to Nacos server
    - QuasarRAT (svchosts.exe)
    - NoodleRAT
    - SPECTRE
    slug: c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071
    - T1041
    - T1090.003
  summary: UAT-10147 targets Windows and Linux web servers globally, leveraging AI-driven
    workflows for automated vulnerability exploitation and post-compromise reconnaissance.
    The actor establishes persistence via rogue RDP users and scheduled tasks while
    exfiltrating system telemetry to cloud-based configuration management sinks.
series:
  index: 3
  slug: uat-10147-integrates-agentic-ai-into-post-compromise-operations
  title: UAT-10147 integrates agentic AI into post-compromise operations
  total: 3
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


# UAT-10147 Network C2 and Exfiltration

This hunt focuses on the network-layer indicators associated with UAT-10147, particularly the use of 'svchosts.exe' (a common typo-squat for QuasarRAT) and the use of curl/certutil to exfiltrate host identity to external configuration servers. We scope to web-facing servers, then parallelize the search for behavioral anomalies and known IOCs to identify compromised assets even if specific domains rotate.

## scope-web-servers
<!-- Scope to Web Server Assets -->
Identify hosts running software typically targeted by UAT-10147 (IIS, Nginx, Apache) to prioritize network analysis on high-risk ingress points.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running web server software. Silence means no such software
  is inventoried, making the group's primary exploitation vector less likely.
reads:
- device_hostname
- package_name
- package_version
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%iis%' OR LOWER(package_name) LIKE '%nginx%' OR LOWER(package_name) LIKE '%apache%') AND (asset_scope IS NULL OR asset_scope = 'endpoint')
```

## corroborate-c2-activity
<!-- Parallel Network and DNS Correlation -->
parallel:
- → typosquatted-process-outbound
- → rare-curl-exfiltration
- → ioc-dns-lookup
join: → triage-investigation

## typosquatted-process-outbound
<!-- Typo-squatted Process Outbound Activity -->
Find network connections from a process named 'svchosts.exe', a known QuasarRAT variant used by UAT-10147 to mimic the legitimate 'svchost.exe'.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Connections from a process with the extra 's'. This is a high-confidence
  signal for malware persistence.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- connection_state
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, connection_state, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%\\svchosts.exe' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-curl-exfiltration
<!-- Rare Curl Exfiltration Sink -->
Stack-count external destinations contacted by curl or certutil to find exfiltration sinks, as seen with Nacos telemetry exfiltration.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: External IPs contacted by few hosts via data transfer tools. Common sinks
  (updates) are filtered by the prevalence count.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- dst_endpoint_ip
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%\\curl.exe' OR LOWER(process_name) LIKE '%\\certutil.exe' OR LOWER(process_name) = 'curl' OR LOWER(process_name) = 'certutil') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING hosts < 3
```

## ioc-dns-lookup
<!-- Known C2 DNS Queries -->
Check the DNS surface for resolutions of the report's specific C2 domain indicators.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_indicators=c2_indicators)
~~~yaml
expected: Resolutions for 'adminapi.tippusoni.in'. Absence of static domains doesn't
  disprove infection; behavioral steps are primary.
reads:
- device_hostname
- query_hostname
- answers
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, query_hostname, answers, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_indicators}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-investigation
<!-- Evaluate C2 and Exfiltration Risk -->
```agent target=hunter
cite: required
context:
- scope-web-servers
- typosquatted-process-outbound
- rare-curl-exfiltration
- ioc-dns-lookup
max_iterations: 5
objective: Analyze the network behavior for hosts identified in the scoping step.
  Distinguish between administrative use of curl and the UAT-10147 pattern of exfiltrating
  system identity to Nacos or other C2 infrastructure.
success_criteria: A verdict per host citing specific network destination IPs or DNS
  queries.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage identifies any host with activity from 'svchosts.exe' OR a confirmed connection to a known C2 indicator from the report" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: missing-network-logging)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Quarantine the host and block the identified destination IP/domain at the egress gateway.
```
→ analyst-triage

## analyst-triage
<!-- Analyst Triage and Investigation -->
```manual target=analyst
Examine the destination traffic from curl. If the destination is a cloud-hosted Nacos server or an unknown IP in the Talos target regions (China, Brazil), escalate to IR. Verify if system metadata was present in the HTTP POST body.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the hosts examined and the evidence of absence for C2 activity.
```
→ end

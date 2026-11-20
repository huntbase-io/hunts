---
analysis: A standard rule alerts on task creation; this hunt asks whether the resulting
  binary is rare in the environment and whether it subsequently communicates with
  specific cloud storage providers, reducing false positives from legitimate administrative
  tasks.
blind_spots:
- id: limited-telemetry-retention
  question: When was the task first created if it was established before the lookback
    window?
  requires: long-term hb_scheduled_job retention
  risk: An implant established months ago might be missed if the scoping query only
    sees recent task modifications.
  stage: persistence-scheduled-task
- id: encrypted-c2-visibility
  question: What specific files are being requested from the Alibaba OSS buckets?
  requires: HTTPS inspection or decrypted SNI logs
  risk: Defenders can see the connection to the OSS domain but cannot see the payload
    path or metadata within the encrypted session.
  stage: c2-alibaba-oss-update
coverage:
- stage: persistence-scheduled-task
  status: covered
  steps:
  - tasks-in-writable-paths
  - rare-implant-processes
- stage: c2-alibaba-oss-update
  status: covered
  steps:
  - dns-to-oss-buckets
  - http-to-oss-buckets
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: initial-access-spoofed-sites
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: delivery-dynamic-archive
  status: out_of_scope
- reason: 'Belongs to another part of the ''Counterfeit installers to system compromise:
    Tracking a deceptive software download campaign'' series.'
  stage: execution-randomized-payloads
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Silver Fox campaign successfully evades file-based blocklists
    by using legitimate update utilities and randomized paths. A behavioral hunt is
    required to find the intersection of persistence and unusual cloud infrastructure
    connections across multinational operations.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has established persistence through a scheduled task that
  executes a randomized binary from a world-writable path, which then uses a legitimate
  update utility to communicate with Alibaba OSS infrastructure.
labels:
- hunt
- attack.t1053.005
- attack.t1071
- attack.t1105
name: Persistent implant using repurposed update utilities
parameters:
  c2_domains:
    default:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - pc-razerzone.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    - n7b8t85zsg.com
    - www.gehie246.com
    - kaspersky-lab.hl.cn
    description: Full FQDNs observed in the campaign used for delivery and C2.
    from:
      kind: article
      observed: '2026-09-01'
      ref: msrc-blog-2026-09-01
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine for process, task, and network events.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: number
  scope_hosts:
    default: []
    description: Hosts to focus on based on the scoping step; leave empty to hunt
      across the entire estate.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: default
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying hosts with scheduled tasks pointing to world-writable
  paths. Narrow the subsequent process and DNS queries to these hosts to reduce noise
  from common third-party updaters.
references:
- name: "MSRC \u2014 Counterfeit installers to system compromise: Tracking a deceptive\
    \ software download campaign"
  url: https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-installers-system-compromise-tracking-deceptive-software-download-campaign/
related:
- hunt: silver-fox-initial-access-spoofed-sites
  reason: This hunt focuses on post-compromise persistence; finding the initial download
    requires web proxy or browser history analysis.
  relation: out-of-scope-alternative
- hunt: counterfeit-software-delivery-randomized-execution
  relation: follows
scenario:
  stages:
  - name: Spoofed software-download sites
    observables:
    - pc-razerzone.com.cn
    - app-microsoft-edge.com.cn
    - kaspersky-lab.hl.cn
    - calibre-ebook.com.cn
    - gehie246.com
    - yimxg25tiy.com
    - cc8ttkv35b.com
    slug: initial-access-spoofed-sites
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Dynamically generated installer archive
    observables:
    - app_setup.6653004.zip
    - zinst.zip
    - zintall.zip
    - intsoft.zip
    - innstll.zip
    - /712down
    - /73inst
    slug: delivery-dynamic-archive
    tactic: execution
    techniques:
    - T1204.002
  - name: Randomized stage-one payload execution
    observables:
    - a_instapp83353001.exe
    - C:\Users\Public\
    - C:\ProgramData\
    - Speech Processing Solutions GmbH
    - Philips Speech Driver Client Configuration
    - PhilipsSpeechDriverConfiguration.exe
    - 'TODO: <Product name>'
    - 6d6ba2bc9ad414837826f7278bc3e0116f1aeda02d0c2284ed65819f5d9180a8
    slug: execution-randomized-payloads
    tactic: execution
    techniques:
    - T1204.002
    - T1036.005
  - name: Implant persistence via Scheduled Task
    observables:
    - svchost.exe -k netsvcs -p -s Schedule
    - C:\ProgramData\
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Repurposed update client C2
    observables:
    - upitem.oss-cn-hangzhou.aliyuncs.com
    - tu_rt.exe
    - _ir_tu2_temp_
    - Indigo Rose TrueUpdate Client
    slug: c2-alibaba-oss-update
    tactic: command-and-control
    techniques:
    - T1071
    - T1105
  summary: This campaign uses high-fidelity vendor look-alike domains to distribute
    dynamically generated installer archives to Chinese-speaking users. Once executed,
    the malicious installers drop randomized payloads that establish persistence via
    Scheduled Tasks and repurpose legitimate update utilities to retrieve further
    stages from Alibaba Cloud infrastructure.
series:
  index: 2
  slug: counterfeit-installers-to-system-compromise-tracking-a-deceptive-software-download-campaign
  title: 'Counterfeit installers to system compromise: Tracking a deceptive software
    download campaign'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Persistent implant using repurposed update utilities

This hunt identifies post-compromise activity associated with the Silver Fox (Yinhu) campaign. It focuses on the persistence stage where the malware stages randomized binaries in ProgramData or Public directories and launches them via the Windows Task Scheduler. The hunt identifies these implants by their unusual execution paths, host-level rarity, and subsequent DNS and HTTP requests to the attacker's Alibaba Cloud infrastructure. An agent weighs these independent behavioral signals to distinguish the implant from legitimate administrative tools and update mechanisms.

## tasks-in-writable-paths
<!-- Scheduled tasks in world-writable paths -->
Identify tasks configured to run executables from ProgramData or Public directories, the primary persistence method for this implant.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Tasks pointing to randomized subdirectories in world-writable paths. Absence
  of results means no such tasks were visible in the snapshot.
reads:
- device_hostname
- job_name
- job_cmd_line
- job_user_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_cmd_line) LIKE '%c:\programdata\%' OR LOWER(job_cmd_line) LIKE '%c:\users\public\%') AND LOWER(job_cmd_line) LIKE '%.exe%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate with process and network activity -->
parallel:
- → rare-implant-processes
- → dns-to-oss-buckets
- → http-to-oss-buckets
join: → triage-implant

## rare-implant-processes
<!-- Rare processes from world-writable paths -->
Stack-count processes in writable paths to isolate randomized implant binaries from fleet-wide administrative tools.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary executing on only a few hosts from a randomized path. Legitimate
  updaters and apps will appear on many more hosts.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 5
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS total_runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%c:\programdata\%' OR LOWER(process_path) LIKE '%c:\users\public\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count <= 5 ORDER BY host_count ASC
```

## dns-to-oss-buckets
<!-- DNS activity to campaign infrastructure -->
Match host activity against the campaign's known Alibaba OSS delivery and C2 infrastructure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS requests for the specific Alibaba OSS buckets. Silence proves absence
  only if DNS logging covers all hosts in scope.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## http-to-oss-buckets
<!-- HTTP requests to campaign infrastructure -->
Corroborate C2 communication using the HTTP surface to identify specific URL patterns or host headers.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Direct HTTP connections to known campaign domains. Silence means no proxy
  or server-side logs recorded these requests.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-implant
<!-- Triage the persistent implant -->
```agent target=hunter
cite: required
context:
- tasks-in-writable-paths
- rare-implant-processes
- dns-to-oss-buckets
- http-to-oss-buckets
max_iterations: 4
objective: Determine if a host is infected by linking a scheduled task in a world-writable
  path to a rare binary execution and observed C2 traffic.
success_criteria: A per-host verdict of malicious, suspicious, or benign citing specific
  telemetry rows.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-telemetry-retention)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect the identified binary from its world-writable path for further analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited telemetry. Confirm if the binary has Indigo Rose TrueUpdate metadata and if it creates temp files following the observed pattern.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the number of confirmed hosts. If the rare-process query yielded high-fidelity hits, promote it to a standing detection rule.
```
→ end

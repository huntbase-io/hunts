---
analysis: This hunt combines prevalence (rare ProgramData binaries) with behavioral
  corroboration (scheduled tasks in writable paths) and specific network infrastructure.
  A single rule on the IP or task name is easily rotated; the combination of a rare
  binary that persists and communicates is a resilient signal.
blind_spots:
- id: incomplete-telemetry
  question: Are there unmanaged hosts in the environment that could be infected but
    are not reporting?
  requires: EDR process/file/task coverage on all endpoints
  risk: An infected but unmanaged server would be invisible to this hunt.
- id: clsid-obfuscation
  question: Can we detect direct COM-based task registration if the job name is randomized?
  requires: Registry activity monitoring for Task CLSIDs
  risk: Adversaries can randomize the task name to bypass 'DocumentsManagerReporter'
    string matches.
  stage: persistence-scheduled-task
coverage:
- reason: Initial phishing links are to Egnyte; while hb_http_activity could see it,
    it is often too noisy for a hunt without specific, rotating link subdomains.
  stage: initial-access-phishing-pdf
  status: not_visible
- reason: Scoping specifically identifies the vulnerable server software named in
    the report.
  stage: initial-access-server-exploitation
  status: covered
  steps:
  - scoping-vulnerable-software
- reason: Implant execution is identified via rare process paths in ProgramData.
  stage: execution-muddyrot-implant
  status: covered
  steps:
  - rare-binaries-programdata
- reason: Covers both the specific task name and behavioral matches for tasks pointing
    at writable directories.
  stage: persistence-scheduled-task
  status: covered
  steps:
  - persistence-muddyrot-task
- stage: c2-raw-tcp
  status: covered
  steps:
  - c2-infrastructure-ips
- reason: Checks for the exfiltration buffer files in unusual paths.
  stage: exfiltration-c2-channel
  status: covered
  steps:
  - implant-buffer-file
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MuddyWater is a persistent actor targeting regional and strategic
    entities. Their shift to a custom implant (MuddyRot) indicates a need to move
    beyond RMM-based detection into behavioral analysis of persistence and raw network
    protocols.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed the MuddyRot implant via phishing or server
  exploitation, establishing persistence through a specific scheduled task and communicating
  via raw TCP to known Iranian-attributed infrastructure.
labels:
- hunt
- attack.t1041
- attack.t1053.005
- attack.t1059.001
- attack.t1090.003
- attack.t1190
- attack.t1566
name: MuddyRot Custom Implant and Persistence
parameters:
  c2_ips:
    default:
    - 91.235.234.202
    - 146.19.143.14
    description: C2 IPs attributed to MuddyRot in recent campaigns.
    from:
      kind: article
      observed: '2024-06-20'
      ref: sekoia-muddyrot
    type: list[ip]
  implant_path_pattern:
    default: '%\\programdata\\softwarememory\\%'
    description: SQL pattern for the MuddyRot installation directory.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt (e.g., Exchange or SharePoint
      servers).
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-exposed Microsoft Exchange or SharePoint servers as a
  primary scoping tier. Widen to all Windows workstations if no signal is found on
  servers.
references:
- name: "Sekoia \u2014 MuddyWater replaces Atera with custom MuddyRot implant"
  url: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
related:
- hunt: atera-rmm-abuse-detection
  reason: This hunt specifically targets the custom replacement for Atera.
  relation: supersedes
scenario:
  stages:
  - name: Spearphishing via PDF and Egnyte
    observables:
    - egnyte.com
    - ZIP archive containing MuddyRot
    - PDF decoys related to online courses or webinars
    slug: initial-access-phishing-pdf
    tactic: initial-access
    techniques:
    - T1566
  - name: Exploitation of Public-Facing Applications
    observables:
    - Microsoft Exchange servers
    - SharePoint servers
    slug: initial-access-server-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: MuddyRot Implant Execution
    observables:
    - documentsmanagerreporter.exe
    - DocumentUpdater mutex
    - LoadLibrary of Kernel32.dll, Advapi32.dll, Ole32.dll, Ws2_32.dll
    - cmd.exe spawning for reverse shell
    slug: execution-muddyrot-implant
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task Persistence
    observables:
    - DocumentsManagerReporter scheduled task
    - c:\programdata\softwarememory\documentsmanagerreporter.exe
    - CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DDBD3E73E6154572DD
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: Command and Control via Raw TCP
    observables:
    - 91.235.234.202
    - 146.19.143.14
    - TCP port 443
    - Raw TCP socket communication
    slug: c2-raw-tcp
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Exfiltration over C2
    observables:
    - exit file used as transfer buffer
    - File upload/download commands via TCP 443
    slug: exfiltration-c2-channel
    tactic: exfiltration
    techniques:
    - T1041
  summary: MuddyWater transitioned from using legitimate RMM tools to a custom C-based
    implant named MuddyRot, delivered via PDF phishing links and exploitation of public-facing
    servers. The implant provides reverse shell capabilities and persistence through
    COM-based scheduled tasks, communicating via raw TCP on port 443.
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


# MuddyRot Custom Implant and Persistence

MuddyWater (MOIS) has recently shifted from using off-the-shelf RMM tools like Atera to a custom C-based implant dubbed 'MuddyRot'. This hunt identifies the implant by its unique persistence mechanism (using Scheduled Task COM objects to evade standard schtasks.exe monitoring), its specific file-path conventions in ProgramData, and its raw TCP C2 traffic to known indicator IPs. It also checks for the 'exit' buffer file used for data exfiltration and initial phishing lures via Egnyte.

## scoping-vulnerable-software
<!-- Scope to internet-facing servers -->
Identify hosts running software frequently targeted by MuddyWater for initial access.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts running Exchange or SharePoint are primary candidates for initial
  exploitation. Silence means no such software was inventoried.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%exchange%' OR LOWER(package_name) LIKE '%sharepoint%' OR LOWER(vendor_name) LIKE '%microsoft%exchange%') AND asset_scope = 'endpoint'
```

## parallel-indicators
<!-- Corroborate MuddyRot Indicators -->
parallel:
- → rare-binaries-programdata
- → persistence-muddyrot-task
- → c2-infrastructure-ips
- → implant-buffer-file
join: → triage-agent

## rare-binaries-programdata
<!-- Rare Binaries in ProgramData -->
Find unique executables running from the specific ProgramData subfolder used by MuddyRot.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, implant_path_pattern=implant_path_pattern)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary named 'documentsmanagerreporter.exe' or similar appearing on very
  few hosts.
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
verified_at: '2026-09-17'
~~~
SELECT process_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE 'c:\\programdata\\%' OR LOWER(process_path) LIKE '{{implant_path_pattern}}') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY process_path HAVING hosts <= 3
```

## persistence-muddyrot-task
<!-- MuddyRot Scheduled Task Persistence -->
Directly search for the scheduled task name and any tasks pointing to writable directories like ProgramData or Temp.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Identification of the 'DocumentsManagerReporter' task or behavioral matches
  for binaries running from ProgramData/Temp via task scheduler.
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
SELECT device_hostname, job_name, job_cmd_line, job_user_name, time FROM hb_scheduled_job WHERE (LOWER(job_name) = 'documentsmanagerreporter' OR LOWER(job_cmd_line) LIKE '%documentsmanagerreporter.exe%' OR (LOWER(job_cmd_line) LIKE '%\\programdata\\%' AND LOWER(job_cmd_line) LIKE '%.exe%') OR (LOWER(job_cmd_line) LIKE '%\\temp\\%' AND LOWER(job_cmd_line) LIKE '%.exe%')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## c2-infrastructure-ips
<!-- Raw TCP Connections to Known IPs -->
Detect outbound traffic to the report's attributed C2 infrastructure on port 443.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_ips=c2_ips)
~~~yaml
expected: Connections to specified IPs from unusual processes. Port 443 is used but
  the protocol is raw TCP, not HTTPS.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## implant-buffer-file
<!-- Unusual Files in Working Directory -->
Generalize the search for exfiltration buffers or unusual files in the implant's directory.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation or modification of files with no extension, .tmp extensions, or
  the specific name 'exit' in MuddyRot-associated paths.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_name) = 'exit' OR LOWER(file_name) NOT LIKE '%.%' OR LOWER(file_name) LIKE '%.tmp') AND (LOWER(file_path) LIKE '%\\programdata\\%' OR LOWER(file_path) LIKE '%\\temp\\%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## triage-agent
<!-- Triage MuddyRot Activity -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-software
- rare-binaries-programdata
- persistence-muddyrot-task
- c2-infrastructure-ips
- implant-buffer-file
max_iterations: 3
objective: Determine if any host shows evidence of MuddyRot infection. Look for rare
  binaries in ProgramData/softwarememory, scheduled tasks pointing to those paths,
  and raw TCP connections to the specified C2 IPs.
success_criteria: A verdict of malicious | suspicious | benign citing specific process,
  task, and network rows.
tools:
- endpoint
- network
```

## route-decision
<!-- Route on Verdict -->
if~: "The triage verdict is malicious for at least one host and includes persistence and network activity." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate the identified rare process, and remove the associated scheduled task. Collect the binary for analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Response -->
```manual target=analyst
Review the triage agent's output and cited rows. If confirmed, look for lateral movement from this host. Provide tuning feedback if benign binaries in ProgramData triggered the baseline query.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document that the MuddyRot indicators were not found on the scoped hosts. Schedule a re-run next month to monitor for new campaigns.
```
→ end

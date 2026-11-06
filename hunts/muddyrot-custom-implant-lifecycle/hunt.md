---
analysis: This phased hunt connects unpatched server vulnerabilities to specific host
  and network indicators that would be too noisy as standalone rules. By pivoting
  from a baseline of rare ProgramData binaries to specific C2 IPs, it provides the
  context an analyst needs to confirm an intrusion rather than an isolated tool detection.
blind_spots:
- id: com-task-registration-blind-spot
  question: Was the scheduled task registered via COM rather than schtasks.exe?
  requires: COM object invocation logging
  risk: The hunt may not see the registration event if it bypasses the schtasks.exe
    utility, relying instead on the visibility of the job store.
  stage: muddyrot-persistence-installation
- id: c2-obfuscated-payloads
  question: What specific commands were sent to the reverse shell?
  requires: Network payload decryption
  risk: MuddyRot obfuscates its C2 traffic using a byte subtraction; raw network logs
    will show the traffic volume but not the operator's intent.
  stage: command-and-control-raw-tcp
coverage:
- stage: initial-access-delivery
  status: covered
  steps:
  - vulnerable-server-scope
- stage: muddyrot-persistence-installation
  status: covered
  steps:
  - detect-implant-file
  - detect-scheduled-task
- stage: command-and-control-raw-tcp
  status: covered
  steps:
  - c2-network-traffic
- stage: interactive-shell-and-file-ops
  status: covered
  steps:
  - rare-programdata-binaries
  - reverse-shell-execution
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: MuddyWater's move to custom implants like MuddyRot bypasses standard
    RMM-based detections. This hunt provides a negative result over the estate for
    this emerging Iranian tradecraft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed the MuddyRot implant on a public-facing server,
  establishing persistence via a custom scheduled task and initiating a reverse shell
  to known Iranian C2 infrastructure.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1053.005
- attack.t1059.003
- attack.t1041
- attack.t1090.003
name: MuddyRot Custom Implant Lifecycle
parameters:
  c2_ips:
    default:
    - 91.235.234.202
    - 146.19.143.14
    description: Known MuddyRot C2 infrastructure IPs.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: list[ip]
  implant_path:
    default: C:\ProgramData\softwarememory\documentsmanagerreporter.exe
    description: Target installation path for the MuddyRot implant.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: path
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of vulnerable servers found in the scoping step; leave
      empty to hunt across the full estate.
    type: list[host]
  task_name:
    default: DocumentsManagerReporter
    description: Name of the persistence scheduled task.
    from:
      kind: article
      observed: '2024-06-20'
      ref: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
    type: string
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize Exchange and SharePoint servers identified in the vulnerability
  scoping step. MuddyWater uses these servers as beachheads before establishing persistent
  implants in ProgramData.
references:
- name: "Sekoia TDR \u2014 MuddyWater replaces Atera with custom MuddyRot implant"
  url: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
related:
- hunt: atera-rmm-abuse-detection
  reason: The report notes MuddyWater is replacing Atera, but older or concurrent
    campaigns may still use the RMM tool.
  relation: alternative
scenario:
  stages:
  - name: Spearphishing or Application Exploitation
    observables:
    - PDF files with Egnyte links
    - Exploitation of Exchange or SharePoint servers
    - Downloads from egnyte.com
    slug: initial-access-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: MuddyRot Deployment and Persistence
    observables:
    - C:\ProgramData\softwarememory\documentsmanagerreporter.exe
    - Scheduled Task named DocumentsManagerReporter
    - COM CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DD
    - Mutex named DocumentUpdater
    slug: muddyrot-persistence-installation
    tactic: persistence
    techniques:
    - T1053.005
    - T1059
  - name: C2 Fingerprinting and Communication
    observables:
    - TCP port 443
    - 91.235.234.202
    - 146.19.143.14
    - Hostname/username string fingerprinting
    slug: command-and-control-raw-tcp
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1041
  - name: Reverse Shell and File Operations
    observables:
    - cmd.exe spawned with anonymous pipes
    - Buffer file named 'exit' in working directory
    - Command IDs 0x1 (Upload), 0x2 (Download), 0x3 (Reverse Shell)
    slug: interactive-shell-and-file-ops
    tactic: execution
    techniques:
    - T1059.003
  summary: MuddyWater transitioned from leveraging legitimate RMM tools to a custom
    C-based implant called MuddyRot, delivered via phishing PDFs with Egnyte links
    or server exploitation. The implant establishes persistence via scheduled tasks
    using COM objects and provides reverse shell and file transfer capabilities over
    raw TCP port 443.
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


# MuddyRot Custom Implant Lifecycle

MuddyWater (MOIS) has transitioned from legitimate RMM tools like Atera to a custom C-based implant named MuddyRot. This hunt identifies the implant across its lifecycle: from the presence of unpatched vulnerabilities to the installation of its documentsmanagerreporter.exe binary in ProgramData, its scheduled task persistence, and finally its raw TCP C2 communication and interactive reverse shell behavior. The hunt follows a phased flow to build confidence from installation to active exploitation.

## vulnerable-server-scope
<!-- Scope vulnerable public-facing servers -->
Identify servers with unpatched vulnerabilities in Exchange or SharePoint, which are primary targets for MuddyWater initial access.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of high-severity vulnerabilities on servers. Silence means no such
  vulnerabilities are currently known.
reads:
- affected_package_name
- affected_package_version
- device_uid
- severity
- severity_id
- status
- title
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_uid, affected_package_name, affected_package_version, title, severity FROM hb_vulnerability_finding WHERE (LOWER(title) LIKE '%exchange%' OR LOWER(title) LIKE '%sharepoint%') AND status != 'suppressed' AND severity_id >= 4
```

## installation-signals
<!-- Search for installation and persistence -->
parallel:
- → detect-implant-file
- → detect-scheduled-task
join: → early-stage-triage

## detect-implant-file
<!-- MuddyRot binary drop in ProgramData -->
Detect the creation of the MuddyRot binary in the specific softwarememory directory.

```sqlite target=endpoint role=detection-candidate params=(implant_path=implant_path, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A high-fidelity hit for the documentsmanagerreporter.exe file creation on
  a server.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) = LOWER('{{implant_path}}') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## detect-scheduled-task
<!-- Implant scheduled task persistence -->
Find the scheduled task used to ensure the implant survives reboots.

```sqlite target=endpoint role=enrichment params=(task_name=task_name, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A task named DocumentsManagerReporter pointing to the implant binary.
reads:
- device_hostname
- job_cmd_line
- job_name
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, job_name, job_cmd_line, time FROM hb_scheduled_job WHERE LOWER(job_name) = LOWER('{{task_name}}') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Triage early-stage indicators -->
```agent target=hunter
cite: required
context:
- vulnerable-server-scope
- detect-implant-file
- detect-scheduled-task
max_iterations: 6
objective: Determine if the file and task artifacts indicate a successful MuddyRot
  deployment on any high-risk host.
success_criteria: A verdict of 'compromised' for any host with matching installation
  signals.
tools:
- endpoint
- network
```

## execution-signals
<!-- Search for follow-on execution and C2 -->
parallel:
- → c2-network-traffic
- → rare-programdata-binaries
- → reverse-shell-execution
join: → follow-on-triage

## c2-network-traffic
<!-- C2 traffic to MuddyWater IPs -->
Detect raw TCP connections to the specific Iranian IPs associated with MuddyRot campaigns.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, lookback_days=lookback_days)
~~~yaml
expected: Network connections from the implant host to known C2 servers on port 443.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-programdata-binaries
<!-- Rare binaries in ProgramData -->
Stack-count binaries in ProgramData to highlight unique implants like MuddyRot that do not appear across the rest of the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The MuddyRot binary should appear as a rare path (host_count = 1).
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_path) LIKE 'c:\programdata\%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## reverse-shell-execution
<!-- Reverse shell cmd.exe activity -->
Identify cmd.exe instances spawned by the implant path, signifying interactive operator activity.

```sqlite target=endpoint role=triage params=(implant_path=implant_path, lookback_days=lookback_days)
~~~yaml
expected: Process events where the implant binary is the parent of a command shell.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) = LOWER('{{implant_path}}') AND LOWER(process_name) LIKE '%cmd.exe' AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Correlate full lifecycle -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- c2-network-traffic
- rare-programdata-binaries
- reverse-shell-execution
max_iterations: 6
objective: Integrate the early-stage compromise verdict with current C2 and shell
  evidence to determine if the intrusion is active.
success_criteria: A verdict of 'malicious' for hosts where the full chain is observed.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the follow-on-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: com-task-registration-blind-spot)
else: → close-out

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, terminate the documentsmanagerreporter.exe process, and delete the DocumentsManagerReporter scheduled task.
```
→ analyst-review

## analyst-review
<!-- Detailed analyst investigation -->
```manual target=analyst
Examine process activity around the time of the reverse shell; look for secondary tools MuddyWater often deploys like SharpTypo or remote management software.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
If no malicious activity was found, record the hosts examined and note that no MuddyRot artifacts were visible within the lookback window.
```
→ end

---
analysis: This is a hunt because it pivots between network sockets, process paths,
  and the absence of HTTP protocol logs. A single rule can flag the IP, but the hunt
  determines if the behavior (raw TCP on 443 + ProgramData binary) matches the MuddyRot
  profile.
blind_spots:
- id: telemetry-gap
  question: whether we can see network sockets from all hosts
  requires: an endpoint agent (osquery) or network flow logs
  risk: A host without an agent or flow logging could be beaconing to MuddyRot infrastructure
    undetected.
  stage: command-and-control-raw-tcp
- id: protocol-obfuscation
  question: if the TCP payload contains the expected obfuscated heartbeat
  requires: Layer-7 deep packet inspection or raw PCAP
  risk: Without L7 analysis, we rely on the absence of HTTP logs to infer a custom
    protocol, which could lead to false positives with other raw TCP applications.
  stage: command-and-control-raw-tcp
coverage:
- stage: command-and-control-raw-tcp
  status: covered
  steps:
  - muddyrot-ip-connections
  - rare-external-443-sockets
  - http-logs-for-c2-ips
- reason: Handled in part 1 of this hunt series.
  stage: initial-access-delivery
  status: out_of_scope
- stage: muddyrot-execution-and-setup
  status: covered
  steps:
  - suspicious-implant-process
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: persistence-scheduled-task
  status: out_of_scope
- reason: Belongs to another part of the 'MuddyWater replaces Atera with custom MuddyRot
    implant' series.
  stage: interactive-shell-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: MuddyWater's shift from legitimate Atera tools to the custom MuddyRot
    implant makes traditional RMM-based detections obsolete. A negative result over
    the estate confirms no active beaconing to these known MOIS nodes.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are using the custom MuddyRot implant to maintain command-and-control
  via raw TCP sockets on port 443, bypassing HTTP-centric security controls and leveraging
  specific hardcoded infrastructure.
labels:
- hunt
- attack.t1041
- attack.t1090.003
name: MuddyRot Raw TCP C2 and Infrastructure
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
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2024-06-20'
      ref: standard hunt parameter
    type: number
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
rationale: The hunt should be scoped to all workstations and servers. Initial priority
  is on servers that have historically had internet exposure or show any unusual scheduled
  tasks.
references:
- name: "Sekoia \u2014 MuddyWater replaces Atera with custom MuddyRot implant"
  url: https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/
related:
- hunt: muddyrot-persistence-scheduled-task
  reason: Persistence mechanisms using Scheduled Tasks are handled in a separate hunt
    focused on hb_scheduled_job.
  relation: out-of-scope-alternative
- hunt: muddyrot-implant-execution-persistence
  relation: follows
scenario:
  stages:
  - name: Initial Access via Phishing or Exploitation
    observables:
    - PDF decoys related to online courses or webinars
    - Links to Egnyte storage service
    - Malicious ZIP archives containing MuddyRot
    - Exploitation of Exchange or SharePoint servers
    slug: initial-access-delivery
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: MuddyRot Implant Execution
    observables:
    - Process documentsmanagerreporter.exe
    - Mutex named DocumentUpdater
    - Dynamic loading of Kernel32.dll, Advapi32.dll, Ole32.dll, and Ws2_32.dll
    - In-memory string deobfuscation
    slug: muddyrot-execution-and-setup
    tactic: execution
    techniques:
    - T1059
  - name: Persistence via Scheduled Task
    observables:
    - Path c:\programdata\softwarememory\documentsmanagerreporter.exe
    - Scheduled task named DocumentsManagerReporter
    - COM object CLSID 0F87369F-A4E5-4CFC-BD3E-73E6154572DDBD3E73E6154572DD
    - Daily execution schedule
    slug: persistence-scheduled-task
    tactic: persistence
    techniques:
    - T1053.005
  - name: C2 Communication over Port 443
    observables:
    - IP 91.235.234.202
    - IP 146.19.143.14
    - TCP port 443
    - Obfuscated C2 traffic (byte subtraction by 3)
    slug: command-and-control-raw-tcp
    tactic: command-and-control
    techniques:
    - T1041
    - T1090.003
  - name: Reverse Shell and File Triage
    observables:
    - cmd.exe spawned via anonymous pipes
    - Buffer file named 'exit' in working directory
    - Hostname and username fingerprinting in format 'hostname/username'
    slug: interactive-shell-and-exfiltration
    tactic: execution
    techniques:
    - T1059.003
  summary: MuddyWater is distributing a new C-based implant named MuddyRot via spear
    phishing PDF lures and Egnyte downloads, replacing their previous use of legitimate
    RMM tools like Atera. The implant establishes persistence via scheduled tasks
    using COM objects and provides reverse shell and file management capabilities
    over raw TCP port 443.
series:
  index: 3
  slug: muddywater-replaces-atera-with-custom-muddyrot-implant
  title: MuddyWater replaces Atera with custom MuddyRot implant
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# MuddyRot Raw TCP C2 and Infrastructure

This hunt targets the command-and-control phase of the MuddyRot implant. Unlike the legitimate RMM tools MuddyWater used previously, MuddyRot utilizes an obfuscated raw TCP protocol on port 443. We identify compromised hosts by looking for direct connections to known C2 IPs, detecting the specific implant binary in ProgramData, and identifying anomalous non-HTTP traffic on common web ports. The hunt combines network, process, and HTTP telemetry to provide a comprehensive view of the adversary's C2 channel.

## muddyrot-ip-connections
<!-- Direct Connections to MuddyRot C2 IPs -->
Identify any hosts communicating with the specific IP addresses named in the MuddyRot research.

```sqlite target=network role=scoping params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Rows indicating connections to the named IPs on port 443. Silence means
  these specific IPs were not contacted.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## behavioral-discovery
<!-- Parallel Behavioral Discovery -->
parallel:
- → suspicious-implant-process
- → rare-external-443-sockets
- → http-logs-for-c2-ips
join: → triage-verdict

## suspicious-implant-process
<!-- MuddyRot Implant Execution Path -->
Detect the MuddyRot binary specifically where it attempts to masquerade in the ProgramData directory.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Execution of 'documentsmanagerreporter.exe' or binaries in the 'softwarememory'
  folder. This is a high-confidence signal.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_path, process_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\programdata\\softwarememory\\%' OR LOWER(process_name) = 'documentsmanagerreporter.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-external-443-sockets
<!-- Rare External Port 443 Destinations -->
Identify anomalous 443 destinations that are not standard web services, which MuddyRot uses for C2.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A destination IP used on port 443 by only a few hosts, characteristic of
  private C2 infrastructure.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT dst_endpoint_ip, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = 443 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING hosts <= 3 ORDER BY hosts ASC
```

## http-logs-for-c2-ips
<!-- HTTP Traffic Check for C2 IPs -->
Verify if traffic to the C2 IPs is actually HTTP. MuddyRot uses raw TCP, so absence of HTTP logs for a 443 socket is a strong indicator of an anomalous protocol.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips)
~~~yaml
expected: Zero rows in HTTP activity for an IP that shows active sockets on port 443
  suggests the use of a custom, non-HTTP protocol like MuddyRot.
reads:
- dst_endpoint_ip
- time
- url_hostname
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT dst_endpoint_ip, url_hostname, COUNT(*) AS requests FROM hb_http_activity WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, url_hostname
```

## triage-verdict
<!-- Triage Verdict per Host -->
```agent target=hunter
cite: required
context:
- muddyrot-ip-connections
- suspicious-implant-process
- rare-external-443-sockets
- http-logs-for-c2-ips
max_iterations: 4
objective: Determine if any host exhibits signs of the MuddyRot implant, particularly
  looking for 'documentsmanagerreporter.exe' or raw TCP port 443 connections to the
  specified IPs or rare destinations.
success_criteria: Verdicts of malicious, suspicious, or benign with supporting citations
  from the query steps.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and begin incident response. Collect the binary from c:\programdata\softwarememory\ for forensics.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the network sockets and process command lines. Specifically check for socket activity on port 443 that has no corresponding web browser or HTTP client logs. Search for signs of string obfuscation (decimal subtraction) in memory if possible.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record that MuddyRot C2 infrastructure and associated behavioral patterns were not found during the lookback period.
```
→ end

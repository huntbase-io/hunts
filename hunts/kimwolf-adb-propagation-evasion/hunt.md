---
analysis: A standard rule for port 5555 triggers on legitimate developer activity;
  this hunt uses a gated agent-led flow to validate network leads against endpoint
  file drops and rare process masquerading.
blind_spots:
- id: no-network-telemetry
  owner: Network Engineering
  question: whether ADB connections occurred without being logged by a network sensor
  remediation: Enable flow logging for all VLANs containing IoT or Android TV devices.
  requires: hb_network_connection with port 5555 coverage on internal segments
  risk: A host can be exploited via ADB without generating a network row, causing
    the lead step to skip it.
  stage: initial-access-adb-misuse
- id: unmanaged-iot-devices
  owner: Asset Management
  question: whether Kimwolf is running on devices without an endpoint agent
  remediation: Enroll Android IoT devices in a managed inventory with process auditing
    enabled.
  requires: hb_process_activity on Android TV devices
  risk: Unmanaged IoT boxes contribute no file or process rows; the hunt only observes
    the managed estate.
  stage: execution-malware-installation
coverage:
- stage: initial-access-adb-misuse
  status: covered
  steps:
  - lead-adb-connections
- stage: execution-malware-installation
  status: covered
  steps:
  - malware-file-drops
- stage: defense-evasion-process-masquerading
  status: covered
  steps:
  - masqueraded-processes
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: c2-ens-resolution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: c2-local-proxy-routing
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: impact-ddos-flooding
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kimwolf v7 weaponizes Android IoT devices for large-scale DDoS; detecting
    initial propagation and masquerading prevents the environment from being used
    as botnet infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder exploits unauthenticated ADB services on port 5555 to drop
  ELF binaries and masquerades as the netd_service system process to avoid detection
  on Android IoT devices.
labels:
- hunt
- attack.t1190
- attack.t1059
- attack.t1036.005
name: Kimwolf ADB Propagation and Evasion
parameters:
  adb_port:
    default: '5555'
    description: The standard port for unauthenticated ADB access.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malware_filenames:
    default:
    - libdevice.so
    - kernel.so
    description: Filenames observed in Kimwolf v7 payloads.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts identified in the lead step to narrow forensics.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and unmanaged IoT segments. While the v7 variant targets
  Android, the AISURU codebase targets Linux IoT; scoping should include both platforms
  if unauthenticated port 5555 is exposed.
references:
- name: "Unit 42 \u2014 Kimwolf v7: An Evolution of the Kimwolf Botnet"
  url: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
related:
- hunt: kimwolf-infrastructure-ens-routing
  reason: This hunt focuses on access and endpoint evasion; blockchain-based C2 resolution
    and Tor routing are handled in a separate infrastructure hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Unauthenticated ADB Access
    observables:
    - Inbound connections to TCP port 5555 (Android Debug Bridge)
    - Use of residential proxy services to tunnel into local networks
    slug: initial-access-adb-misuse
    tactic: initial-access
    techniques:
    - T1190
  - name: Malware Installation via ADB
    observables:
    - Installation of ELF binaries on Android devices
    - Dropped files named libdevice.so or libn[redacted]kernel.so
    slug: execution-malware-installation
    tactic: execution
    techniques:
    - T1059
  - name: Process Name Masquerading
    observables:
    - Process name masked as netd_service
    - Stripped ELF binaries compiled with Android NDK
    - Creation of Unix domain socket beginning with @n[redacted]boxv7
    slug: defense-evasion-process-masquerading
    tactic: defense-evasion
    techniques:
    - T1036.005
  - name: ENS C2 Resolution
    observables:
    - Outbound traffic to 0xrpc.io
    - Outbound traffic to eth.llamarpc.com
    - Outbound traffic to ethereum-rpc.publicnode.com
    - Outbound traffic to eth-protect.rpc.blxrbdn.com
    - Outbound traffic to eth.merkle.io
    - Outbound traffic to eth.rpcuniverse.com
    - DNS queries for ENS C2 domains
    slug: c2-ens-resolution
    tactic: command-and-control
    techniques:
    - T1102.003
  - name: Local Proxy Architecture
    observables:
    - Local network listener on 127.0.0.1:23075
    - 'Connections to v3 Tor .onion address: edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion'
    - Direct C2 connections to 212.193.31.119, 212.193.31.122 (port 13)
    - Direct C2 connections to 212.193.31.92, 212.193.31.158 (port 443)
    slug: c2-local-proxy-routing
    tactic: command-and-control
    techniques:
    - T1090
  - name: DDoS Flood Activities
    observables:
    - HTTP/2 floods with Chrome browser fingerprints
    - High-performance UDP floods using ARM NEON SIMD optimizations
    - TCP SYN, ACK, and RST floods
    - DNS query floods
    - ICMP floods
    slug: impact-ddos-flooding
    tactic: impact
    techniques:
    - T1498.001
  summary: Kimwolf v7 is an evolution of an Android IoT botnet that targets unauthenticated
    ADB interfaces on port 5555 for initial access. The malware employs highly resilient
    command-and-control infrastructure using Ethereum Name Service (ENS) for resolution
    and Tor as a backup, ultimately performing optimized DDoS floods including stealthy
    HTTP/2 browser fingerprinting.
series:
  index: 1
  slug: kimwolf-v7-an-evolution-of-the-kimwolf-botnet
  title: 'Kimwolf v7: An Evolution of the Kimwolf Botnet'
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


# Kimwolf ADB Propagation and Evasion

The Kimwolf (AISURU) botnet targets Android IoT devices by abusing unauthenticated Android Debug Bridge (ADB) services. This hunt identify inbound connections to port 5555 from suspicious external sources as a lead, then gates forensic queries for specific malware file drops and masqueraded processes. An agent correlates the initial network access with endpoint artifacts to confirm the infection chain.

## lead-adb-connections
<!-- Inbound connections to ADB port -->
Identify hosts receiving inbound network traffic on the ADB port as a potential initial access lead.

```sqlite target=network role=scoping params=(adb_port=adb_port, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts receiving traffic on port 5555. Silence suggests no active
  ADB exposure was captured in logs.
reads:
- device_hostname
- src_endpoint_ip
- src_endpoint_port
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, src_endpoint_port, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE dst_endpoint_port = {{adb_port}} AND (LOWER(direction) = 'inbound' OR direction IS NULL) AND time >= datetime('now', '-{{lookback_days}} days')
```

## adb-lead-evaluator
<!-- Evaluate ADB lead -->
```agent target=hunter
cite: required
context:
- lead-adb-connections
max_iterations: 3
objective: Examine src_endpoint_ip values from lead-adb-connections. Focus on external
  IPs, known residential proxy nodes, or IP addresses not part of the internal network.
  Identify which hosts warrant expensive endpoint forensic queries.
success_criteria: A per-host verdict citing suspicious source IPs and identifying
  the most at-risk devices.
tools:
- endpoint
- network
```

## gate-on-adb
<!-- Gate on suspicious ADB -->
if~: "the adb-lead-evaluator finds at least one inbound connection from a non-standard or external source IP" (confidence: high, judge=hunter)
then: → parallel-forensics
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-network-telemetry)
else: → close-out

## parallel-forensics
<!-- Endpoint forensics fan-out -->
parallel:
- → malware-file-drops
- → masqueraded-processes
join: → triage-infection

## malware-file-drops
<!-- Kimwolf ELF binary drops -->
Detect the creation of known Kimwolf file indicators or the 'libn' kernel naming pattern.

```sqlite target=endpoint role=detection-candidate params=(malware_filenames=malware_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation of libdevice.so or kernel.so, likely by an ADB shell or proxy-related
  process.
reads:
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE (instr(',' || '{{malware_filenames}}' || ',', ',' || LOWER(file_name) || ',') > 0 OR LOWER(file_name) LIKE 'libn%kernel.so') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## masqueraded-processes
<!-- Rare masqueraded processes -->
Identify processes masquerading as netd_service that stand out from legitimate system noise.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A netd_service process running from a non-standard path (e.g., /data/local/tmp)
  or with a low host count.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, on_disk, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%netd_service' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path, process_cmd_line, on_disk
```

## triage-infection
<!-- Triage Kimwolf infection -->
```agent target=hunter
cite: required
context:
- adb-lead-evaluator
- malware-file-drops
- masqueraded-processes
max_iterations: 4
objective: Determine if any host shows a sequence of suspicious ADB network activity
  followed by the creation of Kimwolf binaries or a rare instance of a netd_service
  process.
success_criteria: A verdict of malicious | suspicious | benign citing specific rows
  across the three surfaces.
tools:
- endpoint
- network
```

## decision-route
<!-- Route on verdict -->
if~: "the triage-infection verdict is malicious or suspicious for at least one host, confirming ADB activity followed by malware artifacts" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: unmanaged-iot-devices)
else: → manual-review

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Capture the netd_service binary and any identified .so files from /data/local/tmp or other user-writable directories.
```
→ manual-review

## manual-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited rows. Confirm the source IPs for the ADB connections against residential proxy feeds. Verify that the netd_service binary is not a legitimate part of the device OS for that specific hardware vendor.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings. Recommend disabling ADB globally for all Android IoT devices in the estate. If the malware filenames were confirmed, promote the file activity query to a detection rule.
```
→ end

---
analysis: A simple detection rule for the 'netd_service' process might be noisy in
  some IoT environments. This hunt corroborates the process name against file artifacts
  (libdevice.so) and inbound ADB network patterns, providing the multi-surface context
  needed to confirm an active botnet infection.
blind_spots:
- id: incomplete-telemetry-coverage
  question: Does the '@n*boxv7' mutex socket exist on the host?
  requires: unix_domain_socket logs
  risk: While we see the process name, the unix domain socket is the definitive mutex
    for Kimwolf v7 and is not visible in standard process snapshots.
  stage: execution-masquerading-process
- id: residential-proxy-masking
  question: Is the source IP of the ADB connection a residential proxy?
  requires: IP reputation with proxy/residential labels
  risk: Kimwolf uses residential proxies to reach local ADB instances; without source
    IP reputation data, we cannot distinguish these connections from internal management
    traffic.
  stage: initial-access-adb-proxy
coverage:
- stage: initial-access-adb-proxy
  status: covered
  steps:
  - adb-inbound-connections
- stage: execution-masquerading-process
  status: covered
  steps:
  - masqueraded-process-activity
  - malicious-file-activity
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: c2-ens-blockchain-resolution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: c2-tor-and-local-proxy
  status: out_of_scope
- reason: 'Belongs to another part of the ''Kimwolf v7: An Evolution of the Kimwolf
    Botnet'' series.'
  stage: impact-distributed-denial-of-service
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Kimwolf v7 specifically targets unmanaged IoT devices like Android
    TV boxes which often lack standard security agents. A negative result confirms
    that the fleet's exposure to common unauthenticated ADB exploitation is minimized.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using unauthenticated ADB access on port 5555 to install
  Kimwolf malware, which then masquerades as the 'netd_service' system process.
labels:
- hunt
- attack.t1133
- attack.t1036.004
- attack.t1546
name: 'Kimwolf v7: Masquerading and ADB Propagation'
parameters:
  kimwolf_filenames:
    default:
    - libdevice.so
    - kernel.so
    description: Characteristic filenames associated with the Kimwolf binary.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  masquerade_process_names:
    default:
    - netd_service
    description: Common process names used by Kimwolf for masquerading.
    from:
      kind: article
      observed: '2026-08-11'
      ref: unit42-kimwolf-v7
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the hunt on.
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on the 'Android' and 'Linux' platforms first as Kimwolf specifically
  targets these IoT environments. If the estate is large, prioritize devices with
  public-facing IPs or those located in segments that allow inbound 5555/TCP.
references:
- name: "Unit 42 \u2014 Kimwolf v7: An Evolution of the Kimwolf Botnet"
  url: https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/
related:
- hunt: kimwolf-c2-infrastructure-resolution
  reason: This hunt focuses on endpoint infection and masquerading; Ethereum ENS resolution
    and Tor backup C2 are behavioral phases handled in a companion hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Unauthenticated ADB Access
    observables:
    - port 5555
    - residential proxy misuse
    slug: initial-access-adb-proxy
    tactic: initial-access
    techniques:
    - T1133
  - name: Process Masquerading and Mutex
    observables:
    - 'process_name: netd_service'
    - 'file_name: libdevice.so'
    - 'file_name: kernel.so'
    - 'unix_domain_socket: @n*boxv7'
    slug: execution-masquerading-process
    tactic: defence-evasion
    techniques:
    - T1036.004
    - T1546
  - name: ENS Domain C2 Resolution
    observables:
    - 'domain: 0xrpc.io'
    - 'domain: eth.llamarpc.com'
    - 'domain: ethereum-rpc.publicnode.com'
    - 'domain: eth-protect.rpc.blxrbdn.com'
    - 'domain: eth.merkle.io'
    - 'domain: eth.rpcuniverse.com'
    slug: c2-ens-blockchain-resolution
    tactic: command-and-control
    techniques:
    - T1568
    - T1102
  - name: Local Proxy and Tor Backup
    observables:
    - 127.0.0.1:23075
    - edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion
    - 'SOCKS5 greeting: 0x05 0x01 0x00'
    slug: c2-tor-and-local-proxy
    tactic: command-and-control
    techniques:
    - T1090
    - T1090.003
  - name: Vectorized DDoS Flooding
    observables:
    - 'destination_ip: 212.193.31.119'
    - 'destination_ip: 212.193.31.122'
    - 'destination_ip: 212.193.31.92'
    - 'destination_ip: 212.193.31.158'
    - 'destination_port: 13'
    - HTTP/2 browser fingerprints
    - ARM NEON SIMD checksum acceleration
    slug: impact-distributed-denial-of-service
    tactic: impact
    techniques:
    - T1498.001
  summary: Kimwolf v7 is an Android-based IoT botnet that gains initial access through
    unauthenticated ADB on port 5555 via residential proxies. It maintains operational
    resilience using Ethereum Name Service (ENS) for C2 resolution and Tor as a backup,
    ultimately performing high-performance DDoS attacks with browser-fingerprinted
    HTTP/2 floods.
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


# Kimwolf v7: Masquerading and ADB Propagation

Kimwolf (AISURU) v7 is a specialized botnet targeting Android-based IoT devices, such as TV boxes. It propagates by misusing residential proxies to find exposed ADB instances on port 5555. Once on a device, the malware masks its process name as 'netd_service' and drops characteristic ELF binaries such as 'libdevice.so' and 'kernel.so'. This hunt identifies these compromised devices by correlating inbound ADB traffic with masqueraded process activity and specific file drops.

## identify-targetable-iot
<!-- Identify Targetable IoT Assets -->
Identify Android and Linux devices that are within the known target profile of the Kimwolf botnet.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames belonging to Android or Linux systems. Absence means
  no such devices are enrolled.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE (LOWER(platform) LIKE '%android%' OR LOWER(platform) LIKE '%linux%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-compromise
<!-- Corroborate Evidence of Compromise -->
parallel:
- → masqueraded-process-activity
- → malicious-file-activity
- → adb-inbound-connections
join: → triage-kimwolf

## masqueraded-process-activity
<!-- Masqueraded Process Activity -->
Detect the Kimwolf v7 process masquerading as 'netd_service'.

```sqlite target=endpoint role=detection-candidate params=(masquerade_process_names=masquerade_process_names, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A process named 'netd_service' running on an Android or Linux host. Genuine
  Android services usually use 'netd', not 'netd_service'.
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
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE instr(',' || '{{masquerade_process_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## malicious-file-activity
<!-- Malicious ELF File Activity -->
Identify the presence or creation of the specific ELF filenames used by Kimwolf v7.

```sqlite target=endpoint role=enrichment params=(kimwolf_filenames=kimwolf_filenames, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Creation or access of files named 'libdevice.so' or 'kernel.so' on the target
  devices.
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
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{kimwolf_filenames}}' || ',', ',' || file_name || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## adb-inbound-connections
<!-- ADB Inbound Connection Baseline -->
Identify hosts that are unusually exposed to inbound ADB traffic (port 5555).

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts receiving inbound 5555/TCP traffic from a small number of
  unique external IPs, which is common during targeted botnet infection.
prevalence:
  by: src_endpoint_ip
  key:
  - device_hostname
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, COUNT(DISTINCT src_endpoint_ip) AS unique_src_ips, MIN(time) AS first_connection, MAX(time) AS last_connection FROM hb_network_connection WHERE dst_endpoint_port = 5555 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING unique_src_ips <= 3
```

## triage-kimwolf
<!-- Triage Kimwolf Infection -->
```agent target=hunter
cite: required
context:
- identify-targetable-iot
- masqueraded-process-activity
- malicious-file-activity
- adb-inbound-connections
max_iterations: 3
objective: Determine if any host shows evidence of Kimwolf masquerading ('netd_service')
  alongside infection indicators like 'libdevice.so' or inbound port 5555 traffic.
success_criteria: A per-host verdict citing rows from the corroboration steps.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is 'malicious' for at least one host" (confidence: high, judge=hunter)
then: → contain-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry-coverage)
else: → analyst-review

## contain-infected-host
<!-- Contain Infected IoT Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any local credentials. Preserve 'libdevice.so' or 'kernel.so' for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Close-out -->
```manual target=analyst
Verify the triage findings. If 'netd_service' is a false positive from a legitimate app, record the app details for tuning. If confirmed malicious, ensure port 5555 is blocked at the firewall for all IoT segments.
```
→ end

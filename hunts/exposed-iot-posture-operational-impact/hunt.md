---
analysis: A single rule can fire on a specific IoT vulnerability (CVE), but this hunt
  correlates internal behavioral snapshots (rare processes) with external exposure
  findings (Shodan) and cloud control-plane health (Azure IoT Hub) to find compromise
  across disparate surfaces.
blind_spots:
- id: no-endpoint-telemetry
  owner: Infrastructure Team
  question: whether unmanaged or third-party IoT devices are present but not reporting
    to internal inventories
  remediation: Deploy passive network monitoring to identify devices by MAC address
    and OUI.
  requires: an endpoint agent on IoT hardware
  risk: Devices without an agent contribute no process rows; the hunt is limited to
    the enrolled estate and external scans.
  stage: initial-access-eol-exploitation
- id: iot-hub-audit-gap
  owner: Cloud Security
  question: whether specific malicious commands (e.g. temperature changes) were sent
    via the hub
  remediation: Enable and ingest Azure IoT Hub 'CloudToDevice' and 'DeviceTelemetry'
    logs.
  requires: Azure IoT Hub diagnostic logs
  risk: A hub failure indicates a problem but not the specific actor intent; without
    command-level logs, the operational impact cannot be fully attributed.
  stage: operational-impact
coverage:
- stage: initial-access-eol-exploitation
  status: covered
  steps:
  - identify-iot-inventory
  - rare-iot-processes
  - exposed-management-interfaces
- stage: operational-impact
  status: covered
  steps:
  - iot-hub-health
- reason: "Belongs to another part of the 'My IoT devices are no longer supported\
    \ \u2013 is my smart home safe?' series."
  stage: botnet-conscription-and-c2
  status: out_of_scope
- reason: "Belongs to another part of the 'My IoT devices are no longer supported\
    \ \u2013 is my smart home safe?' series."
  stage: dns-redirection-and-phishing
  status: out_of_scope
- reason: "Belongs to another part of the 'My IoT devices are no longer supported\
    \ \u2013 is my smart home safe?' series."
  stage: lateral-movement-from-iot
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: End-of-life IoT devices represent a permanent and unpatchable attack
    surface. A negative result over the enrolled estate confirms that known smart
    hardware is not currently showing signs of exploit-driven behavioral or operational
    failure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited unpatched vulnerabilities in end-of-life IoT
  devices, evidenced by rare process execution on identified smart hardware, unauthorized
  external exposure of management ports, and failing states in the IoT control plane.
labels:
- hunt
- attack.t1190
- attack.t1566
- execution
- impact
- initial access
- lateral movement
- azure
name: Exposed IoT Posture and Operational Impact
parameters:
  iot_keywords:
    default:
    - camera
    - dvr
    - nvr
    - gateway
    - smart
    - iot
    - controller
    description: Keywords used to identify potential IoT devices in inventory or hardware
      vendor lists.
    from:
      kind: manual
      observed: '2026-11-19'
      ref: hunt-config
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for process activity and exposure findings.
    from:
      kind: manual
      observed: '2026-11-19'
      ref: hunt-config
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus the internal process hunt.
    from:
      kind: manual
      observed: '2026-11-19'
      ref: hunt-config
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/internet-of-things/iot-devices-no-longer-supported-smart-home-safe/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with devices identifying as cameras, dvr, or routers. Focus on segments
  hosting facility-management or building security systems.
references:
- name: "ESET Research \u2014 My IoT devices are no longer supported \u2013 is my\
    \ smart home safe?"
  url: https://www.welivesecurity.com/en/internet-of-things/iot-devices-no-longer-supported-smart-home-safe/
related:
- hunt: botnet-conscription-and-c2
  reason: This hunt focuses on the initial compromise and operational impact; conscription
    into a botnet requires separate analysis of outbound traffic patterns.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of EoL IoT Devices
    observables:
    - exposed management ports on DVRs and webcams
    - unpatched firmware on refrigerator controllers
    - no-name Android TV boxes with insecure services
    - pre-installed malware on smart devices
    slug: initial-access-eol-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Botnet Conscription and C2 Communication
    observables:
    - Mozi botnet communication
    - BADBOX 2.0 botnet traffic
    - outbound connections to known botnet controllers
    - unusual process launches on Android TV boxes
    slug: botnet-conscription-and-c2
    tactic: execution
    techniques:
    - T1190
  - name: Traffic Redirection to Phishing Sites
    observables:
    - router DNS settings redirection
    - HTTP traffic to malicious phishing domains
    - hijacked router management traffic
    slug: dns-redirection-and-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Lateral Pivoting from IoT Devices
    observables:
    - internal network scanning from IoT device IP addresses
    - unauthorized connections to computer management ports from smart TVs
    - accessing internal assets via hijacked routers
    slug: lateral-movement-from-iot
    tactic: lateral-movement
    techniques:
    - T1190
  - name: Operational Impact on Smart Devices
    observables:
    - unauthorized temperature adjustments in smart controllers
    - remote operation of smart door locks
    - accessing unauthorized smart camera feeds
    slug: operational-impact
    tactic: impact
    techniques:
    - T1190
  summary: Attackers target unpatched vulnerabilities in End-of-Life (EoL) IoT devices,
    such as routers, cameras, and smart controllers, to gain initial network access.
    Once compromised, these devices are used to pivot into internal networks, redirect
    users to phishing sites, or are conscripted into large-scale botnets like Mozi
    and BADBOX 2.0.
series:
  index: 1
  slug: my-iot-devices-are-no-longer-supported-is-my-smart-home-safe
  title: "My IoT devices are no longer supported \u2013 is my smart home safe?"
  total: 2
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  azure:
    category: siem
    huntbase:
      product: azure
    name: azure
  endpoint:
    category: endpoint
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# Exposed IoT Posture and Operational Impact

This hunt identifies end-of-life or unmanaged IoT devices and correlates their presence with behavioural and operational anomalies. We scope the estate using device inventory to identify hardware typical of IoT systems using keyword matching on vendors and hostnames. We then fan out to check independent signals: rare binaries executing on these hosts, internet-exposed management interfaces for matching IoT products, and non-active operational states in Azure IoT Hub. An agent weighs these results to detect compromised devices that may be impacting physical operations or acting as a network beachhead.

## identify-iot-inventory
<!-- Identify potential IoT inventory -->
Find hosts whose hardware vendor or hostname matches known IoT profiles to scope the behavioral hunt.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts, iot_keywords=iot_keywords)
~~~yaml
expected: A list of hosts with IoT-related hardware or naming conventions. Silence
  indicates no managed IoT devices matching these keywords were found.
reads:
- hostname
- hardware_vendor
- hardware_model
- os_name
- first_seen
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT hostname, hardware_vendor, hardware_model, os_name, first_seen FROM hb_devices WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND (instr(',' || '{{iot_keywords}}' || ',', ',' || LOWER(hostname) || ',') > 0 OR instr(',' || '{{iot_keywords}}' || ',', ',' || LOWER(hardware_vendor) || ',') > 0)
```

## correlate-iot-evidence
<!-- Correlate behavioral and operational evidence -->
parallel:
- → rare-iot-processes
- → exposed-management-interfaces
- → iot-hub-health
join: → triage-iot-risk

## rare-iot-processes
<!-- Rare processes on IoT hosts -->
Identify anomalous binaries or unique process paths on the scoped IoT devices that may indicate malware or exploitation.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries seen on only a few IoT hosts. Silence suggests no unusual process
  execution occurred on the enrolled estate during the window.
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
verified_at: '2026-11-21'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING hosts <= 3 ORDER BY hosts, runs
```

## exposed-management-interfaces
<!-- Exposed IoT management interfaces -->
Identify internet-exposed ports for IoT products that match the identified internal hardware profiles.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: External scan results showing management ports (80, 443, 554, 8000) open
  on your IP space for identified IoT products.
reads:
- domain_or_ip
- port
- product
- version
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT domain_or_ip, port, product, version, discovered_at FROM hb_exposed_assets WHERE (LOWER(product) LIKE '%camera%' OR LOWER(product) LIKE '%dvr%' OR LOWER(product) LIKE '%router%' OR LOWER(product) LIKE '%gateway%') AND discovered_at >= datetime('now', '-{{lookback_days}} days')
```

## iot-hub-health
<!-- IoT Hub operational health -->
Check the Azure IoT Hub control plane for failed provisioning or inactive states that indicate operational impact.

```sqlite target=azure role=triage
~~~yaml
expected: Hubs in a failed or inactive state. This may indicate a control-plane takeover
  or device-level failure following an exploit.
reads:
- name
- state
- provisioning_state
- resource_group
silence: not_evidence_of_absence
source: azure_iothub
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT name, state, provisioning_state, resource_group FROM azure_iothub WHERE state != 'Active' OR provisioning_state = 'Failed'
```

## triage-iot-risk
<!-- Triage IoT risk and compromise -->
```agent target=hunter
cite: required
context:
- identify-iot-inventory
- rare-iot-processes
- exposed-management-interfaces
- iot-hub-health
max_iterations: 6
objective: Determine if any IoT devices have been compromised or targeted by external
  actors based on rare binaries and public exposure.
success_criteria: A final verdict for each identified host or hub, citing evidence
  from the query results.
tools:
- azure
- endpoint
```

## route-on-verdict
<!-- Route on IoT verdict -->
if~: "the triage-iot-risk verdict is malicious for at least one host or hub" (confidence: high, judge=hunter)
then: → isolate-iot-device
indeterminate: → firmware-review
unavailable: → firmware-review (blind_spot: no-endpoint-telemetry)
else: → firmware-review

## isolate-iot-device
<!-- Isolate IoT device -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised IoT device at the network level and revoke its Azure IoT Hub credentials.
```
→ firmware-review

## firmware-review
<!-- Firmware and EoL status review -->
```manual target=analyst
For each host identified in scoping, check the manufacturer website for the current firmware version and EoL date. Document devices that no longer receive security updates.
```
→ impact-analysis

## impact-analysis
<!-- Operational impact analysis -->
```manual target=analyst
Review facility logs (temperature, physical access) for the same period as any identified IoT hub failures to confirm operational impact.
```
→ end

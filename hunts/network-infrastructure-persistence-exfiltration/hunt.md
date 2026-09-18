---
analysis: A single rule for TFTP or Telnet creates excessive noise. This hunt uses
  baseline prevalence to distinguish rare, targeted Russian access from routine enterprise
  management, and pivots across vulnerability context to prioritize hits.
blind_spots:
- id: missing-flow-data
  question: whether short-lived TFTP exfiltration sessions occurred between snapshots
  requires: Continuous flow logging (NetFlow/VPC Flow Logs) in hb_network_connection
  risk: TFTP connections are transient; if the surface only reports live sockets,
    the exfiltration window may be missed.
  stage: collection-exfiltration-tftp
- id: synful-knock-inspection
  question: the presence of 'magic' TCP SYN packets used to wake the SYNful Knock
    implant
  requires: Full Packet Capture or IDS (Suricata/Snort) signatures
  risk: Flow data (5-tuple) does not capture the specific TCP option headers required
    to confirm a SYNful Knock magic packet.
  stage: persistence-firmware-implant
- id: device-terminal-logging
  question: what specific commands the actor executed to modify TACACS+ or ACLs
  requires: Cisco Syslog with ARCHIVE/Command logging enabled
  risk: Network flow logs cannot see internal device terminal commands; without syslog,
    the specific configuration changes are a blind spot until a manual audit.
  stage: execution-device-configuration
coverage:
- blind_spot: device-terminal-logging
  reason: Requires device-native terminal logging (syslog) which is not captured by
    network flow or socket surfaces.
  stage: execution-device-configuration
  status: not_visible
- stage: collection-exfiltration-tftp
  status: covered
  steps:
  - tftp-exfiltration-behavior
  - triage-tundra
- blind_spot: synful-knock-inspection
  reason: SYNful Knock requires deep packet inspection of TCP SYN option headers not
    available in flow data.
  stage: persistence-firmware-implant
  status: not_visible
- stage: persistence-local-accounts
  status: covered
  steps:
  - unauthorized-mgmt-access
  - manual-config-audit
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: reconnaissance-network-scanning
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: initial-access-smart-install-exploit
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: initial-access-snmp-bruteforce
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries like Static Tundra specialize in converting unmanaged
    edge devices into long-term persistence nodes. Because these devices cannot run
    EDR agents, hunting in the network fabric for exfiltration and rare management
    access is the primary method to detect them.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A state-sponsored actor has compromised legacy network devices to exfiltrate
  configuration data via TFTP and maintain persistence through unauthorized management
  access.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1190
- attack.t1020
- attack.t1542.001
- attack.t1136.001
name: Network Infrastructure Persistence and Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of network and vulnerability history to examine.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: hunt-standard
    type: number
  management_ports:
    default:
    - '23'
    - '69'
    - '161'
    - '162'
    - '4786'
    description: Ports for Telnet, TFTP, SNMP, and Cisco Smart Install.
    from:
      kind: article
      observed: '2024-05-22'
      ref: Static Tundra
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hostnames identified in the scoping steps to filter behavioral
      queries.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: scoping-output
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/static-tundra/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Use the vulnerability finding and exposed assets steps to create a list
  of target hostnames. These should be prioritised in the behavioral queries using
  the 'scope_hosts' parameter.
references:
- name: 'Static Tundra: long-term exploitation of end-of-life network devices'
  url: https://blog.talosintelligence.com/static-tundra/
- name: Mandiant - SYNful Knock Cisco IOS Firmware Implant
  url: https://www.mandiant.com/resources/blog/synful-knock-uncovering-a-cisco-ios-implant
related:
- hunt: initial-access-smart-install-exploit
  reason: This hunt focuses on post-compromise persistence; the actual exploitation
    of port 4786 is handled in the initial access series.
  relation: out-of-scope-alternative
- hunt: cisco-edge-exposure-smart-install-exploitation
  relation: follows
scenario:
  stages:
  - name: External Exposure Identification
    observables:
    - Public-facing Cisco devices
    - Shodan and Censys scanning of Cisco IOS assets
    - Targeting telecommunications and manufacturing sectors
    slug: reconnaissance-network-scanning
    tactic: reconnaissance
    techniques:
    - T1595
  - name: Smart Install Exploitation
    observables:
    - CVE-2018-0171
    - Traffic on TCP port 4786
    - Unauthenticated remote code execution on Cisco IOS/XE
    slug: initial-access-smart-install-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: SNMP Community String Abuse
    observables:
    - 'SNMP community strings: ''public'', ''anonymous'''
    - UDP port 161/162 activity
    - Spoofed source IP addresses in SNMP traffic
    slug: initial-access-snmp-bruteforce
    tactic: initial-access
    techniques:
    - T1078
    - T1566
  - name: Post-Exploitation Device Command Execution
    observables:
    - 'Command: ''tftp-server nvram:startup-config'''
    - Modifying TACACS+ configuration to hinder logging
    - Modifying ACLs to permit actor-controlled IP ranges
    slug: execution-device-configuration
    tactic: execution
    techniques:
    - T1059
  - name: Configuration Extraction via TFTP
    observables:
    - TFTP connections (UDP port 69)
    - Retrieval of startup-config or running-config
    - Extraction of SNMP community strings and local credentials
    slug: collection-exfiltration-tftp
    tactic: exfiltration
    techniques:
    - T1041
    - T1020
  - name: SYNful Knock Persistence
    observables:
    - SYNful Knock Cisco IOS firmware implant
    - Crafted TCP SYN 'magic packets' for remote access
    - Persistence through device reboots
    slug: persistence-firmware-implant
    tactic: persistence
    techniques:
    - T1542.001
  - name: Local Account and Service Persistence
    observables:
    - Newly created local privileged user accounts
    - Enabled Telnet service (TCP port 23)
    - Additional SNMP read-write community strings
    slug: persistence-local-accounts
    tactic: persistence
    techniques:
    - T1136.001
    - T1133
  summary: Static Tundra (Russian FSB Center 16) targets end-of-life Cisco network
    devices by exploiting CVE-2018-0171 and SNMP misconfigurations to gain initial
    access. The group maintains multi-year persistence using the SYNful Knock firmware
    implant and local user creation, focusing on configuration theft via TFTP for
    long-term espionage against strategic sectors.
series:
  index: 2
  slug: static-tundra-long-term-exploitation-of-end-of-life-network-devices
  title: 'Static Tundra: long-term exploitation of end-of-life network devices'
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


# Network Infrastructure Persistence and Exfiltration

This hunt identifies post-exploitation activity on network infrastructure, focusing on 'Static Tundra' (Russian FSB) TTPs. It focuses on devices vulnerable to CVE-2018-0171 and targets three behavioral signatures in the network fabric: configuration theft via TFTP, unauthorized management access (Telnet/SNMP), and rare inbound traffic from external source IPs. The hunt is designed to detect persistence that survives reboots and bypasses standard endpoint visibility.

## vulnerable-cisco-assets
<!-- Identify vulnerable Cisco devices -->
Locate assets known to be susceptible to CVE-2018-0171 (Smart Install), the primary vector for Static Tundra.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of unique device IDs with the unpatched vulnerability. Silence suggests
  no known vulnerable devices are reporting.
reads:
- device_uid
- cve_uid
- severity
- affected_package_name
- affected_package_version
- first_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_uid, cve_uid, severity, affected_package_name, affected_package_version, first_seen FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2018-0171' AND status != 'suppressed' ORDER BY first_seen DESC
```

## internet-exposed-management
<!-- Exposed management ports on external assets -->
Narrow the hunt to infrastructure that is visible to internet scanners, representing the external attack surface.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, management_ports=management_ports)
~~~yaml
expected: Internal IPs or external domains with legacy management ports exposed. Silence
  proves absence of exposure in current scanner data.
reads:
- domain_or_ip
- port
- product
- version
- discovered_at
silence: evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT domain_or_ip, port, product, version, discovered_at FROM hb_exposed_assets WHERE (instr(',' || '{{management_ports}}' || ',', ',' || CAST(port AS TEXT) || ',') > 0) AND discovered_at >= datetime('now', '-{{lookback_days}} days')
```

## behavioral-corroboration
<!-- Corroborate behavioral activity -->
parallel:
- → tftp-exfiltration-behavior
- → unauthorized-mgmt-access
- → rare-source-ip-baseline
join: → triage-tundra

## tftp-exfiltration-behavior
<!-- TFTP exfiltration from infrastructure -->
Find TFTP traffic (UDP 69) which Static Tundra uses to pull configs after enabling the local TFTP server.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outbound TFTP connections from routers or switches. Silence is not absolute
  proof of absence without continuous flow logs.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- traffic_bytes
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, traffic_bytes, time FROM hb_network_connection WHERE dst_endpoint_port = 69 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## unauthorized-mgmt-access
<!-- Unauthorized management service usage -->
Identify inbound Telnet or SNMP traffic that could indicate rogue management access for persistence.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Inbound connections to legacy management ports. Persistent sessions from
  unknown external IPs are high-fidelity indicators.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (dst_endpoint_port IN (23, 161, 162)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-source-ip-baseline
<!-- Stack rare management source IPs -->
Identify external or outlier source IPs connecting to infrastructure, filtering out enterprise scanners.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, management_ports=management_ports)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Source IPs connecting to only one or two devices. These represent targeted
  access rather than fleet-wide management.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- src_endpoint_ip
- device_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT device_hostname) AS targets, MIN(time) AS first_access, MAX(time) AS last_access FROM hb_network_connection WHERE (instr(',' || '{{management_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING targets <= 2 ORDER BY targets ASC
```

## triage-tundra
<!-- Analyze network device anomalies -->
```agent target=hunter
cite: required
context:
- vulnerable-cisco-assets
- internet-exposed-management
- tftp-exfiltration-behavior
- unauthorized-mgmt-access
- rare-source-ip-baseline
max_iterations: 5
objective: Determine if any host identified in the scoping steps (CVE-2018-0171 or
  internet-exposed) shows evidence of exfiltration (TFTP) or unauthorized management
  access from rare IPs.
success_criteria: A verdict of malicious for any host combining vulnerability with
  outbound TFTP or rare inbound management traffic.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route based on compromise verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-remediate
indeterminate: → manual-config-audit
unavailable: → manual-config-audit (blind_spot: missing-flow-data)
else: → close-out

## isolate-and-remediate
<!-- Isolate and remediate compromised device -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host at the switch/fabric level. Collect the running-config and startup-config for forensic analysis. Remove any unauthorized 'username' entries or 'snmp-server community' strings. Disable the TFTP server if enabled via 'no tftp-server'. Apply the patch for CVE-2018-0171 or disable Smart Install.
```
→ manual-config-audit

## manual-config-audit
<!-- Detailed configuration audit -->
```manual target=analyst
Review the device configuration for the following artefacts: 1. New 'username' entries with high privilege levels. 2. Rogue 'snmp-server community' strings like 'public', 'anonymous', or 'public-rw'. 3. The presence of 'tftp-server nvram:startup-config' in the running configuration. 4. Modifications to TACACS+ or ACL settings that bypass remote logging or central control.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record that no persistence indicators were found. Ensure all devices identified in the scoping phase (vulnerable to CVE-2018-0171) are tracked for patching or replacement if end-of-life.
```
→ end

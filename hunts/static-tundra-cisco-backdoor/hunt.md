---
analysis: A simple detection rule might flag port 69; this hunt correlates vulnerability
  findings with internet exposure data and uses stack-counting to differentiate between
  widespread scanners and targeted, low-volume persistence from specific state-sponsored
  actors.
blind_spots:
- id: missing-flow-logs
  question: Was TFTP traffic blocked by an upstream firewall before it reached the
    gateway?
  requires: hb_network_connection with full UDP visibility
  risk: A compromise could occur, but if the exfiltration fails or is blocked by an
    unmonitored fabric, the hunt would show silence.
  stage: collection-config-tftp
- id: firmware-magic-packets
  question: Can we see the 'magic' SYN packets for SYNful Knock?
  requires: Network-level PCAP or advanced EDR capable of SYN-packet flag inspection
  risk: Flow logs (hb_network_connection) typically aggregate sessions and do not
    show individual packet flags or data payloads, making 'magic' packets invisible.
  stage: persistence-firmware-implant
coverage:
- stage: collection-config-tftp
  status: covered
  steps:
  - tftp-config-exfiltration
  - triage-signals
- blind_spot: firmware-magic-packets
  reason: Requires visibility into specific TCP SYN packet payloads which are not
    present in hb_network_connection flow data.
  stage: persistence-firmware-implant
  status: not_visible
- stage: persistence-account-creation
  status: covered
  steps:
  - rare-admin-source-ips
  - triage-signals
  - analyst-manual-review
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: initial-access-smart-install-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: initial-access-snmp-defaults
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: defense-evasion-logging-tamper
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: discovery-cdp-enumeration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Network infrastructure devices are high-value targets for espionage
    groups as they offer persistent, unmonitored access to entire network segments.
    Confirming the absence of configuration exfiltration on vulnerable Cisco devices
    is a critical security obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: A state-sponsored actor has exploited legacy Cisco Smart Install vulnerabilities
  to enable TFTP servers for configuration exfiltration and established persistence
  via unauthorized admin protocols or firmware implants.
labels:
- hunt
- attack.t1041
- attack.t1090.003
- attack.t1190
name: 'Static Tundra: Cisco Configuration Exfiltration and Backdooring'
parameters:
  authorized_admin_ips:
    default: []
    description: Known-good internal management IPs to exclude from prevalence counting.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: local-inventory
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of historical network and vulnerability data to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize devices identified as 'gateways' or 'edge' in
  asset management. If hb_vulnerability_finding is sparse, the hb_exposed_assets surface
  is critical to find unmanaged or shadow-IT network devices.
references:
- name: 'Static Tundra: long-term exploitation of end-of-life network devices'
  url: https://blog.talosintelligence.com/static-tundra/
related:
- hunt: discovery-cdp-enumeration
  reason: This hunt focuses on exfiltration/persistence; the discovery stage using
    'show cdp neighbors' is handled by a separate discovery-focused hunt.
  relation: out-of-scope-alternative
- hunt: static-tundra-perimeter-exploitation
  relation: follows
scenario:
  stages:
  - name: Smart Install Remote Code Execution
    observables:
    - CVE-2018-0171
    - TCP port 4786
    - Cisco IOS Smart Install feature
    slug: initial-access-smart-install-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: SNMP Community String Abuse
    observables:
    - UDP port 161
    - Community string 'public'
    - Community string 'anonymous'
    - Spoofed SNMP source IP addresses
    slug: initial-access-snmp-defaults
    tactic: initial-access
    techniques:
    - T1190
  - name: Configuration Exfiltration via TFTP
    observables:
    - tftp-server nvram:startup-config
    - UDP port 69
    - Retrieval of startup configuration files
    slug: collection-config-tftp
    tactic: collection
    techniques:
    - T1041
  - name: SYNful Knock Firmware Implant
    observables:
    - SYNful Knock implant
    - TCP SYN magic packets
    - Modified Cisco IOS image
    slug: persistence-firmware-implant
    tactic: persistence
    techniques:
    - T1090.003
  - name: Unauthorized Local Account Creation
    observables:
    - Privileged local user accounts
    - Enabling TELNET service
    - New SNMP read-write community strings
    slug: persistence-account-creation
    tactic: persistence
    techniques:
    - T1090.003
  - name: Logging and ACL Modification
    observables:
    - Modified TACACS+ configuration
    - Modified Access Control Lists (ACLs)
    slug: defense-evasion-logging-tamper
    tactic: defense-evasion
    techniques:
    - T1041
  - name: Internal Neighbor Discovery
    observables:
    - show cdp neighbors
    slug: discovery-cdp-enumeration
    tactic: discovery
    techniques:
    - T1041
  summary: Static Tundra targets end-of-life Cisco network devices by exploiting CVE-2018-0171
    and weak SNMP configurations to exfiltrate device settings. The group maintains
    long-term persistence using the SYNful Knock firmware implant and by creating
    unauthorized local privileged accounts and SNMP community strings.
series:
  index: 2
  slug: static-tundra-long-term-exploitation-of-end-of-life-network-devices
  title: 'Static Tundra: long-term exploitation of end-of-life network devices'
  total: 2
severity: critical
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


# Static Tundra: Cisco Configuration Exfiltration and Backdooring

This hunt focuses on the post-exploitation phase of Static Tundra (FSB Center 16) activity. We start by identifying Cisco assets vulnerable to CVE-2018-0171 and those exposed to the internet. We then search for the signature behavior of enabling 'tftp-server nvram:startup-config' which manifests as unusual inbound TFTP traffic. Simultaneously, we stack-count management protocol connections (Telnet, SNMP) to identify rare external sources that may indicate backdoored credentials or firmware implants like SYNful Knock.

## vulnerable-cisco-gateways
<!-- Identify vulnerable Cisco gateways -->
Scope the hunt to hosts explicitly flagged with the Smart Install vulnerability (CVE-2018-0171).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of device identifiers that are confirmed vulnerable. Silence indicates
  no known vulnerable assets in the inventory.
reads:
- device_uid
- resource_uid
- affected_package_name
- affected_package_version
- severity
- last_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_uid, resource_uid, affected_package_name, affected_package_version, severity, last_seen FROM hb_vulnerability_finding WHERE cve_uid = 'CVE-2018-0171' AND status != 'suppressed'
```

## exposed-cisco-assets
<!-- Cisco assets exposed to internet scanning -->
Broaden the scope to any Cisco device visible to external scanners (Shodan/Censys) that might be targeted.

```sqlite target=endpoint role=scoping
~~~yaml
expected: Hosts identified by external scanning services. Silence means no Cisco assets
  are indexed as internet-exposed.
reads:
- domain_or_ip
- ip_address
- port
- product
- version
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT domain_or_ip, ip_address, port, product, version, discovered_at FROM hb_exposed_assets WHERE LOWER(product) LIKE '%cisco%' OR LOWER(source_product) LIKE '%cisco%'
```

## corroborate-activity
<!-- Check for exfiltration and persistence signals -->
parallel:
- → tftp-config-exfiltration
- → rare-admin-source-ips
join: → triage-signals

## tftp-config-exfiltration
<!-- TFTP Configuration Exfiltration -->
Detect the use of TFTP (UDP 69) to retrieve configuration files, a core step in the Static Tundra attack chain.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Any inbound TFTP connection to a gateway device. TFTP is rarely used for
  managed devices outside of maintenance windows.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, protocol, COUNT(*) as flow_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE dst_endpoint_port = 69 AND protocol = 'udp' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port
```

## rare-admin-source-ips
<!-- Rare admin protocol sources -->
Identify external or unauthorized IP addresses connecting to Telnet (23) or SNMP (161, 162), which may indicate backdoored accounts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, authorized_admin_ips=authorized_admin_ips)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Individual IPs accessing management ports on a very small number of devices.
  Large counts likely indicate scanners; small counts indicate targeted persistence.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- dst_endpoint_port
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) as target_count, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE dst_endpoint_port IN (23, 161, 162) AND instr(',' || '{{authorized_admin_ips}}' || ',', ',' || src_endpoint_ip || ',') = 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_port HAVING target_count <= 2 ORDER BY target_count ASC
```

## triage-signals
<!-- Analyze compromise indicators -->
```agent target=hunter
cite: required
context:
- vulnerable-cisco-gateways
- exposed-cisco-assets
- tftp-config-exfiltration
- rare-admin-source-ips
max_iterations: 3
objective: Determine if any Cisco device has been compromised by Static Tundra, specifically
  focusing on unauthorized configuration access.
success_criteria: A verdict of malicious, suspicious, or benign for each identified
  host, citing network flows and vulnerability status.
tools:
- endpoint
- network
```

## decide-route
<!-- Route on Triage Verdict -->
if~: "The triage verdict is malicious for one or more Cisco devices." (confidence: high, judge=hunter)
then: → isolate-device
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-flow-logs)
else: → close-out

## isolate-device
<!-- Isolate Compromised Network Device -->
```action target=endpoint
~~~yaml
approval: required
~~~
Place the network device into an isolated management VLAN and disable the Smart Install feature (no vstack) immediately. Collect a copy of the running and startup configurations for analysis.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Configuration Audit -->
```manual target=analyst
Inspect the provided configurations. Look for unauthorized 'username' entries, modified SNMP community strings (e.g., 'anonymous', 'public'), and the presence of 'tftp-server nvram:startup-config'. Check ACLs for modifications that permit access from the identified rare source IPs.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the list of devices audited. If no findings were discovered, document the coverage provided by this hunt and schedule a follow-up for next month to catch newly exposed assets.
```
→ end

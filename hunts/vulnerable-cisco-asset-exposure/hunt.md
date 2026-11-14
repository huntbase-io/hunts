---
analysis: A simple rule for port 4786 traffic lacks the context of whether the device
  is actually vulnerable or if it was discovered by an external scanner. This hunt
  pivots across vulnerability management, attack surface management, and traffic logs
  to provide a high-confidence verdict.
blind_spots:
- id: missing-network-logs
  question: whether any internal scanning or exploitation of port 4786 occurred
  requires: hb_network_connection with full coverage of management subnets
  risk: Lateral movement exploiting Smart Install from a compromised internal host
    would be invisible if logs only cover the perimeter.
  stage: initial-access-smart-install
- id: eol-inventory-staleness
  question: whether legacy devices that do not report to a vulnerability scanner are
    present
  requires: hb_software_inventory with up-to-date EoL data for Cisco hardware
  risk: End-of-life devices often fall out of managed inventory but remain reachable
    via the network, creating a silent entry point.
  stage: vulnerability-identification
coverage:
- stage: vulnerability-identification
  status: covered
  steps:
  - cisco-vulnerability-scope
- stage: initial-access-smart-install
  status: covered
  steps:
  - rare-smart-install-traffic
  - external-asset-exposure
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: configuration-extraction-tftp
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: snmp-abuse-and-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: persistence-firmware-implant
  status: out_of_scope
- reason: 'Belongs to another part of the ''Static Tundra: long-term exploitation
    of end-of-life network devices'' series.'
  stage: defense-evasion-and-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Static Tundra specifically targets unpatched legacy infrastructure
    for long-term intelligence collection; identifying these assets and protocol activity
    is a core defense against Russian state-sponsored espionage.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is identifying and exploiting end-of-life Cisco devices via
  the Smart Install feature on port 4786 to extract configuration files and establish
  persistence.
labels:
- hunt
- attack.t1190
name: Vulnerable Cisco Asset Exposure
parameters:
  cve_id:
    default: CVE-2018-0171
    description: The Cisco Smart Install remote code execution vulnerability ID.
    from:
      kind: article
      observed: '2024-05-20'
      ref: Static Tundra
    type: string
  lookback_days:
    default: '14'
    description: Days of network history to examine for protocol activity.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to focus the hunt on, usually from the scoping
      step.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-input
    type: list[host]
  smart_install_port:
    default: '4786'
    description: The TCP port used by the Cisco Smart Install feature.
    from:
      kind: article
      observed: '2024-05-20'
      ref: Static Tundra
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
rationale: The hunt focuses on Cisco IOS/XE devices. Start with assets known to have
  external exposure in Shodan to prioritize risk.
references:
- name: 'Static Tundra: long-term exploitation of end-of-life network devices'
  url: https://blog.talosintelligence.com/static-tundra/
related:
- hunt: cisco-config-exfiltration-tftp
  reason: The exfiltration of configuration data using TFTP following initial access
    is a separate behavioural stage involving hb_network_connection with different
    port logic.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: End-of-Life Device Vulnerability Identification
    observables:
    - CVE-2018-0171
    - Cisco IOS Software
    - Cisco IOS XE Software
    - End-of-life (EoL) network devices
    slug: vulnerability-identification
    tactic: initial-access
    techniques:
    - T1190
  - name: Smart Install Exploitation
    observables:
    - TCP port 4786
    - Cisco Smart Install protocol activity
    slug: initial-access-smart-install
    tactic: initial-access
    techniques:
    - T1190
  - name: Configuration Exfiltration via TFTP
    observables:
    - tftp-server nvram:startup-config
    - UDP port 69
    - startup-config file retrieval
    slug: configuration-extraction-tftp
    tactic: exfiltration
    techniques:
    - T1041
  - name: SNMP Community String Abuse
    observables:
    - UDP port 161
    - SNMP community string 'public'
    - SNMP community string 'anonymous'
    - Spoofed SNMP source IP addresses
    slug: snmp-abuse-and-execution
    tactic: execution
    techniques:
    - T1090.003
  - name: Firmware Persistence via SYNful Knock
    observables:
    - SYNful Knock implant
    - TCP SYN 'magic packet' to non-standard ports
    - Privileged local user account creation
    slug: persistence-firmware-implant
    tactic: persistence
  - name: Logging Evasion and Lateral Discovery
    observables:
    - TACACS+ configuration modification
    - Access Control List (ACL) modifications
    - show cdp neighbors
    slug: defense-evasion-and-discovery
    tactic: defense-evasion
  summary: Static Tundra, a Russian FSB-linked actor, targets end-of-life Cisco devices
    by exploiting the Smart Install vulnerability (CVE-2018-0171) or abusing SNMP
    with guessed community strings to exfiltrate configurations. They maintain multi-year
    persistence using the SYNful Knock firmware implant and by creating local accounts,
    while evading detection by disabling TACACS+ logging.
series:
  index: 1
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


# Vulnerable Cisco Asset Exposure

Static Tundra (FSB Center 16) has exploited CVE-2018-0171 for over a decade to compromise network infrastructure. This hunt identifies vulnerable Cisco assets by cross-referencing vulnerability findings with external exposure data and internal network traffic on the Smart Install protocol port. The agent weighs the presence of the vulnerability against active protocol traffic to determine if exploitation or scanning is occurring.

## cisco-vulnerability-scope
<!-- Identify devices with Smart Install vulnerability -->
The query finds devices explicitly flagged with CVE-2018-0171 in the vulnerability inventory so the hunt focuses on known exposures.

```sqlite target=endpoint role=scoping params=(cve_id=cve_id)
~~~yaml
expected: Rows indicating specific assets that are unpatched against the Smart Install
  vulnerability. Silence means no known vulnerable devices are currently tracked.
reads:
- device_uid
- resource_uid
- cve_uid
- severity
- status
- first_seen
- last_seen
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_uid, resource_uid, cve_uid, severity, status, first_seen, last_seen FROM hb_vulnerability_finding WHERE cve_uid = '{{cve_id}}' AND status != 'suppressed'
```

## parallel-evidence
<!-- Check exposure and traffic -->
parallel:
- → rare-smart-install-traffic
- → external-asset-exposure
join: → triage-risk

## rare-smart-install-traffic
<!-- Rare Smart Install network traffic -->
The hunt stack-counts connections to port 4786 across the fleet to identify rare or unauthorized protocol usage that deviates from typical management traffic.

```sqlite target=network role=baseline params=(smart_install_port=smart_install_port, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Connections to port 4786 on a small number of hosts. Silence proof that
  no such traffic was logged.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port = {{smart_install_port}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip HAVING COUNT(DISTINCT device_hostname) <= 3 ORDER BY connection_count DESC
```

## external-asset-exposure
<!-- Check for external Smart Install exposure -->
The query identifies if organizational assets are visible to internet scanners on port 4786 by checking external attack surface data.

```sqlite target=endpoint role=enrichment params=(smart_install_port=smart_install_port)
~~~yaml
expected: Asset records confirmed as exposed by Shodan or crt.sh. Silence means no
  assets are currently known to be exposed on this port.
reads:
- domain_or_ip
- port
- product
- version
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT domain_or_ip, port, product, version, discovered_at FROM hb_exposed_assets WHERE port = {{smart_install_port}}
```

## triage-risk
<!-- Weigh vulnerability and activity -->
```agent target=hunter
cite: required
context:
- cisco-vulnerability-scope
- rare-smart-install-traffic
- external-asset-exposure
max_iterations: 4
objective: Determine if any vulnerable Cisco devices are being actively exploited
  based on recent network activity or high-risk exposure.
success_criteria: A per-device verdict of malicious, suspicious, or benign based on
  the overlap of vulnerability and traffic.
tools:
- endpoint
- network
```

## route-on-risk
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-and-disable
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: missing-network-logs)
else: → close-out-negative

## isolate-and-disable
<!-- Restrict Smart Install access -->
```action target=endpoint
~~~yaml
approval: required
~~~
Disable the Smart Install feature on the identified Cisco devices or apply a firewall rule to block all ingress traffic to TCP port 4786.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Forensic log review -->
```manual target=analyst
Examine flow logs for outbound TFTP or SNMP activity following the Smart Install connections to determine if startup-configurations were successfully exfiltrated.
```
→ remediation-task

## remediation-task
<!-- Permanent remediation -->
```manual target=analyst
Coordinate with the network team to apply the patch for CVE-2018-0171 or decommission any end-of-life hardware that cannot be secured.
```
→ end

## close-out-negative
<!-- Close out negative result -->
```manual target=analyst
Record the list of vulnerable devices identified in the scoping step and note the absence of protocol activity on port 4786. Schedule a re-run of the hunt.
```
→ end

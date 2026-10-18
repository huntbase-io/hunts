---
analysis: While a rule can alert on Telnet traffic, this hunt correlates traffic with
  legacy OS inventory and baselines outbound movement from those systems to identify
  internal pivots that standard perimeter rules miss.
blind_spots:
- id: incomplete-network-telemetry
  question: whether protocol tunneling (T1572) is masking the internal insecure traffic
  remediation: Enable application-layer visibility on internal segmentation firewalls.
  requires: Deep Packet Inspection (DPI) or internal firewall logs
  risk: A sophisticated adversary might tunnel Telnet inside another protocol, making
    the connection appear benign to simple port-based queries.
  stage: lateral-protocol-tunneling
- id: missing-host-listeners
  question: which ports are listening on legacy hosts without active sessions
  remediation: Map device_hostname into the hb_network_listener surface.
  requires: hb_network_listener with device_hostname column
  risk: The hunt only sees services that are actively being talked to. Insecure services
    waiting for a 'knock' are missed if no connection occurs in the window.
  stage: legacy-system-discovery
coverage:
- stage: legacy-system-discovery
  status: covered
  steps:
  - legacy-host-inventory
  - insecure-inbound-traffic
- stage: lateral-protocol-tunneling
  status: covered
  steps:
  - lateral-outbound-stack
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: phishing-initial-foothold
  status: out_of_scope
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: third-party-supply-chain-entry
  status: out_of_scope
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: it-ot-gateway-bridging
  status: out_of_scope
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: ot-impact-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Production continuity in manufacturing relies on the security of
    aging HMIs. Identifying unencrypted management exposure reduces the risk of lateral
    movement into critical OT segments.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries target legacy Windows 7 and XP systems used as HMIs to bridge
  into OT networks by using unencrypted management protocols like Telnet and FTP for
  lateral movement.
labels:
- hunt
- attack.t1133
- attack.t1572
- attack.t1021.002
- attack.t1195
- command and control
- discovery
- impact
- initial access
name: Industrial Protocol Abuse on Legacy Manufacturing Assets
parameters:
  insecure_ports:
    default:
    - '21'
    - '23'
    - '80'
    description: Unencrypted ports commonly used for legacy management (FTP, Telnet,
      HTTP).
    from:
      kind: article
      observed: '2026-10-14'
      ref: Huntress Manufacturing Trends 2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames of legacy Windows systems identified in the inventory step;
      leave empty to hunt across the entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/manufacturing-cybersecurity-trends
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on subnets known to house HMI or PLC management workstations. Use
  the OS names to build a target list of legacy devices before proceeding to the network
  traffic queries.
references:
- name: "Huntress \u2014 7 Key Manufacturing Cybersecurity Trends for 2027"
  url: https://www.huntress.com/blog/manufacturing-cybersecurity-trends
related:
- hunt: it-ot-gateway-bridging
  reason: This hunt focuses on the internal legacy systems, not the initial bridge
    from the IT network.
  relation: out-of-scope-alternative
- hunt: abuse-remote-gateways-third-party-access
  relation: follows
scenario:
  stages:
  - name: Corporate Phishing Foothold
    observables:
    - Phishing emails targeting Sales or Finance departments
    - Execution of malicious attachments on corporate laptops
    slug: phishing-initial-foothold
    tactic: initial-access
    techniques:
    - T1566
  - name: Compromised Third-Party Vendor Access
    observables:
    - Use of stolen credentials from specialized machine integrators or HVAC contractors
    - Persistent 'always-on' VPN links from vendor networks
    - Remote management tool logins appearing as routine maintenance
    slug: third-party-supply-chain-entry
    tactic: initial-access
    techniques:
    - T1195
  - name: IT-to-OT Bridge Access
    observables:
    - Access to Citrix or VPN appliances acting as bridges
    - Logins to jump servers positioned between corporate and plant networks
    - Stolen credentials used to cross network segmentation boundaries
    slug: it-ot-gateway-bridging
    tactic: initial-access
    techniques:
    - T1133
  - name: Legacy Industrial Asset Discovery
    observables:
    - Windows 7 and Windows XP systems running as HMIs
    - Legacy PLCs with hard-coded passwords like '1234' or 'password'
    - Unencrypted management ports active on legacy execution systems
    slug: legacy-system-discovery
    tactic: discovery
    techniques:
    - T1133
  - name: Lateral Movement via Tunneling
    observables:
    - Encapsulated network traffic traversing segment digital walls
    - Lateral movement using Telnet (port 23), FTP (port 21), or unencrypted HTTP
      (port 80)
    - Connections to Human-Machine Interfaces (HMIs) and Programmable Logic Controllers
      (PLCs)
    slug: lateral-protocol-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  - name: Operational Technology Ransomware Impact
    observables:
    - Encryption of files on Manufacturing Execution Systems (MES)
    - Manipulation of PLC recipe values or belt speed
    - Disabling of safety sensors on the plant floor
    slug: ot-impact-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Attackers target manufacturing environments by gaining a corporate foothold
    via phishing or compromised third-party vendor VPNs, subsequently pivoting into
    operational technology (OT) networks through jump servers or poorly segmented
    bridges. Once inside, they exploit legacy systems and unencrypted protocols (Telnet,
    HTTP) to manipulate industrial control systems or deploy ransomware that disrupts
    production uptime and assembly lines.
series:
  index: 2
  slug: 7-key-manufacturing-cybersecurity-trends-for-2027-huntress
  title: 7 Key Manufacturing Cybersecurity Trends for 2027 | Huntress
  total: 2
severity: medium
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


# Industrial Protocol Abuse on Legacy Manufacturing Assets

Manufacturing environments often rely on legacy Windows systems (HMI/ICS) that cannot be patched and lack modern security controls. The adversary exploits these systems to bridge the gap into OT networks. This hunt identifies these soft targets and monitors for unencrypted protocol abuse. It inventories legacy OS versions, then fans out to detect inbound management sessions on insecure ports and outbound lateral movement to other internal assets. An agent triages the evidence so an analyst can settle the verdict.

## legacy-host-inventory
<!-- Inventory legacy Windows assets -->
Identify Windows 7 and Windows XP systems that likely serve as HMIs or legacy industrial controllers.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts running outdated operating systems. These are the primary
  targets for monitoring insecure protocol usage.
reads:
- hostname
- os_name
- os_version
- device_uid
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT hostname, os_name, os_version, device_uid, time FROM hb_devices WHERE (LOWER(os_name) LIKE '%windows 7%' OR LOWER(os_name) LIKE '%windows xp%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exposure-fan-out
<!-- Corroborate inbound and outbound exposure -->
parallel:
- → insecure-inbound-traffic
- → lateral-outbound-stack
join: → triage-agent

## insecure-inbound-traffic
<!-- Inbound insecure management sessions -->
Detect when hosts connect to Telnet, FTP, or unencrypted HTTP on legacy manufacturing systems.

```sqlite target=network role=detection-candidate params=(insecure_ports=insecure_ports, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Sessions established to ports 21, 23, or 80. While potentially for maintenance,
  these expose credentials and allow command access.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE direction = 'inbound' AND activity_id = 1 AND instr(',' || '{{insecure_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lateral-outbound-stack
<!-- Baseline outbound lateral movement -->
Identify if legacy systems are being used as jump boxes to scan or connect to other internal OT assets via Telnet or FTP.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count of outbound legacy protocol attempts. Rare destinations or
  high connection counts from a single HMI suggest malicious pivoting.
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
verified_at: '2026-10-15'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND (dst_endpoint_port = 21 OR dst_endpoint_port = 23) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port
```

## triage-agent
<!-- Triage legacy protocol abuse -->
```agent target=hunter
cite: required
context:
- legacy-host-inventory
- insecure-inbound-traffic
- lateral-outbound-stack
max_iterations: 6
objective: Determine if any legacy Windows host identified in the inventory is being
  abused as a lateral movement pivot point or is accepting unauthorized unencrypted
  management traffic.
success_criteria: A detailed verdict citing row evidence for each host showing high-risk
  exposure.
tools:
- endpoint
- network
```

## risk-decision
<!-- Evaluate triage results -->
if~: "the triage verdict is malicious for at least one legacy host exhibiting rare outbound pivoting" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → audit-task
unavailable: → audit-task (blind_spot: incomplete-network-telemetry)
else: → audit-task

## isolate-host
<!-- Isolate legacy asset -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified legacy host from the network. Coordinate with the plant floor manager to ensure production safety systems are not impacted by the isolation.
```
→ audit-task

## audit-task
<!-- Manual audit of legacy listeners -->
```manual target=analyst
Review the identified hosts. If Telnet, FTP, or HTTP (port 80) are being used for routine administration, implement strict IP-based segmentation or plan for migration to a secure jump server. If the traffic is anomalous, perform a full forensic imaging of the host.
```
→ closure-task

## closure-task
<!-- Hunt closure and documentation -->
```manual target=analyst
Log the identified legacy systems in the central asset registry. Share the protocol abuse findings with the IT-OT gateway team to improve segmentation rules.
```
→ end

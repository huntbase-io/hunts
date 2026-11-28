---
analysis: This hunt uses a gated flow to correlate DNS failure patterns with follow-on
  behavioral evidence. A single rule would only catch a static domain; this hunt identifies
  the pivot from C2 failure to internal lateral movement across multiple telemetry
  surfaces.
blind_spots:
- id: gateway-logging-gap
  owner: Network Engineering
  question: whether the device is communicating with other hosts on the same L2 subnet
  remediation: Deploy network sensors at the access layer or use private VLANs to
    force all traffic through a monitored point.
  requires: hb_network_connection from access-layer switches
  risk: Lateral movement between devices on the same subnet that does not pass through
    a monitored L3 gateway will be invisible to these queries.
  stage: botnet-conscription-and-c2
- id: unmanaged-device-blind-spot
  owner: Asset Management
  question: what the specific model and owner are for the identified suspicious IP
  remediation: Integrate DHCP fingerprinting or MAC OUI lookups into the central telemetry
    lake.
  requires: accurate CMDB or MAC OUI integration
  risk: Without agent coverage, identifying the physical device for remediation is
    delayed, extending the window of risk.
  stage: lateral-movement-from-iot
- id: encrypted-dns-blind-spot
  owner: Security Operations
  question: whether the botnet is using DNS-over-HTTPS to hide C2 lookups
  remediation: Block outbound DoH traffic from IoT subnets and enforce internal DNS
    resolution.
  requires: hb_http_activity targeting known DoH endpoints
  risk: If the botnet uses DoH, the lead query will be silent, and the compromise
    will only be visible in later behavioral stages.
  stage: botnet-conscription-and-c2
coverage:
- stage: botnet-conscription-and-c2
  status: covered
  steps:
  - dns-failed-lookups-lead
- stage: dns-redirection-and-phishing
  status: covered
  steps:
  - http-phishing-traffic
- stage: lateral-movement-from-iot
  status: covered
  steps:
  - internal-port-probing
- reason: "Belongs to another part of the 'My IoT devices are no longer supported\
    \ \u2013 is my smart home safe?' series."
  stage: initial-access-eol-exploitation
  status: out_of_scope
- reason: "Belongs to another part of the 'My IoT devices are no longer supported\
    \ \u2013 is my smart home safe?' series."
  stage: operational-impact
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Unsupported and end-of-life IoT devices are vulnerable beachheads
    that lack standard security controls; identifying their compromise through network
    behavior is vital to protecting the primary enterprise network.
  methodology: model-assisted
  trigger: intel-report
hypothesis: End-of-life IoT devices have been conscripted into botnets or hijacked
  for traffic redirection, evidenced by anomalous DNS failure patterns, internal lateral
  probing, or HTTP connections to phishing infrastructure.
labels:
- hunt
- attack.t1190
- attack.t1566
- attack.t1071.001
- attack.t1071.004
- execution
- impact
- initial access
- lateral movement
name: Compromised IoT Network Activity
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  management_ports:
    default:
    - '22'
    - '23'
    - '80'
    - '443'
    - '3389'
    - '5555'
    - '5900'
    description: Management ports commonly targeted during internal propagation.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: threat-intel
    type: list[string]
  phishing_indicators:
    default:
    - login.router-update.invalid
    - security-check.wifi-auth.invalid
    - portal.isp-verify.invalid
    description: Known malicious domains used for redirection or phishing.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: threat-intel
    type: list[domain]
  scope_hosts:
    default: []
    description: Suspicious IPs identified from the lead; leave empty to scan the
      entire estate in behavioral steps.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
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
rationale: Target IoT-specific VLANs, guest networks, and industrial control subnets
  first. Focus the lead query on these zones to minimize noise from enterprise IT
  equipment.
references:
- name: "ESET Research \u2014 IoT devices no longer supported"
  url: https://www.welivesecurity.com/en/internet-of-things/iot-devices-no-longer-supported-smart-home-safe/
related:
- hunt: initial-access-eol-exploitation
  reason: Vulnerability management and the exploitation of EoL software are handled
    in the vulnerability-focused hunt in this series.
  relation: out-of-scope-alternative
- hunt: exposed-iot-posture-operational-impact
  relation: follows
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
  index: 2
  slug: my-iot-devices-are-no-longer-supported-is-my-smart-home-safe
  title: "My IoT devices are no longer supported \u2013 is my smart home safe?"
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Compromised IoT Network Activity

This hunt identifies the network-level behaviors of unmanaged IoT devices that have been compromised. It uses a gated flow, starting with a lead query that identifies hosts with high DNS failure rates, which often indicates botnet C2 or DGA activity. Only when these leads are verified does the hunt pivot into expensive behavioral analysis to find evidence of lateral movement (internal port scanning) and initial access redirection (phishing traffic). The hunt is designed for devices that lack endpoint agents by focusing on network telemetry surfaces.

## dns-failed-lookups-lead
<!-- Lead: High DNS failure volume -->
Identify internal IPs generating a high volume of NXDOMAIN or SERVFAIL responses, suggesting automated C2 or DGA attempts.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of IPs with persistent lookup failures. Silence suggests no heavy
  automated C2 activity is visible on this surface.
reads:
- src_endpoint_ip
- rcode
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT src_endpoint_ip, COUNT(*) as fail_count, COUNT(DISTINCT query_hostname) as unique_domains, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_dns_activity WHERE rcode IN ('NXDOMAIN', 'SERVFAIL') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING fail_count > 50 ORDER BY fail_count DESC
```

## evaluate-dns-lead
<!-- Evaluate DNS leads -->
```agent target=hunter
cite: required
context:
- dns-failed-lookups-lead
max_iterations: 3
objective: Review the DNS lookup failures and determine if the frequency and target
  domains suggest an automated botnet agent.
success_criteria: A verdict for each IP citing specific failure counts.
tools:
- endpoint
- network
- web
```

## gate-on-suspicious-dns
<!-- Gate on suspicious DNS -->
if~: "the evaluate-dns-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → investigate-iot-behavior
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: gateway-logging-gap)
else: → close-out-hunt

## investigate-iot-behavior
<!-- Investigate IoT behaviors -->
parallel:
- → internal-port-probing
- → http-phishing-traffic
join: → confirm-iot-compromise

## internal-port-probing
<!-- Internal management port probing -->
Detect anomalous internal scanning of management ports originating from the suspicious IPs.

```sqlite target=network role=detection-candidate params=(scope_hosts=scope_hosts, management_ports=management_ports, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: One IP hitting multiple internal targets on ports like 23 (Telnet) or 5555
  (ADB).
prevalence:
  by: src_endpoint_ip
  key:
  - src_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT src_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT dst_endpoint_ip) as internal_targets, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_network_connection WHERE direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND instr(',' || '{{management_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, dst_endpoint_port HAVING internal_targets > 5 ORDER BY internal_targets DESC
```

## http-phishing-traffic
<!-- HTTP phishing traffic -->
Identify HTTP requests to known phishing domains, indicating a hijacked IoT gateway or router.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, phishing_indicators=phishing_indicators, lookback_days=lookback_days)
~~~yaml
expected: Connections to phishing infrastructure from internal IPs.
reads:
- src_endpoint_ip
- url_hostname
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-21'
~~~
SELECT src_endpoint_ip, url_hostname, user_agent, COUNT(*) as req_count, MIN(time) as first_seen FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND instr(',' || '{{phishing_indicators}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip, url_hostname, user_agent ORDER BY req_count DESC
```

## confirm-iot-compromise
<!-- Confirm IoT compromise -->
```agent target=hunter
cite: required
context:
- evaluate-dns-lead
- internal-port-probing
- http-phishing-traffic
max_iterations: 5
objective: Determine if the suspicious IP is a compromised IoT device by correlating
  the automated DNS behavior with internal scanning and phishing redirection.
success_criteria: A verdict of malicious or suspicious for any IP showing multiple
  indicators.
tools:
- endpoint
- network
- web
```

## route-to-containment
<!-- Route to containment -->
if~: "the confirm-iot-compromise verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-ip
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: unmanaged-device-blind-spot)
else: → close-out-hunt

## isolate-compromised-ip
<!-- Isolate compromised IP -->
```action target=network
~~~yaml
approval: required
~~~
Isolate the identified IPs at the firewall or router. Place the devices in a quarantine VLAN to prevent lateral movement and C2 participation.
```
→ analyst-validation

## analyst-validation
<!-- Analyst validation -->
```manual target=analyst
Review the cited IPs. Use MAC OUI lookups or internal inventories to identify the device manufacturer and model. Verify if the identified devices are end-of-life.
```
→ close-out-hunt

## close-out-hunt
<!-- Hunt close-out -->
```manual target=analyst
Record all compromised devices. Recommend decommissioning for any identified end-of-life equipment. Document any network segmentation gaps found during the hunt.
```
→ end

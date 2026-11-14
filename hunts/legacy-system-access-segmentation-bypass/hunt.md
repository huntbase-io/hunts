---
analysis: A simple detection rule might alert on a single failed login or a known
  web exploit; this hunt correlates the perimeter noise with internal network discovery
  and unauthorized cross-segment connections to find the full intrusion path.
blind_spots:
- id: limited-segmentation-telemetry
  question: Does the hunt see all traffic across VLANs?
  requires: hb_network_connection from both VPC flow logs and endpoint agents
  risk: If an adversary pivots through a host without an agent or into a segment without
    flow logging, the segmentation violation is invisible.
  stage: segmentation-boundary-violation
- id: packet-payload-visibility
  question: Was the exploit payload successfully blocked by virtual patching?
  requires: NGFW/IPS logs with deep packet inspection results
  risk: hb_http_activity shows the request but not whether an upstream IPS killed
    the session, leading to false positives.
  stage: exploit-public-facing-application
coverage:
- stage: exploit-public-facing-application
  status: covered
  steps:
  - perimeter-exploit-attempts
- stage: unauthorized-remote-bridge
  status: covered
  steps:
  - suspicious-remote-logins
- stage: internal-asset-discovery
  status: covered
  steps:
  - internal-discovery-scans
- stage: segmentation-boundary-violation
  status: covered
  steps:
  - segmentation-violation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI is accelerating the discovery of vulnerabilities in legacy OT
    systems that cannot be patched; identifying segmentation bypass attempts is the
    primary compensatory control for these unpatchable assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting unpatchable public-facing services or unauthorized
  VPN bridges to discover and laterally move toward isolated legacy OT assets.
labels:
- hunt
- attack.t1190
- attack.t1133
- attack.t1046
- attack.t1021
- discovery
- initial access
- lateral movement
name: Legacy System Access and Segmentation Bypass
parameters:
  authorized_admin_ips:
    default:
    - 10.0.0.50
    - 192.168.1.100
    description: IP addresses authorized to manage legacy or OT segments.
    from:
      kind: article
      observed: '2026-09-16'
      ref: https://blog.talosintelligence.com/securing-the-unpatchable-in-an-age-of-ai-driven-vulnerabilities/
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on; defaults to all discovered
      vulnerable assets.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/securing-the-unpatchable-in-an-age-of-ai-driven-vulnerabilities/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on subnets containing OT/ICS or legacy infrastructure. The authorized_admin_ips
  list should be populated with known management workstation or Bastion IP addresses.
references:
- name: "Talos \u2014 Securing the unpatchable in an age of AI-driven vulnerabilities"
  url: https://blog.talosintelligence.com/securing-the-unpatchable-in-an-age-of-ai-driven-vulnerabilities/
related:
- hunt: ot-protocol-anomaly-detection
  reason: This hunt focuses on the boundary violation, not the parsing of specific
    OT protocols like Modbus or DNP3.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Unpatched Public Applications
    observables:
    - Exploit attempts against internet-facing web servers
    - Traffic targeting legacy or end-of-life software components
    - Known-vulnerable software versions on public endpoints
    slug: exploit-public-facing-application
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthorized Remote Service Bridge
    observables:
    - VPN connections from unauthorized or temporary sources
    - Rogue wireless bridges connected to OT environments
    - Unauthorized VPN and remote access shortcuts used by staff/contractors
    slug: unauthorized-remote-bridge
    tactic: initial-access
    techniques:
    - T1133
  - name: Internal Discovery of Isolated Systems
    observables:
    - Internal network fingerprinting of legacy systems
    - Scanning of internal subnets for OT protocols and service ports
    - Identification of predictable network fingerprints from unpatchable hardware
    slug: internal-asset-discovery
    tactic: discovery
    techniques:
    - T1046
  - name: Lateral Movement across Segmentation Boundaries
    observables:
    - Traffic violating micro-segmentation ACLs or VLAN boundaries
    - Unauthorized communication from compromised internal hosts to critical OT segments
    - Deep packet inspection alerts from NGFW/IPS upstream of legacy devices
    slug: segmentation-boundary-violation
    tactic: lateral-movement
    techniques:
    - T1021
  summary: Threat actors leverage AI-accelerated vulnerability discovery to exploit
    unpatchable legacy and OT systems, gaining entry through internet-facing application
    flaws or unauthorized remote access bridges. Once inside, adversaries identify
    and move laterally to isolated critical assets by bypassing intended air gaps
    and micro-segmentation boundaries.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
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


# Legacy System Access and Segmentation Bypass

The adversary exploits unpatchable public-facing services or unauthorized VPN bridges to discover and laterally move toward isolated legacy OT assets. This hunt identifies compromised beachheads and their attempts to violate internal network boundaries. It focuses on systems with known vulnerabilities that cannot be patched, searching for exploit attempts on the perimeter followed by internal scanning or unauthorized cross-segment communication. An analyst reviews the resulting intrusion chains to confirm if attackers bypassed micro-segmentation controls.

## identify-at-risk-assets
<!-- Identify unpatchable or EOL assets -->
Define the scope of the hunt by identifying hosts with high-severity vulnerabilities or software versions known to be end-of-life, joining with device inventory to obtain hostnames.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames and IDs that are vulnerable. Silence means no known-vulnerable
  assets are indexed, which narrows the scope of this hunt.
reads:
- device_uid
- affected_package_name
- affected_package_version
- severity
- title
- hostname
- severity_id
- status
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT d.hostname AS device_hostname, v.device_uid, v.affected_package_name, v.affected_package_version, v.severity, v.title FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE (v.severity_id >= 4 OR LOWER(v.title) LIKE '%unsupported%' OR LOWER(v.title) LIKE '%end of life%') AND v.status != 'suppressed'
```

## early-access-fan-out
<!-- Search for Initial Access attempts -->
parallel:
- → perimeter-exploit-attempts
- → suspicious-remote-logins
join: → triage-early-access

## perimeter-exploit-attempts
<!-- Public-facing exploit attempts -->
Identify web requests containing common exploit patterns targeted at potential legacy interfaces, using lowercase literals for broader coverage.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests with directory traversal or shell commands in the path. Silence
  suggests no common web exploits were observed during the window.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- url_query
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, url_query, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%../%' OR LOWER(url_path) LIKE '%/etc/%' OR LOWER(url_path) LIKE '%cmd.exe%' OR LOWER(url_path) LIKE '%/bin/sh%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## suspicious-remote-logins
<!-- Suspicious VPN or remote logins -->
Find VPN authentications that may represent unauthorized bridges by examining protocol and event types rather than provider metadata.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Successful VPN logins. The analyst should look for unusual source locations
  or accounts that do not typically use VPN access.
reads:
- actor_user_name
- src_endpoint_ip
- src_location_country
- auth_protocol
- event_type
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, auth_protocol, event_type, time FROM hb_auth_signin WHERE (LOWER(auth_protocol) LIKE '%vpn%' OR LOWER(event_type) LIKE '%vpn%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-access
<!-- Triage early access evidence -->
```agent target=hunter
cite: required
context:
- identify-at-risk-assets
- perimeter-exploit-attempts
- suspicious-remote-logins
max_iterations: 3
objective: Identify potential beachhead hosts based on exploit attempts or suspicious
  remote access.
success_criteria: A list of hosts and IPs that are candidates for further lateral
  movement hunting.
tools:
- endpoint
- identity
- network
- web
```

## internal-movement-fan-out
<!-- Hunt for Discovery and Lateral Movement -->
parallel:
- → internal-discovery-scans
- → segmentation-violation
join: → triage-intrusion-chain

## internal-discovery-scans
<!-- Internal discovery and fingerprinting -->
Detect hosts performing internal scanning against multiple ports, excluding authorized administrative traffic to reduce false positives.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, authorized_admin_ips=authorized_admin_ips)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A single internal IP connecting to many ports or many different internal
  targets. Rare behavior stands out from standard client-server traffic.
prevalence:
  by: dst_endpoint_port
  key:
  - src_endpoint_ip
  rare_below: 10
reads:
- src_endpoint_ip
- dst_endpoint_port
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT dst_endpoint_port) AS unique_ports, COUNT(DISTINCT dst_endpoint_ip) AS target_ips, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND NOT (instr(',' || '{{authorized_admin_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING unique_ports > 10 OR target_ips > 5 ORDER BY unique_ports DESC
```

## segmentation-violation
<!-- Segmentation boundary violations -->
Identify traffic to legacy assets from unauthorized source IPs, indicating a bypass of micro-segmentation controls.

```sqlite target=network role=triage params=(authorized_admin_ips=authorized_admin_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Traffic destined for unpatchable hosts from IPs not in the authorized list.
  This indicates the micro-segmentation is either failing or being circumvented.
reads:
- src_endpoint_ip
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- time
- direction
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, device_hostname, time FROM hb_network_connection WHERE direction = 'inbound' AND NOT (instr(',' || '{{authorized_admin_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-intrusion-chain
<!-- Triage the full intrusion chain -->
```agent target=hunter
cite: required
context:
- triage-early-access
- internal-discovery-scans
- segmentation-violation
max_iterations: 6
objective: Determine if a correlated intrusion chain exists from initial access to
  segmentation violation.
success_criteria: A final verdict of malicious if a host identified as a beachhead
  is seen attempting segmentation bypass.
tools:
- endpoint
- identity
- network
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-intrusion-chain verdict is malicious for a specific beachhead host" (confidence: high, judge=hunter)
then: → isolate-beachhead
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: limited-segmentation-telemetry)
else: → close-out

## isolate-beachhead
<!-- Isolate beachhead host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host identified in triage-intrusion-chain and revoke any active VPN sessions for associated users.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Verify the vulnerability status of the destination hosts and cross-reference with NGFW/IPS logs to see if packet-level virtual patching is firing.
```
→ end

## close-out
<!-- Close out and document -->
```manual target=analyst
If no malicious activity was found, document the verified authorized management patterns to tune future runs.
```
→ end

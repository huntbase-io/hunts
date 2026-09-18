---
analysis: A simple detection rule on high data volume produces noise. This hunt requires
  weighing the intersection of a new device profile, a rare internal destination,
  and exfiltration patterns simultaneously.
blind_spots:
- id: unmanaged-assets-blind-spot
  owner: Network Engineering
  question: Are unmanaged assets acting as pivot points?
  remediation: Enable VPC Flow Logs across all production accounts.
  requires: hb_network_connection from network fabric (Flow Logs)
  risk: An adversary can move through unmanaged systems that do not report to EDR,
    breaking the visibility chain.
  stage: cross-system-lateral-movement
- id: encrypted-exfil-blind-spot
  owner: Security Architecture
  question: What content is being exfiltrated over standard HTTPS?
  remediation: Implement TLS decryption at the perimeter for high-risk categories.
  requires: Decrypted network traffic or TLS inspection logs
  risk: While we see volume, we cannot see the data if it uses TLS to legitimate cloud
    storage providers.
  stage: data-exfiltration-c2
coverage:
- stage: cross-system-lateral-movement
  status: covered
  steps:
  - newly-provisioned-endpoints
  - rare-internal-network-activity
- stage: data-exfiltration-c2
  status: covered
  steps:
  - suspicious-dns-patterns
  - high-volume-outbound-transfer
- reason: 'Belongs to another part of the ''Inside the Modern SOC: Defending the Cross-Environment
    Pivot'' series.'
  stage: initial-access-public-exploitation
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the Modern SOC: Defending the Cross-Environment
    Pivot'' series.'
  stage: identity-and-saas-pivot
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the Modern SOC: Defending the Cross-Environment
    Pivot'' series.'
  stage: cloud-infrastructure-reconfiguration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries exploit visibility gaps between disconnected security
    tools. Hunting for the pivot between environments is the most reliable way to
    find low-and-slow breaches.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is moving laterally between internal hosts that do not typically
  interact and is exfiltrating data via high-volume network flows or anomalous DNS
  patterns.
labels:
- hunt
- attack.t1021
- attack.t1041
- attack.t1071.001
- attack.t1071.004
name: Cross-Environment Lateral Movement and Exfiltration
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Hostnames from the scoping step to focus on; leave empty for all.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-scoping
    type: list[host]
  scoping_days:
    default: '7'
    description: Window to identify newly provisioned or first-seen devices.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-scoping
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize newly provisioned cloud instances and workstations in high-privilege
  network zones.
references:
- name: "Unit 42 \u2014 Inside the Modern SOC: Defending the Cross-Environment Pivot"
  url: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
related:
- hunt: initial-access-and-identity-pivot
  reason: This hunt picks up after the initial foothold and identity reconfiguration
    ends.
  relation: precedes
- hunt: cross-environment-pivot-web-to-control-plane
  relation: follows
scenario:
  stages:
  - name: Public-Facing Application Exploitation
    observables:
    - exploitation of internet-facing host
    - vulnerable software products detected on exposed services
    - anomalous HTTP requests to web servers
    slug: initial-access-public-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Identity and SaaS Privilege Escalation
    observables:
    - unfamiliar application requesting elevated permissions
    - permission changes within SaaS applications
    - anomalous authentication failure followed by success
    slug: identity-and-saas-pivot
    tactic: privilege-escalation
    techniques:
    - T1078
  - name: Cloud Resource Manipulation
    observables:
    - cloud administrator provisioning resources outside normal activity
    - new cloud instances or volumes appearing in inventory
    - reconfigured cloud compute infrastructure
    slug: cloud-infrastructure-reconfiguration
    tactic: persistence
    techniques:
    - T1578
  - name: Anomalous Network Lateral Movement
    observables:
    - new network connections between systems that rarely communicate
    - outbound network activity from recently provisioned cloud resources
    slug: cross-system-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1021
  - name: Exfiltration over C2
    observables:
    - sensitive data staged for exfiltration
    - data transfer over existing command and control channels
    - anomalous DNS query patterns
    slug: data-exfiltration-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Adversaries exploit public-facing applications to gain a foothold before
    pivoting across cloud, SaaS, and endpoint environments. They frequently reconfigure
    cloud infrastructure and abuse identity permissions to stage and exfiltrate data
    through established command-and-control channels.
series:
  index: 2
  slug: inside-the-modern-soc-defending-the-cross-environment-pivot
  title: 'Inside the Modern SOC: Defending the Cross-Environment Pivot'
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


# Cross-Environment Lateral Movement and Exfiltration

This hunt targets the 'east-west' and 'north-south' movement that follows a cross-environment pivot. It identifies newly provisioned endpoints that engage in rare internal communication and correlates this with signs of data staging and exfiltration via anomalous DNS query patterns or high-volume outbound network transfers.

## newly-provisioned-endpoints
<!-- Recently first-seen devices -->
Identify hosts that have appeared in the estate recently, representing newly provisioned resources used for a cross-environment pivot.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scoping_days=scoping_days)
~~~yaml
expected: A list of hosts and their primary IPs. Silence means no new devices were
  enrolled in the scoping window.
reads:
- hostname
- ip_address
- device_uid
- first_seen
- os_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT hostname, ip_address, device_uid, first_seen, os_name FROM hb_devices WHERE time >= datetime('now', '-{{lookback_days}} days') AND first_seen >= datetime('now', '-{{scoping_days}} days') AND activity_id = 2
```

## rare-internal-network-activity
<!-- Rare internal network pairs -->
Detect lateral movement by finding host-to-host internal connections that are rare across the fleet, potentially indicating a pivot from a new asset.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Internal traffic between hosts that do not typically communicate. Silence
  suggests no unusual east-west movement from the scoped hosts.
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
- dst_endpoint_port
- process_name
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(*) as conn_count FROM hb_network_connection WHERE state_kind = 'log' AND (instr(dst_endpoint_ip, '10.') = 1 OR instr(dst_endpoint_ip, '192.168.') = 1 OR instr(dst_endpoint_ip, '172.16.') = 1) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, process_name HAVING conn_count < 10 ORDER BY conn_count ASC
```

## corroborate-exfiltration
<!-- Corroborate with Exfiltration Signals -->
parallel:
- → suspicious-dns-patterns
- → high-volume-outbound-transfer
join: → triage-cross-environment-pivot

## suspicious-dns-patterns
<!-- High-entropy or anomalous DNS lookups -->
Detect DNS-based exfiltration or C2 beaconing from the scoped assets.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Long query hostnames containing potential encoded data or high-frequency
  lookups to rare domains.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as query_count, MAX(length(query_hostname)) as max_len FROM hb_dns_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, query_hostname HAVING max_len > 60 OR query_count > 200 ORDER BY query_count DESC
```

## high-volume-outbound-transfer
<!-- High-volume outbound data flows -->
Identify potential volumetric exfiltration to external IP addresses from the scoped assets.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Large transfers (>100MB) from scoped hosts to external destinations. Silence
  suggests exfiltration is not occurring through high-volume direct flows.
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_ip
- traffic_bytes
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes FROM hb_network_connection WHERE state_kind = 'log' AND direction = 'outbound' AND NOT (instr(dst_endpoint_ip, '10.') = 1 OR instr(dst_endpoint_ip, '192.168.') = 1 OR instr(dst_endpoint_ip, '172.16.') = 1) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip, dst_endpoint_ip HAVING total_bytes > 104857600 ORDER BY total_bytes DESC
```

## triage-cross-environment-pivot
<!-- Weigh the cross-domain activity -->
```agent target=hunter
cite: required
context:
- newly-provisioned-endpoints
- rare-internal-network-activity
- suspicious-dns-patterns
- high-volume-outbound-transfer
max_iterations: 4
objective: Determine if any host exhibits both anomalous internal connectivity (lateral
  movement) and signs of data theft (DNS exfiltration or volumetric flows).
success_criteria: A risk verdict (malicious|suspicious|benign) for each host, with
  a timeline of events.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: unmanaged-assets-blind-spot)
else: → close-out

## isolate-endpoint
<!-- Isolate the involved endpoints -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified endpoints via the EDR console and initiate incident response protocols.
```
→ analyst-review

## analyst-review
<!-- Detailed analyst investigation -->
```manual target=analyst
Review the network connection metadata and DNS query patterns. Verify if the processes involved are legitimate admin tools or unauthorized binaries.
```
→ end

## close-out
<!-- Close and log results -->
```manual target=analyst
Record that scoping and behavioral checks were completed with no actionable results.
```
→ end

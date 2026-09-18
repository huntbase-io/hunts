---
analysis: A single detection rule would fire on 'Cloudflared' or 'svchost.exe' in
  Documents, but a hunt correlates these with specific N-central management account
  logons (MSP Support) and known intruder IPs across multiple surfaces to distinguish
  an intrusion from noisy IT admin activity.
blind_spots:
- id: limited-appliance-logging
  owner: Infrastructure Team
  question: Did exploitation occur prior to the current logging window?
  remediation: Configure N-central logs to be forwarded to a central SIEM.
  requires: extended log retention on N-central appliances
  risk: Attackers can delete or rotate logs (envoy_proxy, syslog) to hide the initial
    exploit chain; the hunt would only see the persistent binary residue.
  stage: persistence-c2-cloudflare-tunneling
- id: missing-endpoint-visibility
  owner: Security Engineering
  question: Is the masqueraded binary running on the appliance itself?
  remediation: Deploy endpoint sensors to all management appliances.
  requires: EDR/osquery on the N-central appliance
  risk: If the appliance is a black-box Linux VM without an agent, file and process
    activity cannot be verified directly.
  stage: execution-masqueraded-binary
coverage:
- stage: persistence-c2-cloudflare-tunneling
  status: covered
  steps:
  - detect-malicious-persistence-binaries
  - binary-prevalence
  - c2-network-connections
- stage: execution-masqueraded-binary
  status: covered
  steps:
  - detect-malicious-persistence-binaries
  - binary-prevalence
- stage: lateral-movement-take-control
  status: covered
  steps:
  - take-control-auth-abuse
- reason: Belongs to the initial access hunt in this series.
  stage: reconnaissance-api-probing
  status: out_of_scope
- reason: Belongs to the initial access hunt in this series.
  stage: initial-access-vulnerability-exploitation
  status: out_of_scope
- reason: Belongs to the initial access hunt in this series.
  stage: persistence-account-manipulation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: N-central serves as a 'god-mode' management bridge. Compromise of
    this appliance grants unauthenticated administrative access across the entire
    estate; verifying the absence of persistent backdoors is a critical post-vulnerability
    obligation.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has established persistence on an N-central server using Cloudflare
  tunnels or masqueraded binaries (e.g., svchost.exe in Documents), and moved laterally
  using hijacked 'MSP Support' credentials.
labels:
- hunt
- attack.t1572
- attack.t1090.003
- attack.t1133
- attack.t1036.005
name: N-central Persistence and Lateral Movement
parameters:
  c2_ips:
    default:
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    description: Intruder VPN and proxy IPs associated with N-central exploitation.
    from:
      kind: article
      observed: '2026-09-06'
      ref: huntress-ncentral-exploitation
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to focus on (e.g., known N-central servers). Leave
      empty for whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/n-able-vulnerability-exploitation
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers identified by the scoping query. Focus on domain controllers
  if management account anomalies are detected, as the report indicates prioritisation
  of targeting DCs.
references:
- name: "Huntress \u2014 Critical N-able N-central Vulnerability and Active Exploitation"
  url: https://www.huntress.com/blog/n-able-vulnerability-exploitation
related:
- hunt: n-central-initial-exploitation
  reason: This hunt assumes the attacker has already bypassed authentication; the
    initial exploit involves API manipulation not covered here.
  relation: follows
- hunt: n-central-appliance-exploitation-rogue-identity
  relation: follows
scenario:
  stages:
  - name: N-central API Reconnaissance
    observables:
    - /remoteControlAction.do?method=getPierDetails
    slug: reconnaissance-api-probing
    tactic: discovery
    techniques:
    - T1190
  - name: Exploitation of N-central Vulnerabilities
    observables:
    - CVE-2026-18556
    - CVE-2026-18577
    - CVE-2026-86206
    - CVE-2026-86207
    - CVE-2026-86218
    - URL-encoded %2F in API routes
    slug: initial-access-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Rogue Account Creation and Manipulation
    observables:
    - Email addresses appended with '.invalid'
    - Character swaps in login names
    - MSP Support default username
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1133
  - name: Persistence via Cloudflare Tunnels
    observables:
    - Cloudflared service name
    - Account tag 5568cd69c754b392121f1dbb8f900fda
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    slug: persistence-c2-cloudflare-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  - name: Masqueraded Binary Execution
    observables:
    - svchost.exe located in user Documents folder
    slug: execution-masqueraded-binary
    tactic: execution
    techniques:
    - T1133
  - name: Lateral Movement via Take Control
    observables:
    - Abuse of N-central Take Control feature
    - Windows Application Event ID 4102
    - Windows Application Event ID 8192
    - Windows Application Event ID 8193
    slug: lateral-movement-take-control
    tactic: lateral-movement
    techniques:
    - T1133
  summary: Unauthenticated attackers exploit critical zero-day and authentication
    bypass vulnerabilities in N-able N-central to gain full administrative access.
    The intrusion involves reconnaissance of specific API endpoints, rogue account
    creation using subtle email suffixes like '.invalid', and persistence via Cloudflare
    tunnels and masqueraded binaries before moving laterally across the environment.
series:
  index: 2
  slug: critical-n-able-n-central-vulnerability-and-active-exploitation
  title: Critical N-able N-central Vulnerability and Active Exploitation
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
tlp: clear
type: investigation
---


# N-central Persistence and Lateral Movement

This hunt focuses on post-exploitation activity following an N-central compromise. It examines three distinct surfaces: process execution for masqueraded binaries (svchost.exe in user folders) and Cloudflare tunnel services, network connections to known intruder VPN infrastructure, and authentication logs for the 'MSP Support' account used during Take Control abuse. An analyst-agent weighs the combined evidence to identify compromised management infrastructure.

## identify-ncentral-servers
<!-- Identify N-central Infrastructure -->
Scope the hunt to systems where N-central or N-able software is installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running N-central management software. This provides
  the primary scope for the hunt.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%n-central%' OR LOWER(vendor_name) LIKE '%n-able%') AND asset_scope = 'endpoint'
```

## parallel-investigation
<!-- Analyze Persistence and Lateral Movement -->
parallel:
- → detect-malicious-persistence-binaries
- → binary-prevalence
- → c2-network-connections
- → take-control-auth-abuse
join: → triage-compromise

## detect-malicious-persistence-binaries
<!-- Detect Malicious Persistence Binaries -->
Find Cloudflared services or svchost.exe masquerading in user documents, as reported in N-central incidents.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: svchost.exe running from a non-standard path or the presence of the Cloudflared
  utility. svchost.exe in user profiles is a high-confidence indicator of masquerading.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time, process_name FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%cloudflared%' OR (LOWER(process_name) LIKE '%svchost.exe' AND (LOWER(process_path) LIKE '%\\\\documents\\\\%' OR LOWER(process_path) LIKE '%\\\\users\\\\public\\\\%'))) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## binary-prevalence
<!-- Prevalence of persistence binaries -->
Stack-count the suspected persistence binaries to confirm they are unique to compromised hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A result identifying the persistence binary as rare (seen on 3 or fewer
  hosts).
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 3
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) as host_count FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%cloudflared%' OR LOWER(process_name) LIKE '%svchost.exe%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count <= 3
```

## c2-network-connections
<!-- Outbound Connections to Intruder Infrastructure -->
Identify hosts communicating with the report's VPN and proxy IPs.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from N-central servers or managed endpoints to the designated
  C2 IPs. Silence confirms no direct communication within the window.
reads:
- device_hostname
- dst_endpoint_ip
- process_name
- connection_state
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, dst_endpoint_ip, process_name, connection_state, COUNT(*) as count FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, process_name
```

## take-control-auth-abuse
<!-- Abuse of 'MSP Support' Account -->
Audit sign-ins using the default Take Control service account or from intruder IPs.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Successful logons by the 'MSP Support' user or from an IOC IP address. This
  indicates lateral movement via the management feature.
reads:
- dst_endpoint_name
- actor_user_name
- src_endpoint_ip
- status
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_name, actor_user_name, src_endpoint_ip, status, auth_protocol, time FROM hb_auth_signin WHERE (LOWER(actor_user_name) LIKE '%msp support%' OR instr(',' || '{{c2_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Analyze Compromise Evidence -->
```agent target=hunter
cite: required
context:
- identify-ncentral-servers
- detect-malicious-persistence-binaries
- binary-prevalence
- c2-network-connections
- take-control-auth-abuse
max_iterations: 6
objective: Determine if any N-central server shows signs of persistence (Cloudflared/svchost)
  and concurrent lateral movement (MSP Support login).
success_criteria: A verdict per host (Malicious/Suspicious/Benign) with cited process
  and network evidence.
tools:
- endpoint
- identity
- network
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one N-central server" (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-final-review
unavailable: → analyst-final-review (blind_spot: limited-appliance-logging)
else: → analyst-final-review

## isolate-server
<!-- Isolate Compromised Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised N-central server, rotate management credentials, and capture the 'svchost.exe' or 'cloudflared' binaries for analysis.
```
→ analyst-final-review

## analyst-final-review
<!-- Analyst Final Review -->
```manual target=analyst
Examine any suspicious activity. If no direct compromise was found, verify that the N-central servers are fully patched and restricted by IP allowlists.
```
→ end

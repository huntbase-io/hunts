---
analysis: A standard rule alerts on a single login or shell; this hunt correlates
  a successful third-party login with its preceding foothold and its rare follow-on
  network connections, providing the context needed to distinguish maintenance from
  an intrusion.
blind_spots:
- id: limited-gateway-telemetry
  question: Whether a sign-in leads to execution on a host with no process logging
  requires: Endpoint agent coverage on the gateway host
  risk: If the gateway is a proprietary appliance with no agent, the hunt can see
    the sign-in but not the subsequent bridge processes.
  stage: third-party-supply-chain-entry
- id: always-on-tunnels
  question: If a persistent vendor tunnel is used for silent lateral movement
  requires: Network flow logs with start/end duration
  risk: If a tunnel is already established, sign-in logs will not show a new event,
    and the network activity might blend into existing traffic baselines.
  stage: it-ot-gateway-bridging
coverage:
- stage: phishing-initial-foothold
  status: covered
  steps:
  - phishing-foothold
- stage: third-party-supply-chain-entry
  status: covered
  steps:
  - remote-access-lead
  - evaluate-lead
- stage: it-ot-gateway-bridging
  status: covered
  steps:
  - bridge-traversal
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: legacy-system-discovery
  status: out_of_scope
- reason: Belongs to another part of the '7 Key Manufacturing Cybersecurity Trends
    for 2027 | Huntress' series.
  stage: lateral-protocol-tunneling
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
  justification: Manufacturing production uptime is the primary target for modern
    ransomware. Securing the IT-to-OT bridge is the most critical control for preventing
    a breach in the corporate office from impacting the shop floor.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has breached a manufacturing network by using stolen vendor
  credentials on a VPN gateway or by exploiting a phishing foothold to traverse an
  IT-to-OT jump server.
labels:
- hunt
- attack.t1133
- attack.t1195
- attack.t1566
- attack.t1572
- command and control
- discovery
- impact
- initial access
name: Abuse of Remote Gateways and Third-Party Access
parameters:
  connection_threshold:
    default: '15'
    description: Rare connection count threshold for bridge traversal.
    type: number
  corporate_apps:
    default:
    - outlook.exe
    - chrome.exe
    - msedge.exe
    description: Email and browser processes that might spawn a phishing payload.
    type: list[string]
  gateway_keywords:
    default:
    - vpn-main
    - gateway-01
    - jump-server
    - citrix-ext
    description: Names of remote access or bridge infrastructure assets.
    type: list[string]
  interpreters:
    default:
    - powershell.exe
    - cmd.exe
    - wscript.exe
    description: System interpreters used in initial foothold scripts.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Specific gateways or jump servers to focus on; populate from the
      lead step results.
    type: list[host]
  vendor_accounts:
    default:
    - hvac_admin
    - integrator_service
    - vendor_support
    description: Known vendor or third-party account names.
    from:
      kind: manual
      observed: '2026-10-14'
      ref: incident
    type: list[string]
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers identified as VPN concentrators or IT/OT jump servers.
  The vendor_accounts list should be populated with the names of external contractors
  who have remote access privileges.
references:
- name: 7 Key Manufacturing Cybersecurity Trends for 2027 | Huntress
  url: https://www.huntress.com/blog/manufacturing-cybersecurity-trends
related:
- hunt: ot-ransomware-encryption-indicators
  reason: This hunt focuses on the entry; a follow-on hunt should look for the file-level
    encryption patterns of the ransomware payload itself.
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
  index: 1
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


# Abuse of Remote Gateways and Third-Party Access

Manufacturing networks are increasingly targeted through their remote access infrastructure. Adversaries exploit stolen vendor credentials or phishing footholds to traverse the IT-to-OT bridge and halt production. This hunt identifies successful but anomalous sign-ins from third-party accounts. It then fans out to find evidence of the preceding compromise on corporate laptops and subsequent lateral probing from the gateway into the internal network. An agent weighs these results to determine if an intruder has bridged the network segments.

## remote-access-lead
<!-- Vendor and Gateway Sign-in Lead -->
Identify successful authentications to gateways from vendor accounts or to specific gateway hostnames, handling domain prefixes and partial matches.

```sqlite target=identity role=scoping params=(vendor_accounts=vendor_accounts, gateway_keywords=gateway_keywords, lookback_days=lookback_days)
~~~yaml
expected: Rows show successful logins to critical gateways. Silence means no monitored
  accounts or services were accessed during the window.
reads:
- actor_user_name
- device_hostname
- dst_endpoint_name
- logon_type
- src_endpoint_ip
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, dst_endpoint_name, logon_type, time FROM hb_auth_signin WHERE status_id = 1 AND ( (instr(',' || '{{vendor_accounts}}' || ',', ',' || (CASE WHEN instr(actor_user_name, '\') > 0 THEN SUBSTR(LOWER(actor_user_name), instr(actor_user_name, '\') + 1) ELSE LOWER(actor_user_name) END) || ',') > 0) OR (LOWER(dst_endpoint_name) LIKE '%vpn%' OR LOWER(dst_endpoint_name) LIKE '%gateway%' OR LOWER(dst_endpoint_name) LIKE '%jump%' OR LOWER(dst_endpoint_name) LIKE '%citrix%') OR (instr(',' || '{{gateway_keywords}}' || ',', ',' || LOWER(dst_endpoint_name) || ',') > 0) ) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-lead
<!-- Evaluate Sign-in Lead -->
```agent target=hunter
cite: required
context:
- remote-access-lead
max_iterations: 3
objective: Determine if any sign-in from the lead query looks like credential abuse
  (e.g., unusual geolocations or off-hours maintenance).
success_criteria: Verdicts identifying specific suspicious sessions.
tools:
- endpoint
- identity
- network
```

## gate-on-access
<!-- Gate: Proceed with Fan-out? -->
if~: "the evaluate-lead verdict identifies at least one suspicious or malicious sign-in" (confidence: medium, judge=hunter)
then: → corroborate-activity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-gateway-telemetry)
else: → close-out

## corroborate-activity
<!-- Fan-out: Foothold and Bridge Evidence -->
parallel:
- → phishing-foothold
- → bridge-traversal
join: → final-triage

## phishing-foothold
<!-- Phishing Foothold: Email/Browser Child Processes -->
Identify potential initial compromise on corporate machines where malicious payloads spawn shells, using partial path matching for robust detection.

```sqlite target=endpoint role=detection-candidate params=(corporate_apps=corporate_apps, interpreters=interpreters, lookback_days=lookback_days)
~~~yaml
expected: Processes like PowerShell or CMD spawned directly from Outlook or a browser.
  Silence indicates no obvious script-based payloads ran from common entry apps.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%\outlook.exe' OR LOWER(parent_process_name) LIKE '%\chrome.exe' OR LOWER(parent_process_name) LIKE '%\msedge.exe' OR instr(',' || '{{corporate_apps}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0) AND (LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\cmd.exe' OR LOWER(process_name) LIKE '%\wscript.exe' OR instr(',' || '{{interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## bridge-traversal
<!-- Bridge Traversal: Internal Network Probing -->
Detect bridging behavior where a gateway host initiates rare outbound connections to internal segments, using a tunable threshold.

```sqlite target=network role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days, connection_threshold=connection_threshold)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare outbound connections from gateway machines to internal IP addresses.
  Silence suggests no anomalous probing from the identified gateways.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connection_count FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port HAVING connection_count < {{connection_threshold}} ORDER BY connection_count ASC
```

## final-triage
<!-- Final Triage: Confirm the Bridge -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- phishing-foothold
- bridge-traversal
max_iterations: 5
objective: Determine if a compromised account was used to bridge from a corporate
  foothold into the internal or OT network.
success_criteria: A final verdict of malicious, suspicious, or benign.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on Final Verdict -->
if~: "the final-triage verdict is malicious for at least one host or vendor account" (confidence: high, judge=hunter)
then: → isolate-gateway
indeterminate: → analyst-review
unavailable: → analyst-review
else: → close-out

## isolate-gateway
<!-- Isolate Gateway and Revoke Identity -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised gateway host and revoke the affected vendor account's sessions in the identity provider.
```
→ analyst-review

## analyst-review
<!-- Analyst Post-Mortem -->
```manual target=analyst
Review the correlated timeline; evaluate whether the 'phishing-foothold' query is reliable enough for a permanent detection rule.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Document the hunt outcome, noting that no suspicious gateway activity was found for the lookback period.
```
→ end

---
analysis: A standard rule might flag svchost.exe in user folders, but this hunt correlates
  it with rare discovery activity and known attacker IPs across the fleet. It stack-counts
  discovery tools to separate administrative noise from strategic reconnaissance.
blind_spots:
- id: endpoint-visibility-gap
  question: Are masqueraded binaries running on hosts without monitoring agents?
  requires: endpoint agent installation on all managed hosts
  risk: The RMM can land on unmonitored systems where this behavior is invisible.
  stage: defense-evasion-masquerading
- id: network-log-retention
  question: Did the initial C2 callback happen before the lookback window?
  requires: long-term retention of netflow or socket activity
  risk: Short retention windows may miss the initial beaconing phase.
coverage:
- stage: defense-evasion-masquerading
  status: covered
  steps:
  - masqueraded-svchost
- stage: discovery-process-enumeration
  status: covered
  steps:
  - rare-process-discovery
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: reconnaissance-api-probing
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: initial-access-rce
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: persistence-account-manipulation
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: persistence-c2-tunneling
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: lateral-movement-rmm-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromised RMM tools provide a direct path to total estate control;
    detecting the persistent endpoint-side fallout is the primary means of identifying
    ongoing breaches when appliance logs rotate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder who has compromised an N-central appliance is abusing the
  Take Control feature to drop masqueraded binaries in user folders and perform process
  enumeration on managed hosts.
labels:
- hunt
- attack.t1036.005
- attack.t1057
- attack.t1021.001
- attack.t1090.003
- attack.t1572
name: RMM-Driven Endpoint Lateral Movement and Masquerading
parameters:
  attacker_ips:
    default:
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    description: IP addresses associated with reported N-able exploitation.
    from:
      kind: article
      observed: '2026-09-06'
      ref: huntress-n-able-blog
    type: list[ip]
  discovery_binaries:
    default:
    - tasklist.exe
    - wmic.exe
    - ps.exe
    - whoami.exe
    - systeminfo.exe
    description: Standard binaries used for process discovery and enumeration.
    from:
      kind: manual
      observed: '2026-09-06'
      ref: standard-discovery-tools
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for endpoint activity.
    from:
      kind: manual
      observed: '2026-09-06'
      ref: standard-lookback
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to investigate; paste hostnames from the lead query
      result here to narrow the search.
    from:
      kind: manual
      observed: '2026-09-06'
      ref: scoping-pivot
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
rationale: Prioritize Domain Controllers and file servers; threat actors have been
  observed strategically targeting these high-value assets for enumeration.
references:
- name: "Huntress \u2014 Critical N-able N-central Vulnerability and Active Exploitation"
  url: https://www.huntress.com/blog/n-able-vulnerability-exploitation
related:
- hunt: n-central-appliance-exploitation
  reason: That hunt focuses on the RMM appliance logs for the initial exploit attempt.
  relation: out-of-scope-alternative
- hunt: n-central-web-exploitation-persistence
  relation: follows
scenario:
  stages:
  - name: N-central API Reconnaissance
    observables:
    - GET /remoteControlAction.do?method=getPierDetails
    - 23.234.100.105
    - 173.249.252.200
    - 185.156.46.150
    slug: reconnaissance-api-probing
    tactic: reconnaissance
    techniques:
    - T1190
  - name: Pre-Auth RCE and Auth Bypass
    observables:
    - CVE-2026-86218
    - CVE-2026-18556
    - CVE-2026-18577
    - URL-encoded API requests using %2F
    slug: initial-access-rce
    tactic: initial-access
    techniques:
    - T1190
  - name: Malicious Account Creation
    observables:
    - Email addresses appended with '.invalid'
    - Usernames with subtle character swaps
    - Spoofed domains in email addresses
    slug: persistence-account-manipulation
    tactic: persistence
    techniques:
    - T1136
  - name: Cloudflare Protocol Tunneling
    observables:
    - Service name 'Cloudflared'
    - 'Cloudflare tunnel account tag: 5568cd69c754b392121f1dbb8f900fda'
    slug: persistence-c2-tunneling
    tactic: command-and-control
    techniques:
    - T1572
    - T1090.003
  - name: Masqueraded Binary in User Folder
    observables:
    - svchost.exe located in Documents folder
    slug: defense-evasion-masquerading
    tactic: defense-evasion
    techniques:
    - T1036.005
  - name: Abuse of RMM Take Control
    observables:
    - MSP Support account session logins
    - Take Control session activity (Event IDs 4102, 8192, 8193)
    slug: lateral-movement-rmm-abuse
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Post-Exploitation Process Discovery
    observables:
    - Process list requests following exploitation
    slug: discovery-process-enumeration
    tactic: discovery
    techniques:
    - T1057
  summary: Attackers are exploiting multiple vulnerabilities in N-able N-central,
    including a zero-day RCE, to gain unauthenticated access to RMM consoles. Post-exploitation,
    they maintain persistence via Cloudflare tunnels and malicious user creation before
    using the built-in 'Take Control' feature to move laterally across managed endpoints.
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# RMM-Driven Endpoint Lateral Movement and Masquerading

This hunt identifies the endpoint-side evidence of N-central RMM exploitation. It focuses on identifying masqueraded binaries, specifically svchost.exe running from user-writable paths like Documents, which is an observed post-exploitation technique. The hunt then corroborates this by finding rare process discovery commands and connections to known attacker infrastructure on the affected hosts, allowing an analyst to distinguish intruder activity from legitimate RMM maintenance.

## masqueraded-svchost
<!-- Masqueraded svchost in user paths -->
Identify svchost.exe running from non-standard user-writable paths, a high-fidelity indicator of this campaign.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A row naming a host and user path where svchost.exe is running. Silence
  provides evidence that no such processes are active on enrolled hosts.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) = 'svchost.exe' AND (LOWER(process_path) LIKE '%\\documents\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroboration-fan-out
<!-- Corroborate discovery and network activity -->
parallel:
- → rare-process-discovery
- → attacker-ip-connections
join: → triage-evidence

## rare-process-discovery
<!-- Rare process discovery activity -->
Stack-count discovery commands to identify strategic reconnaissance on suspicious hosts.

```sqlite target=endpoint role=baseline params=(discovery_binaries=discovery_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts running process enumeration tools; widespread administrative
  activity is filtered out.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 5
reads:
- device_hostname
- process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{discovery_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 5 ORDER BY hosts ASC
```

## attacker-ip-connections
<!-- Connections to known attacker IPs -->
Confirm command and control traffic by matching scoped host activity against reported infrastructure.

```sqlite target=network role=enrichment params=(attacker_ips=attacker_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A row showing a suspicious host communicating with a known-malicious IP.
  Absence proves no such connections exist in the telemetry window.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE instr(',' || '{{attacker_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage endpoint evidence -->
```agent target=hunter
cite: required
context:
- masqueraded-svchost
- rare-process-discovery
- attacker-ip-connections
max_iterations: 6
objective: Determine if any host shows evidence of a masqueraded binary accompanied
  by discovery activity or connections to malicious IPs.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  rows.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving a masqueraded svchost process." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-validation
unavailable: → forensic-validation (blind_spot: endpoint-visibility-gap)
else: → forensic-validation

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the endpoint agent and collect the svchost.exe binary from the user path for further analysis.
```
→ forensic-validation

## forensic-validation
<!-- Forensic validation -->
```manual target=analyst
Review the cited rows and check the hb_auth_signin surface for logins by the MSP Support account during the same timeframe. Verify if the svchost.exe binary is signed or presents an unusual metadata signature.
```
→ hunt-close-out

## hunt-close-out
<!-- Hunt close out -->
```manual target=analyst
Ensure the N-central appliance is updated to 2026.3 HF4. Document the observed masquerading paths to refine standing detection rules.
```
→ end

---
analysis: A simple rule for 'cloudflared' triggers on legitimate use; this hunt adds
  value by checking prevalence and correlating with specific intruder C2 infrastructure.
blind_spots:
- id: endpoint-visibility-gap
  question: Are there payloads dropped on systems that do not report to hb_process_activity?
  requires: Endpoint agent on all managed and unmanaged workstations
  risk: A negative result only covers the estate with active telemetry.
  stage: dropped-payload-execution
- id: log-retention-limit
  question: Did the initial tunnel setup occur before the lookback window?
  requires: Extended retention (>30 days) for hb_process_activity
  risk: If logs rotate within 7-14 days, the original execution event may be lost.
  stage: cloudflare-tunnel-persistence
coverage:
- stage: cloudflare-tunnel-persistence
  status: covered
  steps:
  - cloudflare-tunnel-activity
  - malicious-network-connections
- stage: dropped-payload-execution
  status: covered
  steps:
  - rare-svchost-paths
  - payload-file-writes
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: vulnerability-exposure
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: web-reconnaissance-api
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: account-manipulation
  status: out_of_scope
- reason: Belongs to another part of the 'Critical N-able N-central Vulnerability
    and Active Exploitation' series.
  stage: rmm-take-control-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Exploitation of N-central allows 'god-mode' access to the entire
    RMM console. Persistence via tunnels is nearly impossible to block via perimeter
    firewall alone.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established persistence on an N-central server or downstream
  asset using Cloudflare tunnels (marked by a specific account tag) or by dropping
  'svchost.exe' payloads into user-writable folders.
labels:
- hunt
- attack.t1090.003
- attack.t1572
- attack.t1190
name: N-able N-central Tunnel and Payload Persistence
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
    description: Intruder IPs associated with Tzulo VPN and N-able exploitation.
    from:
      kind: article
      observed: '2026-09-06'
      ref: huntress-n-central
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-06'
      ref: default
    type: number
  tunnel_tag:
    default: 5568cd69c754b392121f1dbb8f900fda
    description: Malicious Cloudflare tunnel account tag.
    from:
      kind: article
      observed: '2026-09-06'
      ref: huntress-n-central
    type: string
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
rationale: Start with N-central servers; include all Windows endpoints to capture
  lateral movement where the payload may have spread.
references:
- name: "Huntress \u2014 Critical N-able N-central Vulnerability and Active Exploitation"
  url: https://www.huntress.com/blog/n-able-vulnerability-exploitation
related:
- hunt: n-central-account-manipulation
  reason: Account manipulation is handled in a separate hunt in this series.
  relation: out-of-scope-alternative
- hunt: ncentral-account-remote-session-abuse
  relation: follows
scenario:
  stages:
  - name: N-central Vulnerability Exposure
    observables:
    - CVE-2026-18556
    - CVE-2026-18577
    - CVE-2026-86206
    - CVE-2026-86207
    - CVE-2026-86218
    - N-central versions < 2026.3 HF4
    slug: vulnerability-exposure
    tactic: initial-access
    techniques:
    - T1190
  - name: Web Reconnaissance and API Probing
    observables:
    - /remoteControlAction.do?method=getPierDetails
    - '%2F URL-encoded internal API routes'
    - 23.234.100.105
    - 23.234.97.68
    - 173.249.252.176
    - 185.156.46.150
    - 23.234.94.43
    - 68.235.46.235
    - 173.249.252.200
    slug: web-reconnaissance-api
    tactic: initial-access
    techniques:
    - T1190
  - name: Account Manipulation and Creation
    observables:
    - Accounts appended with '.invalid' (e.g., user@domain.com.invalid)
    - Subtle character swaps in email addresses
    - Login as 'MSP Support'
    slug: account-manipulation
    tactic: persistence
    techniques:
    - T1133
  - name: RMM Take Control Feature Abuse
    observables:
    - MSP Support logins from 173.249.252.200
    - RMM Take Control sessions starting and ending quickly
    - Process list enumeration requests
    slug: rmm-take-control-abuse
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Cloudflare Tunnel Persistence
    observables:
    - Service named 'Cloudflared'
    - Cloudflare tunnel account tag 5568cd69c754b392121f1dbb8f900fda
    slug: cloudflare-tunnel-persistence
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: Malicious Payload Execution
    observables:
    - svchost.exe located in Documents folder
    slug: dropped-payload-execution
    tactic: execution
    techniques:
    - T1190
  summary: Attackers exploit critical vulnerabilities in N-able N-central RMM to achieve
    unauthenticated 'god-mode' access. Following exploitation, they manipulate accounts,
    abuse built-in remote control features for lateral movement, and establish persistence
    via Cloudflare tunnels.
series:
  index: 3
  slug: critical-n-able-n-central-vulnerability-and-active-exploitation
  title: Critical N-able N-central Vulnerability and Active Exploitation
  total: 3
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


# N-able N-central Tunnel and Payload Persistence

This hunt targets the endpoint-visible persistence mechanisms observed in the September 2026 N-able N-central exploitation campaign. It specifically monitors for the creation and execution of svchost.exe in user-writable paths like the Documents folder, and the execution of the Cloudflare tunnel client (cloudflared) with a known malicious account tag. The hunt uses parallel execution to check process rarity, known C2 network connections, and file activity, followed by an agent triage to weigh overlapping indicators on a single host.

## scoping-n-central
<!-- Scope N-central Infrastructure -->
Identify hosts running N-central software or agents to prioritize persistence hunting on the most likely targets.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts acting as RMM servers or managed endpoints. Silence means
  no N-central assets were detected.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%n-central%' OR LOWER(vendor_name) LIKE '%n-able%')
```

## parallel-persistence-checks
<!-- Parallel Persistence Checks -->
parallel:
- → rare-svchost-paths
- → cloudflare-tunnel-activity
- → malicious-network-connections
- → payload-file-writes
join: → triage-persistence

## rare-svchost-paths
<!-- Rare svchost.exe Paths -->
Find instances of svchost.exe running from user-writable paths, a key indicator of the dropped payload.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary named svchost.exe in a user path, seen on very few hosts. Silence
  means no such process is currently active.
prevalence:
  by: device_hostname
  key:
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
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%svchost.exe' AND (LOWER(process_path) LIKE '%\\documents\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_path) HAVING host_count <= 3
```

## cloudflare-tunnel-activity
<!-- Cloudflare Tunnel Activity -->
Identify the 'cloudflared' process or service, specifically checking for the malicious account tag in the command line.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, tunnel_tag=tunnel_tag)
~~~yaml
expected: Execution of cloudflared.exe or the presence of the tag '5568cd69c754b392121f1dbb8f900fda'
  in any command line.
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
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%cloudflared%' OR instr(process_cmd_line, '{{tunnel_tag}}') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## malicious-network-connections
<!-- Connections to Intruder IPs -->
Corroborate endpoint persistence by looking for outbound connections to the campaign's known C2/VPN infrastructure.

```sqlite target=network role=enrichment params=(c2_ips=c2_ips, lookback_days=lookback_days)
~~~yaml
expected: Outbound traffic to the specific IPs listed in the Huntress report. Silence
  says nothing once IPs rotate.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## payload-file-writes
<!-- Payload File Writes -->
Trace the creation of the svchost.exe payload to user-writable folders.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: A file creation event for svchost.exe in a user directory. Silence means
  no such file was created within the logged history.
reads:
- device_hostname
- file_path
- process_name
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, actor_user_name, time FROM hb_file_activity WHERE LOWER(file_name) = 'svchost.exe' AND (LOWER(file_path) LIKE '%\\documents\\%' OR LOWER(file_path) LIKE '%\\users\\public\\%') AND activity_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-persistence
<!-- Triage Persistence Indicators -->
```agent target=hunter
cite: required
context:
- scoping-n-central
- rare-svchost-paths
- cloudflare-tunnel-activity
- malicious-network-connections
- payload-file-writes
max_iterations: 5
objective: Determine if any host shows overlapping indicators of Cloudflare tunneling
  (via service name or account tag) or masqueraded svchost.exe execution in user folders.
success_criteria: A per-host verdict citing specific rows that confirm persistence.
tools:
- endpoint
- network
```

## decision-persistence
<!-- Route on Persistence Verdict -->
if~: "the triage verdict is malicious for at least one host involving tunneling or svchost payloads" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: endpoint-visibility-gap)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not terminate processes until memory has been captured.
```
→ analyst-review

## analyst-review
<!-- Analyst Persistence Review -->
```manual target=analyst
Verify the signature and execution path of 'cloudflared' and 'svchost.exe'. Confirm if the N-central server was patched prior to the event.
```
→ end

## close-out
<!-- Close Out Hunt -->
```manual target=analyst
Record the absence of these specific persistence indicators on the scoping hosts. Recommend scheduling a re-run in 14 days.
```
→ end

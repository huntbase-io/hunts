---
analysis: A simple rule for WMI child processes triggers on every admin login. This
  hunt adds the context of multi-hop proxy egress and uses prevalence to baseline
  'normal' administrative WMI usage, transforming noise into a grounded investigation.
blind_spots:
- id: no-sysmon-pe-metadata
  owner: Detection Engineering
  question: Are renamed shells being detected by their original name?
  remediation: Deploy Sysmon with Event ID 1 enabled on all Windows endpoints.
  requires: Sysmon or EDR with PE header parsing
  risk: If the endpoint agent does not report process_original_file_name, renamed
    shells will only be caught by command-line patterns, which are easier to evade.
  stage: lateral-movement-wmi
- id: tor-over-http
  owner: Network Security
  question: Is Tor traffic being routed through Tor2Web or HTTPS gateways?
  remediation: Implement URL filtering for common Tor2Web gateways.
  requires: hb_http_activity
  risk: Adversaries using HTTPS proxies to access .onion addresses will not generate
    hb_dns_activity rows, making them invisible to this hunt's proxy query.
  stage: c2-multi-hop-proxy
coverage:
- stage: lateral-movement-wmi
  status: covered
  steps:
  - wmi-child-processes
  - anomalous-wmi-pivots
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - rare-proxy-dns-lookups
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Adversaries frequently use WMI for internal movement because it is
    blended with legitimate admin activity. Identifying the intersection of this behavior
    with rare outbound proxy traffic is a high-confidence indicator of a mature threat
    actor.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging WMI for lateral movement to execute shells
  and then establishing command-and-control communication through multi-hop proxy
  networks like Tor to bypass traditional egress monitoring.
labels:
- hunt
- attack.t1047
- attack.t1090.003
name: Remote WMI Execution and Multi-hop Proxy C2
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-07-31'
      ref: standard-lookback
    type: number
  proxy_tlds:
    default:
    - onion
    - onion.ca
    - onion.cab
    - onion.casa
    - onion.city
    - onion.direct
    - hiddenservice.net
    description: Top-level domains or domain fragments associated with multi-hop proxy
      networks.
    from:
      kind: article
      observed: '2024-07-31'
      ref: Elastic Security Labs 9.5
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt; leave empty for fleet-wide.
    from:
      kind: manual
      observed: '2024-07-31'
      ref: analyst-input
    type: list[host]
  suspicious_original_names:
    default:
    - cmd.exe
    - powershell.exe
    - pwsh.exe
    - scrcons.exe
    - wscript.exe
    - cscript.exe
    - schtasks.exe
    - certutil.exe
    description: Original PE filenames for common shells and admin tools spawned via
      WMI.
    from:
      kind: article
      observed: '2024-07-31'
      ref: Elastic Security Labs 9.5
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/agentic-soc-alert-triage-alertzero
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target all Windows hosts. In large environments, prioritize workstations
  first, as servers often have legitimate WMI management overhead that requires stricter
  baselining.
references:
- name: "Elastic Security Labs \u2014 Alert Zero: AI-driven alert triage and attack\
    \ investigation"
  url: https://www.elastic.co/security-labs/blog/agentic-soc-alert-triage-alertzero
related:
- hunt: wmi-event-subscription-persistence
  reason: WMI is also used for persistence via Event Subscriptions, which involves
    the registry and different wmic command lines.
  relation: sibling
scenario:
  stages:
  - name: WMI Remote Execution
    observables:
    - 'wmic.exe /node:'
    - wmiprvse.exe activity
    - process creation via WMI
    - connections on port 135 (DCOM)
    - connections on port 5985 or 5986 (WinRM)
    slug: lateral-movement-wmi
    tactic: execution
    techniques:
    - T1047
  - name: Multi-hop Proxy Command and Control
    observables:
    - DNS queries for .onion domains
    - DNS queries for .onion.ca or .onion.direct
    - Outbound traffic to Tor exit nodes
    - Connections to VPS or Operational Relay Box (ORB) networks
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An adversary leverages Windows Management Instrumentation (WMI) for remote
    command execution and lateral movement across the internal network. Following
    successful movement, the attacker establishes command-and-control using multi-hop
    proxies to mask malicious traffic and evade network-based detections.
severity: medium
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


# Remote WMI Execution and Multi-hop Proxy C2

This hunt identifies the transition from internal lateral movement to external command-and-control. It specifically looks for Windows Management Instrumentation (WMI) provider host (wmiprvse.exe) spawning administrative shells or renamed binaries, stack-counted across the fleet to find anomalies. It simultaneously gathers evidence of rare internal connections on RPC/WinRM ports and DNS lookups for known anonymization networks like Tor, using an agent to correlate these independent signals into a unified attack chain.

## scope-windows-estate
<!-- Scope Windows estate -->
Identify active Windows hosts that could be the target of WMI-based lateral movement.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Windows hostnames. Silence indicates no active Windows hosts are
  reporting telemetry.
reads:
- hostname
- platform
- lifecycle_state
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT hostname, device_uid, os_name, os_version FROM hb_devices WHERE platform = 'windows' AND lifecycle_state = 'running' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY hostname
```

## wmi-child-processes
<!-- Suspicious WMI Child Process Execution -->
Find WMI-initiated execution of shells or administrative tools by checking PE metadata and parentage.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspicious_original_names=suspicious_original_names)
~~~yaml
expected: Rows showing shell activity originating from WMI. A mismatch between process_name
  and original_file_name is a high-confidence signal of binary renaming.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(parent_process_name) LIKE '%\\wmiprvse.exe' AND (instr(',' || '{{suspicious_original_names}}' || ',', ',' || LOWER(process_original_file_name) || ',') > 0 OR LOWER(process_name) LIKE '%cmd.exe%' OR LOWER(process_name) LIKE '%powershell.exe%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-pivots
<!-- Corroborate on Network and Proxy Surfaces -->
parallel:
- → rare-proxy-dns-lookups
- → anomalous-wmi-pivots
join: → triage-agent

## rare-proxy-dns-lookups
<!-- Rare Proxy-Related DNS Activity -->
Identify resolutions for proxy domains and TLDs, stack-counting to isolate one-off activity from noisy but legitimate software.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts, proxy_tlds=proxy_tlds)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Hosts resolving domains linked to Tor or other multi-hop proxies. Small
  host counts (<3) increase the probability of malicious intent.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 4
reads:
- query_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS total_lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{proxy_tlds}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%.hiddenservice.net%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 3 ORDER BY host_count ASC
```

## anomalous-wmi-pivots
<!-- Rare Internal WMI/WinRM Pivots -->
Identify targeted lateral movement by monitoring outbound connections on WMI-related ports (135, 5985, 5986) to rare destination IPs.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of internal IPs receiving WMI traffic from a limited set of sources.
  This filters out enterprise-wide management servers.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 6
reads:
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- time
- direction
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS source_hosts, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port IN (135, 5985, 5986) AND direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING source_hosts <= 5 ORDER BY source_hosts ASC
```

## triage-agent
<!-- Triage Execution and Network Chain -->
```agent target=hunter
cite: required
context:
- wmi-child-processes
- rare-proxy-dns-lookups
- anomalous-wmi-pivots
max_iterations: 6
objective: Determine whether suspicious WMI processes on specific hosts are part of
  a larger intrusion chain involving rare proxy egress or internal lateral pivots.
success_criteria: A per-host verdict of malicious | suspicious | benign citing rows
  from at least two of the three analyzed surfaces.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host AND that host shows WMI execution and either proxy DNS or a rare WMI pivot." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-sysmon-pe-metadata)
else: → analyst-review

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect any binaries cited by the wmi-child-processes step for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Remediation -->
```manual target=analyst
Review the wmi-child-processes command lines for '-enc' or base64 patterns. Verify the DNS lookups against the CISA Tor exit node list. Finalize the triage of suspicious internal pivots.
```
→ end

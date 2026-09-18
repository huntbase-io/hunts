---
analysis: A simple detection rule might look for specific eBPF helper calls, but a
  rootkit can hide the eBPF program itself. This hunt is superior because it uses
  multi-surface correlation (Flow Logs vs Socket Snapshots) to detect the *outcome*
  of the deception, which requires an adversary to manipulate two independent telemetry
  paths simultaneously.
blind_spots:
- id: no-flow-telemetry
  question: Are there network flows occurring that we cannot see because flow logging
    is disabled?
  remediation: Ensure VPC flow logs or host-based network event logging (e.g., Sysmon/Auditd)
    is active for the estate.
  requires: hb_network_connection with state_kind = 'log'
  risk: If only 'live' socket snapshots are available, a rootkit that manipulates
    Netlink will effectively hide its presence, and there will be no baseline log
    to compare against.
  stage: defense-evasion-network-hiding
- id: telemetry-timing-skew
  question: Can we differentiate between a hidden socket and a short-lived ephemeral
    connection?
  remediation: Increase the frequency of socket snapshots or use kernel-level socket
    life-cycle events if available.
  requires: Aligned collection intervals for logs and snapshots
  risk: An ephemeral connection may appear in flow logs but finish before the next
    socket snapshot is taken, creating a false positive for hiding.
coverage:
- stage: defense-evasion-network-hiding
  status: covered
  steps:
  - outbound-traffic-logs
  - socket-snapshot-inventory
  - triage-discrepancies
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - proxy-dns-activity
  - outbound-traffic-logs
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: initial-execution-ebpf-loader
  status: out_of_scope
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: defense-evasion-ebpf-hiding
  status: out_of_scope
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: defense-evasion-anti-debugging
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: EBPF rootkits bypass standard EDR and OS management tools by lying
    at the kernel level. Detecting the discrepancy between what is observed (traffic)
    and what is reported (sockets) is a durable method to expose kernel-level deception.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using an eBPF rootkit to hide C2 connections from user-space
  reporting (Netlink), creating a detectable discrepancy between historical network
  flow logs and point-in-time socket snapshots.
labels:
- hunt
- attack.t1090.003
- attack.t1204.002
name: Hidden Network Connection Discrepancy
parameters:
  c2_proxy_ports:
    default:
    - '443'
    - '9001'
    - '9050'
    - '8080'
    - '4444'
    description: Common proxy and C2 ports to highlight in the discrepancy analysis.
    from:
      kind: article
      observed: '2024-05-15'
      ref: manual
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of historical network traffic and socket snapshots to examine.
    from:
      kind: manual
      observed: '2024-05-15'
      ref: admin
    type: number
  scope_hosts:
    default: []
    description: Optional list of Linux hostnames to narrow the search.
    from:
      kind: manual
      observed: '2024-05-15'
      ref: admin
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scope primarily to Linux servers in public-facing or sensitive zones. Use
  the lookback period to capture historical traffic (logs) that can be compared against
  the 'live' socket state captured periodically.
references:
- name: Detection primitives for eBPF rootkits
  url: https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/
related:
- hunt: ebpf-loader-file-activity
  reason: Detection of the initial payload being dropped and the loader binary executing
    belongs in an execution/file-activity hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious eBPF Rootkit Execution
    observables:
    - LinkPro
    - VoidLink
    - Atomic Arch
    - bpftool
    - sys_enter_bpf
    slug: initial-execution-ebpf-loader
    tactic: execution
    techniques:
    - T1204.002
  - name: eBPF Program and Map Hiding
    observables:
    - bpf_override_return
    - BPF_PROG_GET_NEXT_ID
    - BPF_MAP_GET_NEXT_ID
    - BPF_LINK_GET_NEXT_ID
    - -ENOENT
    - /sys/kernel/debug/tracing/trace_pipe
    - HIDING NEXT_ID
    - BPF cmd
    slug: defense-evasion-ebpf-hiding
    tactic: defense-evasion
    techniques:
    - T1204.002
  - name: Ptrace Attachment Suppression
    observables:
    - PTRACE_ATTACH
    - PTRACE_SEIZE
    - SIGKILL
    - sys_enter_ptrace
    slug: defense-evasion-anti-debugging
    tactic: defense-evasion
    techniques:
    - T1204.002
  - name: Network Socket Hiding via Netlink Tampering
    observables:
    - bpf_probe_write_user
    - ss -tn
    - AF_NETLINK
    - SOCK_DIAG_BY_FAMILY
    - NLM_F_DUMP
    - inet_diag_msg
    - __sys_recvmsg
    slug: defense-evasion-network-hiding
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: Multi-hop Proxy Communication
    observables:
    - TCP traffic on hidden ports
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: Linux malware like VoidLink and LinkPro utilize eBPF rootkits to evade
    detection by tampering with kernel-level introspection and system call responses.
    These campaigns hide network connections from tools like 'ss' and mask malicious
    eBPF programs from 'bpftool' using kernel helpers like bpf_probe_write_user and
    bpf_override_return.
series:
  index: 2
  slug: detection-primitives-for-ebpf-rootkits
  title: Detection primitives for eBPF rootkits
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


# Hidden Network Connection Discrepancy

This hunt identifies eBPF-based rootkits like VoidLink and LinkPro by cross-referencing two distinct telemetry surfaces: historical network flow logs (log) and point-in-time socket snapshots (live). While a rootkit can hide a socket from the 'live' snapshot by manipulating kernel-to-user-space reporting (like the Netlink subsystem used by 'ss'), it is significantly harder to hide the actual traffic from the network fabric or kernel event stream (flow logs). We aggregate outbound traffic to external destinations and compare those destination ports and processes against the reported socket inventory. A persistent flow that never appears as an open socket is a primary indicator of kernel-level evasion. We prioritize ports commonly used by C2 and multi-hop proxies like Tor and Ngrok.

## linux-host-scope
<!-- Identify Linux Assets -->
Identify active Linux systems where eBPF rootkits are applicable to define the baseline population.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Linux hosts. Silence proves the absence of managed Linux systems
  in the reporting window.
reads:
- hostname
- platform
- os_name
- os_version
- device_uid
- activity_id
- time
silence: evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT hostname AS device_hostname, os_name, os_version, device_uid FROM hb_devices WHERE LOWER(platform) = 'linux' AND activity_id = 2 AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-data-collection
<!-- Simultaneous Network and Socket Collection -->
parallel:
- → outbound-traffic-logs
- → socket-snapshot-inventory
- → proxy-dns-activity
join: → triage-discrepancies

## outbound-traffic-logs
<!-- Outbound External Network Traffic -->
Identify external network traffic observed by the host or network fabric that might be hidden from user-space tools.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, c2_proxy_ports=c2_proxy_ports)
~~~yaml
expected: External flows and their owning processes. Silence means no external outbound
  traffic was logged.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- state_kind
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, (instr(',' || '{{c2_proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AS is_c2_port, COUNT(*) as flow_count FROM hb_network_connection WHERE state_kind = 'log' AND direction = 'outbound' AND dst_endpoint_ip NOT LIKE '10.%' AND dst_endpoint_ip NOT LIKE '192.168.%' AND dst_endpoint_ip NOT LIKE '127.%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4, 5 HAVING flow_count > 2
```

## socket-snapshot-inventory
<!-- Reported Socket Inventory -->
Obtain the 'ground truth' according to the operating system's user-space management tools.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A snapshot of currently open sockets. Silence means no sockets were reported
  during collection.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_port
  rare_below: 5
reads:
- device_hostname
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
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, MIN(time) as first_seen FROM hb_network_connection WHERE state_kind = 'live' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4
```

## proxy-dns-activity
<!-- Proxy and C2 DNS Lookups -->
Corroborate discrepancy findings with lookups for multi-hop proxy infrastructure (Tor, Ngrok) or side-channel tunneling.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Lookups for known proxy infrastructure. Silence suggests C2 may be using
  hardcoded IPs or a different proxy method.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as query_count FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%.onion%' OR LOWER(query_hostname) LIKE '%ngrok%' OR LOWER(query_hostname) LIKE '%tunnel%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## triage-discrepancies
<!-- Analyze Traffic-Socket Discrepancy -->
```agent target=hunter
cite: required
context:
- outbound-traffic-logs
- socket-snapshot-inventory
- proxy-dns-activity
max_iterations: 5
objective: Compare 'outbound-traffic-logs' against 'socket-snapshot-inventory' for
  each host. Identify persistent traffic (multiple flows) to an IP/port that never
  appears in the socket list. Prioritize discrepancies on ports in {{c2_proxy_ports}}
  or hosts showing DNS lookups in 'proxy-dns-activity'.
success_criteria: A verdict citing specific IP/ports that appear in logs but not snapshots.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route Based on Discrepancy -->
if~: "The triage identifies a persistent discrepancy between network logs and socket snapshots for an external destination on at least one host." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: no-flow-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Affected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture an eBPF memory dump and forensic image before rebooting, as the rootkit and its loaded programs may reside entirely in kernel memory.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Manual Discrepancy Review -->
```manual target=analyst
1. Inspect destination IPs from 'outbound-traffic-logs' against threat intelligence. 2. Verify if the 'process_name' associated with the log flows is legitimate but suspicious (e.g., systemd talking to Tor). 3. Look for '/sys/kernel/debug/tracing/trace_pipe' content on the host for 'HIDING' messages. 4. Check for ephemeral connection timing skew where short-lived flows might naturally miss a periodic snapshot.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the hosts validated as 'all sockets accounted for'. Update any identified false positives for ephemeral traffic into a tuning list for next month's run.
```
→ end

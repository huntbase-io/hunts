---
analysis: A standard detection rule can alert on the use of 'bpftool' or 'strace',
  but only a hunt can perform the stateful comparison between fabric-level network
  flows and host-level sockets to find discrepancies that a local agent cannot see
  on its own.
blind_spots:
- id: no-network-telemetry
  question: whether outbound traffic exists that the OS is hiding
  requires: VPC Flow Logs or network-layer telemetry in hb_network_connection (state_kind
    = 'log')
  risk: Without fabric-level logs, we only see what the (potentially compromised)
    OS reports. A rootkit hiding from Netlink will hide from our agent as well.
  stage: defense-evasion-connection-hiding
- id: ebpf-disabled-logging
  question: whether the malware is logging its evasion attempts to trace_pipe
  requires: bpf_printk being enabled/used by the malware
  risk: If the malware author removes debug logging (bpf_printk), the 'tracing-pipe-access'
    indicator disappears.
  stage: defense-evasion-ptrace-blocking
coverage:
- stage: defense-evasion-connection-hiding
  status: covered
  steps:
  - ghost-network-connections
- stage: defense-evasion-ptrace-blocking
  status: covered
  steps:
  - debugger-terminations
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: initial-execution-malicious-file
  status: out_of_scope
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: defense-evasion-program-hiding
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: EBPF rootkits undermine the integrity of local security tools by
    lying at the kernel level. Only a cross-surface comparison between the network
    fabric and the endpoint can reliably detect these 'ghost' signals. A negative
    result confirms that the introspection tools used by the SOC remain trustworthy.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed an eBPF rootkit that hides C2 connections from
  local network utilities like 'ss' and prevents forensics by killing debugging tools
  like 'strace' or 'bpftool'.
labels:
- hunt
- attack.t1090.003
- attack.t1562.001
name: eBPF Rootkit Introspection Bypass
parameters:
  known_debuggers:
    default:
    - strace
    - gdb
    - bpftool
    - ss
    - tcpdump
    description: Common introspection and debugging tools targeted by rootkits.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
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
rationale: 'Focus on high-value Linux targets: database servers, domain controllers
  (if Linux-based), and bastion hosts. These are the most likely targets for persistent
  rootkits.'
references:
- name: "Datadog Security Labs \u2014 Detection primitives for eBPF rootkits"
  url: https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/
related:
- hunt: ebpf-program-enumeration-discrepancy
  reason: Detection of LinkPro's program hiding requires running bpftool manually
    to find ID discrepancies, which belongs in a forensic-heavy hunt.
  relation: out-of-scope-alternative
- hunt: ebpf-rootkit-debug-logging-execution
  relation: follows
scenario:
  stages:
  - name: Malicious file execution
    observables:
    - Execution of dropper or eBPF loader binary
    - Loading of eBPF programs into the kernel
    slug: initial-execution-malicious-file
    tactic: execution
    techniques:
    - T1204.002
  - name: Hiding active network connections
    observables:
    - Manipulation of Netlink socket responses using bpf_probe_write_user
    - Inflation of nlmsghdr length fields in ss -tn output
    - Discrepancy between ss utility output and actual established TCP connections
    - kprobe attached to __sys_recvmsg
    - kretprobe attached to __sys_recvmsg
    slug: defense-evasion-connection-hiding
    tactic: defense-evasion
    techniques:
    - T1090.003
  - name: Hiding eBPF program IDs
    observables:
    - sys_enter_bpf tracepoint watching BPF_PROG_GET_NEXT_ID
    - Injection of -ENOENT return value via bpf_override_return
    - Plaintext logs in /sys/kernel/debug/tracing/trace_pipe containing 'HIDING NEXT_ID'
    - 'Plaintext logs in /sys/kernel/debug/tracing/trace_pipe containing ''BPF cmd:
      %d, start_id: %u'''
    - Truncated output in bpftool prog list enumeration
    slug: defense-evasion-program-hiding
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Anti-debugging and ptrace blocking
    observables:
    - sys_enter_ptrace tracepoint intercepting PTRACE_ATTACH (0x10) or PTRACE_SEIZE
      (0x4206)
    - Automated delivery of SIGKILL (9) to processes attempting to trace specific
      PIDs
    - Presence of hidden_pids eBPF map
    slug: defense-evasion-ptrace-blocking
    tactic: defense-evasion
    techniques:
    - T1562.001
  summary: eBPF rootkits such as VoidLink and LinkPro evade detection by manipulating
    kernel-to-userspace memory and return values to hide network connections and malicious
    eBPF programs. These tools utilize specific eBPF helpers like bpf_probe_write_user
    and bpf_override_return to spoof system utility outputs and protect malicious
    processes from being traced.
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


# eBPF Rootkit Introspection Bypass

Linux rootkits like VoidLink and LinkPro use eBPF helpers like `bpf_probe_write_user` and `bpf_override_return` to manipulate kernel responses before they reach userspace. This hunt identifies these rootkits by finding 'ghost' connections—outbound traffic visible to the network fabric but absent from endpoint socket snapshots—and by stack-counting anomalous terminations of system introspection tools that suggest automated evasion.

## scope-linux-hosts
<!-- Scope Linux estate -->
Identify all Linux hosts in the estate to narrow the subsequent behavioural queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of Linux hostnames. Silence means no Linux hosts are enrolled, making
  this hunt inapplicable.
reads:
- device_uid
- hostname
- lifecycle_state
- os_name
- os_version
- platform
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT hostname, device_uid, os_name, os_version FROM hb_devices WHERE LOWER(platform) = 'linux' AND lifecycle_state = 'running'
```

## ghost-network-connections
<!-- Identify Ghost Connections -->
Find network traffic (flows) that exist at the fabric layer but are never reported as open sockets by the endpoint agent, suggesting local hiding.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows where the network sees traffic but the OS claims no socket exists.
  This is the primary indicator of a Netlink-level rootkit like VoidLink.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, protocol, COUNT(CASE WHEN state_kind = 'log' THEN 1 END) AS fabric_flow_count, COUNT(CASE WHEN state_kind = 'live' THEN 1 END) AS agent_socket_count FROM hb_network_connection WHERE time >= datetime('now', '-{{lookback_days}} days') AND direction = 'outbound' GROUP BY 1, 2, 3, 4 HAVING fabric_flow_count > 5 AND agent_socket_count = 0 ORDER BY fabric_flow_count DESC
```

## corroborate-evasion
<!-- Corroborate evasion tactics -->
parallel:
- → debugger-terminations
- → tracing-pipe-access
join: → triage

## debugger-terminations
<!-- Anomalous debugger terminations -->
Count terminations of debugging and network tools; rootkits often deliver SIGKILL to these processes to prevent discovery.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, known_debuggers=known_debuggers)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A high count of 'ss' or 'strace' terminations on a single host. In the context
  of eBPF rootkits, this indicates a defensive hook firing.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, COUNT(*) as kill_events FROM hb_process_activity WHERE activity_id = 2 AND (instr(',' || '{{known_debuggers}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{known_debuggers}}' || ',', ',' || LOWER(process_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3, 4 HAVING kill_events > 1
```

## tracing-pipe-access
<!-- Access to kernel tracing pipe -->
Detect processes reading from the trace_pipe, where LinkPro-style rootkits inadvertently stream their debug logs.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Any process reading the tracing pipe. While often legitimate for admins,
  it is used by rootkit userspace components to receive status updates.
reads:
- device_hostname
- file_path
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_cmd_line, file_path, time FROM hb_file_activity WHERE (LOWER(file_path) = '/sys/kernel/debug/tracing/trace_pipe' OR LOWER(file_path) LIKE '%/trace_pipe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage
<!-- Analyze evasion patterns -->
```agent target=hunter
cite: required
context:
- ghost-network-connections
- debugger-terminations
- tracing-pipe-access
max_iterations: 4
objective: Determine if a host is showing signs of eBPF rootkit activity by weighing
  'ghost' connections against anti-debugging signals.
success_criteria: A verdict of malicious | suspicious | benign per host with evidence
  citations.
tools:
- endpoint
- network
```

## route
<!-- Route on verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately. Capture a full memory dump before rebooting, as eBPF programs live in kernel memory.
```
→ analyst-review

## analyst-review
<!-- Review eBPF indicators -->
```manual target=analyst
Compare the destination IPs found in the fabric logs against your threat intelligence. If the IPs are known C2 and are missing from the endpoint's socket logs, this is a confirmed rootkit. Verify if 'bpftool' is present on the host and whether it fails to run.
```
→ end

## close-out
<!-- Close and document -->
```manual target=analyst
Note the hosts examined and the lack of ghost connections. Schedule a periodic re-run of the fabric vs. agent comparison.
```
→ end

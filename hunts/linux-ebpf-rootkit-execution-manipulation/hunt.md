---
analysis: A standard detection rule might alert on a known loader path, but this hunt
  pivots between execution indicators, kernel debug log artifacts, ptrace-blocking
  behavior, and network prevalence. It specifically searches for the discrepancies
  caused by kernel lies that a single rule cannot reconcile.
blind_spots:
- id: kernel-telemetry-suppression
  question: whether the rootkit has hooked the specific tracepoints our agent uses
    to report process and file activity
  requires: kernel-level introspection that bypasses BPF hooks
  risk: A highly advanced rootkit could suppress the very telemetry used by this hunt,
    making the host appear clean.
  stage: ebpf-rootkit-deployment
- id: netlink-blindness
  question: whether active connections exist that are completely invisible to both
    ss and the local endpoint agent
  requires: non-Netlink network telemetry (e.g., from VPC fabric or mirror)
  risk: VoidLink specifically manipulates Netlink buffers; if the endpoint agent also
    uses Netlink for socket inventory, it will be equally blind to the hidden ports.
  stage: netlink-socket-hiding
coverage:
- stage: ebpf-rootkit-deployment
  status: covered
  steps:
  - loader-execution
- stage: netlink-socket-hiding
  status: covered
  steps:
  - rare-network-egress
- reason: Rootkits using bpf_override_return with -ENOENT truncate the kernel's own
    enumeration; these surfaces read the resulting truncated list and cannot see the
    hidden objects without out-of-band kernel verification.
  stage: ebpf-object-concealment
  status: not_visible
- stage: ptrace-access-denial
  status: covered
  steps:
  - ptrace-blocking-anomalies
- stage: tracing-log-artifacts
  status: covered
  steps:
  - trace-pipe-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: eBPF rootkits represent a Tier 1 evasion capability that defeats
    traditional Linux auditing. Identifying kernel-level manipulation and the artifacts
    left behind is essential for maintaining integrity on critical Linux workloads.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed an eBPF rootkit that hides network connections
  and kernel objects by manipulating syscall returns and tampering with Netlink buffers.
labels:
- hunt
- attack.t1204.002
- attack.t1014
- attack.t1562.001
- attack.t1090.003
name: Linux eBPF Rootkit Execution and Manipulation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to scope the hunt; leave empty to scan
      all Linux hosts.
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
rationale: Focus on high-value Linux infrastructure such as database servers and API
  gateways where network concealment is most likely. Widen the scope to include development
  environments where custom eBPF code might provide cover for rootkit loading.
references:
- name: Detection primitives for eBPF rootkits
  url: https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/
related:
- hunt: rare-linux-kernel-module-load
  reason: Rootkits may also persist via traditional kernel modules; this hunt focuses
    specifically on the eBPF mechanism.
  relation: sibling
scenario:
  stages:
  - name: eBPF Rootkit Execution
    observables:
    - Execution of rootkit loaders (LinkPro, VoidLink)
    - Loading of eBPF programs into the kernel
    slug: ebpf-rootkit-deployment
    tactic: execution
    techniques:
    - T1204.002
  - name: Network Connection Hiding
    observables:
    - Use of bpf_probe_write_user to inflate nlmsg_len
    - Tampering with Netlink socket statistics in __sys_recvmsg
    - Discrepancy between ss output and actual kernel sockets
    - kretprobe attached to __sys_recvmsg
    slug: netlink-socket-hiding
    tactic: defense-evasion
    techniques:
    - T1014
  - name: eBPF Program Concealment
    observables:
    - Use of bpf_override_return to inject -ENOENT
    - Interception of BPF_PROG_GET_NEXT_ID (11)
    - Interception of BPF_MAP_GET_NEXT_ID (12)
    - Interception of BPF_LINK_GET_NEXT_ID (31)
    - Truncated output in bpftool prog list
    slug: ebpf-object-concealment
    tactic: defense-evasion
    techniques:
    - T1014
  - name: Anti-Debugging Ptrace Blocking
    observables:
    - SIGKILL sent to processes calling PTRACE_ATTACH (0x10)
    - SIGKILL sent to processes calling PTRACE_SEIZE (0x4206)
    - Tracepoint attached to sys_enter_ptrace
    slug: ptrace-access-denial
    tactic: defense-evasion
    techniques:
    - T1562.001
  - name: Kernel Debug Log Leakage
    observables:
    - 'BPF cmd: %d, start_id: %u in trace_pipe'
    - 'HIDING NEXT_ID: %u in trace_pipe'
    - Access to /sys/kernel/debug/tracing/trace_pipe
    slug: tracing-log-artifacts
    tactic: defense-evasion
    techniques:
    - T1014
  summary: Linux eBPF rootkits like VoidLink and LinkPro leverage kernel helpers to
    manipulate system call returns and memory in real-time. These tools hide malicious
    network connections by tampering with Netlink response buffers and conceal their
    own eBPF programs from administrative tools by overriding sys_bpf return values.
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


# Linux eBPF Rootkit Execution and Manipulation

This hunt identifies modern Linux eBPF rootkits like VoidLink and LinkPro by searching for the behavioral discrepancies they create. It focuses on identifying suspicious loader execution, kernel debug log artifacts from trace pipes, and defense evasion techniques such as ptrace blocking and Netlink manipulation. The hunt follows a phased approach: it first identifies candidate loaders and debug leaks, then examines follow-on behavior like unexpected utility terminations and rare network connections that standard system tools would hide.

## linux-asset-scope
<!-- Scope Linux assets -->
Identify active Linux hosts where eBPF rootkit activity is possible.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of active Linux hostnames. This provides the candidate set for subsequent
  behavioral queries.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname FROM hb_devices WHERE platform = 'linux' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-indicator-fanout
<!-- Early stage indicators -->
parallel:
- → loader-execution
- → trace-pipe-activity
join: → deployment-triage

## loader-execution
<!-- Suspicious rootkit loaders -->
Find binaries executed from temporary paths or bpftool usage that may load rootkit objects.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Process starts for bpftool or binaries in user-writable paths. Rootkits
  often use bpftool or custom loaders to inject kernel programs.
reads:
- device_hostname
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%' OR LOWER(process_name) LIKE '%bpftool%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## trace-pipe-activity
<!-- Kernel debug log leakage -->
Identify processes reading the trace pipe which reveals rootkit debug strings.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Access events to trace_pipe. LinkPro leaves artifacts like 'HIDING NEXT_ID'
  in this buffer, which tools or attackers may read.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%/trace_pipe' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## deployment-triage
<!-- Weigh deployment evidence -->
```agent target=hunter
cite: required
context:
- loader-execution
- trace-pipe-activity
max_iterations: 3
objective: Determine if any Linux host shows high-confidence evidence of eBPF rootkit
  deployment based on process execution and debug log access.
success_criteria: A per-host summary of suspicious behavior.
tools:
- endpoint
- network
```

## evasion-behavior-fanout
<!-- Evasion and concealment fan-out -->
parallel:
- → ptrace-blocking-anomalies
- → rare-network-egress
join: → rootkit-synthesis

## ptrace-blocking-anomalies
<!-- Ptrace-blocking process anomalies -->
Identify processes that terminate unexpectedly while performing introspection, a common rootkit defense.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Sudden termination of enumeration tools. Rootkits may send SIGKILL to processes
  attempting to attach via ptrace to hidden PIDs.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
- activity_id
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, time FROM hb_process_activity WHERE activity_id = 2 AND (LOWER(process_name) IN ('ss', 'ps', 'bpftool', 'strace', 'gdb')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-network-egress
<!-- Rare network outbound connections -->
Identify outbound connections seen on very few hosts that may be hidden from local utilities like ss.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of IP/port pairs seen on only one or two hosts. This surfaces connections
  the rootkit attempts to hide from local Netlink-based tools.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_network_connection WHERE direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2
```

## rootkit-synthesis
<!-- Synthesize rootkit indicators -->
```agent target=hunter
cite: required
context:
- deployment-triage
- ptrace-blocking-anomalies
- rare-network-egress
max_iterations: 5
objective: Confirm the presence of an active eBPF rootkit by correlating deployment
  indicators (loaders, trace logs) with active evasion (ptrace blocking, rare connections).
success_criteria: A high-confidence per-host verdict citing specific evidence from
  all phases.
tools:
- endpoint
- network
```

## remediation-decision
<!-- Route on rootkit verdict -->
if~: "The synthesis agent identifies correlated evidence of suspicious loader activity, trace pipe logs, and active kernel-level evasion like ptrace blocking." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-forensic-task
unavailable: → analyst-forensic-task (blind_spot: kernel-telemetry-suppression)
else: → analyst-forensic-task

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Before re-imaging, capture a full memory dump and the /sys/kernel/debug/tracing/trace buffer to recover eBPF program IDs.
```
→ analyst-forensic-task

## analyst-forensic-task
<!-- Analyst forensic verification -->
```manual target=analyst
Review the process terminations and loader execution history. Compare the enumerated network connections from this hunt against standard endpoint socket telemetry to confirm hidden flows.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure and tuning -->
```manual target=analyst
Document the rootkit variants and update the suspicious rootkit loaders query with any newly discovered paths or command patterns.
```
→ end

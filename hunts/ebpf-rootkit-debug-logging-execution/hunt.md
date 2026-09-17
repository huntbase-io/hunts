---
analysis: A standard detection rule might flag any binary in /tmp, leading to fatigue.
  This hunt adds critical context by correlating that rarity with interaction with
  the kernel tracing subsystem and a fleet-wide baseline, providing a high-fidelity
  pivot for an analyst.
blind_spots:
- id: trace-pipe-content-missing
  question: What specific debug strings (e.g., 'HIDING NEXT_ID') were written to the
    tracing pipe?
  requires: kernel log collection or direct pipe content monitoring
  risk: We can see the interaction with the pipe but not the plaintext 'smoking gun'
    logs mentioned in the LinkPro research, requiring we rely on process rarity.
  stage: defense-evasion-program-hiding
- id: ephemeral-tmp-files
  question: Did the loader binary delete itself immediately after loading the eBPF
    program?
  requires: real-time process creation events with long retention
  risk: If a snapshot-based tool misses the short window of execution, we may only
    see the file-touch on the pipe without the associated process.
  stage: initial-execution-malicious-file
coverage:
- stage: initial-execution-malicious-file
  status: covered
  steps:
  - suspicious-loader-execution
  - rare-process-baseline
- stage: defense-evasion-program-hiding
  status: covered
  steps:
  - trace-pipe-interaction
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: defense-evasion-connection-hiding
  status: out_of_scope
- reason: Belongs to another part of the 'Detection primitives for eBPF rootkits'
    series.
  stage: defense-evasion-ptrace-blocking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: eBPF rootkits achieve near-total invisibility by subverting the tools
    used for detection. Identifying the loader execution or its debug artifacts is
    one of the few ways to intercept a compromise before the rootkit successfully
    hides itself.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has deployed an eBPF-based rootkit by executing a loader
  from a writable path, which unintentionally leaves plaintext debug artifacts in
  the kernel tracing pipe while attempting to hide program IDs.
labels:
- hunt
- attack.t1204.002
- attack.t1562.001
name: eBPF Rootkit Debug Logging and Execution
parameters:
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
rationale: The hunt should prioritize Linux production servers and admin workstations
  running kernels 4.18+, as these are the primary targets for eBPF rootkits.
references:
- name: Detection primitives for eBPF rootkits
  url: https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/
related:
- hunt: ebpf-connection-hiding-behavior
  reason: Detection of VoidLink's ss-bypass requires deep netlink/syscall tracing
    not covered here.
  relation: out-of-scope-alternative
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
  index: 1
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
tlp: clear
type: investigation
---


# eBPF Rootkit Debug Logging and Execution

eBPF rootkits like LinkPro and VoidLink represent a significant shift in Linux persistence, subverting standard kernel introspection tools. This hunt targets the 'loader' phase and the forensic artifacts left by the bpf_printk helper. By correlating rare process execution in writable Linux paths with unusual access to the kernel tracing filesystem (/sys/kernel/debug/tracing/trace_pipe), we can identify loaders that have successfully bypassed standard enumeration tools like bpftool.

## linux-inventory
<!-- Inventory of Linux Assets -->
Scope the hunt to Linux hosts where eBPF rootkits are viable.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of Linux hosts. Silence means no Linux devices are currently enrolled
  in telemetry.
reads:
- device_uid
- hostname
- last_seen
- os_name
- os_version
- platform
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT hostname, os_name, os_version, device_uid FROM hb_devices WHERE platform = 'Linux' AND last_seen >= datetime('now', '-{{lookback_days}} days')
```

## suspicious-loader-execution
<!-- Suspicious Process Execution from Writable Paths -->
Detect the execution of potential eBPF loaders from common user-writable or temporary paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Binaries running from /tmp or /dev/shm that reference 'bpf'. These are common
  deployment sites for Linux malware.
reads:
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
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/var/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%') AND (LOWER(process_name) LIKE '%loader%' OR LOWER(process_cmd_line) LIKE '%bpf%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate Loader Activity -->
parallel:
- → rare-process-baseline
- → trace-pipe-interaction
join: → ebpf-triage

## rare-process-baseline
<!-- Baseline for Rare Writable-Path Binaries -->
Establish prevalence for the binaries found in the execution step to filter out legitimate admin scripts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Binaries seen on very few hosts. A rootkit loader will typically be unique
  or extremely rare compared to fleet-wide utilities.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '/tmp/%' OR LOWER(process_path) LIKE '/var/tmp/%' OR LOWER(process_path) LIKE '/dev/shm/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_path HAVING host_count <= 2
```

## trace-pipe-interaction
<!-- Interaction with Kernel Trace Pipe -->
Find processes reading or writing to the tracing pipe where LinkPro artifacts are emitted.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Any process other than standard tracing tools (e.g., trace-cmd, bpftool)
  touching this file. This suggests a process is either logging via eBPF or monitoring
  debug logs.
reads:
- activity_name
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, file_path, activity_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%/tracing/trace_pipe' AND time >= datetime('now', '-{{lookback_days}} days')
```

## ebpf-triage
<!-- Triage eBPF Loader Activity -->
```agent target=hunter
cite: required
context:
- suspicious-loader-execution
- rare-process-baseline
- trace-pipe-interaction
max_iterations: 5
objective: Determine if any host shows a rare binary running from a writable path
  that also interacted with /sys/kernel/debug/tracing/trace_pipe, indicating a possible
  eBPF rootkit like LinkPro.
success_criteria: A per-host verdict citing specific PIDs and file interactions.
tools:
- endpoint
```

## route-verdict
<!-- Route Triage Results -->
if~: "The triage verdict is malicious for any host exhibiting rare loader execution and tracing pipe interaction." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: trace-pipe-content-missing)
else: → close-out

## isolate-host
<!-- Isolate Host for Forensic Analysis -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and initiate a memory dump and disk image collection for forensic analysis of eBPF program IDs.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Manually inspect the binary found in /tmp or /dev/shm. If possible, run 'bpftool prog list' and check for discrepancies against 'bpftool prog show id N' for known IDs to confirm hiding behavior.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the hosts scanned and the prevalence of binaries in writable paths for future baseline comparison.
```
→ end

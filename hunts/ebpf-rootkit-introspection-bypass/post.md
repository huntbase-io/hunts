# Detecting eBPF Rootkit Introspection Bypasses through Network Fabric Discrepancies

### Why Now
Modern Linux rootkits have moved beyond simple binary replacement. As detailed by Datadog Security Labs in their research [Detection primitives for eBPF rootkits](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/), tools like VoidLink and LinkPro utilize eBPF helpers such as `bpf_probe_write_user` and `bpf_override_return` to intercept and modify kernel-to-userspace communication. This allows an adversary to hide their presence from standard system utilities like `ss` or `ps` at the source, making them invisible to many host-based detection mechanisms.

### The Hypothesis
We hypothesize that an adversary has deployed an eBPF-based rootkit to maintain persistence and hide C2 traffic. While the rootkit can successfully lie to the local operating system, it cannot manipulate the physical network fabric or the reality of external telemetry. Therefore, discrepancies between what the network fabric records and what the endpoint reports as 'active' sockets will reveal the rootkit's footprint. Additionally, we expect to see evidence of defensive evasion through the automated termination of system introspection and debugging tools.

### How the Hunt Flows
The first phase of the hunt focuses on identifying 'Ghost Connections' by pivoting across the `hb_network_connection` surface. We compare outbound flow logs—telemetry captured from the network layer—against live socket snapshots reported by the endpoint agent. We are specifically looking for high-volume traffic destinations that appear in the fabric logs but have zero corresponding 'live' socket entries on the host. This discrepancy suggests the rootkit is hooked into the Netlink subsystem to filter out its own traffic from local view.

In the second phase, we corroborate this evasion by examining the `hb_process_activity` surface. We look for anomalous termination patterns where common debugging and network utilities, such as `strace`, `bpftool`, or `tcpdump`, are killed immediately upon execution. In an eBPF rootkit scenario, this is often the result of a kprobe or tracepoint hook designed to deliver a `SIGKILL` to any process attempting to inspect kernel state or packet flow.

Finally, we check the `hb_file_activity` surface for access to the kernel tracing pipe. Many rootkits, particularly during their development or early deployment phases, inadvertently leak debug information to `/sys/kernel/debug/tracing/trace_pipe`. While legitimate admins use this pipe, unauthorized or unexpected processes reading from it can indicate a rootkit's userspace component receiving status updates or logs from its kernel-mode programs.

### What This Hunt Cannot See
This hunt has two primary blind spots. First, it relies heavily on the availability of fabric-level network logs (such as VPC Flow Logs). If the environment only provides endpoint-reported network data, the 'ghost connection' logic will fail because the rootkit is successfully deceiving the reporter. Second, if a rootkit author has disabled all debug logging (`bpf_printk`) and does not use aggressive process killing, the secondary indicators of evasion will remain silent.

### How to Run It
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported directly into Huntbase or any other `hunt.md`-aware runtime. Because this is a hunt and not a static detection, it performs stateful comparisons across multiple telemetry sources that are too resource-intensive for standard real-time alerting but are essential for uncovering kernel-level subversion.

# eBPF Rootkit Detection via Loader Execution and Kernel Tracing Pipes

### Why now
Recent research by Datadog Security Labs in their article [Detection primitives for eBPF rootkits](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/) has highlighted how modern Linux rootkits like LinkPro and VoidLink achieve invisibility. These threats often subvert standard kernel introspection tools, such as bpftool, making traditional detection difficult. However, the process of loading these rootkits and their reliance on debug logging provides specific, observable artifacts that can be hunted at scale across a Linux fleet.

### The Hypothesis
Our hunt is based on the premise that an adversary has deployed an eBPF-based rootkit by executing a custom loader from a writable directory (such as /tmp or /dev/shm). We hypothesize that this loader, or the eBPF program itself, unintentionally leaves plaintext debug artifacts in the kernel tracing pipe (/sys/kernel/debug/tracing/trace_pipe) while attempting to hide its presence from the operating system.

### How the Hunt Flows
The first phase involves scoping the environment to identify Linux assets capable of running modern eBPF programs, typically those with kernel versions 4.18 and above. This ensures the hunt is focused on the correct surfaces where these rootkits are functionally viable.

We then look for process execution events originating from common user-writable or temporary paths. We specifically filter for binaries that include keywords like 'bpf' or 'loader' in their name or command line. While this can be noisy in development environments, it serves as the primary entry point for the investigation.

To refine the results, the hunt performs a parallel analysis. We establish a fleet-wide baseline to identify rare binaries that appear on only a handful of hosts. Simultaneously, we examine file activity logs for any process interacting with the kernel tracing pipe. This correlation is key: a rare binary in /tmp that also touches the tracing subsystem is a high-fidelity indicator of a potential rootkit loader.

Finally, the triage phase combines these signals. If a process is both rare and interacting with the tracing pipe, it warrants immediate forensic review, including potential host isolation and memory analysis to confirm if eBPF program IDs are being hidden from the kernel.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, while we can detect the interaction with the tracing pipe, we typically do not see the specific plaintext strings (such as 'HIDING NEXT_ID') without deeper kernel log collection. Second, if a loader binary is programmed to delete itself immediately after the eBPF program is resident in memory, ephemeral process logs may miss the execution window if retention or sampling is insufficient.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It is designed to be imported directly into Huntbase or any other `hunt.md`-aware runtime. Because this is a hunt rather than a static detection, it prioritizes establishing context and rarity over firing on single events, making it suitable for periodic sweeps of production Linux infrastructure.

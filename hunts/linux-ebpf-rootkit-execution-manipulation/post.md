# Hunting Linux eBPF Rootkits via Behavioral Discrepancies

### Why Hunt for eBPF Rootkits?
Modern Linux rootkits increasingly use eBPF to achieve stealth. By attaching programs to kernel functions, an adversary can hide files, network connections, and even other eBPF objects. Traditional tools like `ps` or `ss` rely on the kernel to tell the truth, but a rootkit can manipulate these responses. This hunt follows research from Datadog Security Labs titled [Detection primitives for eBPF rootkits](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/) to identify these kernel-level lies.

### The Hypothesis
An intruder has deployed an eBPF rootkit that hides network connections and kernel objects by manipulating syscall returns and tampering with Netlink buffers.

### How the Hunt Flows
The first query identifies active Linux hosts to establish a target scope. This ensures the hunt runs against relevant infrastructure, such as database servers or API gateways, where rootkit persistence provides the highest value for an attacker.

Next, the hunt searches for early indicators of rootkit deployment in parallel. It monitors for suspicious process execution, specifically looking for binaries running from `/tmp` or `/dev/shm`, or the use of `bpftool` to load kernel objects. Simultaneously, it looks for any process reading from the kernel trace pipe. This file often contains leaked debug strings from rootkits like LinkPro, which can reveal the IDs of hidden objects.

The third phase examines active evasion behavior. Many eBPF rootkits protect themselves by blocking `ptrace` calls, which causes diagnostic tools like `strace`, `gdb`, or even `ps` to terminate unexpectedly. The hunt identifies these sudden terminations. It also builds a baseline of network egress to find connections seen on only one or two hosts. This surfaces outbound traffic that a rootkit might be attempting to hide from local Netlink-based enumeration utilities.

Finally, an automated agent correlates these findings. If a host shows both suspicious loader activity and active evasion signals like `ptrace` blocking, the agent issues a high-confidence verdict for manual review or isolation.

### Blind Spots and Limitations
This hunt faces two primary challenges. First, if a rootkit is advanced enough to suppress the specific kernel tracepoints our agent uses for telemetry, the host may appear clean. This is an inherent risk when hunting kernel-level threats. Second, if both the local diagnostic tools and the security agent rely on Netlink for socket inventory, a rootkit that manipulates Netlink buffers will hide connections from both the system and the security stack.

### How to Run This Hunt
This hunt follows the open `hunt.md` playbook format. You can import it into Huntbase or any other `hunt.md`-aware runtime. Because it pivots between execution history and network prevalence, it functions as a hunt rather than a simple detection rule. It requires behavioral correlation to distinguish between legitimate eBPF development and malicious rootkit activity.

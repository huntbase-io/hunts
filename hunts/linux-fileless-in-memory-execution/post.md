# Hunting Linux Fileless Execution and In-Memory Payloads

### Why this hunt
Linux fileless execution is a standard method for modern rootkits and stealthy implants. Adversaries use these techniques to bypass signature-based controls and file-scanning tools. This hunt design builds on research from Elastic Security Labs in their article, [Linux Detection Engineering — Fileless Execution](https://www.elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution). While a single detection rule for memfd_create might be noisy in development environments, a structured hunt allows an analyst to verify the full execution chain from staging to persistence.

### The Hypothesis
An adversary executes malicious code on Linux hosts by staging payloads in memory-backed file descriptors, using interpreter one-liners, or running unlinked binaries to avoid on-disk detection.

### How the Hunt Flows
The first phase scopes the environment to Linux assets and identifies early staging leads. The hunt queries DNS activity for resolutions to common repositories like GitHub or PyPI. These resolutions often precede the download of a loader or a malicious package used for fileless execution.

Next, the hunt looks for specific behavioral primitives in process telemetry. It searches command lines for memfd_create calls, the use of memory-backed file descriptors in /proc/self/fd, and interpreter one-liners. This identifies the mechanism the adversary uses to transition from a script or download to a running process without a backing file on disk.

In the third phase, the hunt identifies the aftermath of successful execution. One query groups rare processes running from unlinked files — where the original binary was deleted after execution — and baselines them by host count. Simultaneously, another query checks for kernel modules loaded from ephemeral paths like /dev/shm or /tmp, which suggests rootkit activity.

Finally, an automated agent correlates these findings. It looks for hosts where the initial staging leads align with confirmed evasive execution or anomalous module loads to produce a high-confidence verdict for the analyst.

### What this hunt cannot see
This hunt has two primary blind spots. First, kernel module detection relies on telemetry that may require eBPF-based monitoring. On older kernels or systems without finit_module syscall tracking, rootkits loaded through non-standard interfaces might stay hidden. Second, the search for interpreter one-liners is vulnerable to obfuscation. If an adversary pipes base64-encoded or encrypted content directly into a shell or interpreter, the process command line will not reveal the malicious logic.

### How to run it
This hunt is a hunt.md playbook. You can import it directly into Huntbase or any hunt.md-aware runtime. It runs in a phased approach, starting with low-cost scoping queries and progressing to more intensive behavioral analysis once it identifies potential leads.

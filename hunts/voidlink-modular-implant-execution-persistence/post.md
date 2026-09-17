# VoidLink Modular Implant Execution and Persistence Hunt

The recent research by Cisco Talos — VoidLink (https://blog.talosintelligence.com/voidlink/) highlights a sophisticated shift in Linux-based threats. This framework, attributed to UAT-9921, is not a single monolithic binary; it is a modular system written in Zig and C that prioritizes stealth through dynamic plugin loading and kernel-level persistence. This hunt is designed to catch the implant during its execution and persistence phases, specifically focusing on how it integrates with the host system after initial exploitation.

Our hypothesis is that an adversary is executing VoidLink implants and modular plugins from user-writable paths and maintaining persistence via rare kernel modules or eBPF programs. This activity likely follows the exploitation of Java serialization vulnerabilities in infrastructure running services like Apache Dubbo. Because the framework is modular, identifying it requires looking for the pattern of execution rather than specific file signatures.

The hunt begins with a scoping phase using the hb_vulnerability_finding surface. We identify hosts currently exposed to the Java serialization or Apache Dubbo vulnerabilities cited as the primary entry points for VoidLink. This step allows us to prioritize high-risk targets where the modular framework is most likely to have been deployed following a successful exploit.

Next, the hunt pivots to kernel-level evidence using the hb_module_activity surface. We search for Loadable Kernel Modules (.ko files) that are unique to a very small subset of the fleet—specifically three or fewer hosts. Since VoidLink often deploys custom rootkits for persistence, identifying these rare, non-standard modules provides a high-confidence signal of unauthorized kernel modification.

Simultaneously, we examine userland execution signals by querying both hb_module_activity and hb_process_activity. We look for shared objects (.so) and binaries executing from globally writable or temporary directories such as /tmp, /var/tmp, and /dev/shm. VoidLink’s plugins are often dropped and loaded dynamically from these staging areas, which are rarely used by legitimate system processes for library loading.

The final phase involves an automated agent that synthesizes these various signals into a per-host verdict. By correlating the presence of a known vulnerability with the discovery of rare kernel modules or suspicious library loads, the agent can distinguish malicious activity from benign administrative tasks. This approach is essential because a static rule might catch one known filename, but this hunt provides the context to identify the entire modular framework.

This hunt has two notable blind spots. First, if the modular plugins are loaded directly into memory without being written to disk or triggering standard OS loader events, the hb_module_activity surface may miss them. Second, persistence achieved via eBPF programs may not appear in standard kernel module lists. Detecting these requires specialized eBPF auditing tools that are beyond the scope of basic module monitoring.

To run this hunt, you can use the provided hunt.md playbook. It is designed to be imported directly into Huntbase or any hunt.md-aware runtime, allowing you to execute the structured queries and agent-based triage across your Linux fleet.

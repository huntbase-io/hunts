# Finding eBPF Rootkits via Network Flow and Socket Snapshot Discrepancies

The recent research by Datadog Security Labs in [Detection primitives for eBPF rootkits](https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/) highlights a significant shift in Linux post-exploitation. Sophisticated rootkits like VoidLink now use eBPF to hook kernel functions, allowing them to manipulate the reporting of system state to user-space tools. When an admin runs `ss` or `netstat`, the kernel simply lies, omitting the attacker's C2 connections from the output.

### The Hypothesis

Our hypothesis is that while a rootkit can successfully hide a socket from point-in-time reporting by manipulating the Netlink subsystem or seq_file interfaces, it is significantly harder to hide the actual network traffic from the kernel's event stream or the network fabric itself. By comparing what the system says is happening (socket snapshots) against what is actually occurring (flow logs), we can identify these 'ghost' connections.

### How the Hunt Flows

The hunt begins by scoping the environment to active Linux assets. We establish a baseline of managed devices where eBPF programs are supported and where we have the required telemetry surfaces enabled. This is a critical first step to ensure we are not hunting in the dark.

Next, we perform a parallel collection of data from two distinct surfaces. We pull historical outbound network flow logs that represent actual traffic observed over a 14-day window. Simultaneously, we gather periodic 'live' snapshots of the socket inventory as reported by the operating system. We specifically prioritize traffic on common C2 and proxy ports, such as 443, 9001, and 8080.

To add context, we also pull DNS activity looking for lookups related to proxy infrastructure like Tor or Ngrok. These signals are not indicators of a rootkit on their own, but they provide critical pivot points when we find a network discrepancy on a specific host.

Finally, we triage the data by identifying destinations that appear frequently in the flow logs but never appear in the socket snapshots. A persistent outbound connection to an external IP that refuses to show up in the socket table is a primary indicator of kernel-level deception.

### Limitations and Blind Spots

This hunt relies on the availability of historical flow logs. If an environment only provides 'live' socket state, there is no baseline for comparison, and the rootkit’s evasion will be successful. Additionally, short-lived ephemeral connections can create false positives; a connection might start and end between two socket snapshots, appearing in the logs but missing from the snapshots. We address this by looking for persistent or repeated flows rather than isolated events.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. This format allows the hunt to be imported into any hunt.md-aware runtime, such as Huntbase, where the queries and logic can be executed against your telemetry providers. Because this targets the outcome of evasion—the discrepancy—it remains effective even as rootkits evolve their specific hooking techniques.

Detection primitives for eBPF rootkits

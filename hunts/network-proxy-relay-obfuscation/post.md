# Detecting Network Proxy and Relay Obfuscation via Shell Outbound Activity

### Why This Hunt

Adversaries use multi-hop proxies and Operational Relay Box (ORB) networks to hide the origin of their command-and-control (C2) traffic. During a recent Cybersecurity IR Workshop (https://www.microsoft.com/en-us/security/blog/2026/09/01/cybersecurity-ir-workshop-you-shouldnt-miss/), practitioners highlighted the need for behavioral signals that identify relay usage regardless of the specific infrastructure provider. Static indicator lists often fail to keep pace with custom-built ORBs. This hunt focuses on the behavior of administrative tools and shells that should rarely initiate direct connections to the public internet.

### The Hypothesis

An adversary uses multi-hop proxies or ORB networks to disguise command-and-control traffic. This activity is visible through shell processes making outbound connections to rare external IP addresses and resolving proxy-related DNS infrastructure.

### How the Hunt Flows

The first phase identifies shell or administrative processes—such as PowerShell, cmd.exe, and bash—making direct outbound connections to external IP addresses. This query filters out internal address space to isolate potential proxy client traffic. These events serve as the leads for the rest of the investigation.

Following the initial leads, the hunt runs two parallel enrichment steps. The firstStacks outbound destination IPs across the entire fleet. It flags IPs visited by only one or two hosts, which often indicates private relay nodes or VPS-hosted infrastructure rather than common web services. This prevalence check helps distinguish legitimate administrative traffic from targeted adversary activity.

The second enrichment step searches for DNS activity on the suspicious hosts. It looks for resolutions matching known proxy domains or keywords like "onion", "exit-node", or "relay". This provides evidence of specific proxy software or service usage that correlates with the network leads.

An analyst then triages the combined results. If a shell process communicates with a rare IP and the host shows relay-related DNS activity, the analyst concludes the verdict. In cases of malicious activity, the hunt provides steps to isolate the host and capture a memory dump of the shell process to preserve the tunnel configuration before the connection closes.

### What This Hunt Cannot See

This hunt depends on endpoint telemetry. It cannot see activity from unmanaged devices on the network that use multi-hop proxies. Additionally, if an adversary uses hardcoded IP addresses and avoids DNS resolution entirely, the DNS enrichment step will be empty. In those cases, the hunt relies solely on the IP prevalence signal to identify the relay client.

### How to Run It

This hunt is provided as a `hunt.md` playbook. You can import it into Huntbase or any other `hunt.md`-aware runtime. The playbook includes the SQLite-based queries for network and DNS telemetry and guides the user through the triage and response process.

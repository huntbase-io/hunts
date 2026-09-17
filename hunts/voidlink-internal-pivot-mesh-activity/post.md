# Hunting VoidLink Internal Pivot and Mesh Network Activity

### Why now
Recent reporting by [Cisco Talos — VoidLink](https://blog.talosintelligence.com/voidlink/) details the emergence of UAT-9921, a threat actor utilizing a modular ZigLang-based implant known as VoidLink. This framework is particularly concerning due to its use of eBPF rootkits for stealth and its reliance on a mesh networking architecture. By establishing P2P connections and SOCKS proxies on compromised internal servers—specifically targeting Java environments like Apache Dubbo—the adversary can route traffic across segmented networks, making traditional perimeter-focused detection ineffective.

### The Hypothesis
An adversary is using VoidLink's mesh networking and SOCKS capabilities to conduct internal discovery and route C2 traffic through rare, high-port inbound connections on compromised Java application servers. We hypothesize that these servers will exhibit a specific combination of behavior: they will act as the source of internal RFC1918 scanning while simultaneously hosting a rare inbound listener used as a P2P mesh gateway.

### How the hunt flows
The hunt begins by narrowing the scope to the server fleet most likely to be targeted based on known exploits. We use the software inventory surface to identify hosts running Apache Dubbo or specific Java serialization frameworks from vendors like VMware or Pivotal. This ensures the hunt focuses on the high-probability ingress points for this specific campaign.

Once the scope is defined, we initiate a three-pronged parallel search across process and network surfaces. On the process activity surface, we look for execution patterns associated with FSCAN, a tool frequently used by VoidLink operators. We do not just look for the filename, but also the specific command-line flags (-h and -p) used for host and port discovery.

Simultaneously, we analyze outbound network connections to identify hosts reaching out to an anomalous number of internal RFC1918 addresses. By setting a threshold for unique internal IP destinations, we can isolate scanning behavior that deviates from standard server communication patterns. This behavioral marker remains effective even if the adversary renames their scanning tools.

In the third parallel phase, we examine inbound network connections to identify rare high-port listeners. VoidLink implants often act as mesh gateways, accepting traffic from other compromised nodes. We aggregate inbound connections by process and port across the fleet, looking for listeners that appear on fewer than five hosts. This prevalence-based approach helps highlight the unique ingress points of a P2P mesh.

The final phase involves an automated triage where we correlate the signals from the scoping and search steps. A host that is running Dubbo, exhibits high-volume internal scanning, and maintains a rare inbound high-port listener is a high-confidence candidate for a VoidLink mesh node.

### What the hunt cannot see
This hunt relies on host-level telemetry provided by osquery or similar agents. The primary blind spot is VoidLink's use of eBPF rootkits, which can hook system calls to hide sockets and processes from user-land monitoring tools. If the rootkit is successfully deployed, the inbound listener and the scanning processes may be invisible at the endpoint layer. In such cases, correlation with VPC flow logs or network-tap data is required to see the actual traffic.

### How to run it
This hunt is provided as an open hunt.md playbook. You can import this file directly into Huntbase or any other hunt.md-aware runtime. Because it is a hunt, it prioritizes behavioral baselining and prevalence over static signatures, making it suitable for periodic environment-wide sweeps to find persistent infrastructure that detection rules might miss.

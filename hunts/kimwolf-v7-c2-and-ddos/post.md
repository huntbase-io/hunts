# Hunting Kimwolf v7 ENS Resolution and DDoS Activity

Unit 42's analysis of Kimwolf v7, titled 'Kimwolf v7: An Evolution of the Kimwolf Botnet', reveals a significant evolution in how botnets maintain resilience. By moving away from static C2 IPs and toward decentralized Ethereum Name Service (ENS) resolution and Tor-based proxies, the operators have made simple blocklists largely ineffective. This hunt provides a structured approach to identifying these stealthy nodes within an environment by linking DNS precursors to network impact.

### The Hypothesis
We assume a compromised host, typically a Linux-based IoT or Android device, is resolving ENS domains through public Ethereum RPC endpoints to identify its command-and-control infrastructure. Once a connection is established, the malware maintains a local proxy listener on port 23075 to tunnel traffic. Infected devices eventually manifest as high-volume outbound network nodes during coordinated DDoS campaigns.

### How the Hunt Flows
The scoping phase examines DNS telemetry (hb_dns_activity) for queries to specific Ethereum RPC providers, such as 0xrpc.io or llama-rpc. These services are abused to resolve .eth domains that point to the botnet's backend. At this stage, the hunt also flags any lookups for .onion addresses, which indicate the malware is attempting to utilize its integrated Tor proxy for stealthy communication.

Following the identification of potential leads, the hunt pivots to network connection telemetry (hb_network_connection). We look for three indicators in parallel: a local listener on port 23075, outbound connections to rare IP ranges in St. Petersburg associated with known C2 infrastructure, and high-volume outbound traffic spikes. Because these C2 IPs rotate, the hunt uses a prevalence check to find rare connections that match the reported provider behavior.

To differentiate a general infection from an active attack node, we analyze network volume. Kimwolf v7 includes fifteen different DDoS vectors. This phase focuses on high-frequency outbound UDP traffic on port 27015—a common signature for game server floods—and heavy TCP traffic on standard web ports that may indicate HTTP/2 flooding.

Finally, the triage stage correlates these signals. A host demonstrating the precursor DNS lookups, the local proxy listener, and active C2 contact is prioritized for containment. This multi-layered approach is necessary because a single rule on C2 IPs is easily bypassed by Kimwolf's decentralized DNS redundancy.

### What the Hunt Cannot See
The primary limitation of this hunt is the visibility of the target hardware. Many Android-based TV boxes or IoT devices do not support standard endpoint agents, meaning the hunt relies heavily on network-level telemetry and flow logs. Additionally, while we can detect the presence of the Tor proxy and its listeners, the actual content of the commands traversing the Tor tunnel remains encrypted and invisible to deep packet inspection.

### How to Run This Hunt
This hunt is formatted as a hunt.md playbook. It is designed to be imported into Huntbase or any runtime environment that supports the hunt.md standard. It allows practitioners to define parameters like lookback windows and specific RPC domains before execution to match their environment's specific logging retention policies.

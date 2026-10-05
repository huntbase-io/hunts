# Hunting for BPFDoor and AVERAT Passive Network Tunnels

### Why this hunt?

Rapid7 recently detailed how BPFDoor and AVERAT variants compromise network-edge devices by monitoring traffic at the packet level in [SMTP is the key: BPFDoor and AVERAT hitting the network edge](https://www.rapid7.com/blog/post/tr-smtp-is-the-key-bpfdoor-averat-hitting-the-network-edge). These implants avoid traditional detection by not binding to a port. Instead, they use Berkeley Packet Filters to wait for a magic trigger within existing protocols like SMTP and HTTPS.

### The Hypothesis

An adversary deploys a passive BPF-based backdoor that remains dormant until triggered by specially crafted SMTP or HTTPS traffic. This allows for protocol tunneling without maintaining an open listening port or creating standard process-based network artifacts.

### Phase 1: Identifying Network Symmetry

The hunt begins by examining network traffic for symmetric SMTP connections where both the source and destination ports are 25. While legitimate mail transfer agents occasionally display this behavior, it is rare on edge appliances and workstations. The query baselines this activity and filters for low-prevalence connections to find potential BPF Rekoobe blending with legitimate relay traffic.

### Phase 2: Corroborating with System and Web Signals

The hunt pivots to examine two independent signals simultaneously. First, it looks for the creation of AF_PACKET sockets (family 17). These raw sockets allow an implant to sniff traffic without an open port, which is a hallmark of BPF-based backdoors. Second, it searches HTTPS logs for specific mathematical padding in query strings, such as the 9999 pattern the adversary uses to land triggers at specific TCP offsets.

### Phase 3: Triage and Verification

An agent evaluates the combined results from network, system, and web telemetry. It looks for concurrency: does a host showing symmetric SMTP traffic also exhibit raw socket creation or receive padded HTTPS requests? This correlation confirms a verdict of a malicious passive implant rather than isolated benign anomalies. If confirmed, the workflow directs an analyst to isolate the endpoint and perform forensic memory analysis, as rebooting loses the memory-resident BPF filter.

### Blind Spots

This hunt has two primary limitations. First, if the edge proxy does not terminate SSL or log full URL query strings, the HTTPS trigger padding remains invisible. Second, some telemetry implementations for BPF socket events may lack direct hostname mapping, requiring manual correlation between process IDs and timestamps across different data sources.

### How to run it

This hunt is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. Because it relies on correlation across three distinct surfaces, it provides higher confidence than a standalone detection rule.

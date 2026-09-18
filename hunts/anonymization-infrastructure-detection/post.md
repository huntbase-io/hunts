# Detecting Anonymization Infrastructure and Multi-Hop Proxy Tunneling

Adversaries frequently leverage multi-hop proxies and anonymization networks to bypass traditional IP and domain reputation filters. Following the principles outlined in the Microsoft [Cybersecurity IR Workshop](https://www.microsoft.com/en-us/security/blog/2026/09/01/cybersecurity-ir-workshop-you-shouldnt-miss/), our team has developed a new hunt to identify the use of these infrastructures within the enterprise. The goal is to detect not just the final destination of the traffic, but the internal processes facilitating the tunnel.

### The Hypothesis
We hypothesize that an adversary is using multi-hop proxies, onion gateways, or ORB networks to hide C2 traffic. This activity is expected to manifest through specific DNS resolutions for darknet bridges or through outbound network connections from processes that exhibit low prevalence across the fleet when compared by destination port.

### How the Hunt Flows
The hunt begins by defining the population of active assets. We scope the environment to running Windows, Linux, and macOS devices to ensure the subsequent network and DNS analysis is applied to a current and relevant telemetry set.

Next, the hunt focuses on DNS leads. We look for resolutions involving known anonymity TLDs like .onion and .i2p, as well as clearweb gateways such as Tor2Web or I2P bridges. While many of these might be blocked at the perimeter, the presence of these queries in endpoint telemetry indicates a process is actively attempting to establish a darknet connection.

In parallel, the hunt examines network-level activity through two distinct lenses. First, it performs a direct check against known ORB and VPS exit node IPs. Second, and more importantly, it performs a prevalence analysis on all outbound connections. It flags any process connecting to a destination port that is seen on fewer than three hosts across the entire fleet. This identifies non-standard tunneling tools and custom-configured proxies that lack static signatures.

The final phase involves an automated triage of these signals. If a host shows both a DNS lead for an anonymity gateway and a rare process-port outbound connection, it is prioritized for forensic review. Analysts are directed to examine process activity for evidence of code injection or unusual parent-child hierarchies that suggest a legitimate process has been co-opted for tunneling.

### Limitations and Blind Spots
This hunt has two primary blind spots. First, if an adversary uses DNS-over-HTTPS (DoH) within a browser or a specialized tool, the resolutions for darknet gateways will not appear in standard DNS logs. Second, while the ORB IP list provides quick hits, it is not exhaustive. The hunt relies heavily on the prevalence logic to catch connections to ephemeral or residential proxy nodes that are not yet cataloged in threat intelligence feeds.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any security orchestration platform that supports the hunt.md standard. Because it relies on prevalence and baseline comparison, it is best run over a 14-day lookback window to provide sufficient context for identifying rare activity.

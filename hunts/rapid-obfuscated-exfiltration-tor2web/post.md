# Hunting Rapid Obfuscated Exfiltration via Tor2Web Gateways

Recent research from Elastic Security Labs, [Data access: the hidden cost of security vendor lock-in](https://www.elastic.co/security-labs/blog/siem-data-export-comparison), highlights a critical challenge: the speed of modern intrusions. When 'breakout'—the time from initial access to lateral movement or exfiltration—happens in under 30 minutes, relying on batched logs or standard binary detection is insufficient. 

We have published a new hunt design focused on identifying rapid, obfuscated data exfiltration that leverages public Tor2Web gateways. Unlike traditional Tor usage which requires a specific binary, Tor2Web allows standard applications to reach .onion services via HTTP. This makes the activity look like typical web traffic to many security controls, effectively bypassing binary-centric detection.

### The Hypothesis
An adversary is using public Tor2Web gateways (such as onion.pet or tor2web.org) to proxy command-and-control traffic and exfiltrate data. By doing so, they avoid the signature-based detection of Tor clients while initiating high-volume data transfers shortly after gaining access to a host.

### How the Hunt Flows
The hunt begins with a scoping phase to identify active systems, followed by a lead-generation step that monitors DNS activity. We look for resolutions of a known list of Tor2Web gateways or domains following the `*.onion.*` pattern. This identifies the potential obfuscation channel but is not enough on its own to confirm a threat.

Next, the hunt pivots into a parallel corroboration phase. We examine two distinct surfaces: network flow logs for outbound connections exceeding 100MB per process, and Azure AD sign-in reports for identity-level risk signals (medium or high risk) occurring in the same window. This allows us to separate routine web browsing or security research from a concerted exfiltration attempt.

Finally, an analysis phase correlates these signals. We look for the specific host where the gateway resolution, the volumetric transfer, and the risky identity signal overlap within a one-hour window. This provides a high-confidence lead for an analyst to investigate file staging or directory traversal.

### Blind Spots and Limitations
This hunt relies heavily on the availability of byte-count telemetry in network flow logs. If your EDR or network sensors log the connection attempt but not the volume of data transferred, it becomes difficult to distinguish C2 heartbeats from true exfiltration. Furthermore, as noted in the Elastic research, if identity provider logs are delayed due to batching, the risk signal might only appear after the exfiltrated data has already left the environment.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime compatible with the `hunt.md` standard. Because it targets behavior rather than specific malware signatures, we recommend running it as a periodic check on server workloads and developer machines where Tor-like connectivity is highly unexpected.

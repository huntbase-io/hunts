# Detecting Phased Intrusion Lifecycles with Google Threat Intelligence

### Why this hunt

Elastic Security Labs recently detailed their integration with Google Threat Intelligence in the post [From API key to live threat detections in minutes](https://www.elastic.co/security-labs/blog/elastic-security-google-threat-intelligence). While this integration enables rapid ingestion of high-fidelity indicators, a simple match often lacks the necessary context to determine the actual risk to the environment. This hunt bridges that gap by following the full intrusion lifecycle from initial access to final impact.

### The Hypothesis

An adversary exploits a vulnerable service or uses phishing to establish a beachhead. They then maintain communication via multi-hop proxy networks before moving toward their ultimate objective, which involves mass file modification for ransomware or resource hijacking for cryptocurrency mining.

### Scoping and Early Signals

The hunt begins by scoping the environment for hosts with severe vulnerabilities (severity_id >= 4). This identifies the primary blast radius where an exploit is most likely to land. Simultaneously, the workflow searches for early beachhead signals by checking DNS activity for GTI-flagged domains and multi-hop proxy addresses, such as .onion sites. This phase identifies hosts attempting to contact infrastructure associated with phishing or C2 operations.

### Execution and Breach Evidence

The second phase matches process activity against GTI-verified malware hashes. This provides a high-confidence signal of code execution on the endpoint. An analyst or automated agent then evaluates these results together. By correlating the host vulnerability status with DNS resolutions and malicious hash matches, the hunt confirms if an adversary has successfully landed and executed code on a target system.

### Follow-on Behavior and Impact

The final phase pivots to late-stage intrusion behaviors. The query searches for active network connections to known-malicious C2 infrastructure. It also looks for high-volume file modifications, a hallmark of ransomware encryption, and command-line indicators associated with cryptomining. These behaviors distinguish a successful compromise from an isolated, blocked indicator by showing the progression toward impact.

### Blind Spots

This hunt has two primary limitations. First, it relies on endpoint telemetry retention. If initial access occurred prior to the current lookback window, the beachhead evidence may have aged out, making the intrusion appear as an isolated late-stage event. Second, it focuses on file-based execution hashes. It cannot identify memory-only malware or fileless threats that never drop a binary to the disk, potentially missing the initial execution stage.

### How to run

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime aware of the hunt.md format. It operates in two phases, allowing an analyst to validate early signals before committing to deep filesystem analysis. This sequential approach reduces noise and focuses effort on confirmed threats rather than isolated indicator matches.

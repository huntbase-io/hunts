# Identifying Direct-to-IP Malware Connections by Correlating DNS Silence

Recent research from Unit 42, titled [Almost Half of Malware Samples Communicate Direct to IP](https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/), highlights a significant shift in malware transport. Approximately 47% of malware samples bypass DNS-based security by connecting directly to hard-coded IP addresses (D2IP). This behavior effectively renders sinkholes, DNS filtering, and domain-based reputation systems useless for these specific threats.

### The Hypothesis
Our hunt is built on the premise that legitimate application behavior is typically preceded by a DNS query. If a process initiates an outbound connection to an external IP address without first resolving a hostname, and that process is not a known system updater or global service, it is likely using hard-coded infrastructure. We hypothesize that by identifying processes that are 'DNS-silent' while active on the network, we can find malware even when its specific C2 IP has not yet been added to threat intelligence feeds.

### How the Hunt Flows
The hunt begins with an initial scoping phase that checks for direct hits against the specific malicious IPs identified in the Unit 42 report. This provides immediate value by surfacing known threats already present in the environment within the selected lookback window.

In the second phase, we move beyond static indicators to baseline rare outbound traffic. We focus on network connections to external IPs on non-standard web ports (excluding 80 and 443) and filter for rarity. We look for connections that occur on only a small handful of hosts, which helps filter out noisier global services and standard enterprise software.

Simultaneously, we enrich our view by gathering a summary of all DNS activity per process. This step is critical for distinguishing 'well-behaved' software from D2IP threats. We map out which processes are responsible for legitimate DNS traffic across the fleet to establish a baseline of expected behavior.

In the final triage phase, a correlation agent compares these datasets. It identifies processes that established network connections but never appeared in the DNS summary logs. This gap—network activity without DNS resolution—becomes our primary lead for identifying suspicious, hard-coded communication patterns.

### Limitations and Blind Spots
This hunt has two primary technical hurdles. First, network socket telemetry often lacks reliable hostname fields, requiring us to perform the more complex cross-surface correlation between network and DNS logs rather than a simple join. Second, there is a risk associated with telemetry retention. If a malware sample resolves a domain once and maintains a long-lived connection for weeks, the original DNS query may have rotated out of the logs, making the process appear DNS-silent when it is not. 

### How to Run This Hunt
This design is published as a `hunt.md` playbook. It is a portable, structured format that can be imported into the Huntbase runtime or any hunt.md-aware tool. The queries are written in SQLite-compatible DSL, designed for correlation across network and DNS surfaces. Because this is a hunt rather than a detection, it is intended to be run periodically to catch persistent or low-and-slow threats that do not trigger immediate alerts.

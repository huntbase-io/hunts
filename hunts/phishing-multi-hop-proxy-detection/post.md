# Correlating Phishing Execution with Multi-hop Proxy C2

### The Context
Recent discussions around SOC workflows, such as those highlighted in Elastic Security — SOC case management and detection rule history (https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history), emphasize the need for context when triaging alerts. A single alert for a PowerShell execution might be noise; the same execution occurring immediately after a browser download and followed by a connection to a rare proxy node is an incident. This hunt focuses on that specific sequence.

### The Hypothesis
An adversary gains initial access through a phishing lure and communicates with a multi-hop proxy or Obfuscated Relay Bridge (ORB) network to disguise command-and-control traffic. By chaining the delivery vector to the communication channel, we bypass the noise of common administrative scripting.

### How the Hunt Flows
The hunt begins by identifying the attack surface. A scoping query checks software inventory logs for workstations running common productivity applications, including Outlook, Chrome, and Edge. This limits the subsequent high-volume telemetry searches to the hosts most likely to be targeted by a phishing campaign.

Next, the hunt runs two searches in parallel to find evidence of both the entry point and the C2 channel. The first branch looks for script interpreters or shells spawned directly by mail clients or browsers. This captures the moment a malicious attachment or link executes code. The second branch scans network logs for outbound connections to common proxy and Tor ports, such as 9001 or 1080. It uses a prevalence filter to ignore connections made by more than five hosts, focusing the results on rare, potentially malicious endpoints.

Finally, the hunt uses an analyst or automated agent to correlate these two findings on a per-host basis. The triage step weighs the timing and the command lines involved to determine if the process activity and network traffic represent a single intrusion. If the link is confirmed, the playbook provides instructions for host isolation and forensic review.

### Blind Spots
This hunt has two primary limitations. First, it requires process-enriched network logs to definitively link a specific interpreter to a network connection. On hosts where these logs lack process IDs, the correlation depends on timing alone. Second, while the hunt identifies the existence of a proxy tunnel, it cannot see the encrypted commands inside. Further host-level forensics are necessary to determine what actions the adversary took once the channel was established.

### How to Run it
This playbook is an open hunt.md document. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. Because it uses prevalence-based filtering, it is best run over a 14-day lookback period to establish a clean baseline of normal network activity.

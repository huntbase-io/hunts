# Hunt for Cloud Workload Compromise and Alert Suppression

### Why now

The recent analysis by Sekoia on 6 AI SOC Integrations Actually Worth Connecting (https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting) emphasizes the need for security teams to bridge gaps between disparate logging sources. While automated integrations assist in data flow, the logic that connects a runtime anomaly to a network violation remains a human-driven requirement. We designed this hunt to validate that connectivity, ensuring that a compromise in a cloud workload does not go unnoticed as it progresses toward data encryption or alert suppression.

### The hypothesis

An adversary has compromised a cloud workload using valid credentials and is moving across network segments before encrypting data and suppressing alerts via webhooks.

### How the hunt flows

The hunt begins with scoping by identifying every host running web or application services. The first query filters process activity for common paths like /var/www or /opt, alongside Python and Java runtimes. This narrows the investigative surface to active workloads likely to be targeted for initial access.

The second phase looks for early execution indicators in parallel. One branch identifies processes launched from writable paths like /tmp or /dev/shm. A second branch monitors file activity for access to sensitive system secrets, including shadow files and SAM hives. An analyst then evaluates if the processes in temporary directories are responsible for the file touches, establishing a high-confidence verdict of workload compromise.

The third phase investigates the attack's expansion and impact. The hunt queries network connections for blocked traffic to restricted segments, identifying microsegmentation violations. Simultaneously, it aggregates file activity to detect mass modifications indicative of ransomware and monitors HTTP traffic for outbound requests to alerting platforms like Slack or iLert. This determines if the actor is attempting to hide their activity by tampering with incident management webhooks.

### What the hunt cannot see

This hunt relies on specific telemetry that may not be available in all environments. If the environment lacks VPC flow logs or host-based network fabric monitoring, the query for segmentation violations will return no results, creating a blind spot for successful lateral movement. Additionally, the mass file modification check uses a threshold of 50 files. An adversary who targets only high-value configuration files or specific encryption keys will evade this detection logic.

### How to run it

This hunt is published as a hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the necessary SQLite queries and decision gates to move from scoping to host isolation. Because this is a hunt, it focuses on correlating multiple low-fidelity signals—such as a single blocked network connection paired with a /tmp execution—to identify a malicious chain that standard detection rules often ignore.

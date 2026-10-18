# Hunting for Linux Reverse Shells and Mailbox Exfiltration (CL-UNK-1211)

### Why this hunt

Unit 42 recently detailed a campaign they call [AI-Powered Espionage Campaign Targets Government Linux Infrastructure](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/). The threat actor uses AI-assisted scripting to speed up their discovery and data collection phases. This hunt targets the active intrusion stage where the adversary establishes interactive control and gathers mail data.

### The Hypothesis

An adversary uses in-memory reverse shells to conduct interactive discovery and exfiltrate government mailboxes. They likely use AI-assisted scripting patterns to maintain efficiency and avoid disk-based detection.

### How the Hunt Flows

The first phase looks for the characteristic behavioral patterns of in-memory reverse shells. The query examines hb_process_activity for command lines involving mkfifo paired with nc, /dev/tcp/ redirects, or specific Python subprocess calls. This lead provides the entry point for the investigation.

If the lead returns suspicious activity, the hunt fans out into a parallel corroboration phase. One branch checks for network connections to known C2 IP addresses from the hb_network_connection surface. This confirms if the shell is communicating with the infrastructure identified in the report.

The second parallel branch stacks directory enumeration and compression commands involving mail storage. By looking for zip, tar, or find commands in /var/qmail/ or /maildir/ paths, the hunt identifies data collection. It filters frequent administrative backups to highlight rare, targeted exfiltration.

The final stage weighs the evidence from all branches. An analyst or an automated agent triages the findings to confirm an active intrusion. If the shell, network traffic, and collection patterns align, the hunt triggers host isolation.

### What this hunt cannot see

This hunt has specific blind spots. If an adversary executes a bash redirect inside a complex script using eval or within a pre-existing shell session without spawning a new process, the command line may not appear in process logs. Additionally, the hunt identifies network connections to C2 IPs but cannot inspect encrypted WebSocket traffic. While it sees the destination, it cannot confirm the specific protocol or URI path without a decrypting proxy.

### How to run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It requires Linux process and network auditing to be effective, specifically targeting mail servers where the adversary is most active.

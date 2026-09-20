# Hunting Tampered Exodus Wallet Persistence and C2

### Why this hunt

Huntress recently detailed a campaign involving a modular RAT hidden within a tampered Exodus crypto wallet installer in their post [The Crypto Wallet That Never Opened](https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat). The adversary uses a legitimate, signed Electron runtime to execute malicious JavaScript. They suppress the application user interface to remain hidden while establishing persistence and connecting to a remote server. This hunt identifies the specific forensic footprint left by this installer, focusing on the persistence and communication stages that a standard antivirus might miss due to the use of signed binaries.

### Hypothesis

An intruder deploys a tampered Exodus wallet that suppresses its UI and maintains persistence through a headless PowerShell scheduled task while communicating with a hardcoded C2 IP.

### How the hunt flows

The first phase examines scheduled tasks across the fleet. The adversary maintains persistence using a task named INetHealth. This query looks for that specific task name or any scheduled job that invokes PowerShell with the --headless flag, which is a key indicator of the UI suppression technique used in this campaign.

Next, the hunt branches into parallel searches for execution and network evidence. One branch inspects process activity for Exodus.exe running from non-standard locations. Legitimate installations typically reside in Program Files, but this threat stages files in the AppData ExdBackupTool directory. The query stacks these paths to find anomalies that appear on only a few hosts.

The second parallel branch monitors network connections for direct communication with the hardcoded C2 IP address 35.212.159.20. Identifying this traffic provides high-confidence evidence of active command-and-control activity, especially when originating from the same hosts that exhibit the suspicious scheduled tasks or application paths.

Finally, the hunt uses an automated agent to triage the findings. The agent evaluates whether the combination of headless persistence, rare file paths, and known-bad network traffic confirms a compromise. If the evidence is conclusive, the hunt provides instructions to isolate the host and collect the malicious directory for further forensic analysis.

### What this hunt cannot see

This hunt relies on file paths and parent process relationships. It cannot perform runtime introspection or memory-map analysis to confirm if specific BrowserWindow methods were overwritten in memory. If an attacker uses a remote WebDAV share via search-ms for the initial execution, file creation events on the local disk will be absent. In such cases, the hunt relies entirely on process start events and network telemetry.

### How to run it

This hunt is packaged as an open hunt.md playbook. You can import this file directly into Huntbase or any security platform that supports the hunt.md format to begin execution. The queries use standard telemetry from process, network, and scheduled task logs. It is best suited for workstations where users may manage crypto assets or perform user-driven web activities.

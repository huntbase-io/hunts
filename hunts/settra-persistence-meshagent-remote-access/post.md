# Hunting Settra Ransomware Persistence via MeshAgent and Remote Access

### Why this hunt? 1004655389658742805

Huntress recently detailed a variant of Settra ransomware that uses MeshAgent for persistence. This legitimate remote management tool allows attackers to maintain access without triggering alerts for common backdoors. The report, [Ready, Settra, Go: New Settra Ransomware Variant Deploys MeshAgent RMM](https://www.huntress.com/blog/new-settra-ransomware-variant), highlights how attackers establish initial access via remote services and then deploy MeshAgent. Hunting for this specific RMM behavior helps catch the intrusion before the attacker deploys the ransomware launcher or moves to file encryption.

### The Hypothesis

An adversary establishes a beachhead via compromised external remote services and installs MeshAgent, potentially renamed to mvtcs.exe, to maintain persistent command-and-control access.

### How the Hunt Flows

The hunt begins by scoping successful sign-ins on remote access surfaces like RDP and VPN. This step identifies which hosts and users are most likely to be the entry point for the intrusion. By looking for successful logins from unusual sources or protocols, we create a targeted list of endpoints for more intensive investigation.

The next phase runs two queries in parallel to find evidence of MeshAgent. The first query searches process activity for rare binaries. It doesn't just look for filenames; it inspects the original file name metadata for "MeshAgent." This catches instances where the attacker renames the file to blend in with legitimate system processes, a common tactic in recent Settra incidents.

Simultaneously, the second query checks network telemetry for connections to specific IP addresses associated with Settra C2 infrastructure. If a host has a rare RMM binary and is also talking to these IPs, the suspicion of a malicious intrusion increases significantly. The hunt combines these signals to identify active persistence.

Finally, an analyst reviews the results. The goal is to link the initial remote login to the subsequent deployment of the tool and its network activity. If the signals align, the hunt provides a path for immediate host isolation to prevent the final ransomware stage.

### What This Hunt Cannot See

Visibility depends heavily on the source telemetry. If the network fabric does not capture flow logs, the hunt can identify the MeshAgent process but cannot confirm if it successfully established a command-and-control channel. Furthermore, if the VPN provider does not integrate with the central authentication surface, the initial entry point may remain hidden. This makes it harder to correlate the entry point with the internal persistence activity.

### How to Run This Hunt

This hunt is a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard. It uses SQLite-based queries against standardized tables for authentication, process activity, and network connections. Use the scoping notes to focus the heavy queries on specific hosts identified during the sign-in analysis. This allows you to hunt effectively across large estates without overwhelming the data platform.

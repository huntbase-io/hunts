# Hunting UAT-6275 Espionage Activity in Government and Infrastructure

### Why This Hunt Now

Recent reporting from Talos, [The Q3 Vulnerability Pulse: Discovery ≠ Exploitation](https://blog.talosintelligence.com/the-q3-vulnerability-pulse-discovery-exploitation/), highlights how adversaries exploit the gap between a published vulnerability and its actual exploitation in the wild. UAT-6275 specifically targets regional government and critical infrastructure by abusing edge appliances and using custom persistence mechanisms. We provide this hunt as a `hunt.md` playbook to help practitioners identify these intrusion chains before data exfiltration occurs.

### The Hypothesis

An espionage actor establishes a beachhead via edge appliance exploitation or archive delivery. They establish persistence through scheduled tasks and maintain access via a PowerShell-based reverse shell to exfiltrate diplomatic or economic intelligence.

### How the Hunt Flows

The hunt begins by scoping the environment for vulnerable edge appliances. The first query searches the vulnerability surface for findings related to Ivanti bypasses or SonicWall SSRF. This step identifies the hosts most likely to serve as the initial entry point for the actor.

Following the scoping phase, the hunt executes a parallel search for initial execution evidence. One branch searches file activity for known malicious hashes and files dropped by archive utilities like WinRAR. The other branch monitors script activity for PowerShell execution that pulls payloads from GitHub using `IEX` or `DownloadString` commands.

An automated agent evaluates the initial findings to determine if an infection beachhead exists. If the likelihood is high, the hunt pivots into a second parallel phase focused on post-exploitation behavior. The hunt stacks scheduled tasks across the environment to find rare command lines used for persistence and monitors network connections for outbound TCP traffic from PowerShell or known malicious binaries.

A final triage stage correlates the early-stage signals with the persistence and network evidence. An analyst or agent confirms the full intrusion chain, allowing for a high-confidence verdict. If the hunt confirms a malicious intrusion, the workflow includes steps to isolate the compromised host via the endpoint agent.

### What the Hunt Cannot See

This hunt contains two primary blind spots. First, it lacks visibility into the initial bypass if it occurs entirely on an appliance without an EDR agent. We only see the follow-on activity once the actor touches a monitored Windows host. Second, the hunt may miss command-and-control traffic if the actor uses a custom reverse shell wrapped in TLS on port 443, as the network query looks for connection metadata rather than decrypted packet content.

### How to Run It

This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the hunt.md specification. It uses parameters for lookback windows and specific hashes, allowing you to update the hunt as new UAT-6275 indicators emerge.

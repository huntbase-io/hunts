# Hunting Node.js Backdoor Persistence in User AppData

### Why Now

Microsoft recently detailed a campaign titled [Impersonating IT support: how threat actors turn a remote session into enterprise-wide access](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/). In these attacks, adversaries use social engineering to convince users to run installers that place a legitimate Node.js runtime and a malicious script in user-writable directories. This approach bypasses many security tools that only inspect binary reputations.

### The Hypothesis

An intruder maintains interactive control via a Node.js implant staged in a user profile, performing Active Directory reconnaissance and moving laterally via WinRM. The adversary uses the legitimate Node.js executable to blend in with developer activity, but their file paths and network behaviors reveal the intrusion.

### How the Hunt Flows

The first phase scopes the environment for Node.js execution in unusual locations. The query searches process activity for `node.exe` or renamed copies running from `AppData\Local` or other user-specific paths. This surface focuses on the beachhead where the initial implant resides.

Next, the hunt correlates these executions against two distinct signals: path rarity and reconnaissance script blocks. We stack-count the execution paths across the fleet to find directories unique to only a few hosts. Simultaneously, we inspect script activity for indicators of domain enumeration, such as `adsisearcher` or WMI checks for antivirus and virtual machine environments. This helps distinguish a developer using Node.js from an adversary performing discovery.

Finally, the hunt pivots to network connections. We look for outbound traffic on port 5985 (WinRM) originating from the identified Node.js processes or user-writable paths. This specific movement indicates the operator is attempting to pivot from the initial beachhead toward identity servers or other sensitive internal targets.

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it cannot inspect the specific JavaScript instructions sent over encrypted HTTPS C2 channels. If the intruder changes their reconnaissance patterns entirely in memory, we may miss the specific actions they take. Second, the lateral movement query targets the default WinRM port 5985. If the adversary uses a non-standard port or a different protocol like SMB for movement, this specific step will not flag the activity.

### How to Run This Hunt

This hunt is available as an open `hunt.md` playbook. You can import it directly into Huntbase or any security platform that supports the `hunt.md` standard. The playbook includes the SQLite queries for process, script, and network surfaces, along with triage instructions for confirming malicious intent.

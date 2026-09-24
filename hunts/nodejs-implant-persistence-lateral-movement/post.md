# Hunting Node.js Backdoor Persistence and WinRM Lateral Movement

### The IT Support Trap

The adversary exploits trust through Microsoft Teams to establish a foothold in the enterprise. In "Impersonating IT support: how threat actors turn a remote session into enterprise-wide access" (https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/), Microsoft describes a campaign where actors masquerade as help desk personnel to gain remote access. Once a victim grants permission, the attacker deploys a Node.js-based backdoor to maintain a presence and expand throughout the network. This move bypasses many email-based security layers, making post-access hunting essential.

### Hypothesis

An intruder uses a portable Node.js runtime and an obfuscated implant staged in LocalAppData to move laterally via WinRM after initial social engineering.

### How the Hunt Flows

The hunt begins by identifying the staging of the runtime. The first phase scans process activity for Node.js or renamed binaries executing from the AppData folder. While legitimate developers use Node.js, a portable instance running from a non-technical user profile indicates highly suspicious staging activity.

Next, the hunt gathers persistence evidence in parallel. It checks registry Run keys that point to executable code in LocalAppData and searches for rare files with extensions like .tmp or .cfg in user profiles. This phase establishes a baseline of anomalous file activity on the suspected hosts and identifies the potential loader files used by the implant.

An analyst then triages these signals to confirm beachheads. Once identified, the hunt pivots to investigate the interactive stage of the attack. It filters outbound network connections on port 5985 to find WinRM-based lateral movement originating from the compromised machines. This identifies where the attacker is attempting to move next.

Finally, the hunt examines follow-on reconnaissance and execution. It looks for Active Directory discovery commands and rundll32.exe activity specifically associated with the flagged users and hosts. Narrowing the scope to these specific entities helps distinguish malicious operator activity from routine administrative tasks.

### Blind Spots

This hunt relies on process and network telemetry. If the environment lacks outbound socket data, the hunt cannot track the attacker's movement from the beachhead to sensitive internal servers. Additionally, Node.js implants often run tasking in memory or delete temporary files immediately after execution. These ephemeral artifacts can hide the exact nature of the data stolen or the specific commands run during the operator's session.

### How to Run This Hunt

We published this hunt as an open hunt.md playbook. This format allows you to import the logic into Huntbase or any runtime that supports the hunt.md specification. It includes parameters for tuning file extensions and lookback periods to fit your environment's specific baseline. Because this is a hunt, it focuses on identifying the structural behavior of the campaign rather than relying on brittle, easily changed indicators.

# Hunting Identity-Led Ransomware Chains in Government Environments

### Why this hunt matters
According to "Preparing governments for an era of interconnected cyber risk" (https://blogs.microsoft.com/on-the-issues/2026/10/01/preparing-governments-for-an-era-of-interconnected-cyber-risk/), government agencies are primary targets for identity-based ransomware. Attackers are no longer just exploiting software bugs; they are stealing credentials to move through networks as legitimate users. This hunt detects that progression across multiple stages of an intrusion.

### The Hypothesis
An adversary compromises a government identity via phishing, uses those valid accounts to harvest further credentials, and eventually encrypts files to achieve impact.

### How the hunt flows
The first phase uses software inventory data to scope the hunt. We focus on hosts running browsers, VPN clients, and productivity software like Outlook. This ensures we are looking at the endpoints most likely to be the initial entry point for a phishing campaign or supply chain compromise.

Once scoped, the hunt examines HTTP traffic and authentication logs in parallel. We look for connections to known or rare phishing domains while simultaneously identifying anomalous sign-in patterns, such as credentials used from rare source IPs. This phase identifies the successful beachhead before it can expand.

An automated triage agent then correlates these findings. If a host shows both suspicious network activity and unusual identity activity, the agent flags it for deeper inspection. This reduces noise by focusing on hosts where multiple indicators of compromise overlap in a short window.

The hunt then pivots to the endpoint's behavior. We search process activity for in-memory credential dumping tools that leave no trace on disk. At the same time, we analyze file telemetry for spikes in mass file updates or deletions, which are characteristic of ransomware encryption.

In the final stage, the playbook correlates the early access evidence with the impact indicators. A host showing a full chain — from a rare domain visit to mass file encryption — is automatically isolated from the network. This stops the spread while an analyst performs a forensic review of the impacted files.

### What the hunt cannot see
This hunt relies on file-level telemetry to confirm impact. If a host lacks file activity logging, mass encryption events will not be detected. Additionally, the hunt may miss session hijacking if the attacker uses a stolen token from a geography that matches the legitimate user's history, bypassing source IP anomalies.

### How to run it
This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any other hunt.md-aware runtime. The playbook includes all necessary queries, parameters for common phishing domains, and automated triage logic to guide you through the investigation process.

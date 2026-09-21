# Hunting for Entra ID Agent User Impersonation in Teams

### Why hunt for Agent User identities?

Recent research from Red Canary, titled [Investigating suspicious AI workflows in Microsoft Entra Agent ID](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/), details how attackers can abuse the 'Agent User' OAuth flow. These identities allow AI agents to act on behalf of users without traditional interactive MFA. Because these accounts are often trusted by default and used for automated tasks, they provide a quiet path for attackers to send malicious Teams messages or access sensitive data via the Microsoft Graph API.

### The Hypothesis

An adversary uses the Entra ID Agent User OAuth flow to impersonate an AI agent and dispatch malicious content via Microsoft Teams. They use Graph API cmdlets from a compromised host to send these messages, relying on the 'user_fic' grant type to bypass standard authentication hurdles.

### How the Hunt Flows

The hunt begins at the cloud authentication surface. The first step queries sign-in logs to identify any identities authenticating to Microsoft Teams using the federated identity credentials (user_fic) specific to Agent User impersonation. This provides a focused list of active agent identities and their source IP addresses to narrow the scope of behavioral analysis.

Once the hunt identifies active agent logons, it branches into two parallel behavioral queries. The first query searches for rare PowerShell script blocks on endpoints that call specific Microsoft Graph Beta cmdlets, such as New-MgBetaTeamChannelMessage. It uses prevalence counting to ignore common automation and isolate manual or new message dispatch activity. The second query examines HTTP telemetry for rare User-Agent strings hitting Graph API endpoints, specifically looking for PowerShell-based traffic that does not match the established fleet baseline.

Finally, the hunt uses an automated agent to correlate these signals. The agent looks for temporal proximity between the cloud sign-in and the endpoint execution. If a specific host executes messaging scripts within a short window of an Agent User logon, the hunt flags the activity for manual review and potential revocation.

### Blind Spots and Limitations

This hunt relies on two critical visibility requirements. First, it requires PowerShell Script Block Logging (Event ID 4104) to see the content of the Beta cmdlets. If logging is disabled, the hunt cannot distinguish between different types of Graph API automation. Second, identifying rare User-Agents requires TLS decryption of traffic to graph.microsoft.com. Without decryption, the hunt must rely entirely on endpoint script logs, which an attacker might attempt to clear or bypass.

### How to Run This Hunt

This hunt is available as an open-source `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other hunt.md-aware runtime. Because this is a hunt rather than a static detection, it uses prevalence counting and cross-surface correlation to find activity that standard alerts typically miss. To get started, provide a lookback window and optional host scope to the playbook parameters.

Red Canary — Investigating suspicious AI workflows in Microsoft Entra Agent ID

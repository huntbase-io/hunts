# Hunting UNK_DeadDrop and Overlord RAT in Developer Environments

### Why Now

Recent research from Proofpoint (https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal) details a targeted campaign against developers. The UNK_DeadDrop campaign uses social engineering to trick developers into cloning repositories that execute the Overlord RAT. This malware specifically targets browser credentials and cryptocurrency wallets. Because developers often handle sensitive API keys and financial assets, identifying this activity early is a priority.

### The Hypothesis

A developer has cloned a malicious repository that executed an Overlord-derived RAT to steal browser credentials and cryptocurrency wallets before cleaning up its own files. The adversary relies on the high level of trust developers place in source control and shared code to bypass standard endpoint protections.

### How the Hunt Flows

The first phase identifies the relevant population within the estate. A query against process activity surfaces hosts running IDEs like VS Code or Cursor. This narrows the scope of the hunt to the high-value developer workstations most likely to be targeted by the UNK_DeadDrop campaign.

The hunt then launches a parallel search for initial infection markers. It looks for the execution of platform-specific Go binaries associated with the Overlord framework while simultaneously checking DNS activity for known C2 domains. This stage provides the first indicators of an active RAT on the identified workstations.

Next, the hunt pivots to behavioral evidence of successful compromise. It searches for outbound network connections with high aggregate traffic volume, representing the potential exfiltration of browser profiles or wallet files. In parallel, it monitors file activity for the automated deletion of directories like .vscode and vendor, which the malware uses as an anti-forensic measure to hide its presence.

In the final phase, an analyst or automated agent evaluates the relationship between these signals. A confirmed intrusion verdict depends on seeing the full chain: the execution of the RAT binary followed by significant data transfer and workspace cleanup.

### Blind Spots

This hunt has two primary blind spots. First, it cannot inspect the encrypted WebSocket traffic used by the Overlord framework to see specific commands. We can see that a connection exists, but not which modules the adversary activates. Second, it relies on file deletion telemetry to identify cleanup. If a developer manually cleans their workspace after a project, it may create a false positive without process context for the deletion events.

### How to Run This Hunt

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries and manage the workflow. The playbook includes parameters for C2 domains and binary names that you can update as new intelligence becomes available from the UNK_DeadDrop campaign.

# Hunting Unauthorized ScreenConnect and SCKit Client Deployments

### Why now
High-trust administrative tools like ScreenConnect are frequent targets for abuse. Microsoft recently published research on SCKit (https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/), a toolkit attackers use to deploy unauthorized remote access clients. These deployments often bypass traditional identity perimeters by using existing management infrastructure.

### Hypothesis
An intruder abuses ScreenConnect management consoles or extension vulnerabilities to silently deploy unauthorized remote-access clients and the SCKit loader toolkit to managed endpoints.

### How the hunt flows
The first phase scopes the estate by inventorying hosts that run ScreenConnect or ConnectWise software. This inventory identifies the potential attack surface and focuses the hunt on endpoints where the software is already present or recently installed. This scoping ensures the subsequent, more detailed queries target relevant hosts rather than the entire fleet.

The hunt then pivots to find leads involving silent MSI installations. It specifically searches for command lines containing sc.msi or session markers such as c=Exploited. These leads, often initiated via curl or msiexec, provide high-confidence indicators of unauthorized deployment activity rather than standard software updates. This phase acts as a filter to capture high-confidence signals of abuse.

An analyst evaluates these leads to determine if the command structure matches patterns seen in SCKit research. This manual gate is critical. It ensures that the hunt only proceeds to more resource-intensive queries when a lead appears suspicious. This prevents the noise of legitimate MSP maintenance from overwhelming the triage process.

If the lead passes the evaluation gate, the hunt gathers evidence in parallel. One query examines PowerShell script blocks for known SCKit loaders like stage0loader.ps1 or lateral movement scripts. Simultaneously, another query stacks MSI installation commands across the entire fleet to identify rare outliers. Legitimate management activity usually appears on dozens of hosts, while SCKit deployments typically target a specific subset of the estate.

The final phase correlates the behavioral lead with the script content and prevalence data. An analyst reviews the combined evidence to reach a final verdict. If the activity is confirmed as malicious, the hunt provides instructions for immediate host isolation and forensic capture. This structured approach moves from broad scoping to surgical response based on corroborated evidence.

### What the hunt cannot see
This hunt relies on agent coverage. It cannot identify unauthorized clients installed on unmanaged endpoints, which could serve as blind beachheads. Furthermore, while the hunt detects the SCKit loader scripts, it requires PowerShell Script Block Logging (Event ID 4104) to see the actual commands executed after the scripts are decrypted in memory. Without this logging, the hunt confirms the presence of the toolkit but not the specific actions taken by the intruder.

### How to run it
This hunt is provided as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to automate the lead generation and evidence gathering phases. The structured flow guides an analyst through the triage process to ensure a consistent response to ScreenConnect abuse. The playbook includes the specific parameters for lookback periods and known SCKit script filenames identified in the source research.

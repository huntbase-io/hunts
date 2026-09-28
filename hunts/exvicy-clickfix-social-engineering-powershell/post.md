# Hunting Exvicy ClickFix Social Engineering and PowerShell Execution

### Why this hunt

Sekoia recently published an analysis of Exvicy (https://www.sekoia.com/blog/exvicy-a-copycat-of-the-errtraffic-malware-distribution-framework), a Malware-as-a-Service framework that copies the ErrTraffic ClickFix technique. The framework targets victims through compromised WordPress sites, presenting a fake error page. This lure convinces the user to press Win+R and paste a malicious PowerShell command from their clipboard. Because the execution relies on manual user action and common system tools, it often evades standard web filters and endpoint blocks that look for automated drive-by downloads.

### The Hypothesis

An adversary is using compromised WordPress sites to deliver Exvicy ClickFix lures that trick users into executing a PowerShell downloader via social engineering keyboard shortcuts. The hunt assumes that while the initial web visit may look like normal traffic, the combination of a visit to a rare URI path followed immediately by a PowerShell process making an external network connection indicates a successful compromise.

### How the Hunt Flows

The hunt begins by scoping the environment for interaction with known Exvicy infrastructure or URI patterns. The first query identifies hosts that have resolved specific C2 domains or accessed web paths like /embed/ or /api.php. These paths are common in Exvicy lures hosted on compromised sites. By narrowing the fleet to these specific hosts, we reduce the noise for the more intensive behavioral analysis.

Next, the hunt performs a prevalence check on the identified web traffic. Legitimate WordPress sites are common, but the specific URIs used by Exvicy typically appear on a very small number of hosts within a single environment. The hunt stacks these hostnames and paths, filtering for those seen on fewer than five devices. This step isolates the specific compromised domains relevant to your environment.

Once the suspicious web activity is confirmed, the hunt pivots to endpoint telemetry. It searches for any PowerShell process on the scoped hosts that establishes an outbound network connection to a non-internal IP address. This is the critical execution indicator. Standard users rarely use PowerShell to connect to the public internet, making this a high-confidence signal when it occurs minutes after a suspicious web lure loads.

Finally, an analyst correlates these phases. The hunt confirms a verdict of 'malicious' if a host shows a temporal link between the rare web lure interaction and the subsequent PowerShell network connection. This chain provides the evidence needed to trigger isolation and forensic recovery.

### What this hunt cannot see

This hunt has two primary blind spots. First, it cannot directly observe the clipboard. Because ClickFix uses JavaScript to write commands to the user's clipboard, we cannot prove the 'copy' event occurred; we only see the resulting 'paste' and execution. Second, the hunt requires process-to-network correlation. If your environment lacks endpoint telemetry that links a specific process (powershell.exe) to a socket event, the execution phase will not return results.

### How to run it

This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries against your telemetry provider. The playbook includes automated triage steps to help you prioritize hosts based on the rarity of the domains they visited.

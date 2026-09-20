# Hunting Rogue ScreenConnect and Persistent VBScript Chains

### Why now
Huntress recently published [Rogue ScreenConnect Installations Suggest Worm-Like Activity](https://www.huntress.com/blog/rogue-screenconnect-installations). The report describes a campaign where attackers use social engineering to trick users into installing remote access tools, which then execute a multi-stage script chain for persistence.

### The Hypothesis
An adversary is using social engineering to deploy rogue ScreenConnect clients that execute a multi-stage VBScript chain for host profiling and persistent access via registry run keys.

### How the hunt flows
The hunt first inventories the estate for ScreenConnect or ConnectWise software. This scoping step identifies the total footprint of remote monitoring tools across the fleet. It does not provide a verdict but focuses subsequent behavioral queries on relevant hosts.

Next, the hunt searches for Quick Assist usage and ScreenConnect setup files in non-standard locations. It specifically flags instances where a ScreenConnect process spawns wscript.exe. This anomalous parent-child relationship marks the start of the malicious script execution chain.

The hunt then pivots to identify registry Run keys and rare VBScripts. It searches for specific file names like 1.vbs or windowsservicehost.vbs. It also looks for scripts that profile the host by checking for security software like Huntress, CrowdStrike, or SentinelOne.

Finally, an analyst correlates the early access evidence with the identified persistence keys. If the full chain exists—from social engineering tool usage to registry-based persistence—the analyst moves to isolate the host and collect forensic samples from the user's Temp and AppData folders.

### What the hunt cannot see
This hunt requires visibility into script block content to confirm the adversary's profiling logic. Without this, the analyst cannot easily distinguish malicious scripts from legitimate IT tasks. Additionally, the final payload within the encrypted sys_cache.zip remains hidden unless an analyst recovers the AES key or memory captures.

### How to run it
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the phased queries across your EDR or logging surfaces. It uses a structured logic to reduce false positives from legitimate administrative activity.

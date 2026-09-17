# Hunting Rogue ScreenConnect Persistence and VBScript C2 Activity

### Why Now
Recent reporting from Huntress in [Rogue ScreenConnect Installations Across Unrelated Hosts](https://www.huntress.com/blog/rogue-screenconnect-installations) highlights a trend where adversaries install legitimate Remote Monitoring and Management (RMM) tools to establish persistence. These installations often use VBScript-based loaders and specific registry modifications to ensure survival across reboots, occasionally displaying worm-like behavior to spread across unrelated environments.

### The Hypothesis
We hypothesize that an adversary has established persistence on a target endpoint via a specific registry run key named `WindowsServiceHost`. This key points to a VBScript payload, which subsequently communicates with dynamic DNS domains or staging IPs. This activity occurs shortly after the unauthorized installation of ScreenConnect or UltraViewer binaries.

### How the Hunt Flows
The hunt begins by scoping the environment for process execution related to common RMM tools. While many organizations use these legitimately, identifying the specific hosts where ScreenConnect or UltraViewer have run provides a focused starting point for telemetry analysis across registry and network surfaces.

Next, we pivot to registry telemetry to look for the `WindowsServiceHost` run key. The hunt specifically looks for entries where this key contains a `.vbs` file path. Because an attacker might rename this key, we also perform a prevalence stack-count on all VBScripts registered in the `CurrentVersion\Run` hive. By filtering for scripts that appear on very few hosts, we can isolate unique malicious loaders from standard enterprise scripts.

Finally, the hunt correlates these persistence indicators with network activity. We look for connections to specific IP addresses and DNS queries for dynamic DNS providers like `anondns.net` or `opik.net`. The goal is to see if a process—specifically `wscript.exe` or an RMM binary—is actively reaching out to the infrastructure identified in the campaign. The presence of both the specific registry key and the network traffic constitutes a high-confidence indicator of compromise.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, if your endpoint telemetry relies on periodic snapshots rather than continuous logging of registry modifications, you may miss ephemeral persistence where a key is created, used to trigger a payload, and then immediately deleted. Second, because much of the command-and-control traffic uses legitimate services like Dropbox, this hunt may not see the specific file transfers if network telemetry is limited to destination IPs and DNS without deep packet inspection or HTTP-level logs.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other `hunt.md`-aware runtime to execute the queries against your telemetry provider. Because this is a hunt and not a static detection, it is designed to be iterated upon by analysts to separate authorized RMM use from the rogue activity described in the source report.

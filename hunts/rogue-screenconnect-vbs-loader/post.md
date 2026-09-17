# Hunting Rogue ScreenConnect Instances and VBScript Loader Chains

### Why This Hunt

Recent reporting by Huntress in their article [Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like Activity](https://www.huntress.com/blog/rogue-screenconnect-installations) highlights a campaign where attackers use rogue ScreenConnect instances to execute a sequential VBScript loader. These installations often originate from social engineering or Quick Assist scams and lead to the deployment of persistent loaders. We are publishing this hunt to help practitioners identify the specific parent-child relationships and file artifacts associated with this activity.

### The Hypothesis

An intruder is utilizing rogue ScreenConnect instances to execute a sequential VBScript loader chain (1.vbs, 2.vbs, etc.) that profiles the host for EDR presence and establishes persistence through the registry, often mimicking a worm-like propagation across different environments.

### How the Hunt Flows

The first phase focuses on scoping. We use the `hb_software_inventory` surface to identify hosts where ScreenConnect or UltraViewer are installed. While many organizations use these tools legitimately, the hunt looks for installations in unusual paths or instances that deviate from the known-good fleet baseline.

Next, we pivot to process behavior using `hb_process_activity`. The core indicator is the RMM binary (e.g., ScreenConnect.WindowsClient.exe) spawning `wscript.exe` or `cscript.exe`. This relationship is highly anomalous for standard administrative tasks and serves as our primary lead for further investigation.

Once suspicious executions are identified, we perform stack-counting on the script command-line arguments. By baselining `wscript` arguments across the estate, we can isolate rare scripts—such as those named 1.vbs or WindowsServiceHost.vbs—that have only appeared on a small number of hosts within the last 14 days.

The final phase involves corroborating file artifacts via `hb_file_activity`. We look for specific files like `value.txt`, `map.txt`, and `out.enc` written to `%TEMP%` or `%APPDATA%` directories. We also inventory the security products on those hosts to understand the context of the attacker's profiling logic, which specifically looks for processes like SentinelService.exe or Huntress.exe.

### Blind Spots

There are two primary limitations to consider. First, if your environment has short process log retention, rogue installations that occurred more than 14 days ago may no longer show the behavioral link between the RMM tool and the script host. Second, if an attacker uses a different scripting engine or advanced obfuscation that hides the script file name from the command line, the prevalence-based detection may require deeper inspection of script block logs.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the SQLite queries for each surface and an automated triage step to help synthesize the findings into a per-host verdict.

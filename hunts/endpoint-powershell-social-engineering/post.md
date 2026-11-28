# Endpoint PowerShell Execution from Social Engineering

### Why This Hunt

Huntress recently detailed how adversaries use ClickFix tactics in their blog, Three Attacks, Zero Exploits in Microsoft 365 (https://www.huntress.com/blog/three-attacks-zero-exploits-microsoft-365). These attacks bypass technical MFA controls by tricking a user into manually running a command. Since standard security tools do not block the user, we hunt for the artifacts of the execution itself.

### The Hypothesis

An adversary tricks a user into running a malicious PowerShell command via the Windows Run dialog. They do this by mimicking a CAPTCHA or a fix on a look-alike SharePoint site. Once the user pastes and runs the code, the script exfiltrates session tokens to a remote server.

### How the Hunt Flows

The first phase focuses on process activity in the hb_process_activity surface. The lead query identifies PowerShell instances where the parent process is Windows Explorer. This relationship is common when a user types a command into the Win+R Run dialog. The hunt stacks these command lines across the environment and keeps only the rarest entries. Legitimate administrative commands often appear on many hosts, while social engineering payloads typically appear on a single host.

The second phase runs three checks in parallel to gather evidence. We pull the full PowerShell script block content from hb_script_activity to look for obfuscation or token-theft logic. We search DNS logs in hb_dns_activity for look-alike Microsoft 365 or SharePoint domains. We also read the user's Run dialog history (the RunMRU registry key in hb_registry_activity), where the pasted command itself is recorded.

The final phase checks temporal correlation. An analyst or agent checks if a phishing domain lookup occurred within ten minutes of the rare PowerShell execution. If the script content involves web requests or encoded strings and the timing matches the DNS activity, we confirm the compromise.

### Blind Spots

This hunt has two primary limitations. It depends on PowerShell script block logging to see the actual intent of the script. If logging is disabled, we only see the command line, which attackers often truncate or obfuscate. The Run dialog check needs registry telemetry for the RunMRU key. Without it, we cannot see the pasted command once the process has exited.

### How to Run It

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any tool that supports the hunt.md format. The playbook contains the logic to automate the stacking and temporal correlation between endpoint execution and network traffic.

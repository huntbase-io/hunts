# Hunting for Adversary Use of Signed Coding Agents

### Why now
Adversaries increasingly target developers to bypass security controls. Elastic Security Labs published [Living off the coding agent](https://www.elastic.co/security-labs/threat-command/coding-agent-launchagent-tunnel-detection), detailing how signed GenAI tools like Claude and Cursor can serve as proxies for shell execution and persistent tunnels. Because these tools have legitimate reasons to run code and manage files, traditional detections often fail to distinguish between a developer's prompt and an attacker's command.

### The hypothesis
An adversary uses a signed coding agent to proxy shell execution, establish reverse tunnels for service exposure, and install LaunchAgent persistence on a developer workstation. The high reputation of the signing certificate masks the malicious activity, allowing the attacker to stage scripts and maintain access without triggering basic process alerts.

### How the hunt flows
The hunt begins by narrowing the search to endpoints where known coding agents are installed. The first query checks software inventory for packages like Claude and Cursor. This scoping ensures the subsequent behavioral analysis focuses only on the systems where these specific tools operate, reducing the data volume for the analyst.

Next, the hunt runs two parallel checks for early execution signs. One branch searches for interactive shells, such as zsh or bash, parented by the coding agents. The other branch looks for scripts running from temporary paths or using the Model Context Protocol (MCP). An automated triage agent reviews these process trees and command lines to determine if the activity matches standard development patterns or indicates scripted automation.

If the initial triage finds suspicious execution, the hunt moves to a second parallel phase to look for outcomes. It searches for rare LaunchAgent persistence, stacking commands across the fleet to find outliers. Simultaneously, it checks DNS logs for connections to known tunnel brokers like lhr.life or trycloudflare.com. The hunt correlates these network hits with the process IDs of the coding agents.

Finally, the hunt combines the execution evidence with any observed persistence or network connections. A final triage verdict determines if the activity chain confirms an intrusion. If the verdict is malicious, the hunt provides a direct action to isolate the host and revoke associated tokens.

### What the hunt cannot see
This hunt has two primary blind spots. First, command-line truncation at the endpoint or SIEM level can hide evidence of credential exposure or specific tunnel configurations. If a curl command body is cut off, the triage agent may fail to identify malicious data exfiltration. Second, the hunt relies on new job events for LaunchAgents. If an adversary modifies an existing plist file in a way that does not trigger a 'create' event, the persistence query may miss the change.

### How to run it
This hunt is provided as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md standard. The playbook includes all required SQL queries for software inventory, process activity, and DNS logs. To run it, specify your lookback window and any host-level scoping to target your developer subnets.

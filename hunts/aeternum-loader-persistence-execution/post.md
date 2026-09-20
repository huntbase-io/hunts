# Aeternum Botnet Persistence and Execution Patterns

### Why Now
Unit 42 recently detailed a persistent threat in their report, [The Permanent Threat: Analyzing Aeternum’s Blockchain-Based C2 Operations and Communications](https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/). This adversary uses the Polygon blockchain for command and control, making network-based detection difficult. Because the network traffic often resembles legitimate blockchain RPC calls, hunting for the botnet's host-side persistence and execution patterns provides a more reliable path to discovery.

### Hypothesis
The Aeternum loader establishes persistence by creating a uniquely named LNK file in the user Startup directory and executes auxiliary binaries from the local AppData profile.

### How the Hunt Flows
The first phase identifies Windows endpoints where the Aeternum PE loader can execute. The hunt begins with a cheap lead query that searches for specific shortcut file patterns, such as `wmi_framework_apikey_wmsnet_%.lnk`, within user Startup folders. This initial check acts as a high-confidence trigger for the rest of the investigation.

If the lead query returns results, the hunt enters a triage phase. An analyst or automated agent evaluates the file activity to confirm the shortcut matches the known Aeternum pattern. This gating step ensures that more resource-intensive queries only run when evidence of persistence exists.

Once a lead is confirmed, the hunt expands into two parallel paths. The first path searches for known auxiliary binaries used by the loader, including `wmiframework.exe` and `zrvesjqzwq.exe`. The second path performs a frequency analysis of all executables running from user-writable paths like `AppData\Local` and `Users\Public`. By stacking these binaries across the fleet, the hunt identifies the primary loader even if the adversary has renamed the original `Build.exe` file.

In the final phase, the hunt correlates the persistence shortcut with the execution evidence. A host showing both a malicious shortcut and rare process execution in a user profile confirms an active infection. The hunt then provides instructions to isolate the affected host and remove the malicious files.

### Blind Spots
This hunt relies on file activity telemetry for user profile Startup paths. If the endpoint agent does not capture file creation events in these specific directories, the lead query will return no results. Additionally, the hunt cannot see activity on unmanaged hosts that lack a reporting agent. While the persistence mechanism is a strong indicator, an adversary who moves away from Startup-based persistence would bypass the initial trigger of this specific playbook.

### How to Run It
This hunt is a `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the open `hunt.md` format. The playbook includes the necessary SQLite queries and logic to gate the investigation, ensuring you only perform deep analysis on hosts showing initial signs of compromise.

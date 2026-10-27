# Hunting MythicRatatoskr Backdoors and Sandworm Handover

### Why now: The UAC-0099 and Sandworm Handover

Recent reporting from [ESET Research](https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/) describes a collaboration between the initial access broker UAC-0099 and the Sandworm group. The adversary follows a specific progression: initial access via phishing leads to the MATCHWOK backdoor, which eventually hands off control to a sophisticated mesh-network backdoor called MythicRatatoskr. This transition is a precursor to destructive data-wiping attacks, making early discovery of the persistent backdoor critical.

### The Hypothesis

An adversary establishes initial access using a scheduled task to deploy the MATCHWOK backdoor. They subsequently install the MythicRatatoskr backdoor, which uses the Yggdrasil mesh network for stealthy C2 communication to bypass traditional network filtering and egress monitoring.

### How the Hunt Flows

The first phase scopes the environment for the initial beachhead. A query scans scheduled task metadata for the specific task name used by UAC-0099. This step identifies which hosts require deeper inspection and provides a temporal anchor for the rest of the hunt.

Once the hunt identifies potential hosts, it corroborates the access markers in parallel. It examines PowerShell script logs for the execution of payloads staged in temporary directories and searches the registry for the specific run-key persistence associated with the MATCHWOK infection. This step builds confidence that the initial access chain succeeded.

The hunt then pivots to the MythicRatatoskr deployment. It searches for specific binary filenames and service installations while simultaneously baselining rare network traffic. This network search focuses on the deprecated IPv6 range (200::/7) that the Yggdrasil mesh protocol uses. Finding these IPv6 connections on a small number of hosts provides a high-confidence signal of a decentralized backdoor.

Finally, the hunt synthesizes these phases. An analyst evaluates whether the hosts with early access markers are the same hosts showing mesh-network activity. This full-chain assessment confirms the transition from a simple phishing infection to a sophisticated, long-term persistence mechanism.

### What the Hunt Cannot See

Visibility into the Yggdrasil mesh depends entirely on the granularity of IPv6 logging. If network sensors do not capture traffic in the 200::/7 range or if EDR agents do not report IPv6 destination addresses for local processes, the network-based corroboration will fail. Furthermore, if the adversary rotates binary filenames or task names beyond the known parameters, the scoping phase may return zero results even if the backdoor exists.

### How to Run the Hunt

This hunt is an open hunt.md playbook. You can import the file into Huntbase or any other runtime that supports the hunt.md format. The playbook uses SQLite-based DSL for its queries and includes logic for scoping hosts, triaging results, and isolating compromised systems. To begin, set the lookback_days parameter to cover at least 60 days of telemetry to capture the full progression from initial access to backdoor installation.

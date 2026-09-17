# Hunting for MacSync Stealer Wallet Trojanization and Data Staging

Our team recently analyzed a campaign involving a macOS infostealer that leverages fake software ads to deliver a remote access trojan. The source material for this hunt is the report by Huntress, [MacSync Stealer: How a Google Search for Claude Led to a macOS Infostealer](https://www.huntress.com/blog/fake-claude-macsync), which details how attackers target users searching for developer tools. While the campaign involves multiple stages of persistence and remote access, this hunt focuses specifically on the final impact: the theft of cryptocurrency assets through application trojanization.

### The Hypothesis
We hypothesize that an adversary has successfully modified local cryptocurrency wallet applications on macOS endpoints. This modification involves replacing legitimate application files with malicious versions designed to phish for wallet recovery phrases. We further expect that stolen data is being staged in a specific archive located at `/tmp/osalogging.zip` before being exfiltrated to the attacker's infrastructure.

### How the Hunt Flows
The hunt begins by narrowing the scope to the macOS fleet. Since the MacSync payload is specific to the Darwin platform, we filter for these devices to ensure subsequent telemetry analysis is relevant and performant.

Next, we search for the specific file path `/tmp/osalogging.zip`. This is a hardcoded staging location identified in the MacSync campaign. The creation or modification of this file is treated as a high-confidence indicator of activity, though its absence does not clear a host if the attacker has updated their naming convention.

To account for variations in staging, we pivot to a prevalence-based check. We identify any ZIP archives created in the `/tmp` directory that appear on a very small number of hosts across the organization. This helps surface randomized staging filenames that would otherwise bypass a signature-based search.

We then correlate these staging signals with file activity in directories associated with popular wallet applications, such as Ledger, Exodus, and MetaMask. We are specifically looking for writes or modifications to these application bundles, which suggests the trojanization process where legitimate binaries are replaced with malicious ones.

Finally, we check for network connections to known exfiltration IP addresses. By joining file-system anomalies with network-layer telemetry, we build a higher-confidence case for actual data theft rather than just localized software tampering.

### Limitations and Blind Spots
The primary blind spot for this hunt is file-level visibility. Effective detection of application trojanization requires robust logging from the macOS Endpoint Security Framework (ESF). Without detailed file activity events, it is difficult to distinguish between legitimate application updates and the stealthy replacement of internal app bundle files. Additionally, if an attacker uses unique staging paths for every victim, our prevalence logic becomes the only line of defense against randomized filenames.

### Beyond Simple Detection
This is designed as a hunt rather than a static detection because it correlates activity across three different surfaces: device inventory, file system modifications, and network connections. A standard alert on `/tmp/osalogging.zip` might be ignored as a low-priority indicator, but when paired with rare application modifications and C2 traffic, it provides the context needed for immediate response. This hunt is provided as a `hunt.md` playbook, which can be imported directly into Huntbase or any compatible runtime for execution against your macOS telemetry.

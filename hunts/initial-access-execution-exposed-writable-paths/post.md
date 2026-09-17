# Hunting for Execution in Writable Paths on Exposed Assets

The research published by Unit 42, "Unmasking Cloud Identities: From Behavioral Clustering to Automated Detection" (https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/), highlights the power of behavioral patterns in identifying compromised assets. While their research focuses on cloud identity clustering, the underlying principle of correlating exposure with specific execution behaviors is universally applicable to endpoint defense. This hunt translates those concepts into a practical playbook for detecting initial access and execution via exposed, vulnerable assets.

### The Hypothesis

Our hypothesis is that an intruder has successfully exploited an internet-facing vulnerability and is now executing a malicious payload from a user-writable path. This activity is typically characterized by rare process launches and suspicious script activity on hosts that have a high-risk profile based on their external exposure and vulnerability status.

### How the Hunt Flows

The hunt begins with a scoping phase focused on the external attack surface. We identify assets that are directly reachable from the internet and correlate them with high-severity vulnerability findings. This allows us to prioritize our search on the hosts most likely to be targeted by automated exploit kits or manual intrusion attempts. By narrowing the focus to these high-risk candidates, we significantly reduce the volume of telemetry requiring analysis.

The lead behavior phase identifies binaries executing from non-system, user-writable directories. This includes paths such as Downloads, /tmp, /var/tmp, or AppData. These locations are common staging areas for attackers who do not yet have the privileges to write to protected system directories. We look for specific file extensions associated with payloads, including both traditional executables and script-based stagers.

To separate legitimate administrative activity or common software updates from malicious behavior, we apply a prevalence baseline. We stack-count the identified paths across the entire fleet over a two-week period. Paths that appear on a small number of hosts are flagged for deeper investigation. This approach is highly effective at filtering out ubiquitous tools like Slack or Teams, which frequently run or update from user-specific paths but appear on many machines.

The enrichment phase adds necessary context to the rare executions. We look for outbound network connections originating from the same process paths, which could indicate command-and-control (C2) communication. Simultaneously, we examine script activity for signs of obfuscated commands or automated staging, such as PowerShell's Invoke-Expression (IEX) or shell-based downloaders like curl or wget piped directly into sh.

### Blind Spots

This hunt has specific limitations. It relies on having endpoint telemetry for every internet-exposed asset. If an asset is exposed but unmanaged, this hunt will not see the activity. Additionally, it focuses on process-level execution. Sophisticated exploits that result in purely in-memory execution or code injection into an existing, trusted process may not trigger these process-based leads.

### How to Run it

This playbook is provided as a hunt.md file. It is designed to be imported into Huntbase or any other hunt.md-aware runtime environment. Because it uses multi-signal correlation and fleet-wide prevalence rather than simple static signatures, it functions as a true hunt. This approach reduces alert fatigue and focuses analyst time on the most credible signals of compromise.

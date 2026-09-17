# Hunting for UNK_DeadDrop Overlord RAT and Credential Exfiltration

### Why now

Recent research from Proofpoint, [Don’t Fear the Repo: UNK_DeadDrop Phishing Campaign Targets Developers](https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal), details a campaign targeting software developers and security researchers. The actors use social engineering on GitHub to deliver the Overlord RAT and a Node.js-based credential stealer. Because this threat targets high-value assets like cryptocurrency wallets and sensitive source code access, we have published a structured hunt to identify post-exploitation activity on potentially compromised endpoints.

### The Hypothesis

Our hunt is based on the hypothesis that an intruder has successfully established a persistent backdoor using the Overlord RAT framework or a Node.js stealer. If present, the malware will actively harvest browser credentials and cryptocurrency wallets, eventually exfiltrating this data to actor-controlled infrastructure via direct connections or multi-hop proxies.

### How the Hunt Flows

The hunt begins by scoping the environment for the specific Go-based Overlord RAT binaries and the Windows launcher script identified in the research. We look for process execution events across Windows, Linux, and macOS surfaces, focusing on filenames like `google-update-support-linux-amd64` and the `run-update-hidden-launch.vbs` script. This provides an immediate list of high-confidence candidates for further investigation.

Next, the hunt pivots to file system telemetry. We monitor for processes—specifically the identified RAT binaries or Node.js—accessing sensitive paths such as browser 'Login Data', 'Cookies', and cryptocurrency wallet files. The presence of ZIP file creation by these processes is also flagged as a likely indicator of data staging for exfiltration.

To identify command-and-control (C2) activity, the hunt baselines outbound network connections. We specifically look for rare destinations contacted by the suspected processes. By counting the prevalence of destination IPs across the fleet, we can highlight unique C2 infrastructure that may not yet appear in threat intelligence feeds. We also include an enrichment step to check for known C2 domains like `runoptions.runon` in DNS logs.

Finally, the hunt uses an automated triage step to weigh the collected evidence. It correlates process, file, and network findings to provide a per-host verdict. If the evidence suggests a high-confidence infection, the playbook provides instructions for host isolation and credential revocation.

### What this Hunt Cannot See

There are two primary blind spots to consider. First, this hunt relies on comprehensive endpoint telemetry. If hosts are not enrolled in your collection platform, they may harbor infections that this hunt will not detect. Second, if the actor uses fully encrypted C2 channels without unique domain names (e.g., direct IP connections over TLS), the network detection layer will be less effective, and the hunt will rely almost entirely on process and file-level behavioral indicators.

### How to Run this Hunt

This hunt is provided as a `hunt.md` playbook. It is designed to be machine-readable and can be imported directly into Huntbase or any other runtime environment that supports the `hunt.md` standard. The queries are formatted in SQLite for broad compatibility with various security data lakes and EDR platforms. Since this is a hunt rather than a static detection, it is intended to be run periodically or in response to specific intelligence updates to identify activity that may have bypassed initial security controls.

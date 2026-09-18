# Hunting for Volume Shadow Copy Abuse and Credential Exfiltration

### Background
Recent research from Huntress, titled [How Attackers Abuse VSS, and How Huntress Detects It](https://www.huntress.com/blog/vss-abuse-explained), highlights how adversaries frequently target the Volume Shadow Copy Service. VSS is a dual-use mechanism: it provides the necessary infrastructure for legitimate backups, but it also allows attackers to create snapshots of locked system files like the Active Directory database (ntds.dit) for offline cracking, or to delete recovery points entirely before deploying ransomware.

### The Hypothesis
This hunt is built on the hypothesis that an adversary is actively manipulating VSS to either facilitate credential theft or ensure the success of a disruptive attack. Because administrators also use VSS tools for maintenance, a simple detection on tool execution is often too noisy. We focus on the intersection of tool usage, process rarity, and subsequent file-level intent.

### How the Hunt Flows
The hunt begins by scoping the environment using the `hb_devices` surface. We specifically isolate Windows Domain Controllers and high-value servers where the impact of credential theft or data encryption is highest. This ensures the hunt remains performant and focused on high-risk assets.

Next, we pivot to `hb_process_activity` to identify the use of `vssadmin.exe` or `wmic.exe`. We are looking for specific command-line arguments related to shadow copy creation (often used for staging NTDS exfiltration) or deletion (used to prevent rollbacks). At this stage, we are collecting leads, not making final judgments.

To separate legitimate administration from an attack, we run two parallel corroboration phases using `hb_file_activity`. The first branch looks for processes accessing `ntds.dit` within a shadow copy path—a clear indicator of credential staging. The second branch looks for high-volume file modifications by processes that are rare across the fleet. This allows us to identify potential ransomware activity that may have been preceded by VSS deletion.

The final phase uses a triage agent to correlate these signals. It looks for temporal proximity between the VSS manipulation and the suspicious file activity, providing a verdict based on the full lifecycle of the observed behavior.

### Limitations and Blind Spots
No hunt is exhaustive. This playbook primarily relies on command-line monitoring. If an attacker uses direct Win32 API calls (via PowerShell or a custom binary) to interact with the VSS provider, they may bypass the process activity checks. We also note that during periods of extreme disk I/O, such as mass encryption, endpoint agents may suppress file events to maintain system stability, which could impact our file churn calculations.

### Running the Hunt
This hunt is packaged as an open `hunt.md` playbook. It can be imported into Huntbase or any runtime compatible with the `hunt.md` format. It is designed to be run periodically against server estates to identify latent persistence or staging activity that does not trigger standard real-time alerts. 

By focusing on the 'why'—correlating the tool with the result—this hunt provides a higher degree of confidence than isolated detection rules.

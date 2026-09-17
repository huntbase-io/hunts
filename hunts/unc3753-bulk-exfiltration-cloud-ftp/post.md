# Hunting UNC3753: Bulk Exfiltration via Cloud and FTP Utilities

### The Context of UNC3753 Exfiltration

Recent reporting by Mandiant in their article "UNC3753 targeted campaign against US law firms" (https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms) highlights a persistent threat to the legal sector. UNC3753, also known as Luna Moth, typically concludes their intrusion by moving massive amounts of sensitive data—often measured in gigabytes—within a single business day. Because they use legitimate tools and public cloud infrastructure, simple detection rules often fail to provide the context needed to stop the theft in progress.

### The Hypothesis

Our hunt is built on the hypothesis that an adversary has staged sensitive legal data and is using specialized transfer tools (WinSCP, Rclone) or web-based uploads to exfiltrate it to non-corporate cloud storage accounts. By looking for the specific footprint of these tools combined with network throughput anomalies, we can differentiate between a sysadmin doing their job and an adversary emptying a file share.

### How the Hunt Flows

The hunt begins with a scoping phase focused on process activity. We look for the execution of common exfiltration and FTP utilities such as WinSCP, Rclone, FileZilla, and SFTP. The query specifically targets workstations, especially in legal or finance departments, where these tools are rarely part of the standard software image.

Next, the hunt performs a fleet-wide rarity analysis. We stack-count the identified tools by process name and path across the entire environment. If a transfer utility appears on only a few hosts and has a recent first-seen timestamp, it increases the likelihood that the binary was deployed by an external actor rather than an internal IT team.

To corroborate the process execution, we pivot to network connection logs. We look for outbound flows that exceed a 50MB threshold. This provides the "anchor" IPs needed to verify if the rare processes identified earlier are actually moving significant data. Without this step, a simple execution of WinSCP is just a low-fidelity alert.

Finally, we examine HTTP activity. We specifically look for POST methods and large response bodies involving known file-sharing or self-destructing text domains like privnote.com, mega.nz, or Dropbox. This allows us to catch browser-based exfiltration that might bypass the process-based checks in the first phase.

### What This Hunt Cannot See

There are two primary blind spots to consider. First, if your network telemetry lacks byte counters (flow logs without traffic size), we cannot distinguish between a massive exfiltration event and a routine heartbeat connection. Second, if your forward proxy does not log HTTP methods or request sizes for encrypted traffic, browser-based uploads to consumer cloud storage remain largely transparent.

### Why This is a Hunt, Not a Detection

A detection rule for WinSCP execution is noisy and often ignored in environments with active IT departments. This is a hunt because it requires the correlation of three distinct surfaces—process, network, and HTTP—to build a case for malicious intent. It uses the rarity of a tool's prevalence to prioritize investigation rather than firing on every execution.

This hunt is provided as a hunt.md playbook. It can be imported directly into Huntbase or any hunt.md-aware runtime to automate the data collection and correlation phases, leaving the final verdict to the analyst.

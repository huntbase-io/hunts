# Hunting for Sensitive Document Staging and Exfiltration in Law Firms

Recent reporting on the [UNC3753 targeted campaign against US law firms](https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms) highlights a remarkably fast pivot from initial access to data theft. In many cases, adversaries move from the first vishing-based entry to full exfiltration in under 24 hours. Because the goal is extortion, the adversary focuses on high-value PII and sensitive financial records stored in legal document management systems.

### The Hypothesis
Our hunt is built on the hypothesis that an intruder has already identified sensitive records via iManage or similar repositories. To move this data, they are staging files—often renamed or compressed—into user-writable profile paths like `Downloads` or `AppData` before exfiltrating them via portable transfer tools or direct web-based uploads to consumer cloud storage.

### How the Hunt Flows
The hunt begins with a scoping phase using the `hb_software_inventory` surface. We first identify endpoints running iManage or WorkSite software. These systems are the primary targets for harvesting, and narrowing our focus to these hosts reduces the noise of common administrative file movement elsewhere in the environment.

Next, the hunt pivots to behavioral file analytics using `hb_file_activity`. We look for the creation of files in user profile paths that contain sensitive keywords like 'W-2', '1099', 'SSN', or 'audit'. This step is specifically designed to catch the 'staging' behavior where documents are consolidated before the final push out of the network.

Simultaneously, we monitor `hb_process_activity` for the execution of rare transfer utilities. Rather than simply alerting on any instance of WinSCP or Rclone, we look for these tools running from non-standard paths or appearing on very few hosts. This distinguishes legitimate administrative use from portable binaries dropped by an actor.

Finally, we check `hb_http_activity` for outbound POST or PUT requests to known consumer cloud storage domains. The hunt then uses a triage agent to correlate these signals. If a host shows sensitive file staging and the execution of a transfer tool within a tight temporal window, it is escalated for immediate containment.

### What This Hunt Cannot See
There are necessary limitations to this telemetry. Without decrypted SSL inspection, we can identify that an upload occurred to a domain like Google Drive, but we cannot see the specific filenames being exfiltrated. Furthermore, if the adversary searches for documents directly within the iManage application without downloading them to the local profile first, we lose visibility into the discovery phase. Finally, this hunt relies on network and process telemetry; it cannot track physical data theft via USB media.

### How to Run It
This hunt is packaged as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the hunt.md format. By providing the logic as a structured playbook, we allow practitioners to automate the correlation of file staging and network exfiltration that would otherwise require manual, time-intensive analysis.

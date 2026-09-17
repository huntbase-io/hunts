# Hunting Precursors to Volume Shadow Copy Abuse and Lateral Movement

### Why Now

Recent analysis from Huntress, titled [How Attackers Abuse VSS, and How Huntress Detects It](https://www.huntress.com/blog/vss-abuse-explained), highlights how adversaries manipulate Volume Shadow Copies (VSS) to delete backups or extract sensitive data from the NTDS.dit file. While the actual deletion or creation of a shadow copy is a critical event, the steps leading up to it—specifically the lateral movement to servers and the discovery of backup infrastructure—offer a window for proactive hunting before the impact occurs.

### The Hypothesis

We hypothesize that an adversary is using PsExec to move laterally to Windows servers, particularly Domain Controllers and file servers. Once established, they execute session or network discovery to identify high-value targets, including backup infrastructure (e.g., Veeam, Synology, or Rubrik), as a precursor to VSS manipulation or credential theft.

### The Hunt Flow

The hunt begins by scoping the environment to identify Windows servers and Domain Controllers. These hosts are the primary targets for large-scale ransomware impact and sensitive data storage. By narrowing the focus to these critical assets, we reduce the noise from workstation-level administrative activity.

Next, we examine process activity for the execution of the PsExec service (PSEXESVC) or command shells spawned by it. While PsExec is a staple for IT administrators, its appearance on sensitive servers followed by discovery commands is a significant pivot point. We specifically look for the service being initiated on hosts identified in the scoping phase.

Following the identification of lateral movement, the hunt transitions to stacking discovery tools. We look for the execution of binaries like `qwinsta.exe`, `vssadmin.exe`, and `nltest.exe`. By counting the distinct number of hosts where these tools are used, we can isolate rare, targeted execution patterns that deviate from fleet-wide administrative baselines.

Finally, we correlate process-level activity with DNS reconnaissance. Attackers often need to locate storage devices or backup servers within the network. This phase scans for DNS queries containing keywords such as 'backup', 'veeam', or 'nas', as well as high-fidelity signals like DNS zone transfer (AXFR) requests, which are rarely legitimate in modern environments.

### Blind Spots

This hunt relies heavily on process telemetry. If a server lacks comprehensive EDR logging or if an attacker uses short-lived processes that bypass the polling interval, the lateral movement phase may be missed. Additionally, if an adversary performs IP-based scanning for SMB or RDP targets without resolving DNS names, the network reconnaissance step will not provide a signal.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported directly into Huntbase or any runtime environment that supports the `hunt.md` standard. The playbook includes the necessary SQL queries to pull data from process and network surfaces, allowing you to triage the results and isolate potentially compromised beachheads.

Source: [How Attackers Abuse VSS, and How Huntress Detects It](https://www.huntress.com/blog/vss-abuse-explained)

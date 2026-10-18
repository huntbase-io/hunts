# Akira Ransomware: Hunting GOST Tunneling and Data Impact

### Why Now
The Akira ransomware group continues to refine its post-compromise tactics, often using legitimate tools to blend in with administrative activity. This hunt identifies the specific toolmarks left by the GOST proxy and RClone during the critical window between initial access and final encryption. It is based on the analysis "Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack" (https://www.huntress.com/blog/mapping-akira-ransomware-attack) by Huntress.

### The Hypothesis
An adversary establishes a beachhead by deploying a GOST tunneling tool for persistence and uses RClone for exfiltration, followed by shadow copy deletion and Akira ransomware encryption.

### Discovery in PerfLogs
The hunt starts by scoping the environment for activity in the C:\PerfLogs directory. This location is a common staging area for Akira’s toolkit. The first query looks for file creation or modifications in this path and checks for known file hashes identified in the report. This provides a baseline list of hosts showing the earliest toolmarks of the intrusion.

### Persistence and Exfiltration
Once an analyst identifies suspicious hosts, the hunt pivots to find persistence and data staging evidence. The hunt runs two queries in parallel. One checks for network connections originating from the PerfLogs directory, specifically looking for egress to known C2 IPs or high-port traffic characteristic of a GOST tunnel. The second query performs a prevalence check on RClone. Since RClone is often used for legitimate data transfers, the hunt looks for hosts where it is rare—appearing on three or fewer machines. This prevalence check helps distinguish administrative use from adversary staging.

### Inhibiting Recovery
The third phase focuses on system impact. The hunt searches for the specific recovery inhibition techniques used by Akira. It searches hb_script_activity for PowerShell commands that invoke Win32_ShadowCopy to delete volume shadow copies. This is a high-fidelity indicator that an adversary is preparing the system for encryption. While backup software might touch shadow copies, the combination of this command with previous staging indicators increases the confidence of the hunt.

### Ransomware Artifacts
The final phase identifies the ransomware artifacts themselves. The hunt searches for the win.exe binary in suspect directories and looks for the specific akira_log files created during the encryption process. This step confirms that the adversary has moved from preparation to the final impact phase. By combining the persistence, exfiltration, and impact signals, an analyst confirms the full attack chain across the environment.

### Blind Spots
This hunt relies on PowerShell Script Block Logging (Event ID 4104) to identify shadow copy deletion. If this logging is disabled, the recovery inhibition phase remains invisible. Additionally, the network query focuses on known C2 IPs and high-port egress. A tunnel using an unreported IP or chained through a local proxy may not trigger the network connections query.

### How to Run This Hunt
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries against your telemetry. Because this is a hunt rather than a single detection, it guides an analyst through the pivots from staging to impact, ensuring that tools like RClone are evaluated in context rather than as isolated alerts.

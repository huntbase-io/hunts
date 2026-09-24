# Hunting Lunar Spider Persistence and FTP Exfiltration

### Why Now: Lunar Spider Intrusion Analysis 2025

The DFIR Report recently published From a Single Click: How Lunar Spider Enabled a Near Two-Month Intrusion (https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion/). The report details a long-term compromise where the threat actor maintained access for nearly sixty days. This hunt focuses on identifying the custom .NET backdoor used for persistence and the subsequent data exfiltration.

### The Hypothesis

The adversary maintains long-term access via a masqueraded .NET backdoor and exfiltrates data via Rclone over FTP to a rare external destination.

### Phase 1: Process Masquerading

The hunt begins by inspecting process activity for masqueraded binaries. The adversary uses filenames like lsassa.exe, lsasss.exe, or lssas.exe to mimic the legitimate Local Security Authority Subsystem Service. We specifically target these names when they execute from suspicious paths like \Users\Public\ or \ProgramData\. While the name mimics a system process, its execution from a user-writable directory or as a .NET binary distinguishes it from the real lsass.exe.

### Phase 2: Persistence and Exfiltration Pivots

Next, the hunt pivots to scheduled tasks. The adversary creates tasks to ensure their backdoor runs consistently. We query for tasks that reference the identified malicious file paths or names. This step confirms how the adversary survives reboots and maintains their foothold without manual intervention.

In parallel, the hunt baselines network traffic for rare outbound FTP connections. While many environments use FTP, it is rarely used to send large volumes of data to unknown external IPs from a single workstation. We use stack-counting to identify destinations seen from very few hosts that exhibit high traffic volume. We focus on port 21 traffic that originates from hosts where we also see the masqueraded binaries.

We also check script activity for Rclone usage. The adversary uses Rclone to automate the theft of sensitive data. The hunt looks for Rclone commands like sync or copy and script names such as backup_sync.ps1. Finding these scripts provides high-confidence evidence of an active exfiltration operation and often identifies the specific folders being targeted for theft.

### Triage and Verdict

The final stage uses an agent to weigh the combined signals. If a host executes the masqueraded binary, has an associated scheduled task, and shows rare outbound FTP traffic, the agent marks it as malicious for immediate isolation. This multi-surface correlation ensures we do not alert on every instance of FTP traffic or every custom scheduled task.

### Blind Spots and Limitations

Telemetry retention is the primary blind spot. Since the intrusion lasted two months, a standard 14-day log retention window might miss the initial persistence setup or early exfiltration events. Furthermore, the hunt relies on keyword matching in scripts. If the adversary uses PowerShell obfuscation or hex encoding to hide strings like rclone, the script-based queries will fail to trigger.

### How to Run This Hunt

The hunt exists as an open hunt.md playbook. You can import it into Huntbase or any tool that supports the hunt.md format. Before running, adjust the lookback_days parameter to match your organization's telemetry retention to ensure coverage of long-dwell threats.

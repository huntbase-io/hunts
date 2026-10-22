# SafePay Lateral Movement and Discovery Hunt

### Understanding SafePay Tactics

The CISA advisory #StopRansomware: SafePay Ransomware (https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a) details the group's reliance on legitimate tools for post-exploitation. SafePay actors establish a foothold and use repurposed administrative tools, credential dumpers, and anomalous RDP or SMB sessions to move laterally toward file shares. This behavior often evades simple detection rules because the tools — like AnyDesk or PsExec — are frequently used by legitimate IT staff.

### The Hunt Flow

The hunt begins with an inventory of RMM software. The first query identifies hosts running AnyDesk, TeamViewer, or ScreenConnect. This establishes the initial search scope by finding potential persistence points. While these tools are common, their presence on high-value systems or in segments where they are not authorized is a strong indicator of actor persistence.

Next, the hunt splits into two parallel tracks to gather evidence of active movement. The first track searches process activity for high-integrity execution of discovery and bypass tools such as SharpShares, NetExec, and Mimikatz. The hunt specifically filters for high-integrity or system-level execution. This focuses the investigation on instances where the actor successfully bypassed User Account Control (UAC) or used an elevated service to run their recon.

The second track baselines successful internal sign-ins via RDP and SMB. Instead of looking for a specific signature, it identifies rare authentication paths. It groups logins by user and source IP to find low-volume sessions that differ from standard administrative patterns. This is effective for finding actors who use stolen credentials to navigate the network without triggering traditional alerts.

An agent then weighs the findings. It distinguishes authorized admin work from a SafePay intrusion by correlating the tool execution with the rare sign-ins. If the agent confirms an active threat, the hunt routes the host to an isolation task. This action removes the endpoint from the network fabric and terminates active RDP sessions, containing the threat before encryption starts.

### Why This Is a Hunt

A single detection rule for a specific filename is easily bypassed if the actor renames the binary. This hunt is more resilient because it looks for the effect: high-integrity execution of recon functionality combined with anomalous authentication. We look for patterns of behavior rather than static indicators, which is necessary when actors use legitimate RMM tools for malicious ends.

### Blind Spots

The hunt has two primary blind spots. First, it requires endpoint agent coverage on all internal servers. If an actor runs NetExec from an unmanaged host, the process activity will not be recorded. Second, the hunt may miss in-memory scripts. SafePay uses ShareFinder.ps1 for AD enumeration; if the actor loads the script content directly into memory, the logs show the PowerShell launch but not the specific commands.

### How to Run

This hunt is published as a hunt.md playbook. You can import it into Huntbase or any compatible runtime. Because it is a playbook, it provides an ordered, repeatable way to investigate these techniques across your entire estate.

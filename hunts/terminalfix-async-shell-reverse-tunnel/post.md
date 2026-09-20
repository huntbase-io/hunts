# Hunting TerminalFix PowerShell Loops and Python Reverse Tunnels

### The TerminalFix Persistence Strategy

Microsoft recently published a detailed analysis of the TerminalFix campaign at https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/. The adversary uses a multi-stage strategy to maintain command-and-control access after a social engineering compromise. This hunt focuses on the specific implants used to sustain this persistent connection.

### Hypothesis

An intruder establishes long-term command-and-control presence using a PowerShell file-watch loop for asynchronous command execution and a Python-based reverse tunnel for persistent network-level proxying.

### Identifying the Network Lead

The hunt begins by identifying the network lead in hb_dns_activity. We look for resolutions of gitnow.dev and other known campaign infrastructure. These lookups serve as the primary indicator that a host is attempting to establish or maintain its reverse tunnel connection. Identifying these lookups early allows an analyst to scope the potential compromise to a specific set of endpoints before beginning more resource-intensive queries.

### Searching for the Asynchronous Shell

After identifying a lead, we pivot to hb_script_activity to find the command loop. The adversary uses the PowerShell FileSystemWatcher class to monitor a specific text file for updates. When the file changes, the script reads the content and passes it to Invoke-Expression. This method allows the attacker to execute arbitrary commands without spawning new, suspicious processes for every action. The hunt looks for this specific combination of monitoring and execution logic within captured script blocks. This behavioral focus makes the hunt more resilient than simple filename detections.

### Detecting the Reverse Tunnel

In parallel, we search hb_process_activity for the reverse tunnel client. The intruder typically runs a Python script named client.py using the pythonw.exe binary. Running under pythonw.exe allows the process to remain hidden from the taskbar and terminal. We baseline these processes across the environment to identify rare instances running from unusual directories like ProgramData. This step uses frequency analysis to separate legitimate developer tools from malicious implants.

### Triage and Correlation

The final phase correlates these signals. A single DNS lookup or a legitimate Python script might be benign, but the co-occurrence of these three indicators on a single host strongly suggests an active intrusion. This is why this logic is a hunt rather than a single detection: we aggregate the network leads, the PowerShell command loop signatures, and the rare Python process metadata to produce a high-confidence verdict. By weighing evidence from three different surfaces, the hunt confirms the presence of an active command-and-control channel.

### Blind Spots and Limitations

This hunt has two primary blind spots. First, it requires PowerShell Script Block Logging to be enabled. Without EID 4104 data, the file-watch script remains invisible to the hb_script_activity surface. Second, the Python tunnel may be ephemeral. If the attacker only establishes the connection during specific windows, periodic process snapshots might miss the active tunnel.

### Execution

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook automates the correlation between network, script, and process data to produce an actionable host verdict. It ensures that responders have the full context of the intrusion before initiating containment.

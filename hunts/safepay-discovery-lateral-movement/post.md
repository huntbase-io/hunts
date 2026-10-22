# SafePay Ransomware: Hunting for Internal Discovery and Lateral Movement

### The Context
SafePay ransomware actors often exploit known vulnerabilities for initial access before beginning a period of internal discovery. CISA recently detailed these tactics in advisory AA26-293A (#StopRansomware: SafePay Ransomware). Once inside, the adversary focuses on identifying high-value targets and moving laterally using tools that frequently blend into legitimate IT operations.

### The Hypothesis
An adversary uses legitimate administrative tools and scripts to enumerate network shares and move laterally via remote management protocols while disabling local security software.

### How the Hunt Flows
The hunt starts by examining process execution logs for a specific set of administrative and Remote Monitoring and Management (RMM) tools. It identifies tools like PsExec, AnyDesk, and ScreenConnect. Rather than alerting on every execution, the first phase filters for rare occurrences across the fleet. This identifies hosts where these tools appear outside of their typical administrative footprint.

The second phase runs two queries in parallel to provide context to the identified tools. The first query searches script activity logs for specific functions associated with network share discovery and Active Directory enumeration. It looks for content like ShareFinder or Get-NetShare that attackers use to find sensitive data or backup servers.

The second parallel query examines network connections to remote management ports such as RDP (3389) and WinRM (5985, 5986). It stacks these connections to find rare outbound patterns. If a host identified in the process phase also shows outbound RDP activity to a server it does not usually manage, the confidence of the finding increases.

Finally, the hunt synthesizes these findings. An analyst or automated agent triages the results by correlating the process, script, and network evidence. This multi-surface approach helps separate an IT administrator performing maintenance from an intruder mapping the network.

### Blind Spots and Limitations
This hunt relies heavily on endpoint visibility. If the adversary pivots from an unmanaged beachhead host—such as a personal laptop or a legacy server without an agent—the initial share enumeration remains invisible. The hunt only detects the activity when the actor interacts with a managed resource.

Additionally, the script analysis uses string matching for known tools and cmdlets. If the adversary uses Base64 encoding or complex character replacement to obfuscate their PowerShell commands, the string-based filters will not catch the activity.

### Why This is a Hunt
Legitimate use of AnyDesk, TeamViewer, or PsExec is common in many enterprises. A standard detection rule for these tools often creates too much noise for a security operations center to handle. This hunt is not a simple alert; it is a structured investigation that requires correlating three different types of evidence to find the signal in the noise.

### How to Run the Hunt
This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any other runtime that supports the hunt.md format. The playbook contains the logic to automate the initial data gathering and provide a structured interface for triage.

# Apache ActiveMQ Post-Exploitation and LockBit Ransomware Hunt

### Why This Hunt Matters

Recent observations by [The DFIR Report](https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/) in "Apache ActiveMQ Exploit Leads to LockBit Ransomware" show a rapid transition from initial access to full impact. Once an adversary exploits CVE-2023-46604, they quickly harvest credentials and move laterally. In one case, the actor deployed LockBit ransomware within 90 minutes of the second intrusion phase. This hunt focuses on identifying that lateral movement and subsequent ransomware execution before encryption is completed.

### Hypothesis

An attacker transitions from an exploited ActiveMQ server to lateral movement via RDP using stolen credentials, ultimately deploying LockBit ransomware from user-writable directories or with specific password-protected execution flags.

### How the Hunt Flows

The hunt begins by scoping the environment to identify systems running Apache ActiveMQ. The first query checks software inventory logs for any host with ActiveMQ installed. This establishes a baseline of potential beachheads where the adversary likely gained their initial foothold.

Next, the hunt enters a parallel analysis phase. It queries authentication logs for RDP connections originating from the scoped ActiveMQ hosts while simultaneously searching for rare process executions. This second search looks for binaries running from the Downloads directory or processes using the `-pass` command-line flag, which is characteristic of LockBit deployments.

An agent then correlates these signals. It links the identified ActiveMQ infrastructure to subsequent RDP logons and suspicious process starts. By grouping these events by host, the hunt provides a clear picture of how the adversary moved through the network and where they attempted to execute their payload.

### Blind Spots

Log rotation is the primary risk for this hunt. If the environment rotates Windows Event Logs in 14 days or less, the initial credential harvesting and movement—which may occur several days before the final impact—will be missing. Additionally, the adversary often uses transient batch files, like `rdp.bat`, to modify firewall rules. If file activity collection is not near real-time, these deleted files may escape detection.

### Why This Is a Hunt, Not a Detection

A standard detection rule might alert on any use of the `-pass` flag, but this often creates noise from legitimate administrative tools. This hunt specifically correlates that flag with ActiveMQ infrastructure and RDP authentication patterns within a targeted lookback window. It transforms broad telemetry into a specific intrusion narrative, distinguishing a targeted campaign from routine maintenance.

### How to Run It

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any other `hunt.md`-aware runtime. It uses standard SQL for queries against endpoint and authentication surfaces. Simply set your lookback period and let the agent triage the results to identify compromised hosts.

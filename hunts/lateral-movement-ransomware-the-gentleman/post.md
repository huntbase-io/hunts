# Hunting The Gentleman Ransomware From RMM Beachhead to GPO Encryption

### Why hunt for The Gentleman ransomware

A recent report by the DFIR Report, [Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware](https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/), details a rapid progression from remote management tools to full domain encryption. The adversary uses legitimate RMM tools like GoTo Resolve and SoftPerfect Network Scanner to establish a beachhead and map the environment. Because these tools often appear in administrative contexts, standard detections may overlook them until the final encryption stage. This hunt provides a structured way to correlate these administrative tools with the high-fidelity signals of a ransomware kill chain.

### The hypothesis

An adversary has moved laterally from an RMM-controlled beachhead using NetExec or GoTo Resolve to dump credentials and exfiltrate data to Wasabi before initiating domain-wide encryption via GPO.

### How the hunt flows

The hunt begins by scoping the environment for portable RMM and network scanning tools. The first query searches the process activity surface for GoTo Resolve or SoftPerfect (NetScan) execution. These tools serve as the primary indicator of where the adversary is active. Finding these binaries on workstations or servers that do not typically run them defines the scope for the subsequent investigative phases.

Once a beachhead is identified, the hunt pivots into a parallel investigation of credential access and lateral movement. The logic looks for LSASS memory dumping using the comsvcs.dll ordinal #24 technique and identifies the execution of tools like Mimikatz or NetExec. To account for renamed binaries, the query checks original file names and looks for specific command-line strings that are rare across the estate. A triage agent then weighs this evidence to produce a per-host verdict.

Following the identification of movement, the hunt looks for evidence of data exfiltration and final-stage impact. The third phase examines DNS activity for lookups to Wasabi cloud storage domains, which the adversary uses alongside Rclone to stage and steal data. Simultaneously, the hunt looks for destructive commands, including the deletion of volume shadow copies and the tampering of Microsoft Defender via PowerShell.

In the final phase, an agent correlates the early movement evidence with the exfiltration and impact findings. This allows an analyst to distinguish between unauthorized IT work and a logical progression of an active ransomware intrusion. If the kill chain is confirmed, the playbook provides immediate containment actions to isolate the affected hosts.

### What the hunt cannot see

This hunt focuses on process and network artifacts. If an adversary executes Mimikatz or NetExec entirely in memory without spawning new processes or leaving command-line strings, these queries will miss the activity. Memory forensics or process injection hooks would be required for that visibility. Additionally, while the hunt identifies the impact of GPO-driven ransomware, it does not audit the Active Directory changes directly. Analysts must manually review Event ID 5136 on domain controllers to confirm when and how a malicious GPO was created.

### How to run the hunt

We provide this hunt as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other hunt.md-aware runtime. You can run the queries against your process and DNS telemetry to find the described behaviors in your environment. If you find matches for the RMM beachhead or destructive commands, follow the included containment steps immediately.

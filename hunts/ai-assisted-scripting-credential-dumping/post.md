# Hunting AI-Generated Script Patterns and VSS Credential Dumping

Adversaries are increasingly using Large Language Models (LLMs) to overcome tactical hurdles during active intrusions. A recent report from Unit 42, [Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America](https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/), highlights how clusters like CL-CRI-1131 use AI for rapid troubleshooting. This results in a distinct 'trial and error' behavioral footprint, characterized by sequentially named scripts and binary iterations that traditional, static detections often overlook.

### The Hypothesis
Our hypothesis is that an intruder, following an initial beachhead via phishing, is using iterative, LLM-generated scripts to conduct credential dumping and deploy proxy tools. We expect to see a pattern of sequential batch files (e.g., 1.bat, 2.bat) or scripts with filenames reflecting LLM temperature settings or output types (e.g., _creative.py, _focused.py) alongside high-signal activity like Volume Shadow Copy (VSS) abuse.

### How the Hunt Flows
The hunt begins by scoping the active Windows estate. Because the primary goal of these campaigns is often the dumping of SAM or NTDS.dit files for credential harvesting, we first isolate hosts where `vssadmin` or `ntdsutil` have been used to create shadow copies. This provides a high-signal starting point for deeper investigation.

Once a candidate host is identified, we move into a parallel investigation phase. We look for the 'trial and error' naming convention in process logs, specifically searching for rare, sequentially numbered batch files and scripts containing AI-specific adjectives in their filenames. This pattern is a direct artifact of an attacker using an LLM to generate code, running it, hitting an error, and asking the LLM for a revised version.

Simultaneously, we enrich the host data by checking for known hashes and process names associated with the SockTz Go-based proxy, a common tool in the Brazilian activity cluster. Finally, we pivot back to identify potential initial access vectors by looking for resume-themed file activity in landing zones like Downloads or Desktop folders, which often precede these script execution patterns.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, without enhanced script block logging (such as PowerShell 4104) or command-line auditing, we only see the filename of the iterative scripts, not the logic contained within. If an attacker deletes the scripts immediately after execution, the 'why' of the troubleshooting becomes harder to reconstruct. Second, if shadow copies are created and then deleted immediately after a copy operation, point-in-time forensic tools may miss the transient existence of the VSS artifact.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any hunt.md-aware runtime. By automating the correlation between high-signal credential dumping and low-signal naming patterns, practitioners can identify human-in-the-loop AI orchestration that a standard detection rule might miss as a series of unrelated events.

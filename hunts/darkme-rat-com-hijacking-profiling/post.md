# DarkMe RAT: COM Hijacking and Application Profiling

### Why this hunt
Huntress recently detailed the evolution of DarkMe (also known as Water Hydra) in their report "DarkMe RAT Abandons Exploits" (https://www.huntress.com/blog/darkme-rat-abandons-exploits). While this APT group previously relied on zero-day vulnerabilities, the adversary now uses a sophisticated multi-stage VB6 loader to deliver their infostealer. This shift highlights a move toward stealthy, living-off-the-land techniques that evade traditional file-based detection.

### Hypothesis
The adversary establishes persistence and stealthy execution by hijacking a COM object through a script and launching it with the rundll32 /sta flag. Following this, the malware performs broad profiling of local financial, crypto, and security applications to identify valuable data for exfiltration.

### Hunt Flow
The hunt begins by scoping the environment for the exemsi MSI Wrapper version 11.0.53.0. DarkMe campaigns use this specific wrapper version for initial delivery. Identifying hosts with this software narrows the search to the most likely beachheads for further investigation.

The second phase identifies the core loader activity through two parallel queries. One query searches for script activity involving Windows Script Host (.wsf) files that import the target CLSID ({CFDC57BA-1705-45AF-BA10-EFC3D592982B}) into the registry. The other query looks for rundll32.exe processes using the /sta flag. This flag initializes a Single Threaded Apartment, which is a requirement for the VB6-based COM server. When an analyst finds both events on the same host, it confirms a successful COM hijacking.

The third phase investigates persistence. The adversary registers a custom "Locked" protocol handler under the classes registry hive and adds entries to the standard Run keys. These entries point to the rundll32 /sta command line, ensuring the malware executes whenever the user logs in or a specific protocol is invoked.

The final phase uses stack-counting to find the malware's functional modules. The adversary stages files like Coconout.dll and Use.dll in the AppData\ComponentsFolder. Because legitimate applications rarely use this specific folder name for executable components, we stack-count every binary in this path across the fleet. Binaries that appear on only one or two hosts are highly suspicious and likely represent the DarkMe RAT modules.

This is a hunt because it pivots between four distinct surfaces—script activity, registry keys, process command lines, and binary prevalence—to reconstruct a chain that evades single-surface detection rules.

### Blind Spots
This hunt has two primary blind spots. First, it requires robust script block logging and registry auditing. If the environment does not capture the content of script executions or registry changes, the analyst must rely solely on the rundll32 process command lines. Second, while the hunt identifies that profiling is occurring, the specific list of 329 targeted applications is hex-encoded inside the malware's binary. An analyst must perform forensic analysis of the Zeta_Component.log file to see which applications the malware actually found on a specific host.

### How to run it
This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook automates the scoping, the parallel loader checks, and the prevalence analysis, allowing you to triage the entire estate for DarkMe persistence markers in a single workflow.

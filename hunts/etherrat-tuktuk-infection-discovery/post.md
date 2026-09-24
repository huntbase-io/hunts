# Hunting EtherRAT and TukTuk Initial Infection and Discovery

### Why now

The DFIR Report recently detailed an intrusion where EtherRAT and TukTuk C2 activity preceded a ransomware deployment. Their report, [Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware](https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/), highlights how an attacker uses trojanized software to gain a foothold. The actor often hides the malware inside an MSI installer masquerading as a legitimate system utility like RAMMap. We built this hunt to find these specific execution chains in telemetry before the final ransomware phase begins.

### The Hypothesis

An intruder gains initial access via a trojanized MSI installer, establishes persistence using a Node.js-based EtherRAT, and performs system discovery or sideloads TukTuk payloads.

### How the hunt flows

The hunt begins by scoping endpoints for suspicious MSI execution. The first query looks for msiexec.exe spawning command shells or specific scripts like mvnvmuyj.cmd. This step identifies the initial delivery of the malicious payload where the MSI installer executes embedded logic to drop follow-on components.

Next, the hunt moves into a parallel phase to find persistence and deployment markers. One query searches for the creation of portable Node.js runtimes and configuration files in user AppData or Temp folders. Simultaneously, another query identifies rare registry Run keys that point to these profile-path binaries. This correlation helps distinguish legitimate Node.js usage from the EtherRAT installation, as the intruder typically places the runtime in a randomized folder under the user's local profile.

If the early infection markers exist, the hunt investigates post-compromise activity. It searches for automated reconnaissance scripts that enumerate security products or domain settings, often using PowerShell to check for specific antivirus products. Finally, the hunt looks for legitimate binaries, such as Greenshot or SyncTrayzor, loading rare modules from user-writable paths to identify TukTuk sideloading. The adversary uses these trusted processes to host their C2 communication modules.

### What the hunt cannot see

This hunt relies on module load visibility to detect sideloading. If an endpoint does not provide hb_module_activity telemetry, the sideloaded TukTuk payload remains hidden from those specific steps. Additionally, adversaries may split discovery commands across multiple script blocks. If your telemetry does not support script block reassembly, simple keyword matches might fail to catch fragmented reconnaissance activity. The hunt also assumes the intruder follows the reported MSI-to-Node.js path; if they use a different initial access vector, the scoping step will show no results.

### How to run it

This hunt is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The design uses parameterized lookbacks and host scoping. You can run the initial MSI check across the fleet and then use those results to narrow your focus for the more resource-intensive module and registry queries. The playbook includes a human-in-the-loop triage step where an analyst confirms the transition from persistence to active reconnaissance.

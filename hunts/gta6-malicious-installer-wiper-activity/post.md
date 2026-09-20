# Hunt for Fake GTA6 Installers and Chaos Wiper Activity

### Why This Hunt Matters

Adversaries frequently exploit major cultural events and software releases to bypass technical controls through social engineering. In a recent analysis titled [Grand Theft Auto VI hype leads to malware](https://www.huntress.com/blog/fake-gta6-download-malware-analysis), Huntress researchers detailed a campaign using fake GTA6 installers to deploy remote access trojans (RATs) and the Chaos wiper. Unlike traditional ransomware, this wiper family often destroys data permanently while masquerading as an extortion attempt.

### The Hypothesis

An intruder exploits GTA6 hype to deploy a fake installer that stages multiple RATs and executes a destructive wiper masquerading as ransomware. The adversary relies on users having administrative privileges to execute the final destructive payload, which overwrites files larger than 200MB with random bytes.

### How the Hunt Flows

The first phase identifies Windows hosts and scans process telemetry for known malicious filenames. The query looks for executables like gta6installer.exe or the presence of checkinternetconnection.bat in command-line arguments. This initial lead provides a list of potentially compromised endpoints without scanning the entire estate for generic behavior.

Once a lead is identified, the hunt evaluates the process context. The analyst or an automated agent reviews the results to determine if the activity matches the reported campaign. This gate ensures that resource-intensive queries only run on hosts with a high probability of infection.

Following a positive lead, the hunt fans out to look for secondary staging and impact artifacts in parallel. One branch searches for rare binaries executing from writable user directories like ProgramData or AppData. A second branch monitors file activity for the creation of read_it.txt, the specific ransom note dropped by the Chaos wiper family.

In the final phase, the hunt synthesizes these findings. An analyst confirms the verdict by correlating the initial lure with the presence of rare staged binaries and confirmed file destruction. This multi-surface view separates a blocked download from a successful, destructive compromise.

### Blind Spots

This hunt depends heavily on process command-line logging. If the environment only provides process names, the adversary can bypass the initial lead query by renaming the installer. Additionally, the malware often deletes its own staging scripts shortly after execution. If telemetry retention is too short or if deletion events are not captured, the hunt may lose the evidence of initial deployment. Finally, without file creation events, the hunt cannot verify if the wiper successfully executed its destructive routine.

### How to Run This Hunt

This hunt is packaged as a `hunt.md` playbook. You can import it directly into Huntbase or any security platform that supports the `hunt.md` standard. The playbook includes the logic to scope the search, gate the expensive queries, and synthesize a final verdict across file and process surfaces.

Source: [Huntress — Grand Theft Auto VI hype leads to malware](https://www.huntress.com/blog/fake-gta6-download-malware-analysis)

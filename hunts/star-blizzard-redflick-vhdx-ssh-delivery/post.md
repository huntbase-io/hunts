# Hunting Star Blizzard RedFlick VHDX and SSH Malware Delivery

### Why Now
Microsoft recently detailed a new infection chain in their article, Star Blizzard refines phishing and malware delivery with the RedFlick technique (https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/). This group, linked to FSB Centre 18, has moved away from simpler delivery methods toward a complex, multi-layered approach that avoids standard file-on-disk detections and relies on native Windows utilities and SSH.

### The Hypothesis
An adversary gains initial access via phishing and uses the RedFlick technique to deliver a backdoor through VHDX-mounted scripts, SSH-based MSI downloads, and CPL-driven scheduled tasks.

### How the Hunt Flows
The hunt begins with a scoping phase to identify workstations with archive and PDF software, such as WinRAR or Acrobat. This inventory provides the necessary context for the analyst when triage begins, as the initial delivery often involves password-protected archives and decoy lures.

The first active phase gathers early infection evidence by monitoring two surfaces in parallel. It searches for HTTP activity directed toward specific mail providers or URLs containing campaign-themed keywords. Simultaneously, it looks for rare conhost.exe instances launching BAT or LNK scripts. This combination suggests a user opened a lure from a mounted VHDX file, which conhost then executes in a hidden window.

The second phase focuses on the technical anchors of the RedFlick delivery and persistence. It queries process activity for ssh.exe used with the PermitLocalCommand=yes option. The adversary uses this specific flag to execute commands and download MSI installers upon connection. At the same time, the hunt searches for scheduled tasks that use control.exe to load .cpl files, which is how the adversary maintains persistence and loads the final loader.

Finally, the hunt uses an automated analysis step to correlate these signals. It bridges the gap between the initial network contact and the subsequent process behavior to confirm if a host has progressed through the entire RedFlick chain.

### Blind Spots
This hunt lacks direct visibility into the specific VHDX volume mount events (Windows Event ID 12) unless the environment collects volume telemetry. While we see the resulting script execution, we cannot always link it to a specific file name on the mounted drive. Additionally, if the adversary deletes the MSI installer immediately after the scheduled task is created, identifying the specific payload hash depends on having file-write telemetry or forensic remnants in the user's temporary directories.

### How to Run It
This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. The playbook includes automated triage steps and logic to route confirmed compromises for host isolation and session revocation.

# Hunting UNK_DeadDrop RAT Activity in Developer Environments

### Why Now
Proofpoint recently published a report titled "Don’t Fear the Repo: UNK_DeadDrop Phishing Campaign Targets Developers to Steal" (https://www.proofpoint.com/us/blog/threat-insight/dont-fear-repo-unkdeaddrop-phishing-campaign-targets-developers-steal). The report details a DPRK-aligned cluster targeting developers via malicious Git repositories and VSIX extensions. The primary payload is 'Overlord,' a Go-based RAT designed to exfiltrate sensitive assets before performing a destructive cleanup to hide its tracks.

### The Hypothesis
An intruder has deployed a cross-platform RAT within developer workspaces, likely disguised as a legitimate Google update service. This RAT is currently exfiltrating browser-stored credentials and cryptocurrency wallets while performing anti-forensic cleanup by deleting the developer's source files and environment variables.

### How the Hunt Flows

**Scoping Developer Assets**
We begin by identifying high-value targets within the estate. This step uses software inventory data to isolate hosts running development tools like VS Code or Cursor. Since the campaign specifically targets these environments, narrowing the scope ensures the hunt remains performant and minimizes noise from standard office workstations.

**Identifying Lead Indicators**
The hunt then searches for the Overlord RAT binary. It looks for Go-based processes or binaries with 'Google update' descriptions running from user-writable directories that should not contain such executables, specifically `.vscode` and `node_modules`. This focuses on the behavioral anomaly of execution location rather than just file hash.

**Corroborating Network and Credential Access**
Once suspicious processes are identified, we pivot to network and file activity. We look for outbound DNS queries to known campaign C2 domains originating from IDE child processes. Simultaneously, we inspect file activity for non-browser processes—such as custom Go binaries or shell interpreters—accessing sensitive browser 'Login Data' or crypto wallet extension directories.

**Detecting Anti-Forensic Cleanup**
The final phase monitors for the RAT's 'cleanup' module. We look for a high volume of file deletions affecting source code (`.go`, `.py`, `.js`) and `.env` files. If these deletions are performed by a process other than `git` within a short window, it provides strong evidence of the Overlord RAT attempting to erase the evidence of its presence.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, if the underlying telemetry only records file 'open' or 'update' events without specific 'read' activity, we may capture noise from legitimate tools and require manual verification. Second, because the Overlord RAT's cleanup module is designed to delete the malware binary itself, ephemeral process execution may be missed if historical process logging is not enabled or if the binary exists for only a few seconds.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported directly into Huntbase or any other `hunt.md`-aware runtime. Because this is a hunt rather than a simple detection, it relies on correlating multiple weak signals—such as file paths, process descriptions, and deletion counts—to build a high-confidence verdict.
